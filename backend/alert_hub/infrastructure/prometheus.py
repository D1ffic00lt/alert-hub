from __future__ import annotations

import asyncio
import base64
import json
import math
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import httpx

from alert_hub.domain.monitoring import job_globs_to_re2
from alert_hub.infrastructure.url_safety import Resolver, UnsafeURL, validate_monitoring_url
from alert_hub.settings import Settings

type FixedQueryName = Literal[
    "connection_test",
    "reachability",
    "firing_alerts",
    "key_jobs_up",
    "alert_hub_health",
]

FIXED_PROMQL: dict[FixedQueryName, str] = {
    "connection_test": "vector(1)",
    "reachability": "probe_success",
    "firing_alerts": 'ALERTS{alertstate="firing"}',
    "key_jobs_up": 'up{job=~"prometheus|alertmanager|blackbox.*"}',
    "alert_hub_health": 'up{job=~"alert[-_]?hub.*"}',
}


def fixed_promql(query_name: FixedQueryName, job_globs: Sequence[str] | None = None) -> str:
    if job_globs is None:
        return FIXED_PROMQL[query_name]
    if query_name not in {"key_jobs_up", "alert_hub_health"}:
        raise ValueError(f"{query_name} does not accept job patterns")
    regex = job_globs_to_re2(job_globs)
    return f"up{{job=~{json.dumps(regex)}}}"


@dataclass(frozen=True, slots=True)
class VectorSample:
    labels: dict[str, str]
    value: float
    timestamp: datetime


class PrometheusQueryError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail[:1_000]
        super().__init__(self.detail)


class PrometheusClient(Protocol):
    def validate_url(self, value: str) -> str: ...

    async def query(
        self,
        url: str,
        credentials: Mapping[str, Any],
        query_name: FixedQueryName,
        *,
        job_globs: Sequence[str] | None = None,
    ) -> list[VectorSample]: ...


def parse_vector_response(payload: object, *, max_samples: int) -> list[VectorSample]:
    if not isinstance(payload, dict):
        raise PrometheusQueryError("invalid_response", "Prometheus response must be an object")
    if payload.get("status") != "success":
        error_type = str(payload.get("errorType") or "query_failed")
        error = str(payload.get("error") or "Prometheus query failed")
        raise PrometheusQueryError(error_type, error)
    data = payload.get("data")
    if not isinstance(data, dict) or data.get("resultType") != "vector":
        raise PrometheusQueryError(
            "invalid_result_type", "Prometheus query did not return an instant vector"
        )
    result = data.get("result")
    if not isinstance(result, list):
        raise PrometheusQueryError("invalid_response", "Prometheus vector result must be a list")
    if len(result) > max_samples:
        raise PrometheusQueryError("too_many_samples", "Prometheus result exceeds the sample limit")
    samples: list[VectorSample] = []
    for index, raw in enumerate(result):
        if not isinstance(raw, dict):
            raise PrometheusQueryError(
                "invalid_sample", f"Prometheus sample {index} must be an object"
            )
        metric = raw.get("metric")
        value = raw.get("value")
        if not isinstance(metric, dict) or not isinstance(value, list) or len(value) != 2:
            raise PrometheusQueryError(
                "invalid_sample", f"Prometheus sample {index} has an invalid shape"
            )
        try:
            timestamp = float(value[0])
            sample_value = float(value[1])
        except (TypeError, ValueError) as exc:
            raise PrometheusQueryError(
                "invalid_sample", f"Prometheus sample {index} has a non-numeric value"
            ) from exc
        if not math.isfinite(timestamp) or not math.isfinite(sample_value):
            raise PrometheusQueryError(
                "invalid_sample", f"Prometheus sample {index} contains a non-finite value"
            )
        try:
            occurred_at = datetime.fromtimestamp(timestamp, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise PrometheusQueryError(
                "invalid_sample", f"Prometheus sample {index} has an invalid timestamp"
            ) from exc
        labels = {str(key): str(label) for key, label in metric.items()}
        samples.append(VectorSample(labels=labels, value=sample_value, timestamp=occurred_at))
    return samples


class PrometheusHTTPClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver = socket.getaddrinfo,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self.resolver = resolver

    def validate_url(self, value: str) -> str:
        return validate_monitoring_url(
            value,
            allow_http=self.settings.allow_http_monitoring_urls,
            allow_private=self.settings.allow_private_monitoring_urls,
            resolver=self.resolver,
        )

    def _timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.settings.prometheus_connect_timeout_seconds,
            read=self.settings.prometheus_read_timeout_seconds,
            write=self.settings.prometheus_write_timeout_seconds,
            pool=self.settings.prometheus_pool_timeout_seconds,
        )

    @staticmethod
    def _authorization(
        credentials: Mapping[str, Any],
    ) -> tuple[dict[str, str], httpx.BasicAuth | None]:
        auth_type = str(credentials.get("auth_type") or "none")
        if auth_type == "bearer":
            token = str(credentials.get("bearer_token") or "")
            if not token:
                raise PrometheusQueryError("credentials", "Bearer credentials are incomplete")
            return {"Authorization": f"Bearer {token}"}, None
        if auth_type == "basic":
            username = str(credentials.get("username") or "")
            password = str(credentials.get("password") or "")
            if not username or not password:
                raise PrometheusQueryError("credentials", "Basic credentials are incomplete")
            # httpx.BasicAuth prevents accidental line-break/header injection and follows RFC 7617.
            return {}, httpx.BasicAuth(username, password)
        if auth_type != "none":
            raise PrometheusQueryError("credentials", "Unsupported datasource authentication mode")
        return {}, None

    async def query(
        self,
        url: str,
        credentials: Mapping[str, Any],
        query_name: FixedQueryName,
        *,
        job_globs: Sequence[str] | None = None,
    ) -> list[VectorSample]:
        # Repeat DNS/address validation immediately before every request. Redirects are never
        # followed, which closes the common public-to-private redirect bypass.
        try:
            # System DNS resolution is blocking. Keep it off the sole MVP event loop so a slow
            # resolver cannot stall ingest, health, and notification work on this node.
            normalized = await asyncio.to_thread(self.validate_url, url)
        except UnsafeURL as exc:
            raise PrometheusQueryError("unsafe_url", str(exc)) from exc
        headers, auth = self._authorization(credentials)
        headers["Accept"] = "application/json"
        query_url = f"{normalized.rstrip('/')}/api/v1/query"
        params = {
            "query": fixed_promql(query_name, job_globs),
            "timeout": f"{self.settings.prometheus_query_timeout_seconds:g}s",
        }
        try:
            async with (
                httpx.AsyncClient(
                    transport=self.transport,
                    timeout=self._timeout(),
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    "GET",
                    query_url,
                    params=params,
                    headers=headers,
                    auth=auth,
                ) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise PrometheusQueryError(
                        "redirect_rejected", "Prometheus redirects are not allowed"
                    )
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self.settings.prometheus_max_response_bytes:
                        raise PrometheusQueryError(
                            "response_too_large", "Prometheus response exceeds the byte limit"
                        )
                if response.status_code in {401, 403}:
                    raise PrometheusQueryError(
                        "authentication_failed", "Prometheus rejected datasource credentials"
                    )
                if response.status_code < 200 or response.status_code >= 300:
                    raise PrometheusQueryError(
                        "http_error", f"Prometheus returned HTTP {response.status_code}"
                    )
        except PrometheusQueryError:
            raise
        except httpx.TimeoutException as exc:
            raise PrometheusQueryError("timeout", "Prometheus request timed out") from exc
        except httpx.HTTPError as exc:
            raise PrometheusQueryError("transport", "Prometheus request failed") from exc
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PrometheusQueryError("invalid_json", "Prometheus returned invalid JSON") from exc
        return parse_vector_response(
            payload,
            max_samples=self.settings.prometheus_max_samples,
        )


def basic_authorization_value(username: str, password: str) -> str:
    """Small test/documentation helper for verifying Basic auth without logging secrets."""

    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {encoded}"
