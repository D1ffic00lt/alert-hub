from __future__ import annotations

import asyncio
import base64
import json
import math
import re
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import httpx

from alert_hub.domain.monitoring import job_globs_to_re2
from alert_hub.infrastructure.url_safety import Resolver, UnsafeURL, validate_monitoring_url
from alert_hub.settings import Settings

type PublicQueryName = Literal[
    "connection_test",
    "reachability",
    "firing_alerts",
    "key_jobs_up",
    "alert_hub_health",
]
type CheckQueryName = Literal[
    "check_info",
    "check_state",
    "check_status",
    "check_last_run",
    "check_canary_success",
    "check_target_success",
    "check_target_state",
    "check_duration",
    "check_ttfb",
    "check_egress_state",
    "check_egress_match",
    "check_errors_total",
]
type AvailabilityQueryName = Literal[
    "availability_average_24h",
    "availability_average_7d",
    "availability_average_30d",
    "availability_samples_24h",
    "availability_samples_7d",
    "availability_samples_30d",
    "availability_last_sample_24h",
    "availability_last_sample_7d",
    "availability_last_sample_30d",
]
type FixedQueryName = PublicQueryName | CheckQueryName | AvailabilityQueryName
type ReachabilityLabelMode = Literal["canonical", "server"]

REACHABILITY_PROMQL: dict[ReachabilityLabelMode, str] = {
    "canonical": 'probe_success{source_region!="",target_name!=""}',
    "server": 'probe_success{source_server!="",target_server!=""}',
}

FIXED_PROMQL: dict[FixedQueryName, str] = {
    "connection_test": "vector(1)",
    "reachability": REACHABILITY_PROMQL["canonical"],
    "firing_alerts": 'ALERTS{alertstate="firing"}',
    "key_jobs_up": 'up{job=~"prometheus|alertmanager|blackbox.*"}',
    "alert_hub_health": 'up{job=~"alert[-_]?hub.*"}',
    "check_info": "synthetic_check_info",
    "check_state": "synthetic_check_state",
    "check_status": "synthetic_check_status",
    "check_last_run": "synthetic_check_last_run_timestamp_seconds",
    "check_canary_success": "synthetic_check_canary_success",
    "check_target_success": "synthetic_check_target_success",
    "check_target_state": "synthetic_check_target_state",
    "check_duration": "synthetic_check_duration_seconds",
    "check_ttfb": "synthetic_check_ttfb_seconds",
    "check_egress_state": "synthetic_check_egress_state",
    "check_egress_match": "synthetic_check_egress_match",
    "check_errors_total": "synthetic_check_errors_total",
    "availability_average_24h": "avg_over_time(probe_success[24h])",
    "availability_average_7d": "avg_over_time(probe_success[7d])",
    "availability_average_30d": "avg_over_time(probe_success[30d])",
    "availability_samples_24h": "count_over_time(probe_success[24h])",
    "availability_samples_7d": "count_over_time(probe_success[7d])",
    "availability_samples_30d": "count_over_time(probe_success[30d])",
    "availability_last_sample_24h": "timestamp(last_over_time(probe_success[24h]))",
    "availability_last_sample_7d": "timestamp(last_over_time(probe_success[7d]))",
    "availability_last_sample_30d": "timestamp(last_over_time(probe_success[30d]))",
}

AVAILABILITY_QUERY_NAMES: dict[
    Literal["24h", "7d", "30d"],
    tuple[AvailabilityQueryName, AvailabilityQueryName, AvailabilityQueryName],
] = {
    "24h": (
        "availability_average_24h",
        "availability_samples_24h",
        "availability_last_sample_24h",
    ),
    "7d": (
        "availability_average_7d",
        "availability_samples_7d",
        "availability_last_sample_7d",
    ),
    "30d": (
        "availability_average_30d",
        "availability_samples_30d",
        "availability_last_sample_30d",
    ),
}


def fixed_promql(
    query_name: FixedQueryName,
    job_globs: Sequence[str] | None = None,
    *,
    reachability_label_mode: ReachabilityLabelMode | None = None,
) -> str:
    if query_name == "reachability":
        if job_globs is not None:
            raise ValueError("reachability does not accept job patterns")
        return REACHABILITY_PROMQL[reachability_label_mode or "canonical"]
    if reachability_label_mode is not None:
        raise ValueError(f"{query_name} does not accept a reachability label mode")
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


@dataclass(frozen=True, slots=True)
class AlertRule:
    file: str
    group: str
    name: str
    state: Literal["firing", "pending", "inactive"]
    health: str
    firing_instances: int
    pending_instances: int
    last_evaluation: datetime | None
    evaluation_time_seconds: float | None
    last_error: str | None
    labels: dict[str, str]
    annotations: dict[str, str]


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
        reachability_label_mode: ReachabilityLabelMode | None = None,
        evaluated_at: datetime | None = None,
        allow_non_finite_values: bool = False,
    ) -> list[VectorSample]: ...

    async def alert_rules(
        self,
        url: str,
        credentials: Mapping[str, Any],
    ) -> list[AlertRule]: ...


_URL_RE = re.compile(r"(?i)\bhttps?://[^\s\]})>,;]+")
_AUTH_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*[^\s,;]+(?:\s+[^\s,;]+)?"
)
_SECRET_RE = re.compile(
    r"(?i)\b(bearer|password|token|api[-_ ]?key)"
    r"\s*[:=]\s*[^\s,;]+"
)


def safe_upstream_text(value: object, *, limit: int = 500) -> str | None:
    """Return bounded operator context without reflecting upstream addresses or credentials."""

    if not isinstance(value, str) or not value.strip():
        return None
    redacted = _URL_RE.sub("[redacted-url]", value.strip())
    redacted = _AUTH_RE.sub(lambda match: f"{match.group(1)}=[redacted]", redacted)
    redacted = _SECRET_RE.sub(lambda match: f"{match.group(1)}=[redacted]", redacted)
    redacted = " ".join(redacted.split())
    return redacted[:limit] or None


def _bounded_string_map(value: object, *, max_items: int) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    pairs = sorted(
        (key, item)
        for key, item in value.items()
        if isinstance(key, str) and isinstance(item, str) and key
    )
    return {key[:128]: item[:2_048] for key, item in pairs[:max_items]}


def _parse_rule_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_alert_rules_response(
    payload: object,
    *,
    max_rules: int,
    max_instances: int,
) -> list[AlertRule]:
    if not isinstance(payload, dict):
        raise PrometheusQueryError("invalid_response", "Prometheus response must be an object")
    if payload.get("status") != "success":
        raise PrometheusQueryError("rules_failed", "Prometheus rules request failed")
    data = payload.get("data")
    groups = data.get("groups") if isinstance(data, dict) else None
    if not isinstance(groups, list):
        raise PrometheusQueryError("invalid_response", "Prometheus rule groups must be a list")

    parsed: list[AlertRule] = []
    instances_seen = 0
    for group_index, raw_group in enumerate(groups):
        if not isinstance(raw_group, dict):
            raise PrometheusQueryError(
                "invalid_rule_group", f"Prometheus rule group {group_index} must be an object"
            )
        group_name = raw_group.get("name")
        file_name = raw_group.get("file")
        raw_rules = raw_group.get("rules")
        if not isinstance(group_name, str) or not isinstance(raw_rules, list):
            raise PrometheusQueryError(
                "invalid_rule_group", f"Prometheus rule group {group_index} has an invalid shape"
            )
        for rule_index, raw_rule in enumerate(raw_rules):
            if len(parsed) >= max_rules:
                raise PrometheusQueryError(
                    "too_many_rules", "Prometheus rules result exceeds the rule limit"
                )
            if not isinstance(raw_rule, dict) or not isinstance(raw_rule.get("name"), str):
                raise PrometheusQueryError(
                    "invalid_rule",
                    f"Prometheus rule {group_index}:{rule_index} has an invalid shape",
                )
            alerts = raw_rule.get("alerts")
            if alerts is None:
                alerts = []
            if not isinstance(alerts, list):
                raise PrometheusQueryError(
                    "invalid_rule",
                    f"Prometheus rule {group_index}:{rule_index} alerts must be a list",
                )
            instances_seen += len(alerts)
            if instances_seen > max_instances:
                raise PrometheusQueryError(
                    "too_many_samples", "Prometheus rules result exceeds the alert instance limit"
                )
            firing = 0
            pending = 0
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                alert_state = str(alert.get("state") or "").lower()
                firing += alert_state == "firing"
                pending += alert_state == "pending"
            raw_state = str(raw_rule.get("state") or "").lower()
            state: Literal["firing", "pending", "inactive"]
            if firing or raw_state == "firing":
                state = "firing"
            elif pending or raw_state == "pending":
                state = "pending"
            else:
                state = "inactive"
            evaluation_time = raw_rule.get("evaluationTime")
            try:
                parsed_evaluation_time = (
                    float(evaluation_time)
                    if isinstance(evaluation_time, str | int | float)
                    else None
                )
            except (TypeError, ValueError):
                parsed_evaluation_time = None
            if parsed_evaluation_time is not None and (
                not math.isfinite(parsed_evaluation_time) or parsed_evaluation_time < 0
            ):
                parsed_evaluation_time = None
            parsed.append(
                AlertRule(
                    file=file_name if isinstance(file_name, str) else "",
                    group=group_name,
                    name=str(raw_rule["name"]),
                    state=state,
                    health=str(raw_rule.get("health") or "unknown").lower()[:64],
                    firing_instances=firing,
                    pending_instances=pending,
                    last_evaluation=_parse_rule_time(raw_rule.get("lastEvaluation")),
                    evaluation_time_seconds=parsed_evaluation_time,
                    last_error=safe_upstream_text(raw_rule.get("lastError")),
                    labels=_bounded_string_map(raw_rule.get("labels"), max_items=32),
                    annotations=_bounded_string_map(raw_rule.get("annotations"), max_items=16),
                )
            )
    return parsed


def parse_vector_response(
    payload: object,
    *,
    max_samples: int,
    allow_non_finite_values: bool = False,
) -> list[VectorSample]:
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
        if not math.isfinite(timestamp) or (
            not allow_non_finite_values and not math.isfinite(sample_value)
        ):
            raise PrometheusQueryError(
                "invalid_sample", f"Prometheus sample {index} contains a non-finite value"
            )
        try:
            occurred_at = datetime.fromtimestamp(timestamp, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise PrometheusQueryError(
                "invalid_sample", f"Prometheus sample {index} has an invalid timestamp"
            ) from exc
        # Prometheus label names and values are strings. Do not turn malformed JSON values
        # such as `null` into plausible public identifiers (for example, the string "None").
        # Dropping the malformed pair lets the Checks allowlist reject a missing `check_id`
        # without leaking or inventing data, while unknown well-formed labels remain harmless.
        labels = {
            key: label
            for key, label in metric.items()
            if isinstance(key, str) and isinstance(label, str)
        }
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

    async def _request_json(
        self,
        url: str,
        credentials: Mapping[str, Any],
        path: str,
        *,
        params: Mapping[str, str],
    ) -> object:
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
        request_url = f"{normalized.rstrip('/')}{path}"
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
                    request_url,
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
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PrometheusQueryError("invalid_json", "Prometheus returned invalid JSON") from exc

    async def query(
        self,
        url: str,
        credentials: Mapping[str, Any],
        query_name: FixedQueryName,
        *,
        job_globs: Sequence[str] | None = None,
        reachability_label_mode: ReachabilityLabelMode | None = None,
        evaluated_at: datetime | None = None,
        allow_non_finite_values: bool = False,
    ) -> list[VectorSample]:
        params = {
            "query": fixed_promql(
                query_name,
                job_globs,
                reachability_label_mode=reachability_label_mode,
            ),
            "timeout": f"{self.settings.prometheus_query_timeout_seconds:g}s",
        }
        if evaluated_at is not None:
            params["time"] = evaluated_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        payload = await self._request_json(
            url,
            credentials,
            "/api/v1/query",
            params=params,
        )
        return parse_vector_response(
            payload,
            max_samples=self.settings.prometheus_max_samples,
            allow_non_finite_values=allow_non_finite_values,
        )

    async def alert_rules(
        self,
        url: str,
        credentials: Mapping[str, Any],
    ) -> list[AlertRule]:
        payload = await self._request_json(
            url,
            credentials,
            "/api/v1/rules",
            params={"type": "alert"},
        )
        return parse_alert_rules_response(
            payload,
            max_rules=self.settings.prometheus_max_samples,
            max_instances=self.settings.prometheus_max_samples,
        )


def basic_authorization_value(username: str, password: str) -> str:
    """Small test/documentation helper for verifying Basic auth without logging secrets."""

    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {encoded}"
