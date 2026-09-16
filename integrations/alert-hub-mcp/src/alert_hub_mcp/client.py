from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Mapping, Sequence
from typing import Any
from uuid import uuid4

import httpx

from alert_hub_mcp.config import MCPSettings, NodeConfig

_ERROR_CODES = {
    401: "authentication_failed",
    403: "permission_denied",
    404: "not_found",
    422: "invalid_request",
    429: "rate_limited",
}


class AlertHubClient:
    """Bounded read-only HTTP client for operator-configured Alert Hub nodes."""

    def __init__(
        self,
        settings: MCPSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self._transport = transport

    def configured_nodes(self) -> list[dict[str, str]]:
        return [{"name": node.name, "base_url": node.base_url} for node in self.settings.nodes]

    async def get_all(
        self,
        path: str,
        *,
        params: Mapping[str, str | int | bool] | None = None,
        node: str | None = None,
    ) -> dict[str, Any]:
        selected, selection_error = self._select_nodes(node)
        if selection_error is not None:
            return selection_error
        results = await asyncio.gather(
            *(self._request(candidate, path, params=params) for candidate in selected)
        )
        return _envelope(list(results))

    async def get_many(
        self,
        requests: Sequence[tuple[str, str, Mapping[str, str | int | bool] | None]],
        *,
        node: str | None = None,
    ) -> dict[str, dict[str, Any]]:
        selected, selection_error = self._select_nodes(node)
        if selection_error is not None:
            return {name: selection_error for name, _, _ in requests}
        semaphore = asyncio.Semaphore(8)

        async def bounded_request(
            candidate: NodeConfig,
            path: str,
            params: Mapping[str, str | int | bool] | None,
        ) -> dict[str, Any]:
            async with semaphore:
                return await self._request(candidate, path, params=params)

        tasks = [
            bounded_request(candidate, path, params)
            for _, path, params in requests
            for candidate in selected
        ]
        raw_results = await asyncio.gather(*tasks)
        width = len(selected)
        return {
            request_name: _envelope(list(raw_results[index * width : (index + 1) * width]))
            for index, (request_name, _, _) in enumerate(requests)
        }

    def _select_nodes(
        self, node: str | None
    ) -> tuple[tuple[NodeConfig, ...], dict[str, Any] | None]:
        if node is None:
            return self.settings.nodes, None
        selected = tuple(candidate for candidate in self.settings.nodes if candidate.name == node)
        if selected:
            return selected, None
        return (), {
            "status": "configuration_error",
            "nodes": [],
            "error": {
                "code": "unknown_node",
                "detail": f"Unknown node {node!r}; use one returned by list_configured_nodes",
            },
        }

    def _verify(self) -> ssl.SSLContext | bool:
        if self.settings.ca_bundle is None:
            return True
        return ssl.create_default_context(cafile=self.settings.ca_bundle)

    async def _request(
        self,
        node: NodeConfig,
        path: str,
        *,
        params: Mapping[str, str | int | bool] | None,
    ) -> dict[str, Any]:
        request_id = str(uuid4())
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.settings.token}",
            "User-Agent": "alert-hub-mcp/0.1",
            "X-Request-ID": request_id,
        }
        timeout = httpx.Timeout(self.settings.timeout_seconds)
        try:
            async with (
                httpx.AsyncClient(
                    timeout=timeout,
                    follow_redirects=False,
                    trust_env=False,
                    verify=self._verify(),
                    transport=self._transport,
                ) as client,
                client.stream(
                    "GET",
                    f"{node.base_url}{path}",
                    params=params,
                    headers=headers,
                ) as response,
            ):
                body = await self._bounded_body(response)
        except httpx.TimeoutException:
            return _request_error(node, request_id, "request_timeout", "Alert Hub timed out")
        except httpx.ConnectError:
            return _request_error(
                node,
                request_id,
                "connection_failed",
                "Could not connect to Alert Hub",
            )
        except httpx.RequestError:
            return _request_error(
                node,
                request_id,
                "request_failed",
                "Alert Hub request failed before a response was received",
            )
        except ValueError as exc:
            return _request_error(node, request_id, "response_too_large", str(exc))

        response_request_id = response.headers.get("x-request-id") or request_id
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _request_error(
                node,
                response_request_id,
                "invalid_response",
                "Alert Hub returned a non-JSON response",
                http_status=response.status_code,
            )
        if not 200 <= response.status_code < 300:
            code = _ERROR_CODES.get(
                response.status_code,
                "alert_hub_unavailable" if response.status_code >= 500 else "http_error",
            )
            result = _request_error(
                node,
                response_request_id,
                code,
                _safe_detail(data),
                http_status=response.status_code,
            )
            result["data"] = data
            retry_after = response.headers.get("retry-after")
            if retry_after:
                result["error"]["retry_after"] = retry_after
            return result
        return {
            "node": node.name,
            "base_url": node.base_url,
            "ok": True,
            "http_status": response.status_code,
            "request_id": response_request_id,
            "data": data,
        }

    async def _bounded_body(self, response: httpx.Response) -> bytes:
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                declared = 0
            if declared > self.settings.max_response_bytes:
                raise ValueError("Alert Hub response exceeded the configured byte limit")
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self.settings.max_response_bytes:
                raise ValueError("Alert Hub response exceeded the configured byte limit")
            chunks.append(chunk)
        return b"".join(chunks)


def _safe_detail(data: Any) -> str:
    if isinstance(data, dict):
        detail = data.get("detail")
        if isinstance(detail, str):
            return detail[:1_000]
        if detail is not None:
            return json.dumps(detail, ensure_ascii=False, default=str)[:1_000]
    return "Alert Hub rejected the request"


def _request_error(
    node: NodeConfig,
    request_id: str,
    code: str,
    detail: str,
    *,
    http_status: int | None = None,
) -> dict[str, Any]:
    return {
        "node": node.name,
        "base_url": node.base_url,
        "ok": False,
        "http_status": http_status,
        "request_id": request_id,
        "error": {"code": code, "detail": detail},
    }


def _envelope(results: list[dict[str, Any]]) -> dict[str, Any]:
    available = sum(bool(result.get("ok")) for result in results)
    if not results or available == 0:
        status = "unavailable"
    elif available != len(results):
        status = "partial"
    else:
        embedded_states = {
            str(data.get("data_state") or data.get("status") or "ok")
            for result in results
            if isinstance((data := result.get("data")), dict)
        }
        if embedded_states and embedded_states <= {"unavailable"}:
            status = "unavailable"
        elif embedded_states & {"partial", "unavailable"}:
            status = "partial"
        else:
            status = "ok"
    return {"status": status, "nodes": results}
