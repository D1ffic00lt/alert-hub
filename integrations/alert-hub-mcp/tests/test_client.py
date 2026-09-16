from __future__ import annotations

import json

import httpx
import pytest

from alert_hub_mcp.client import AlertHubClient
from alert_hub_mcp.config import MCPSettings, NodeConfig


def settings(*nodes: NodeConfig, max_response_bytes: int = 65_536) -> MCPSettings:
    return MCPSettings(
        nodes=nodes,
        token=f"ahs_{'1' * 36}.secret",
        max_response_bytes=max_response_bytes,
    )


@pytest.mark.asyncio
async def test_get_all_preserves_per_node_results_and_auth_header() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "down.example":
            return httpx.Response(503, json={"detail": "Database is busy"})
        return httpx.Response(200, json={"status": "ok"}, headers={"x-request-id": "up-1"})

    client = AlertHubClient(
        settings(
            NodeConfig("down", "https://down.example"),
            NodeConfig("up", "https://up.example"),
        ),
        transport=httpx.MockTransport(handler),
    )

    result = await client.get_all("/api/v1/cluster/status")

    assert result["status"] == "partial"
    assert [node["ok"] for node in result["nodes"]] == [False, True]
    assert result["nodes"][0]["error"]["code"] == "alert_hub_unavailable"
    assert result["nodes"][0]["data"] == {"detail": "Database is busy"}
    assert result["nodes"][1]["request_id"] == "up-1"
    assert {request.headers["authorization"] for request in requests} == {
        f"Bearer ahs_{'1' * 36}.secret"
    }
    assert all(request.method == "GET" for request in requests)


@pytest.mark.asyncio
async def test_unknown_node_is_a_structured_configuration_error() -> None:
    client = AlertHubClient(settings(NodeConfig("only", "https://only.example")))

    result = await client.get_all("/api/v1/incidents", node="missing")

    assert result == {
        "status": "configuration_error",
        "nodes": [],
        "error": {
            "code": "unknown_node",
            "detail": "Unknown node 'missing'; use one returned by list_configured_nodes",
        },
    }


@pytest.mark.asyncio
async def test_invalid_and_oversized_responses_fail_closed() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/invalid"):
            return httpx.Response(200, content=b"not-json")
        return httpx.Response(200, content=json.dumps({"value": "x" * 1_000}).encode())

    client = AlertHubClient(
        settings(NodeConfig("one", "https://one.example"), max_response_bytes=100),
        transport=httpx.MockTransport(handler),
    )

    invalid = await client.get_all("/invalid")
    oversized = await client.get_all("/large")

    assert invalid["nodes"][0]["error"]["code"] == "invalid_response"
    assert oversized["nodes"][0]["error"]["code"] == "response_too_large"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_type", "error_code"),
    [
        (httpx.ReadTimeout, "request_timeout"),
        (httpx.ConnectError, "connection_failed"),
        (httpx.ReadError, "request_failed"),
    ],
)
async def test_transport_failures_are_redacted(exception_type, error_code) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise exception_type("sensitive transport detail", request=request)

    client = AlertHubClient(
        settings(NodeConfig("one", "https://one.example")),
        transport=httpx.MockTransport(handler),
    )

    result = await client.get_all("/api/v1/incidents")

    assert result["status"] == "unavailable"
    assert result["nodes"][0]["error"]["code"] == error_code
    assert "sensitive" not in result["nodes"][0]["error"]["detail"]


@pytest.mark.asyncio
async def test_http_error_maps_code_detail_and_retry_after() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            json={"detail": {"code": "busy", "wait": 2}},
            headers={"retry-after": "2"},
        )

    client = AlertHubClient(
        settings(NodeConfig("one", "https://one.example")),
        transport=httpx.MockTransport(handler),
    )

    result = await client.get_all("/api/v1/incidents")

    error = result["nodes"][0]["error"]
    assert error["code"] == "rate_limited"
    assert error["retry_after"] == "2"
    assert "busy" in error["detail"]
