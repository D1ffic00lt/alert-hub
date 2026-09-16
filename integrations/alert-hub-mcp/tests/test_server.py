from __future__ import annotations

import httpx
import pytest
from mcp import Client

from alert_hub_mcp.client import AlertHubClient
from alert_hub_mcp.config import MCPSettings, NodeConfig
from alert_hub_mcp.server import create_server


@pytest.mark.asyncio
async def test_server_exposes_only_bounded_read_tools() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"items": []})

    alert_hub = AlertHubClient(
        MCPSettings(
            nodes=(NodeConfig("ru", "https://ru-api.example"),),
            token=f"ahs_{'1' * 36}.secret",
        ),
        transport=httpx.MockTransport(handler),
    )

    async with Client(create_server(alert_hub)) as client:
        tools = await client.list_tools()
        names = {tool.name for tool in tools.tools}
        assert names == {
            "diagnose_alert_hub",
            "get_alert_rules",
            "get_availability",
            "get_check",
            "get_cluster_status",
            "get_incident",
            "get_metrics_reachability",
            "get_metrics_summary",
            "list_checks",
            "list_configured_nodes",
            "list_incidents",
            "run_named_metric_query",
        }
        result = await client.call_tool(
            "list_incidents",
            {"limit": 999, "offset": -10, "query": "problem"},
        )

    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["status"] == "ok"
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.params["limit"] == "200"
    assert requests[0].url.params["offset"] == "0"
    assert requests[0].url.params["view"] == "compact"


@pytest.mark.asyncio
async def test_every_operational_tool_maps_to_a_fixed_get_endpoint() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/checks/summary"):
            return httpx.Response(200, json={"data_state": "ready", "down": 0})
        return httpx.Response(200, json={"status": "ok"})

    alert_hub = AlertHubClient(
        MCPSettings(
            nodes=(NodeConfig("ru", "https://ru-api.example"),),
            token=f"ahs_{'1' * 36}.secret",
        ),
        transport=httpx.MockTransport(handler),
    )
    calls = {
        "diagnose_alert_hub": {},
        "get_alert_rules": {"state": "firing", "page_size": 500},
        "get_availability": {"window": "7d"},
        "get_check": {"check_id": "checkout:eu"},
        "get_cluster_status": {},
        "get_incident": {"incident_id": "11111111-1111-1111-1111-111111111111"},
        "get_metrics_reachability": {},
        "get_metrics_summary": {},
        "list_checks": {"status": "down", "limit": 500},
        "list_configured_nodes": {},
        "run_named_metric_query": {"query": "key_jobs_up"},
    }

    async with Client(create_server(alert_hub)) as client:
        for name, arguments in calls.items():
            result = await client.call_tool(name, arguments)
            assert result.is_error is False, name

    assert requests
    assert all(request.method == "GET" for request in requests)
    paths = {request.url.path for request in requests}
    assert "/api/v1/incidents/11111111-1111-1111-1111-111111111111" in paths
    assert "/api/v1/checks/checkout:eu" in paths
    assert "/api/v1/metrics/queries/key_jobs_up" in paths


@pytest.mark.asyncio
async def test_detail_tools_reject_path_shaped_identifiers_without_http() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request: {request.url}")

    alert_hub = AlertHubClient(
        MCPSettings(
            nodes=(NodeConfig("ru", "https://ru-api.example"),),
            token="ahs_token",
        ),
        transport=httpx.MockTransport(handler),
    )

    async with Client(create_server(alert_hub)) as client:
        incident = await client.call_tool("get_incident", {"incident_id": "../metrics/summary"})
        check = await client.call_tool("get_check", {"check_id": "../summary"})

    assert incident.structured_content is not None
    assert incident.structured_content["status"] == "invalid_request"
    assert check.structured_content is not None
    assert check.structured_content["status"] == "invalid_request"
