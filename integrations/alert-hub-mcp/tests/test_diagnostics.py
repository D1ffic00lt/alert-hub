from __future__ import annotations

from typing import Any

import pytest

from alert_hub_mcp.diagnostics import diagnose


class FakeClient:
    async def get_many(self, requests, *, node=None) -> dict[str, dict[str, Any]]:
        del requests, node
        return {
            "readiness": {
                "status": "ok",
                "nodes": [{"node": "ru", "ok": True, "data": {"status": "ok"}}],
            },
            "cluster": {
                "status": "ok",
                "nodes": [
                    {
                        "node": "ru",
                        "ok": True,
                        "data": {"nodes": [{"id": "nl", "health": "offline"}]},
                    }
                ],
            },
            "key_jobs": {
                "status": "ok",
                "nodes": [
                    {
                        "node": "ru",
                        "ok": True,
                        "data": {
                            "samples": [
                                {
                                    "datasource_id": "prometheus",
                                    "metric": {"job": "grafana", "instance": "grafana:3000"},
                                    "value": 0,
                                }
                            ]
                        },
                    }
                ],
            },
            "checks": {
                "status": "ok",
                "nodes": [
                    {
                        "node": "ru",
                        "ok": True,
                        "data": {"data_state": "ready", "down": 2, "stale": 1},
                    }
                ],
            },
            "reachability": {
                "status": "partial",
                "nodes": [
                    {
                        "node": "ru",
                        "ok": True,
                        "data": {
                            "status": "partial",
                            "errors": [
                                {
                                    "code": "prometheus_unavailable",
                                    "detail": "connection failed",
                                    "datasource_id": "prometheus",
                                }
                            ],
                        },
                    }
                ],
            },
        }


@pytest.mark.asyncio
async def test_diagnose_correlates_failures_and_marks_untrusted_text() -> None:
    result = await diagnose(FakeClient())  # type: ignore[arg-type]

    assert result["status"] == "unavailable"
    assert {issue["code"] for issue in result["issues"]} >= {
        "peer_offline",
        "target_down",
        "checks_down",
        "checks_stale",
        "reachability_partial",
        "prometheus_unavailable",
    }
    assert "untrusted data" in result["note"]


@pytest.mark.asyncio
async def test_diagnose_reports_request_failure_and_ignores_malformed_items() -> None:
    class FailureClient:
        async def get_many(self, requests, *, node=None) -> dict[str, dict[str, Any]]:
            del requests, node
            return {
                "readiness": {
                    "status": "unavailable",
                    "nodes": [
                        None,
                        {
                            "node": "nl",
                            "ok": False,
                            "error": {"code": "request_timeout", "detail": "timed out"},
                        },
                        {"node": "bad", "ok": True, "data": []},
                    ],
                }
            }

    result = await diagnose(FailureClient())  # type: ignore[arg-type]

    assert result["status"] == "unavailable"
    assert result["issues"] == [
        {
            "severity": "critical",
            "node": "nl",
            "component": "readiness",
            "code": "request_timeout",
            "detail": "timed out",
        }
    ]


@pytest.mark.asyncio
async def test_diagnose_uses_degraded_for_warning_only() -> None:
    class WarningClient:
        async def get_many(self, requests, *, node=None) -> dict[str, dict[str, Any]]:
            del requests, node
            return {
                "cluster": {
                    "status": "ok",
                    "nodes": [
                        {
                            "node": "ru",
                            "ok": True,
                            "data": {"nodes": [{"id": "nl", "health": "degraded"}]},
                        }
                    ],
                }
            }

    result = await diagnose(WarningClient())  # type: ignore[arg-type]

    assert result["status"] == "degraded"
    assert result["issues"][0]["code"] == "peer_degraded"


@pytest.mark.asyncio
async def test_diagnose_reports_unknown_selected_node() -> None:
    class MissingNodeClient:
        async def get_many(self, requests, *, node=None) -> dict[str, dict[str, Any]]:
            del node
            return {
                name: {
                    "status": "configuration_error",
                    "nodes": [],
                    "error": {"code": "unknown_node", "detail": "Unknown node 'missing'"},
                }
                for name, _path, _params in requests
            }

    result = await diagnose(MissingNodeClient(), node="missing")  # type: ignore[arg-type]

    assert result["status"] == "unavailable"
    assert {issue["code"] for issue in result["issues"]} == {"unknown_node"}
    assert {issue["node"] for issue in result["issues"]} == {"missing"}
