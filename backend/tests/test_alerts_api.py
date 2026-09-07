from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from alert_hub.infrastructure.prometheus import (
    FIXED_PROMQL,
    PrometheusQueryError,
    parse_alert_rules_response,
)


def _vector(*samples: tuple[dict[str, str], float, float]) -> dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {"metric": labels, "value": [timestamp, str(value)]}
                for labels, value, timestamp in samples
            ],
        },
    }


def _rules(*rules: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "groups": [
                {
                    "name": "platform",
                    "file": "/etc/prometheus/rules/platform.yml",
                    "rules": list(rules),
                }
            ]
        },
    }


def _rule(
    name: str,
    *,
    state: str = "inactive",
    health: str = "ok",
    alerts: list[dict[str, str]] | None = None,
    last_error: str = "",
    category: str | None = None,
) -> dict[str, Any]:
    labels = {"severity": "critical", "team": "platform"}
    if category is not None:
        labels["alert_category"] = category
    return {
        "name": name,
        "state": state,
        "health": health,
        "alerts": alerts or [],
        "lastEvaluation": "2026-09-07T00:00:00Z",
        "evaluationTime": 0.012,
        "lastError": last_error,
        "labels": labels,
        "annotations": {"summary": f"{name} summary"},
    }


def _create_datasource(
    client: TestClient,
    auth: dict[str, str],
    *,
    name: str,
    host: str,
    label_mode: str = "canonical",
) -> str:
    response = client.post(
        "/api/v1/prometheus-datasources",
        headers=auth,
        json={
            "name": name,
            "url": f"https://{host}:9090",
            "reachability_label_mode": label_mode,
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def test_alert_rule_parser_normalizes_states_bounds_fields_and_redacts_errors() -> None:
    parsed = parse_alert_rules_response(
        _rules(
            _rule(
                "CheckoutDown",
                state="pending",
                health="error",
                alerts=[{"state": "pending"}, {"state": "firing"}],
                last_error=(
                    "query failed at https://admin:secret@prometheus.internal/api "
                    "Authorization: Bearer super-secret"
                ),
            )
        ),
        max_rules=10,
        max_instances=10,
    )

    assert len(parsed) == 1
    rule = parsed[0]
    assert (rule.state, rule.firing_instances, rule.pending_instances) == ("firing", 1, 1)
    assert rule.last_evaluation == datetime(2026, 9, 7, tzinfo=UTC)
    assert rule.labels == {"severity": "critical", "team": "platform"}
    assert rule.last_error is not None
    assert "prometheus.internal" not in rule.last_error
    assert "super-secret" not in rule.last_error

    bounded = parse_alert_rules_response(
        _rules(_rule("A" * 300, category="custom-" + "x" * 3_000)),
        max_rules=10,
        max_instances=10,
    )[0]
    assert len(bounded.name) == 200
    assert len(bounded.labels["alert_category"]) == 2_048

    with pytest.raises(PrometheusQueryError, match="rule limit"):
        parse_alert_rules_response(_rules(_rule("A"), _rule("B")), max_rules=1, max_instances=10)
    with pytest.raises(PrometheusQueryError, match="instance limit"):
        parse_alert_rules_response(
            _rules(_rule("A", alerts=[{"state": "firing"}, {"state": "firing"}])),
            max_rules=10,
            max_instances=1,
        )


def test_alert_rules_are_grouped_by_dynamic_category_filterable_and_partial(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
) -> None:
    requested_paths: list[str] = []

    def prometheus(request: httpx.Request) -> httpx.Response:
        requested_paths.append(str(request.url))
        assert request.url.path == "/api/v1/rules"
        assert request.url.params["type"] == "alert"
        if request.url.host == "8.8.8.8":
            return httpx.Response(503, request=request, text="secret upstream body")
        if request.url.host == "9.9.9.9":
            return httpx.Response(
                200,
                request=request,
                json=_rules(
                    _rule(
                        "ApiDown",
                        state="pending",
                        alerts=[{"state": "pending"}],
                        category="infrastructure",
                    ),
                    _rule(
                        "DatabaseRuleBroken",
                        health="error",
                        last_error="query evaluation failed",
                        category="database",
                    ),
                    _rule("XrayLatencyHigh", state="pending", category="xray"),
                ),
            )
        return httpx.Response(
            200,
            request=request,
            json=_rules(
                _rule("ZuluInactive"),
                _rule(
                    "ApiDown",
                    state="firing",
                    health="error",
                    alerts=[{"state": "firing"}, {"state": "pending"}],
                    last_error="failed https://prometheus.private/query token=secret-token",
                    category="infrastructure",
                ),
            ),
        )

    app.state.prometheus_http_transport = httpx.MockTransport(prometheus)
    datasource_id = _create_datasource(client, auth, name="Primary Prometheus", host="1.1.1.1")
    secondary_id = _create_datasource(client, auth, name="Secondary Prometheus", host="9.9.9.9")
    _create_datasource(client, auth, name="Unavailable Prometheus", host="8.8.8.8")

    response = client.get("/api/v1/alert-rules?page_size=10", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["data_state"] == "partial"
    assert body["totals"] == {
        "rules": 4,
        "firing_rules": 1,
        "pending_rules": 2,
        "error_rules": 2,
        "datasources": 3,
        "related_incidents": 0,
    }
    assert body["filtered_rules"] == 4
    assert body["categories"] == ["database", "infrastructure", "xray"]
    assert body["has_uncategorized"] is True
    assert body["last_successful_refresh"] is not None
    assert body["pagination"] == {
        "page": 1,
        "page_size": 10,
        "total_items": 4,
        "total_pages": 1,
    }
    assert body["rules"][0]["name"] == "ApiDown"
    assert body["rules"][0]["category"] == "infrastructure"
    assert body["rules"][0]["state"] == "firing"
    assert body["rules"][0]["firing_instances"] == 1
    assert body["rules"][0]["pending_instances"] == 2
    assert body["rules"][0]["datasource_count"] == 2
    assert [item["datasource_name"] for item in body["rules"][0]["replicas"]] == [
        "Primary Prometheus",
        "Secondary Prometheus",
    ]
    assert body["rules"][0]["replicas"][0]["labels"]["alert_category"] == "infrastructure"
    assert body["rules"][0]["replicas"][0]["incidents_href"] == (
        f"/incidents?alertname=ApiDown&datasource_id={datasource_id}"
    )
    stable_id = body["rules"][0]["id"]
    assert body["errors"][0] == {
        "datasource_id": body["errors"][0]["datasource_id"],
        "datasource_name": "Unavailable Prometheus",
        "code": "http_error",
        "detail": "Prometheus returned an unsuccessful HTTP status",
    }
    serialized = response.text
    assert "secret-token" not in serialized
    assert "prometheus.private" not in serialized
    assert "secret upstream body" not in serialized

    error_filtered = client.get(
        "/api/v1/alert-rules",
        headers=auth,
        params={"state": "error", "category": "database"},
    ).json()
    assert [item["name"] for item in error_filtered["rules"]] == ["DatabaseRuleBroken"]

    datasource_filtered = client.get(
        "/api/v1/alert-rules",
        headers=auth,
        params={"datasource_id": secondary_id, "state": "pending", "q": "api"},
    ).json()
    assert [item["name"] for item in datasource_filtered["rules"]] == ["ApiDown"]
    assert datasource_filtered["rules"][0]["id"] == stable_id
    assert datasource_filtered["rules"][0]["state"] == "pending"
    assert [item["datasource_id"] for item in datasource_filtered["rules"][0]["replicas"]] == [
        secondary_id
    ]

    uncategorized = client.get(
        "/api/v1/alert-rules", headers=auth, params={"uncategorized": "true"}
    ).json()
    assert [(item["category"], item["name"]) for item in uncategorized["rules"]] == [
        (None, "ZuluInactive")
    ]
    assert all("/api/v1/rules?type=alert" in value for value in requested_paths)


def test_alert_rule_pagination_keeps_categories_on_one_page(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
) -> None:
    rules = [
        *(_rule(f"Infrastructure{index:02d}", category="infrastructure") for index in range(15)),
        *(_rule(f"Tls{index:02d}", category="tls") for index in range(4)),
        *(_rule(f"Xray{index:02d}", category="xray") for index in range(14)),
    ]

    def prometheus(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, request=request, json=_rules(*rules))

    app.state.prometheus_http_transport = httpx.MockTransport(prometheus)
    _create_datasource(client, auth, name="Primary Prometheus", host="1.1.1.1")

    default_page = client.get("/api/v1/alert-rules", headers=auth).json()
    assert default_page["pagination"] == {
        "page": 1,
        "page_size": 200,
        "total_items": 33,
        "total_pages": 1,
    }
    assert {item["category"] for item in default_page["rules"]} == {
        "infrastructure",
        "tls",
        "xray",
    }
    assert len(default_page["rules"]) == 33

    first = client.get(
        "/api/v1/alert-rules", headers=auth, params={"page": 1, "page_size": 25}
    ).json()
    second = client.get(
        "/api/v1/alert-rules", headers=auth, params={"page": 2, "page_size": 25}
    ).json()

    assert first["pagination"] == {
        "page": 1,
        "page_size": 25,
        "total_items": 33,
        "total_pages": 2,
    }
    assert {item["category"] for item in first["rules"]} == {"infrastructure", "tls"}
    assert len(first["rules"]) == 19
    assert {item["category"] for item in second["rules"]} == {"xray"}
    assert len(second["rules"]) == 14


@pytest.mark.parametrize("window", ["24h", "7d", "30d"])
def test_observed_availability_uses_only_fixed_queries_and_marks_stale_and_unknown(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
    window: str,
) -> None:
    now = datetime.now(UTC)
    evaluated = now.timestamp()
    fresh = (now - timedelta(seconds=30)).timestamp()
    stale = (now - timedelta(minutes=10)).timestamp()
    requested_queries: list[str] = []

    def prometheus(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/query"
        query = request.url.params["query"]
        requested_queries.append(query)
        labels_fresh = {"source_region": "ru", "target_name": "api"}
        labels_stale = {"source_region": "de", "target_name": "api"}
        labels_unknown = {"source_region": "nl", "target_name": "portal"}
        if query == FIXED_PROMQL[f"availability_average_{window}"]:
            payload = _vector(
                (labels_fresh, 0.999, evaluated),
                (labels_stale, 0.95, evaluated),
                (labels_unknown, 1, evaluated),
            )
        elif query == FIXED_PROMQL[f"availability_samples_{window}"]:
            payload = _vector(
                (labels_fresh, 100, evaluated),
                (labels_stale, 90, evaluated),
            )
        elif query == FIXED_PROMQL[f"availability_last_sample_{window}"]:
            payload = _vector(
                (labels_fresh, fresh, evaluated),
                (labels_stale, stale, evaluated),
            )
        else:  # pragma: no cover - proves the endpoint owns the query set
            raise AssertionError(f"Unexpected query: {query}")
        return httpx.Response(200, request=request, json=payload)

    app.state.prometheus_http_transport = httpx.MockTransport(prometheus)
    _create_datasource(client, auth, name="Primary Prometheus", host="1.1.1.1")

    response = client.get("/api/v1/availability", headers=auth, params={"window": window})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["data_state"] == "ok"
    assert body["window"] == window
    assert [(item["source"], item["data_state"]) for item in body["targets"]] == [
        ("de", "stale"),
        ("ru", "ok"),
        ("nl", "unknown"),
    ]
    by_source = {item["source"]: item for item in body["targets"]}
    assert by_source["ru"]["observed_availability_percent"] == 99.9
    assert by_source["ru"]["samples_count"] == 100
    assert by_source["nl"]["observed_availability_percent"] is None
    assert by_source["nl"]["samples_count"] is None
    assert set(requested_queries) == {
        FIXED_PROMQL[f"availability_average_{window}"],
        FIXED_PROMQL[f"availability_samples_{window}"],
        FIXED_PROMQL[f"availability_last_sample_{window}"],
    }
    assert client.get("/api/v1/availability?window=1h", headers=auth).status_code == 422


def test_alert_endpoints_report_not_configured(client: TestClient, auth: dict[str, str]) -> None:
    rules = client.get("/api/v1/alert-rules", headers=auth).json()
    availability = client.get("/api/v1/availability?window=24h", headers=auth).json()
    assert rules["data_state"] == "not_configured"
    assert rules["rules"] == []
    assert availability["data_state"] == "not_configured"
    assert availability["targets"] == []
