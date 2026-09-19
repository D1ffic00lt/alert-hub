from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from alert_hub.api import alerts as alerts_api
from alert_hub.application.prometheus import DatasourceHistoryResult
from alert_hub.infrastructure.prometheus import (
    FIXED_PROMQL,
    MatrixSeries,
    PrometheusQueryError,
    RangeSample,
    alert_history_promql,
    parse_alert_rules_response,
    parse_matrix_response,
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


def _matrix(*series: tuple[dict[str, str], list[tuple[float, float]]]) -> dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": labels,
                    "values": [[timestamp, str(value)] for timestamp, value in values],
                }
                for labels, values in series
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


def test_alert_history_matrix_parser_bounds_total_points() -> None:
    parsed = parse_matrix_response(
        _matrix(
            (
                {"alertname": "ApiDown", "alert_category": "infrastructure"},
                [(1_700_000_000, 1), (1_700_003_600, 2)],
            )
        ),
        max_samples=2,
    )
    assert parsed[0].labels == {
        "alertname": "ApiDown",
        "alert_category": "infrastructure",
    }
    assert [sample.value for sample in parsed[0].samples] == [1, 2]

    with pytest.raises(PrometheusQueryError, match="sample limit"):
        parse_matrix_response(
            _matrix(({"alertname": "ApiDown"}, [(1_700_000_000, 1), (1_700_003_600, 2)])),
            max_samples=1,
        )
    with pytest.raises(PrometheusQueryError, match="sample limit"):
        parse_matrix_response(
            _matrix(({"alertname": "A"}, []), ({"alertname": "B"}, [])),
            max_samples=1,
        )


def test_alert_history_crosses_out_only_when_every_active_instance_is_silenced() -> None:
    starts_at = datetime(2026, 9, 7, tzinfo=UTC)
    bucket = timedelta(hours=1)
    sample_at = starts_at + bucket
    labels_a = {
        "alertname": "ApiDown",
        "alert_category": "infrastructure",
        "alertstate": "firing",
        "instance": "api-a",
    }
    labels_b = {**labels_a, "instance": "api-b"}
    result = DatasourceHistoryResult(
        "prom-1",
        "Primary Prometheus",
        [
            MatrixSeries(labels_a, [RangeSample(2, sample_at)]),
            MatrixSeries(labels_b, [RangeSample(2, sample_at)]),
        ],
    )
    identity_a = alerts_api._history_instance_identity("prom-1", labels_a)
    identity_b = alerts_api._history_instance_identity("prom-1", labels_b)
    assert identity_a is not None
    assert identity_b is not None
    evidence = {identity_a: starts_at, identity_b: starts_at}

    partly_silenced = alerts_api._history_response_series(
        [result],
        starts_at=starts_at,
        bucket=bucket,
        bucket_count=1,
        mute_ranges={identity_a: [(starts_at, sample_at)]},
        mute_observed_from=evidence,
    )
    assert partly_silenced[0]["states"] == ["firing"]
    assert partly_silenced[0]["muted"] == [False]

    fully_silenced = alerts_api._history_response_series(
        [result],
        starts_at=starts_at,
        bucket=bucket,
        bucket_count=1,
        mute_ranges={
            identity_a: [(starts_at, sample_at)],
            identity_b: [(starts_at, sample_at)],
        },
        mute_observed_from=evidence,
    )
    assert fully_silenced[0]["muted"] == [True]


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


def test_alert_history_uses_fixed_range_query_and_marks_local_silence(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[dict[str, str]] = []

    def prometheus(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/query_range"
        params = dict(request.url.params)
        requested.append(params)
        start = datetime.fromisoformat(params["start"].replace("Z", "+00:00")).timestamp()
        end = datetime.fromisoformat(params["end"].replace("Z", "+00:00")).timestamp()
        return httpx.Response(
            200,
            request=request,
            json=_matrix(
                (
                    {"alertname": "ApiDown", "alert_category": "infrastructure"},
                    [(start, 1), (end, 2)],
                )
            ),
        )

    app.state.prometheus_http_transport = httpx.MockTransport(prometheus)
    datasource_id = _create_datasource(
        client,
        auth,
        name="Primary Prometheus",
        host="1.1.1.1",
    )
    source_response = client.post(
        "/api/v1/sources",
        headers=auth,
        json={"name": "History source", "kind": "generic_json", "region": "test"},
    )
    assert source_response.status_code == 201, source_response.text
    source = source_response.json()
    fired_at = datetime.now(UTC) - timedelta(minutes=5)
    ingest = client.post(
        f"/ingest/v1/events/{source['id']}",
        headers={"Authorization": f"Bearer {source['token']}"},
        json={
            "schema_version": 1,
            "external_event_id": "history-api-down",
            "dedup_key": "history-api-down",
            "status": "firing",
            "title": "API down",
            "severity": "critical",
            "starts_at": fired_at.isoformat(),
            "labels": {
                "alertname": "ApiDown",
                "alert_category": "infrastructure",
                "prometheus_datasource_id": datasource_id,
            },
        },
    )
    assert ingest.status_code == 200, ingest.text
    incident_id = ingest.json()["incident_ids"][0]
    silenced = client.post(
        f"/api/v1/incidents/{incident_id}/silence",
        headers=auth,
        json={"reason": "planned maintenance"},
    )
    assert silenced.status_code == 200, silenced.text
    repeated_firing = client.post(
        f"/ingest/v1/events/{source['id']}",
        headers={"Authorization": f"Bearer {source['token']}"},
        json={
            "schema_version": 1,
            "external_event_id": "history-api-down-repeat",
            "dedup_key": "history-api-down",
            "status": "firing",
            "title": "API down",
            "severity": "critical",
            "starts_at": fired_at.isoformat(),
            "labels": {
                "alertname": "ApiDown",
                "alert_category": "infrastructure",
                "prometheus_datasource_id": datasource_id,
            },
        },
    )
    assert repeated_firing.status_code == 200, repeated_firing.text
    assert repeated_firing.json()["incident_ids"] == [incident_id]

    response = client.get("/api/v1/alert-history?window=24h", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["window"] == "24h"
    assert body["bucket_seconds"] == 3_600
    assert len(body["buckets"]) == 24
    assert body["datasources"] == [{"id": datasource_id, "name": "Primary Prometheus"}]
    assert len(body["series"]) == 1
    history = body["series"][0]
    assert history["states"][0] == "pending"
    assert history["states"][-1] == "firing"
    assert history["muted"][-1] is True
    assert history["mute_source"] == "alert_hub"
    assert len(requested) == 1
    assert requested[0]["query"] == alert_history_promql("24h")
    assert "max by" not in requested[0]["query"]
    assert requested[0]["step"] == "3600s"
    assert client.get("/api/v1/alert-history?window=1h", headers=auth).status_code == 422

    monkeypatch.setattr(alerts_api, "_MAX_ALERT_HISTORY_EVENTS", 1)
    limited = client.get("/api/v1/alert-history?window=24h", headers=auth)
    assert limited.status_code == 503
    assert limited.json()["detail"] == "Alert history silence evidence exceeds the safe event limit"


def test_alert_endpoints_report_not_configured(client: TestClient, auth: dict[str, str]) -> None:
    rules = client.get("/api/v1/alert-rules", headers=auth).json()
    history = client.get("/api/v1/alert-history?window=30d", headers=auth).json()
    availability = client.get("/api/v1/availability?window=24h", headers=auth).json()
    assert rules["data_state"] == "not_configured"
    assert rules["rules"] == []
    assert history["data_state"] == "not_configured"
    assert history["series"] == []
    assert availability["data_state"] == "not_configured"
    assert availability["targets"] == []
