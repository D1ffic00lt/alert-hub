from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from alert_hub.domain.events import utc_now
from alert_hub.infrastructure.db.models import HeartbeatState, Incident, Source
from alert_hub.workers.heartbeat import evaluate_heartbeats


def _create_source(
    client: TestClient,
    auth: dict[str, str],
    kind: str,
    *,
    config: dict | None = None,
) -> dict:
    response = client.post(
        "/api/v1/sources",
        headers=auth,
        json={
            "name": f"{kind} test",
            "kind": kind,
            "region": "test",
            "config": config or {},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_bootstrap_status_login_refresh_and_me(client: TestClient, auth: dict[str, str]) -> None:
    status = client.get("/api/v1/auth/bootstrap/status")
    assert status.json()["required"] is False
    assert status.json()["bootstrap_required"] is False

    me = client.get("/api/v1/auth/me", headers=auth)
    assert me.status_code == 200
    assert me.json()["username"] == "admin"

    old_refresh = client.cookies.get("alert_hub_refresh")
    refreshed = client.post(
        "/api/v1/auth/refresh",
        headers={"X-CSRF-Token": auth["X-CSRF-Token"], "Origin": "http://testserver"},
    )
    assert refreshed.status_code == 200, refreshed.text
    assert client.cookies.get("alert_hub_refresh") != old_refresh


def test_generic_ingest_is_idempotent_and_incident_can_be_resolved(
    client: TestClient, auth: dict[str, str]
) -> None:
    source = _create_source(client, auth, "generic_json")
    payload = {
        "schema_version": 1,
        "external_event_id": "evt-1",
        "dedup_key": "api-server-down",
        "status": "firing",
        "title": "API server down",
        "description": "No response from health endpoint",
        "severity": "critical",
        "starts_at": "2026-09-01T12:00:00Z",
        "labels": {"service": "api", "region": "test"},
        "annotations": {"owner": "platform"},
    }
    ingest_headers = {"Authorization": f"Bearer {source['token']}"}
    url = f"/ingest/v1/events/{source['id']}"
    first = client.post(url, headers=ingest_headers, json=payload)
    second = client.post(url, headers=ingest_headers, json=payload)
    assert first.status_code == 200, first.text
    assert first.json()["accepted"] == 1
    assert second.status_code == 200, second.text
    assert second.json()["accepted"] == 0
    assert second.json()["duplicates"] == 1

    listing = client.get("/api/v1/incidents", headers=auth)
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    incident_id = listing.json()["items"][0]["id"]
    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=auth)
    assert len(detail.json()["timeline"]) == 1
    assert detail.json()["labels"]["service"] == "api"

    resolved = client.post(
        f"/api/v1/incidents/{incident_id}/resolve",
        headers=auth,
        json={"reason": "manually verified"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["incident"]["status"] == "resolved"
    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=auth)
    assert [item["event_type"] for item in detail.json()["timeline"]] == [
        "firing",
        "resolved",
    ]


def test_alertmanager_group_normalizes_each_alert_and_deduplicates(
    client: TestClient, auth: dict[str, str]
) -> None:
    source = _create_source(client, auth, "alertmanager")
    payload = {
        "version": "4",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "FirstDown", "instance": "one", "severity": "critical"},
                "annotations": {"summary": "First is down"},
                "startsAt": "2026-09-01T12:00:00Z",
                "fingerprint": "fp-one",
            },
            {
                "status": "firing",
                "labels": {"alertname": "SecondDown", "instance": "two", "severity": "warn"},
                "annotations": {"summary": "Second is down"},
                "startsAt": "2026-09-01T12:01:00Z",
                "fingerprint": "fp-two",
            },
        ],
    }
    headers = {"Authorization": f"Bearer {source['token']}"}
    url = f"/ingest/v1/alertmanager/{source['id']}"
    first = client.post(url, headers=headers, json=payload)
    second = client.post(url, headers=headers, json=payload)
    assert first.json()["accepted"] == 2
    assert second.json()["duplicates"] == 2
    assert client.get("/api/v1/incidents", headers=auth).json()["total"] == 2


def test_late_heartbeat_fires_then_resolves_on_next_ping(
    client: TestClient, auth: dict[str, str], app
) -> None:
    source = _create_source(
        client,
        auth,
        "heartbeat",
        config={"interval_seconds": 10, "grace_seconds": 5, "severity": "critical"},
    )
    with app.state.session_factory.begin() as db:
        state = db.get(HeartbeatState, source["id"])
        assert state is not None
        state.last_received_at = utc_now() - timedelta(seconds=60)

    ping = client.post(
        f"/ingest/v1/heartbeat/{source['id']}",
        headers={"Authorization": f"Bearer {source['token']}"},
    )
    assert ping.status_code == 200, ping.text
    listing = client.get("/api/v1/incidents", headers=auth).json()
    assert listing["total"] == 1
    assert listing["items"][0]["status"] == "resolved"
    incident_id = listing["items"][0]["id"]
    timeline = client.get(f"/api/v1/incidents/{incident_id}", headers=auth).json()["timeline"]
    assert [event["event_type"] for event in timeline] == ["firing", "resolved"]


def test_heartbeat_patch_validation_and_scheduler_isolation(
    client: TestClient,
    auth: dict[str, str],
    app,
    settings,
) -> None:
    poisoned = _create_source(
        client,
        auth,
        "heartbeat",
        config={"interval_seconds": 10, "grace_seconds": 0},
    )
    healthy = _create_source(
        client,
        auth,
        "heartbeat",
        config={"interval_seconds": 10, "grace_seconds": 0},
    )
    rejected = client.patch(
        f"/api/v1/sources/{poisoned['id']}",
        headers=auth,
        json={"config": {"interval_seconds": "not-a-number"}},
    )
    assert rejected.status_code == 422

    now = utc_now()
    with app.state.session_factory.begin() as db:
        poisoned_source = db.get(Source, poisoned["id"])
        assert poisoned_source is not None
        # Simulate an invalid value received from a legacy/compromised peer. One bad
        # source must never abort evaluation of the remaining heartbeat sources.
        poisoned_source.config_json = {"interval_seconds": "not-a-number"}
        for source_id in (poisoned["id"], healthy["id"]):
            state = db.get(HeartbeatState, source_id)
            assert state is not None
            state.last_received_at = now - timedelta(seconds=60)
        assert evaluate_heartbeats(db, settings, now=now) == 1

    with app.state.session_factory() as db:
        incidents = db.scalars(select(Incident)).all()
        assert [incident.source_id for incident in incidents] == [healthy["id"]]


def test_created_source_returns_ready_absolute_webhook_and_example(
    client: TestClient,
    auth: dict[str, str],
) -> None:
    source = _create_source(client, auth, "alertmanager")
    expected = f"http://testserver/ingest/v1/alertmanager/{source['id']}"
    assert source["webhook_url"] == expected
    assert f"url: {expected}" in source["example"]
    assert "YOUR_HOST" not in source["example"]


def test_cluster_cursor_and_query_require_separate_bearer(
    client: TestClient, auth: dict[str, str]
) -> None:
    _create_source(client, auth, "generic_json")
    unauthorized = client.get("/internal/v1/sync/cursors")
    assert unauthorized.status_code == 401
    headers = {"Authorization": "Bearer test-cluster-key-with-enough-entropy"}
    cursors = client.get("/internal/v1/sync/cursors", headers=headers)
    assert cursors.status_code == 200
    page = client.post(
        "/internal/v1/sync/events/query",
        headers=headers,
        json={"cursor": {}, "limit": 100},
    )
    assert page.status_code == 200, page.text
    assert page.json()["events"]


def test_health_and_prometheus_metrics(client: TestClient) -> None:
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").status_code == 200
    deep = client.get("/health/deep")
    assert deep.status_code == 200
    assert deep.json()["channels"] == {
        "status": "not_configured",
        "enabled": 0,
        "outbox_pending": 0,
        "failed_delivery_records": 0,
    }
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "alert_hub_build_info" in metrics.text
    assert "alert_hub_incidents_open" in metrics.text
