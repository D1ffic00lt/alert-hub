from __future__ import annotations

import base64
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select

from alert_hub.domain.events import utc_now
from alert_hub.infrastructure.db.models import (
    HeartbeatState,
    Incident,
    Node,
    NotificationChannel,
    Outbox,
    Source,
)
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
    assert "send_resolved: true" in source["example"]
    assert "type: Bearer" in source["example"]
    assert "YOUR_HOST" not in source["example"]

    generic = _create_source(client, auth, "generic_json")
    assert '"schema_version":1' in generic["example"]
    assert '"external_event_id":"example-1"' in generic["example"]
    assert f'"starts_at":"{generic["created_at"].replace("+00:00", "Z")}"' in generic["example"]
    assert "--connect-timeout 5 --max-time 10" in generic["example"]

    heartbeat = _create_source(client, auth, "heartbeat")
    assert "--connect-timeout 5 --max-time 10" in heartbeat["example"]


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


def test_cluster_status_exposes_runtime_health_and_lag(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    class PeerSnapshot:
        state = {
            "url": "https://peer-remote.example.test",
            "up": True,
            "last_success_at": "2026-09-02T17:00:00Z",
            "last_error": None,
            "failures": 0,
            "lag_seconds": 1.25,
        }

        def status_snapshot(self) -> dict[str, dict]:
            return {"remote-node": dict(self.state)}

    with app.state.session_factory.begin() as db:
        db.add(
            Node(
                id="remote-node",
                name="Remote node",
                region="remote",
                private_peer_url="https://peer-remote.example.test",
                enabled_roles=["sync"],
                software_version="v0.1.4",
            )
        )
        db.add(Outbox(topic="pending", payload_json={}))
        db.add(Outbox(topic="completed", payload_json={}, completed_at=utc_now()))
    snapshot = PeerSnapshot()
    app.state.peer_sync_worker = snapshot

    response = client.get("/api/v1/cluster/status", headers=auth)
    assert response.status_code == 200, response.text
    nodes = {item["id"]: item for item in response.json()["nodes"]}
    assert nodes["test-node"]["health"] == "healthy"
    assert nodes["test-node"]["sync_lag_seconds"] == 0.0
    assert nodes["test-node"]["outbox_pending"] == 1
    assert nodes["remote-node"]["health"] == "healthy"
    assert nodes["remote-node"]["sync_lag_seconds"] == 1.25
    assert nodes["remote-node"]["last_sync_success_at"] == "2026-09-02T17:00:00Z"
    assert nodes["remote-node"]["peer_failures"] == 0
    assert nodes["remote-node"]["outbox_pending"] is None

    snapshot.state.update({"up": False, "failures": 1, "lag_seconds": 1.25})
    degraded = client.get("/api/v1/cluster/status", headers=auth)
    assert degraded.status_code == 200, degraded.text
    degraded_nodes = {item["id"]: item for item in degraded.json()["nodes"]}
    assert degraded_nodes["remote-node"]["health"] == "degraded"
    assert degraded_nodes["remote-node"]["sync_lag_seconds"] is None

    snapshot.state.update({"failures": 3})
    offline = client.get("/api/v1/cluster/status", headers=auth)
    assert offline.status_code == 200, offline.text
    offline_nodes = {item["id"]: item for item in offline.json()["nodes"]}
    assert offline_nodes["remote-node"]["health"] == "offline"

    snapshot.state.update({"failures": 0, "last_success_at": None})
    unknown = client.get("/api/v1/cluster/status", headers=auth)
    assert unknown.status_code == 200, unknown.text
    unknown_nodes = {item["id"]: item for item in unknown.json()["nodes"]}
    assert unknown_nodes["remote-node"]["health"] == "unknown"


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
        "providers": {
            "web_push": {
                "status": "not_configured",
                "enabled_channels": 0,
                "worker_enabled": True,
                "sender_configured": False,
                "issues": ["missing_vapid_private_key"],
            }
        },
    }
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "alert_hub_build_info" in metrics.text
    assert "alert_hub_incidents_open" in metrics.text


def test_deep_health_reports_web_push_sender_capability(
    client: TestClient,
    app,
    settings,
    tmp_path,
) -> None:
    with app.state.session_factory.begin() as db:
        db.add(
            NotificationChannel(
                name="Browser push",
                kind="web_push",
                enabled=True,
                encrypted_config=b"",
                eligible_nodes_or_regions={},
            )
        )

    missing = client.get("/health/deep")
    assert missing.status_code == 200
    assert missing.json()["status"] == "ok"
    assert missing.json()["channels"]["status"] == "misconfigured"
    assert missing.json()["channels"]["providers"]["web_push"] == {
        "status": "misconfigured",
        "enabled_channels": 1,
        "worker_enabled": True,
        "sender_configured": False,
        "issues": ["missing_vapid_private_key"],
    }
    # Deep health is informational and must not change local readiness.
    assert client.get("/health/ready").status_code == 200

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_path = tmp_path / "vapid-private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    settings.vapid_private_key_file = private_path
    settings.vapid_public_key = base64.urlsafe_b64encode(public_key).rstrip(b"=").decode()
    settings.vapid_subject = "mailto:ops@example.test"

    configured = client.get("/health/deep").json()["channels"]
    assert configured["status"] == "configured"
    assert configured["providers"]["web_push"] == {
        "status": "configured",
        "enabled_channels": 1,
        "worker_enabled": True,
        "sender_configured": True,
        "issues": [],
    }

    other_public_key = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    settings.vapid_public_key = base64.urlsafe_b64encode(other_public_key).rstrip(b"=").decode()
    invalid_pair = client.get("/health/deep").json()["channels"]
    assert invalid_pair["status"] == "misconfigured"
    assert invalid_pair["providers"]["web_push"]["issues"] == ["invalid_vapid_key_material"]

    settings.vapid_public_key = base64.urlsafe_b64encode(public_key).rstrip(b"=").decode()
    settings.vapid_subject = "ftp://ops.example.test"
    invalid_subject = client.get("/health/deep").json()["channels"]
    assert invalid_subject["status"] == "misconfigured"
    assert invalid_subject["providers"]["web_push"]["issues"] == ["invalid_vapid_subject"]

    settings.vapid_subject = "https://ops.example.test"
    settings.notify_enabled = False
    disabled = client.get("/health/deep").json()["channels"]
    assert disabled["status"] == "worker_disabled"
    assert disabled["providers"]["web_push"]["status"] == "worker_disabled"
    assert disabled["providers"]["web_push"]["issues"] == ["notification_worker_disabled"]
    assert client.get("/health/ready").status_code == 200
