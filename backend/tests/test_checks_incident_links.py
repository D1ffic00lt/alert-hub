from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from alert_hub.api.incidents import _related_checks
from alert_hub.main import create_app
from alert_hub.settings import Settings


def _authenticated_client(
    tmp_path: Path, *, checks_enabled: bool
) -> tuple[TestClient, dict[str, str]]:
    database_name = "enabled.db" if checks_enabled else "disabled.db"
    app = create_app(
        Settings(
            environment="test",
            database_url=f"sqlite:///{tmp_path / database_name}",
            auto_create_schema=True,
            node_id="checks-link-node",
            signing_key="checks-link-signing-key-with-enough-entropy",
            cluster_secret="checks-link-cluster-key-with-enough-entropy",
            bootstrap_token="checks-link-bootstrap",
            cookie_secure=False,
            trusted_origins=["http://testserver"],
            peer_allowed_cidrs=[],
            heartbeat_scan_seconds=0,
            notify_enabled=False,
            sync_enabled=False,
            checks_enabled=checks_enabled,
        )
    )
    client = TestClient(app, base_url="http://testserver")
    client.__enter__()
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": "checks-link-bootstrap",
            "username": "admin",
            "password": "a-strong-test-password",
        },
    )
    assert bootstrap.status_code == 201, bootstrap.text
    return client, {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def test_incident_detail_returns_all_safe_historical_check_links(tmp_path: Path) -> None:
    client, auth = _authenticated_client(tmp_path, checks_enabled=True)
    try:
        source = client.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "Checks alerts", "kind": "generic_json", "region": "test"},
        ).json()
        ingest_headers = {"Authorization": f"Bearer {source['token']}"}
        for index, check_id in enumerate(
            (
                "public-api",
                "checkout-flow",
                "https://internal.example/token",
                " public-api ",
                "10.0.0.1",
                "123e4567-e89b-12d3-a456-426614174000",
                "edge-10.0.0.1",
                "agent-123e4567-e89b-12d3-a456-426614174000",
                "token:supersecret",
                "summary",
            )
        ):
            response = client.post(
                f"/ingest/v1/events/{source['id']}",
                headers=ingest_headers,
                json={
                    "schema_version": 1,
                    "external_event_id": f"checks-alert-{index}",
                    "dedup_key": "shared-incident",
                    "status": "firing",
                    "title": "Synthetic check failed",
                    "severity": "critical",
                    "starts_at": f"2026-09-05T12:0{index}:00Z",
                    "labels": {"check_id": check_id},
                },
            )
            assert response.status_code == 200, response.text

        incident = client.get("/api/v1/incidents", headers=auth).json()["items"][0]
        detail = client.get(f"/api/v1/incidents/{incident['id']}", headers=auth)
        assert detail.status_code == 200
        assert detail.json()["checks_relation_state"] == "available"
        assert detail.json()["related_checks"] == [
            {"check_id": "public-api", "href": "/checks/public-api"},
            {"check_id": "checkout-flow", "href": "/checks/checkout-flow"},
        ]
    finally:
        client.__exit__(None, None, None)


def test_incident_links_are_absent_when_checks_are_disabled(tmp_path: Path) -> None:
    client, auth = _authenticated_client(tmp_path, checks_enabled=False)
    try:
        source = client.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "Alerts", "kind": "generic_json", "region": "test"},
        ).json()
        response = client.post(
            f"/ingest/v1/events/{source['id']}",
            headers={"Authorization": f"Bearer {source['token']}"},
            json={
                "schema_version": 1,
                "external_event_id": "disabled-check-alert",
                "dedup_key": "disabled-check-incident",
                "status": "firing",
                "title": "Alert remains available",
                "severity": "warning",
                "starts_at": "2026-09-05T12:00:00Z",
                "labels": {"check_id": "public-api"},
            },
        )
        assert response.status_code == 200
        incident = client.get("/api/v1/incidents", headers=auth).json()["items"][0]
        assert incident["checks_relation_state"] == "disabled"
        assert incident["related_checks"] == []
    finally:
        client.__exit__(None, None, None)


def test_incident_historical_check_links_are_stable_and_bounded() -> None:
    incident = SimpleNamespace(
        labels_json={"check_id": "check-000"},
        events=[
            SimpleNamespace(payload_json={"labels": {"check_id": f"check-{index:03d}"}})
            for index in range(205)
        ],
    )

    links, total = _related_checks(incident, include_timeline=True)

    assert total == 205
    assert len(links) == 200
    assert links[0]["check_id"] == "check-000"
    assert links[-1]["check_id"] == "check-199"
