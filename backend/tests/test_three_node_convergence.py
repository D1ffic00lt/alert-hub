from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from alert_hub.infrastructure.db.models import Incident, IncidentEvent
from alert_hub.main import create_app
from alert_hub.settings import Settings
from alert_hub.workers.sync import PeerSyncWorker


def _settings(tmp_path: Path, node_id: str) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / f'{node_id}.db'}",
        auto_create_schema=True,
        node_id=node_id,
        node_name=node_id,
        node_region=node_id.removeprefix("node-"),
        signing_key="shared-test-signing-key-with-enough-entropy",
        cluster_secret="shared-test-cluster-key-with-enough-entropy",
        bootstrap_token=f"bootstrap-{node_id}",
        cookie_secure=False,
        trusted_origins=["http://testserver"],
        heartbeat_scan_seconds=0,
        sync_page_size=2,
        sync_interval_seconds=0.1,
    )


def _bootstrap(client: TestClient, node_id: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": f"bootstrap-{node_id}",
            "username": "admin",
            "password": "a-strong-test-password",
            "device_name": node_id,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return {
        "Authorization": f"Bearer {body['access_token']}",
        "X-CSRF-Token": body["csrf_token"],
    }


def _pull(target_app: object, target_settings: Settings, source_app: object) -> None:
    async def run() -> None:
        transport = httpx.ASGITransport(app=source_app)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport) as client:
            worker = PeerSyncWorker(
                target_app.state.session_factory,  # type: ignore[attr-defined]
                target_settings.model_copy(update={"peer_urls": ["http://simulated-private-peer"]}),
                client=client,
            )
            await worker.sync_once()
            assert worker.states["http://simulated-private-peer"].last_error is None

    asyncio.run(run())


def _event(
    *, external_event_id: str, status: str, starts_at: str, ends_at: str | None = None
) -> dict[str, object]:
    return {
        "external_event_id": external_event_id,
        "dedup_key": "shared-database-down",
        "status": status,
        "title": "Shared database is down",
        "description": "Three-node convergence regression",
        "severity": "critical",
        "starts_at": starts_at,
        "ends_at": ends_at,
        "labels": {"service": "database", "target_name": "shared-db"},
        "annotations": {"runbook": "db-recovery"},
    }


def _assert_projection(app: object, expected_status: str, expected_events: int) -> None:
    with app.state.session_factory() as db:  # type: ignore[attr-defined]
        incidents = db.scalars(select(Incident)).all()
        timeline = db.scalars(select(IncidentEvent)).all()
        assert len(incidents) == 1
        assert incidents[0].status == expected_status
        assert len(timeline) == expected_events
        assert len({event.event_key for event in timeline}) == expected_events


def test_three_nodes_converge_after_partition_out_of_order_resolve_and_refire(
    tmp_path: Path,
) -> None:
    """Exercise three autonomous SQLite nodes without pretending this is a network drill."""

    settings = {node: _settings(tmp_path, node) for node in ("node-ru", "node-nl", "node-de")}
    apps = {node: create_app(node_settings) for node, node_settings in settings.items()}

    with (
        TestClient(apps["node-ru"], base_url="http://testserver") as ru,
        TestClient(apps["node-nl"], base_url="http://testserver") as nl,
        TestClient(apps["node-de"], base_url="http://testserver") as de,
    ):
        auth = _bootstrap(ru, "node-ru")
        source_response = ru.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "Shared database", "kind": "generic_json", "region": "ru"},
        )
        assert source_response.status_code == 201, source_response.text
        source = source_response.json()

        # All nodes learn the source before the simulated network partition.
        _pull(apps["node-nl"], settings["node-nl"], apps["node-ru"])
        _pull(apps["node-de"], settings["node-de"], apps["node-ru"])

        ingest_path = f"/ingest/v1/events/{source['id']}"
        source_auth = {"Authorization": f"Bearer {source['token']}"}
        firing = _event(
            external_event_id="occurrence-1-firing",
            status="firing",
            starts_at="2026-09-01T10:00:00Z",
        )
        resolved = _event(
            external_event_id="occurrence-1-resolved",
            status="resolved",
            starts_at="2026-09-01T10:00:00Z",
            ends_at="2026-09-01T10:05:00Z",
        )

        # RU and NL independently receive the same alert while DE sees resolve first.
        # Duplicate firing must collapse by event key after the partition heals.
        assert ru.post(ingest_path, headers=source_auth, json=firing).status_code == 200
        assert nl.post(ingest_path, headers=source_auth, json=firing).status_code == 200
        assert de.post(ingest_path, headers=source_auth, json=resolved).status_code == 200

        # RU and NL reconnect first while DE remains isolated.
        _pull(apps["node-ru"], settings["node-ru"], apps["node-nl"])
        _pull(apps["node-nl"], settings["node-nl"], apps["node-ru"])
        _assert_projection(apps["node-ru"], "open", 1)
        _assert_projection(apps["node-nl"], "open", 1)
        _assert_projection(apps["node-de"], "resolved", 1)

        # DE returns. Relay through different peers and repeat once to cover cursor paging.
        for target, source_node in (
            ("node-ru", "node-de"),
            ("node-nl", "node-ru"),
            ("node-de", "node-nl"),
            ("node-ru", "node-nl"),
            ("node-nl", "node-de"),
            ("node-de", "node-ru"),
        ):
            _pull(apps[target], settings[target], apps[source_node])

        for app in apps.values():
            _assert_projection(app, "resolved", 2)

        refiring = _event(
            external_event_id="occurrence-2-firing",
            status="firing",
            starts_at="2026-09-01T11:00:00Z",
        )
        assert nl.post(ingest_path, headers=source_auth, json=refiring).status_code == 200

        _pull(apps["node-ru"], settings["node-ru"], apps["node-nl"])
        _pull(apps["node-de"], settings["node-de"], apps["node-ru"])
        _pull(apps["node-nl"], settings["node-nl"], apps["node-de"])

        for app in apps.values():
            _assert_projection(app, "open", 3)
