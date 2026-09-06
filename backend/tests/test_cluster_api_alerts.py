from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from alert_hub.application.cluster_health import CLUSTER_API_HEALTH_SOURCE_ID
from alert_hub.application.sync import IncomingClusterEvent, apply_cluster_events
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    Incident,
    IncidentEvent,
    Node,
    Outbox,
    PeerEndpointIdentity,
)
from alert_hub.workers.sync import PeerSyncWorker


def test_bulk_api_down_alert_setting_opens_and_resolves_offline_incident(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    class OfflinePeerSnapshot:
        def status_snapshot(self) -> dict[str, dict[str, object]]:
            return {
                "remote-node": {
                    "up": False,
                    "failures": 3,
                    "last_success_at": "2026-09-06T10:00:00Z",
                    "lag_seconds": 0,
                }
            }

    with app.state.session_factory.begin() as db:
        db.add(
            Node(
                id="remote-node",
                name="Germany",
                region="DE",
                private_peer_url="https://de-peer.example.test",
                enabled_roles=["sync", "notify"],
                software_version="v0.1.4",
            )
        )
    app.state.peer_sync_worker = OfflinePeerSnapshot()

    enabled = client.patch(
        "/api/v1/cluster/nodes/api-down-alerts",
        headers=auth,
        json={"node_ids": ["remote-node", "remote-node"], "enabled": True},
    )
    assert enabled.status_code == 200, enabled.text
    assert enabled.json() == {
        "updated": 1,
        "unchanged": 0,
        "alerts_opened": 1,
        "nodes": [{"id": "remote-node", "api_down_alert_enabled": True}],
    }

    status = client.get("/api/v1/cluster/status", headers=auth)
    assert status.status_code == 200
    remote = next(item for item in status.json()["nodes"] if item["id"] == "remote-node")
    assert remote["api_down_alert_enabled"] is True
    assert remote["health"] == "offline"

    incidents = client.get("/api/v1/incidents?status=active", headers=auth)
    assert incidents.status_code == 200, incidents.text
    assert incidents.json()["items"][0]["title"] == "API unavailable: Germany"
    assert incidents.json()["items"][0]["severity"] == "critical"
    assert incidents.json()["items"][0]["source_name"] == "Cluster API health"

    # The managed source powers routing and replication but is not editable as a
    # regular webhook source in the operator UI.
    sources = client.get("/api/v1/sources", headers=auth)
    assert sources.status_code == 200
    assert sources.json() == []
    managed_source_update = client.patch(
        f"/api/v1/sources/{CLUSTER_API_HEALTH_SOURCE_ID}",
        headers=auth,
        json={"enabled": True},
    )
    assert managed_source_update.status_code == 404

    disabled = client.patch(
        "/api/v1/cluster/nodes/api-down-alerts",
        headers=auth,
        json={"node_ids": ["remote-node"], "enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["updated"] == 1
    assert disabled.json()["alerts_opened"] == 0

    with app.state.session_factory() as db:
        incident = db.scalar(
            select(Incident).where(Incident.source_id == CLUSTER_API_HEALTH_SOURCE_ID)
        )
        assert incident is not None and incident.status == "resolved"
        assert int(db.scalar(select(func.count(IncidentEvent.id))) or 0) == 2
        assert int(db.scalar(select(func.count(Outbox.id))) or 0) == 2
        setting_events = db.scalars(
            select(ClusterEvent).where(ClusterEvent.entity_type == "node_api_alert_setting")
        ).all()
        assert [event.payload_json["enabled"] for event in setting_events] == [True, False]


def test_bulk_api_down_alert_setting_rejects_unknown_nodes_atomically(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    response = client.patch(
        "/api/v1/cluster/nodes/api-down-alerts",
        headers=auth,
        json={"node_ids": ["test-node", "missing-node"], "enabled": True},
    )
    assert response.status_code == 404
    assert response.json()["detail"]["node_ids"] == ["missing-node"]
    with app.state.session_factory() as db:
        node = db.get(Node, "test-node")
        assert node is not None and node.api_down_alert_enabled is False
        assert (
            int(
                db.scalar(
                    select(func.count(ClusterEvent.event_id)).where(
                        ClusterEvent.entity_type == "node_api_alert_setting"
                    )
                )
                or 0
            )
            == 0
        )


def test_peer_worker_alerts_after_threshold_and_resolves_after_recovery(
    app,
    settings,
) -> None:
    base_url = "http://germany-peer"
    worker_settings = settings.model_copy(
        update={
            "peer_urls": [base_url],
            "sync_backoff_initial_seconds": 0.1,
            "sync_backoff_max_seconds": 0.1,
            "sync_backoff_jitter_ratio": 0.0,
            "sync_interval_seconds": 0.1,
        }
    )
    clock = [0.0]
    available = [False]

    def peer(request: httpx.Request) -> httpx.Response:
        if not available[0]:
            return httpx.Response(503, request=request)
        if request.url.path.endswith("/nodes/health"):
            return httpx.Response(
                200,
                request=request,
                json={
                    "status": "ok",
                    "node_id": "germany-node",
                    "region": "DE",
                    "software_version": "v0.1.4",
                    "cursor": {},
                },
            )
        assert json.loads(request.content)["cursor"] == {}
        return httpx.Response(
            200,
            request=request,
            json={"events": [], "cursor": {}, "has_more": False},
        )

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(peer)) as http_client:
            worker = PeerSyncWorker(
                app.state.session_factory,
                worker_settings,
                client=http_client,
                monotonic=lambda: clock[0],
            )
            for attempt in range(4):
                clock[0] = attempt * 0.1
                await worker.sync_once()
            with app.state.session_factory() as db:
                events = db.scalars(select(IncidentEvent).order_by(IncidentEvent.occurred_at)).all()
                assert [event.event_type for event in events] == ["firing"]
            available[0] = True
            clock[0] = 0.4
            await worker.sync_once()

    with TestClient(app):
        with app.state.session_factory.begin() as db:
            db.add(
                Node(
                    id="germany-node",
                    name="Germany",
                    region="DE",
                    enabled_roles=["sync", "notify"],
                    software_version="v0.1.4",
                    api_down_alert_enabled=True,
                )
            )
            db.add(
                PeerEndpointIdentity(
                    base_url=base_url,
                    node_id="germany-node",
                )
            )
        asyncio.run(scenario())
        with app.state.session_factory() as db:
            incident = db.scalar(
                select(Incident).where(Incident.source_id == CLUSTER_API_HEALTH_SOURCE_ID)
            )
            assert incident is not None and incident.status == "resolved"
            events = db.scalars(select(IncidentEvent).order_by(IncidentEvent.occurred_at)).all()
            assert [event.event_type for event in events] == ["firing", "resolved"]


def test_replicated_api_alert_setting_waits_for_node_inventory(app, settings) -> None:
    setting_event = IncomingClusterEvent(
        event_id="10000000-0000-0000-0000-000000000001",
        origin_node_id="remote-origin",
        origin_seq=1,
        entity_type="node_api_alert_setting",
        entity_id="late-node",
        operation="upsert",
        occurred_at=datetime(2026, 9, 6, 10, 0, tzinfo=UTC),
        payload={"enabled": True},
    )
    node_event = IncomingClusterEvent(
        event_id="10000000-0000-0000-0000-000000000002",
        origin_node_id="remote-origin",
        origin_seq=2,
        entity_type="node",
        entity_id="late-node",
        operation="upsert",
        occurred_at=datetime(2026, 9, 6, 10, 1, tzinfo=UTC),
        payload={
            "name": "Late node",
            "region": "DE",
            "public_api_url": "https://late.example.test",
            "private_peer_url": "https://late-peer.example.test",
            "enabled_roles": ["sync"],
            "created_at": "2026-09-06T09:00:00Z",
            "software_version": "v0.1.4",
        },
    )

    with TestClient(app):
        with app.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [setting_event], settings).applied == 1
        with app.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [node_event], settings).applied == 1
        with app.state.session_factory() as db:
            node = db.get(Node, "late-node")
            assert node is not None and node.api_down_alert_enabled is True
