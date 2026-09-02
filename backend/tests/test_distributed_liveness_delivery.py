from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from alert_hub.application.heartbeats import record_heartbeat_observation
from alert_hub.application.incidents import incident_projection_id
from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
    ProviderRegistry,
    deterministic_delivery_id,
    enqueue_notification_event,
)
from alert_hub.application.sync import IncomingClusterEvent, apply_cluster_events
from alert_hub.domain.routing import NodeCandidate, rank_delivery_nodes
from alert_hub.infrastructure.db.base import new_id
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    Delivery,
    HeartbeatState,
    Incident,
    IncidentEvent,
    Node,
    NotificationChannel,
    NotificationRoute,
    Source,
)
from alert_hub.main import create_app
from alert_hub.settings import Settings
from alert_hub.workers.heartbeat import evaluate_heartbeats
from alert_hub.workers.notifications import NotificationOutboxProcessor
from alert_hub.workers.sync import PeerSyncWorker


class _SuccessProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[NotificationMessage, DeliveryTarget]] = []

    async def send(
        self,
        message: NotificationMessage,
        target: DeliveryTarget,
    ) -> DeliveryResult:
        self.calls.append((message, target))
        return DeliveryResult("succeeded", "http_204")


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _settings(tmp_path: Path, node_id: str) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / f'{node_id}.db'}",
        auto_create_schema=True,
        node_id=node_id,
        node_name=node_id,
        node_region=node_id,
        signing_key="shared-test-signing-key-with-enough-entropy",
        cluster_secret="shared-test-cluster-key-with-enough-entropy",
        bootstrap_token=f"bootstrap-{node_id}",
        cookie_secure=False,
        trusted_origins=["http://testserver"],
        heartbeat_scan_seconds=0,
        sync_page_size=1,
        notify_enabled=False,
        sync_enabled=True,
        notification_failover_base_seconds=60,
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


def _pull(target_app: Any, target_settings: Settings, source_app: Any) -> None:
    async def run() -> None:
        transport = httpx.ASGITransport(app=source_app)
        async with httpx.AsyncClient(transport=transport) as client:
            worker = PeerSyncWorker(
                target_app.state.session_factory,
                target_settings.model_copy(
                    update={
                        "peer_urls": ["http://simulated-private-peer"],
                        "sync_enabled": True,
                    }
                ),
                client=client,
            )
            await worker.sync_once()
            assert worker.states["http://simulated-private-peer"].last_error is None

    asyncio.run(run())


def _assert_resolved_heartbeat(app: Any, source_id: str) -> None:
    with app.state.session_factory() as db:
        incident = db.scalar(select(Incident).where(Incident.source_id == source_id))
        assert incident is not None and incident.status == "resolved"
        timeline = db.scalars(
            select(IncidentEvent)
            .where(IncidentEvent.incident_id == incident.id)
            .order_by(IncidentEvent.occurred_at, IncidentEvent.event_key)
        ).all()
        assert [event.event_type for event in timeline] == ["firing", "resolved"]
        assert len({event.event_key for event in timeline}) == 2
        state = db.get(HeartbeatState, source_id)
        assert state is not None and state.missed is False


def test_heartbeat_observations_prevent_false_misses_and_resolve_out_of_order(
    tmp_path: Path,
) -> None:
    settings = {node: _settings(tmp_path, node) for node in ("node-a", "node-b", "node-c")}
    apps = {node: create_app(node_settings) for node, node_settings in settings.items()}

    with (
        TestClient(apps["node-a"], base_url="http://testserver") as client_a,
        TestClient(apps["node-b"], base_url="http://testserver") as client_b,
        TestClient(apps["node-c"], base_url="http://testserver") as client_c,
    ):
        del client_b, client_c
        auth = _bootstrap(client_a, "node-a")
        response = client_a.post(
            "/api/v1/sources",
            headers=auth,
            json={
                "name": "Shared heartbeat",
                "kind": "heartbeat",
                "config": {"interval_seconds": 60, "grace_seconds": 0},
            },
        )
        assert response.status_code == 201, response.text
        source_id = response.json()["id"]
        _pull(apps["node-b"], settings["node-b"], apps["node-a"])
        _pull(apps["node-c"], settings["node-c"], apps["node-a"])

        with apps["node-a"].state.session_factory.begin() as db:
            source = db.get(Source, source_id)
            assert source is not None
            state = db.get(HeartbeatState, source_id)
            assert state is not None
            # Anchor the synthetic observation after the persisted heartbeat epoch.
            # A wall-clock constant eventually becomes older than created_at and
            # correctly gets ignored as a stale replicated observation.
            base = max(source.created_at, state.last_received_at) + timedelta(seconds=1)
            record_heartbeat_observation(db, source, settings["node-a"], base)
        _pull(apps["node-b"], settings["node-b"], apps["node-a"])

        with apps["node-b"].state.session_factory.begin() as db:
            assert (
                evaluate_heartbeats(db, settings["node-b"], now=base + timedelta(seconds=30)) == 0
            )
            assert db.scalar(select(Incident).where(Incident.source_id == source_id)) is None
            assert (
                evaluate_heartbeats(db, settings["node-b"], now=base + timedelta(seconds=61)) == 1
            )

        # C learns the recovery before it learns B's missed event. Applying the older
        # firing later must synthesize the same deterministic resolution.
        recovered_at = base + timedelta(seconds=62)
        with apps["node-a"].state.session_factory.begin() as db:
            source = db.get(Source, source_id)
            assert source is not None
            record_heartbeat_observation(db, source, settings["node-a"], recovered_at)
        _pull(apps["node-c"], settings["node-c"], apps["node-a"])
        _pull(apps["node-c"], settings["node-c"], apps["node-b"])
        _assert_resolved_heartbeat(apps["node-c"], source_id)

        # B instead learns the observation after its local firing; that order must also resolve.
        _pull(apps["node-b"], settings["node-b"], apps["node-a"])
        _assert_resolved_heartbeat(apps["node-b"], source_id)

        # Relay the histories back to A and prove all projections converge without duplicates.
        _pull(apps["node-a"], settings["node-a"], apps["node-b"])
        _pull(apps["node-a"], settings["node-a"], apps["node-c"])
        _assert_resolved_heartbeat(apps["node-a"], source_id)


def _seed_notification_projection(
    app: Any,
    *,
    node_ids: tuple[str, str],
    source_id: str,
    incident_id: str,
    event_id: str,
    event_key: str,
    channel_id: str,
    now: datetime,
) -> None:
    cipher = app.state.envelope_cipher
    assert cipher is not None
    with app.state.session_factory.begin() as db:
        for node_id in node_ids:
            node = db.get(Node, node_id)
            if node is None:
                db.add(
                    Node(
                        id=node_id,
                        name=node_id,
                        region=node_id,
                        enabled_roles=["notify"],
                    )
                )
            else:
                node.enabled_roles = ["notify"]
        db.add(
            Source(
                id=source_id,
                name="Shared source",
                kind="generic_json",
                token_hash="not-a-real-token",
            )
        )
        db.flush()
        db.add(
            Incident(
                id=incident_id,
                source_id=source_id,
                fingerprint="f" * 64,
                title="Database down",
                description="Shared logical alert",
                severity="critical",
                status="open",
                labels_json={"service": "database"},
                annotations_json={},
                starts_at=now,
                last_event_at=now,
            )
        )
        db.flush()
        event = IncidentEvent(
            id=event_id,
            origin_node_id=event_id,
            origin_seq=1,
            event_key=event_key,
            incident_id=incident_id,
            event_type="firing",
            occurred_at=now,
            received_at=now,
            payload_json={
                "dedup_key": "database-down",
                "title": "Database down",
                "severity": "critical",
            },
        )
        db.add(event)
        db.add(
            NotificationChannel(
                id=channel_id,
                name="Webhook",
                kind="generic_webhook",
                enabled=True,
                encrypted_config=cipher.encrypt_json(
                    {"url": "https://1.1.1.1/hook"},
                    context=f"channel:{channel_id}:config",
                ),
                eligible_nodes_or_regions={},
            )
        )
        db.add(
            NotificationRoute(
                id=new_id(),
                name="Critical alerts",
                priority=0,
                severity_filter=["critical"],
                channel_ids=[channel_id],
            )
        )
        db.flush()
        enqueue_notification_event(db, event)


def test_connected_nodes_use_logical_event_identity_and_replicated_receipt(
    tmp_path: Path,
) -> None:
    node_ids = ("notify-a", "notify-b")
    settings = {node: _settings(tmp_path, node) for node in node_ids}
    apps = {node: create_app(node_settings) for node, node_settings in settings.items()}
    now = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
    source_id = new_id()
    incident_id = new_id()
    event_key = "same-logical-event-key"
    channel_id = new_id()
    providers = {node: _SuccessProvider() for node in node_ids}
    clocks = {node: _Clock(now) for node in node_ids}

    with (
        TestClient(apps[node_ids[0]], base_url="http://testserver"),
        TestClient(apps[node_ids[1]], base_url="http://testserver"),
    ):
        for node in node_ids:
            _seed_notification_projection(
                apps[node],
                node_ids=node_ids,
                source_id=source_id,
                incident_id=incident_id,
                event_id=f"event-{node}",
                event_key=event_key,
                channel_id=channel_id,
                now=now,
            )

        ranking = rank_delivery_nodes(
            event_key,
            channel_id,
            [NodeCandidate(node, node, frozenset({"notify"})) for node in node_ids],
            {},
        )
        owner, secondary = ranking
        processors = {
            node: NotificationOutboxProcessor(
                apps[node].state.session_factory,
                settings[node],
                apps[node].state.envelope_cipher,
                ProviderRegistry({"generic_webhook": providers[node]}),
                now=clocks[node],
            )
            for node in node_ids
        }

        assert asyncio.run(processors[secondary].run_once()) == 1
        assert providers[secondary].calls == []
        assert asyncio.run(processors[owner].run_once()) == 1
        assert len(providers[owner].calls) == 1

        _pull(apps[secondary], settings[secondary], apps[owner])
        with apps[secondary].state.session_factory() as db:
            delivery = db.scalar(select(Delivery))
            assert delivery is not None and delivery.status == "succeeded"
            assert delivery.event_id == f"event-{secondary}"

        clocks[secondary].value += timedelta(seconds=60)
        assert asyncio.run(processors[secondary].run_once()) == 1
        assert providers[secondary].calls == []
        assert sum(len(provider.calls) for provider in providers.values()) == 1


def test_incident_and_receipt_in_same_sync_page_project_receipt_once(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, "notify-secondary")
    app = create_app(settings)
    now = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
    source_id = new_id()
    incident_id = incident_projection_id(source_id, "f" * 64)
    local_event_id = new_id()
    remote_event_id = new_id()
    event_key = "same-page-logical-event"
    channel_id = new_id()
    receipt_event_id = new_id()
    delivery_id = deterministic_delivery_id(event_key, channel_id, None)

    with TestClient(app, base_url="http://testserver"):
        _seed_notification_projection(
            app,
            node_ids=(settings.node_id, "notify-owner"),
            source_id=source_id,
            incident_id=incident_id,
            event_id=local_event_id,
            event_key=event_key,
            channel_id=channel_id,
            now=now,
        )
        incident_payload = {
            "event_key": event_key,
            "fingerprint": "f" * 64,
            "source_id": source_id,
            "dedup_key": "database-down",
            "status": "firing",
            "title": "Database down",
            "description": "Shared logical alert",
            "severity": "critical",
            "starts_at": now.isoformat(),
            "ends_at": None,
            "labels": {"service": "database"},
            "annotations": {},
            "external_event_id": "same-page-event",
        }
        receipt_payload = {
            "delivery_id": delivery_id,
            "event_id": remote_event_id,
            "source_event_key": event_key,
            "channel_id": channel_id,
            "subscription_id": None,
            "owner_node_id": "notify-owner",
            "attempt": 1,
            "status": "succeeded",
            "provider_status": "http_204",
            "error_code": None,
            "created_at": now.isoformat(),
            "finished_at": now.isoformat(),
            "receipt_event_id": receipt_event_id,
            "receipt_origin_node_id": "notify-owner",
            "receipt_origin_seq": 2,
            "receipt_occurred_at": now.isoformat(),
            "receipt_event_key": f"delivery:{delivery_id}:notify-owner:1:succeeded",
        }
        incoming = [
            IncomingClusterEvent(
                event_id=remote_event_id,
                origin_node_id="notify-owner",
                origin_seq=1,
                entity_type="incident",
                entity_id=incident_id,
                operation="firing",
                occurred_at=now,
                payload=incident_payload,
            ),
            IncomingClusterEvent(
                event_id=receipt_event_id,
                origin_node_id="notify-owner",
                origin_seq=2,
                entity_type="delivery_receipt",
                entity_id=delivery_id,
                operation="delivery_succeeded",
                occurred_at=now,
                payload=receipt_payload,
            ),
        ]

        with app.state.session_factory.begin() as db:
            result = apply_cluster_events(db, incoming, settings)
            assert result.applied == 2

        with app.state.session_factory() as db:
            delivery = db.get(Delivery, delivery_id)
            assert delivery is not None and delivery.status == "succeeded"
            receipt_timeline = db.scalars(
                select(IncidentEvent).where(IncidentEvent.id == receipt_event_id)
            ).all()
            assert len(receipt_timeline) == 1


def test_partitioned_duplicate_deliveries_keep_distinct_receipt_history(
    tmp_path: Path,
) -> None:
    sender_ids = ("notify-a", "notify-b")
    all_ids = (*sender_ids, "notify-observer")
    settings = {node: _settings(tmp_path, node) for node in all_ids}
    apps = {node: create_app(settings[node]) for node in all_ids}
    now = datetime(2026, 9, 2, 13, 0, tzinfo=UTC)
    source_id = new_id()
    incident_id = new_id()
    event_key = "partitioned-logical-event"
    channel_id = new_id()
    providers = {node: _SuccessProvider() for node in sender_ids}

    with (
        TestClient(apps["notify-a"], base_url="http://testserver"),
        TestClient(apps["notify-b"], base_url="http://testserver"),
        TestClient(apps["notify-observer"], base_url="http://testserver"),
    ):
        for node in all_ids:
            _seed_notification_projection(
                apps[node],
                node_ids=sender_ids,
                source_id=source_id,
                incident_id=incident_id,
                event_id=f"event-{node}",
                event_key=event_key,
                channel_id=channel_id,
                now=now,
            )

        for node in sender_ids:
            processor = NotificationOutboxProcessor(
                apps[node].state.session_factory,
                settings[node],
                apps[node].state.envelope_cipher,
                ProviderRegistry({"generic_webhook": providers[node]}),
                now=_Clock(now + timedelta(seconds=60)),
            )
            assert asyncio.run(processor.run_once()) == 1
            assert len(providers[node].calls) == 1

        receipt_ids: set[str] = set()
        for node in sender_ids:
            with apps[node].state.session_factory() as db:
                receipt = db.scalar(
                    select(ClusterEvent).where(ClusterEvent.entity_type == "delivery_receipt")
                )
                assert receipt is not None
                receipt_ids.add(receipt.event_id)
        assert len(receipt_ids) == 2

        for node in sender_ids:
            _pull(apps["notify-observer"], settings["notify-observer"], apps[node])

        with apps["notify-observer"].state.session_factory() as db:
            receipts = db.scalars(
                select(ClusterEvent).where(ClusterEvent.entity_type == "delivery_receipt")
            ).all()
            assert {receipt.event_id for receipt in receipts} == receipt_ids
            delivery = db.scalar(select(Delivery))
            assert delivery is not None and delivery.status == "succeeded"
            receipt_timeline = db.scalars(
                select(IncidentEvent).where(IncidentEvent.event_type == "delivery_succeeded")
            ).all()
            assert len(receipt_timeline) == 2
