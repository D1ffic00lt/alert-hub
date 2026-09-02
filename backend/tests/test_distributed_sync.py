from __future__ import annotations

import asyncio
import base64
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from alert_hub.application.sync import (
    IncomingClusterEvent,
    advance_peer_cursor,
    apply_cluster_events,
)
from alert_hub.infrastructure.db.models import (
    AuditLog,
    ClusterEvent,
    Incident,
    IncidentEvent,
    Node,
    NotificationChannel,
    NotificationRoute,
    PrometheusDatasource,
    PushSubscription,
    Session,
    Source,
    SyncCursor,
    User,
)
from alert_hub.main import create_app
from alert_hub.settings import Settings
from alert_hub.workers import sync as sync_worker_module
from alert_hub.workers.sync import PeerSyncWorker


def _settings(tmp_path: Path, node_id: str) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / f'{node_id}.db'}",
        auto_create_schema=True,
        node_id=node_id,
        node_name=node_id,
        node_region="test",
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


def _pull(target_app, target_settings: Settings, source_app) -> PeerSyncWorker:
    async def run() -> PeerSyncWorker:
        transport = httpx.ASGITransport(app=source_app)
        async with httpx.AsyncClient(transport=transport) as client:
            worker_settings = target_settings.model_copy(
                update={"peer_urls": ["http://configured-peer"]}
            )
            worker = PeerSyncWorker(
                target_app.state.session_factory,
                worker_settings,
                client=client,
            )
            await worker.sync_once()
            return worker

    return asyncio.run(run())


def _generic_payload() -> dict[str, object]:
    return {
        "external_event_id": "same-external-event",
        "dedup_key": "database-down",
        "status": "firing",
        "title": "Database is down",
        "description": "The primary database is unavailable",
        "severity": "critical",
        "starts_at": "2026-09-01T10:00:00Z",
        "labels": {"service": "database"},
        "annotations": {"runbook": "db-recovery"},
    }


def test_empty_cursor_bootstraps_new_node_and_replicates_sensitive_state(
    tmp_path: Path,
) -> None:
    settings_a = _settings(tmp_path, "node-a")
    settings_b = _settings(tmp_path, "node-b")
    app_a = create_app(settings_a)
    app_b = create_app(settings_b)

    with (
        TestClient(app_a, base_url="http://testserver") as client_a,
        TestClient(app_b, base_url="http://testserver") as client_b,
    ):
        auth = _bootstrap(client_a, "node-a")
        access_token = auth["Authorization"]
        raw_refresh = client_a.cookies.get(settings_a.refresh_cookie_name)
        assert raw_refresh

        source_response = client_a.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "Generic", "kind": "generic_json", "region": "test"},
        )
        assert source_response.status_code == 201, source_response.text
        source = source_response.json()
        ingest = client_a.post(
            f"/ingest/v1/events/{source['id']}",
            headers={"Authorization": f"Bearer {source['token']}"},
            json=_generic_payload(),
        )
        assert ingest.status_code == 200, ingest.text

        channel_response = client_a.post(
            "/api/v1/channels",
            headers=auth,
            json={
                "name": "Telegram",
                "kind": "telegram",
                "config": {"bot_token": "replicated-secret", "chat_id": "123"},
            },
        )
        assert channel_response.status_code == 201, channel_response.text

        push_response = client_a.post(
            "/api/v1/push/subscriptions",
            headers=auth,
            json={
                "endpoint": "https://1.1.1.1/push/replicated-device",
                "keys": {
                    "p256dh": base64.urlsafe_b64encode(os.urandom(65)).decode(),
                    "auth": base64.urlsafe_b64encode(os.urandom(16)).decode(),
                },
                "device_name": "node-a-browser",
            },
        )
        assert push_response.status_code == 201, push_response.text

        worker = _pull(app_b, settings_b, app_a)
        assert worker.states["http://configured-peer"].last_error is None

        me = client_b.get("/api/v1/auth/me", headers={"Authorization": access_token})
        assert me.status_code == 200, me.text
        assert me.json()["username"] == "admin"

        # A shared raw cookie can refresh on another node because only its hash is replicated.
        csrf = client_a.cookies.get(settings_a.csrf_cookie_name)
        client_b.cookies.set(settings_b.refresh_cookie_name, raw_refresh)
        client_b.cookies.set(settings_b.csrf_cookie_name, str(csrf))
        refresh = client_b.post(
            "/api/v1/auth/refresh",
            headers={"Origin": "http://testserver", "X-CSRF-Token": str(csrf)},
        )
        assert refresh.status_code == 200, refresh.text

        with app_b.state.session_factory() as db:
            assert int(db.scalar(select(func.count(User.id))) or 0) == 1
            assert int(db.scalar(select(func.count(Session.id))) or 0) == 1
            assert int(db.scalar(select(func.count(Source.id))) or 0) == 1
            assert int(db.scalar(select(func.count(Incident.id))) or 0) == 1
            assert int(db.scalar(select(func.count(IncidentEvent.id))) or 0) == 1
            assert int(db.scalar(select(func.count(NotificationChannel.id))) or 0) == 1
            assert int(db.scalar(select(func.count(PushSubscription.id))) or 0) == 1
            assert int(db.scalar(select(func.count(Node.id))) or 0) == 2
            serialized_history = "\n".join(
                str(event.payload_json) for event in db.scalars(select(ClusterEvent)).all()
            )
            assert raw_refresh not in serialized_history
            assert "replicated-secret" not in serialized_history

        assert client_a.delete(f"/api/v1/sources/{source['id']}", headers=auth).status_code == 204
        assert (
            client_a.delete(
                f"/api/v1/channels/{channel_response.json()['id']}", headers=auth
            ).status_code
            == 204
        )
        assert (
            client_a.delete(
                f"/api/v1/push/subscriptions/{push_response.json()['id']}", headers=auth
            ).status_code
            == 204
        )
        second_pull = _pull(app_b, settings_b, app_a)
        assert second_pull.states["http://configured-peer"].last_error is None
        with app_b.state.session_factory() as db:
            replicated_source = db.get(Source, source["id"])
            replicated_channel = db.get(NotificationChannel, channel_response.json()["id"])
            replicated_push = db.get(PushSubscription, push_response.json()["id"])
            assert replicated_source is not None and replicated_source.deleted_at is not None
            assert replicated_channel is not None and replicated_channel.deleted_at is not None
            assert replicated_push is not None and replicated_push.disabled_at is not None


def test_user_and_session_in_same_sync_page_are_projected_once(tmp_path: Path) -> None:
    settings_a = _settings(tmp_path, "same-page-a")
    settings_b = _settings(tmp_path, "same-page-b")
    app_a = create_app(settings_a)
    app_b = create_app(settings_b)

    with (
        TestClient(app_a, base_url="http://testserver") as client_a,
        TestClient(app_b, base_url="http://testserver") as client_b,
    ):
        # Prime the cursor with node-a seq=1. Bootstrap then emits session seq=2
        # followed by user seq=3, so the configured two-event page contains both.
        first_pull = _pull(app_b, settings_b, app_a)
        assert first_pull.states["http://configured-peer"].last_error is None

        auth = _bootstrap(client_a, "same-page-a")
        second_pull = _pull(app_b, settings_b, app_a)
        assert second_pull.states["http://configured-peer"].last_error is None

        me = client_b.get("/api/v1/auth/me", headers={"Authorization": auth["Authorization"]})
        assert me.status_code == 200, me.text
        with app_b.state.session_factory() as db:
            assert int(db.scalar(select(func.count(User.id))) or 0) == 1
            assert int(db.scalar(select(func.count(Session.id))) or 0) == 1


def test_repeated_state_upserts_in_same_sync_page_project_once(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "node-page-target")
    app = create_app(settings)
    occurred_at = datetime(2026, 9, 2, 15, 25, tzinfo=UTC)
    node_id = "ru"
    base_payload: dict[str, object] = {
        "name": "ru",
        "region": "ru",
        "public_api_url": "https://alerts.example.test",
        "private_peer_url": "https://peer-ru.example.test",
        "enabled_roles": ["ingest", "notify", "sync"],
        "created_at": occurred_at.isoformat(),
    }
    incoming = [
        IncomingClusterEvent(
            event_id="node-upsert-v0.1.1",
            origin_node_id=node_id,
            origin_seq=1,
            entity_type="node",
            entity_id=node_id,
            operation="upsert",
            occurred_at=occurred_at,
            payload={**base_payload, "software_version": "v0.1.1"},
        ),
        IncomingClusterEvent(
            event_id="node-upsert-v0.1.2",
            origin_node_id=node_id,
            origin_seq=2,
            entity_type="node",
            entity_id=node_id,
            operation="upsert",
            occurred_at=occurred_at + timedelta(minutes=43),
            payload={**base_payload, "software_version": "v0.1.2"},
        ),
        IncomingClusterEvent(
            event_id="route-upsert-old",
            origin_node_id=node_id,
            origin_seq=3,
            entity_type="notification_route",
            entity_id="primary-route",
            operation="upsert",
            occurred_at=occurred_at + timedelta(minutes=44),
            payload={"name": "Old route", "priority": 1},
        ),
        IncomingClusterEvent(
            event_id="route-upsert-latest",
            origin_node_id=node_id,
            origin_seq=4,
            entity_type="notification_route",
            entity_id="primary-route",
            operation="upsert",
            occurred_at=occurred_at + timedelta(minutes=45),
            payload={"name": "Latest route", "priority": 2},
        ),
        IncomingClusterEvent(
            event_id="datasource-upsert-old",
            origin_node_id=node_id,
            origin_seq=5,
            entity_type="prometheus_datasource",
            entity_id="primary-prometheus",
            operation="upsert",
            occurred_at=occurred_at + timedelta(minutes=46),
            payload={"name": "Old Prometheus", "url": "https://old.example.test"},
        ),
        IncomingClusterEvent(
            event_id="datasource-upsert-latest",
            origin_node_id=node_id,
            origin_seq=6,
            entity_type="prometheus_datasource",
            entity_id="primary-prometheus",
            operation="upsert",
            occurred_at=occurred_at + timedelta(minutes=47),
            payload={"name": "Latest Prometheus", "url": "https://new.example.test"},
        ),
    ]

    with TestClient(app, base_url="http://testserver"):
        with app.state.session_factory.begin() as db:
            result = apply_cluster_events(db, incoming, settings)
            assert result.applied == 6
            assert result.duplicates == 0

        with app.state.session_factory.begin() as db:
            retry = apply_cluster_events(db, incoming, settings)
            assert retry.applied == 0
            assert retry.duplicates == 6

        with app.state.session_factory() as db:
            nodes = db.scalars(select(Node).where(Node.id == node_id)).all()
            assert len(nodes) == 1
            assert nodes[0].software_version == "v0.1.2"
            assert nodes[0].last_seen_at == occurred_at + timedelta(minutes=43)
            routes = db.scalars(
                select(NotificationRoute).where(NotificationRoute.id == "primary-route")
            ).all()
            assert len(routes) == 1
            assert routes[0].name == "Latest route"
            assert routes[0].priority == 2
            datasources = db.scalars(
                select(PrometheusDatasource).where(PrometheusDatasource.id == "primary-prometheus")
            ).all()
            assert len(datasources) == 1
            assert datasources[0].name == "Latest Prometheus"
            assert datasources[0].url == "https://new.example.test"


def test_same_page_bootstrap_conflict_records_one_audit_entry(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "bootstrap-page-target")
    app = create_app(settings)
    occurred_at = datetime(2026, 9, 2, 16, tzinfo=UTC)
    incoming = [
        IncomingClusterEvent(
            event_id=f"bootstrap-{sequence}",
            origin_node_id="bootstrap-origin",
            origin_seq=sequence,
            entity_type="user",
            entity_id=f"admin-{sequence}",
            operation="bootstrap",
            occurred_at=occurred_at + timedelta(seconds=sequence),
            payload={
                "username": f"admin-{sequence}",
                "password_hash": f"opaque-password-hash-{sequence}",
                "is_admin": True,
                "created_at": (occurred_at + timedelta(seconds=sequence)).isoformat(),
            },
        )
        for sequence in (1, 2)
    ]

    with TestClient(app, base_url="http://testserver"):
        with app.state.session_factory.begin() as db:
            result = apply_cluster_events(db, incoming, settings)
            assert result.applied == 2
            assert result.duplicates == 0

        with app.state.session_factory.begin() as db:
            retry = apply_cluster_events(db, incoming, settings)
            assert retry.applied == 0
            assert retry.duplicates == 2

        with app.state.session_factory() as db:
            conflicts = db.scalars(
                select(AuditLog).where(AuditLog.action == "bootstrap_conflict_detected")
            ).all()
            assert len(conflicts) == 1
            assert conflicts[0].details_json["user_ids"] == ["admin-1", "admin-2"]


def test_partitioned_identical_alerts_converge_to_one_incident_and_event(
    tmp_path: Path,
) -> None:
    settings_a = _settings(tmp_path, "partition-a")
    settings_b = _settings(tmp_path, "partition-b")
    app_a = create_app(settings_a)
    app_b = create_app(settings_b)

    with (
        TestClient(app_a, base_url="http://testserver") as client_a,
        TestClient(app_b, base_url="http://testserver") as client_b,
    ):
        auth = _bootstrap(client_a, "partition-a")
        source_response = client_a.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "Partition source", "kind": "generic_json"},
        )
        source = source_response.json()
        _pull(app_b, settings_b, app_a)

        for client in (client_a, client_b):
            response = client.post(
                f"/ingest/v1/events/{source['id']}",
                headers={"Authorization": f"Bearer {source['token']}"},
                json=_generic_payload(),
            )
            assert response.status_code == 200, response.text

        _pull(app_a, settings_a, app_b)
        _pull(app_b, settings_b, app_a)

        incident_ids: list[str] = []
        for app in (app_a, app_b):
            with app.state.session_factory() as db:
                incidents = db.scalars(select(Incident)).all()
                timeline = db.scalars(select(IncidentEvent)).all()
                assert len(incidents) == 1
                assert len(timeline) == 1
                assert incidents[0].status == "open"
                incident_ids.append(incidents[0].id)
                incident_origins = {
                    event.origin_node_id
                    for event in db.scalars(
                        select(ClusterEvent).where(ClusterEvent.entity_type == "incident")
                    ).all()
                }
                assert incident_origins == {"partition-a", "partition-b"}
        assert incident_ids[0] == incident_ids[1]


def test_out_of_order_duplicate_application_and_cursor_gap_safety(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "projection-node")
    app = create_app(settings)
    occurred = datetime(2026, 9, 1, 10, tzinfo=UTC)
    seq_two = IncomingClusterEvent(
        event_id="00000000-0000-0000-0000-000000000002",
        origin_node_id="remote-origin",
        origin_seq=2,
        entity_type="regression",
        entity_id="entity",
        operation="upsert",
        occurred_at=occurred,
        payload={"sequence": 2},
    )
    seq_one = IncomingClusterEvent(
        event_id="00000000-0000-0000-0000-000000000001",
        origin_node_id="remote-origin",
        origin_seq=1,
        entity_type="regression",
        entity_id="entity",
        operation="upsert",
        occurred_at=occurred,
        payload={"sequence": 1},
    )

    with TestClient(app):
        with app.state.session_factory.begin() as db:
            result = apply_cluster_events(db, [seq_two, seq_two], settings)
            assert result.applied == 1
            assert result.duplicates == 1
            assert advance_peer_cursor(db, "remote-peer", {"remote-origin": 2}) == {}

        with app.state.session_factory.begin() as db:
            result = apply_cluster_events(db, [seq_one, seq_two], settings)
            assert result.applied == 1
            assert result.duplicates == 1
            assert advance_peer_cursor(db, "remote-peer", {"remote-origin": 2}) == {
                "remote-origin": 2
            }


def test_split_brain_bootstrap_is_detected_and_disables_local_admin(tmp_path: Path) -> None:
    settings_a = _settings(tmp_path, "bootstrap-a")
    settings_b = _settings(tmp_path, "bootstrap-b")
    app_a = create_app(settings_a)
    app_b = create_app(settings_b)
    with (
        TestClient(app_a, base_url="http://testserver") as client_a,
        TestClient(app_b, base_url="http://testserver") as client_b,
    ):
        _bootstrap(client_a, "bootstrap-a")
        _bootstrap(client_b, "bootstrap-b")
        _pull(app_b, settings_b, app_a)

        with app_b.state.session_factory() as db:
            local_user = db.scalar(select(User).where(User.username == "admin"))
            assert local_user is not None
            assert local_user.disabled_at is not None
            conflict = db.scalar(
                select(AuditLog).where(AuditLog.action == "bootstrap_conflict_detected")
            )
            assert conflict is not None
            assert conflict.details_json["requires_manual_resolution"] is True


def test_worker_exponential_backoff_with_jitter_cap(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "backoff-node").model_copy(
        update={
            "peer_urls": ["http://unavailable-peer"],
            "sync_backoff_initial_seconds": 1.0,
            "sync_backoff_max_seconds": 4.0,
            "sync_backoff_jitter_ratio": 0.2,
        }
    )
    app = create_app(settings.model_copy(update={"peer_urls": []}))
    clock = [0.0]
    requests = [0]

    def unavailable(request: httpx.Request) -> httpx.Response:
        requests[0] += 1
        return httpx.Response(503, request=request)

    async def scenario() -> PeerSyncWorker:
        async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
            worker = PeerSyncWorker(
                app.state.session_factory,
                settings,
                client=client,
                monotonic=lambda: clock[0],
                random_value=lambda: 0.5,
            )
            await worker.sync_once()
            state = worker.states["http://unavailable-peer"]
            assert (state.failures, state.next_attempt_at) == (1, 1.0)
            clock[0] = 0.5
            await worker.sync_once()
            assert requests[0] == 1
            clock[0] = 1.0
            await worker.sync_once()
            assert (state.failures, state.next_attempt_at) == (2, 3.0)
            clock[0] = 3.0
            await worker.sync_once()
            assert (state.failures, state.next_attempt_at) == (3, 7.0)
            clock[0] = 7.0
            await worker.sync_once()
            assert (state.failures, state.next_attempt_at) == (4, 11.0)
            return worker

    with TestClient(app):
        worker = asyncio.run(scenario())
    assert worker.states["http://unavailable-peer"].last_error


def test_worker_retries_out_of_order_page_without_advancing_over_gap(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "page-node").model_copy(
        update={"peer_urls": ["http://page-peer"]}
    )
    app = create_app(settings.model_copy(update={"peer_urls": []}))
    clock = [0.0]
    query_count = [0]
    occurred_at = "2026-09-01T10:00:00Z"

    def event(sequence: int) -> dict[str, object]:
        return {
            "event_id": f"00000000-0000-0000-0000-{sequence:012d}",
            "origin_node_id": "page-origin",
            "origin_seq": sequence,
            "entity_type": "regression",
            "entity_id": "page-entity",
            "operation": "upsert",
            "occurred_at": occurred_at,
            "payload": {"sequence": sequence},
        }

    def peer(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/nodes/health"):
            return httpx.Response(
                200,
                request=request,
                json={
                    "status": "ok",
                    "node_id": "page-peer",
                    "region": "test",
                    "software_version": "test",
                    "cursor": {"page-origin": 2},
                },
            )
        body = json.loads(request.content)
        query_count[0] += 1
        assert body["cursor"] == {}
        events = [event(2), event(2)] if query_count[0] == 1 else [event(1), event(2)]
        return httpx.Response(
            200,
            request=request,
            json={"events": events, "cursor": {"page-origin": 2}, "has_more": False},
        )

    async def scenario() -> PeerSyncWorker:
        async with httpx.AsyncClient(transport=httpx.MockTransport(peer)) as client:
            worker = PeerSyncWorker(
                app.state.session_factory,
                settings,
                client=client,
                monotonic=lambda: clock[0],
            )
            await worker.sync_once()
            with app.state.session_factory() as db:
                assert db.scalar(select(func.count(SyncCursor.id))) == 0
            clock[0] = settings.sync_interval_seconds
            await worker.sync_once()
            return worker

    with TestClient(app):
        worker = asyncio.run(scenario())
        with app.state.session_factory() as db:
            cursor = db.scalar(select(SyncCursor).where(SyncCursor.peer_node_id == "page-peer"))
            assert cursor is not None and cursor.origin_seq == 2
            assert (
                int(
                    db.scalar(
                        select(func.count(ClusterEvent.event_id)).where(
                            ClusterEvent.origin_node_id == "page-origin"
                        )
                    )
                    or 0
                )
                == 2
            )
    assert query_count[0] == 2
    assert worker.states["http://page-peer"].last_error is None


def test_worker_rejects_oversized_peer_response_without_cursor_advance(tmp_path: Path) -> None:
    settings = _settings(tmp_path, "bounded-peer-node").model_copy(
        update={
            "peer_urls": ["http://bounded-peer"],
            "sync_max_response_bytes": 1_024,
        }
    )
    app = create_app(settings.model_copy(update={"peer_urls": []}))

    def peer(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/nodes/health"):
            return httpx.Response(
                200,
                request=request,
                json={
                    "status": "ok",
                    "node_id": "bounded-peer",
                    "region": "test",
                    "software_version": "test",
                    "cursor": {"remote-origin": 1},
                },
            )
        return httpx.Response(200, request=request, content=b"x" * 1_025)

    async def scenario() -> PeerSyncWorker:
        async with httpx.AsyncClient(transport=httpx.MockTransport(peer)) as client:
            worker = PeerSyncWorker(app.state.session_factory, settings, client=client)
            await worker.sync_once()
            return worker

    with TestClient(app):
        worker = asyncio.run(scenario())
        with app.state.session_factory() as db:
            assert db.scalar(select(func.count(SyncCursor.id))) == 0
    state = worker.states["http://bounded-peer"]
    assert state.failures == 1
    assert state.last_error is not None
    assert "SYNC_MAX_RESPONSE_BYTES" in state.last_error


def test_worker_owned_http_client_ignores_proxy_env_and_redirects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = _settings(tmp_path, "http-client-node").model_copy(update={"peer_urls": []})
    app = create_app(settings)
    captured: dict[str, object] = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(sync_worker_module.httpx, "AsyncClient", FakeAsyncClient)
    worker = PeerSyncWorker(app.state.session_factory, settings)
    asyncio.run(worker.sync_once())
    app.state.engine.dispose()

    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False
