from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import select

from alert_hub.api import statistics as statistics_api
from alert_hub.application import statistics as statistics_application
from alert_hub.application.statistics import StatisticsSnapshotCache, statistics_snapshot
from alert_hub.application.sync import IncomingClusterEvent, apply_cluster_events
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    Incident,
    IncidentEvent,
    NotificationChannel,
    Source,
)
from alert_hub.main import create_app
from alert_hub.settings import Settings


def _source(source_id: str, name: str, region: str | None) -> Source:
    return Source(
        id=source_id,
        name=name,
        kind="generic_json",
        region=region,
        token_hash=f"hash-{source_id}",
    )


def _channel(channel_id: str, name: str, kind: str) -> NotificationChannel:
    return NotificationChannel(
        id=channel_id,
        name=name,
        kind=kind,
        encrypted_config=b"test-only-envelope",
    )


def _incident(
    incident_id: str,
    source_id: str,
    *,
    starts_at: datetime,
    severity: str,
    status: str,
    acknowledged_at: datetime | None = None,
    resolved_at: datetime | None = None,
) -> Incident:
    return Incident(
        id=incident_id,
        source_id=source_id,
        fingerprint=f"fingerprint-{incident_id}",
        title=incident_id,
        severity=severity,
        status=status,
        starts_at=starts_at,
        last_event_at=resolved_at or acknowledged_at or starts_at,
        acknowledged_at=acknowledged_at,
        resolved_at=resolved_at,
    )


def _receipt(
    receipt_id: str,
    *,
    sequence: int,
    event_type: str,
    occurred_at: datetime,
    channel_id: str,
    status: str,
) -> ClusterEvent:
    return ClusterEvent(
        event_id=receipt_id,
        origin_node_id="replicated-delivery-node",
        origin_seq=sequence,
        entity_type="delivery_receipt",
        entity_id=f"delivery-{receipt_id}",
        operation=event_type,
        occurred_at=occurred_at,
        payload_json={"channel_id": channel_id, "status": status},
    )


def _lifecycle(
    event_id: str,
    *,
    incident_id: str,
    sequence: int,
    event_type: str,
    occurred_at: datetime,
    starts_at: datetime | None = None,
    source_id: str | None = None,
    severity: str | None = None,
    event_key: str | None = None,
) -> IncidentEvent:
    payload: dict[str, str] = {}
    if starts_at is not None:
        payload["starts_at"] = starts_at.isoformat()
    if source_id is not None:
        payload["source_id"] = source_id
    if severity is not None:
        payload["severity"] = severity
    return IncidentEvent(
        id=event_id,
        origin_node_id="statistics-lifecycle",
        origin_seq=sequence,
        event_key=event_key or f"event-{event_id}",
        incident_id=incident_id,
        event_type=event_type,
        occurred_at=occurred_at,
        payload_json=payload,
    )


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
        peer_allowed_cidrs=[],
        heartbeat_scan_seconds=0,
        notify_enabled=False,
        sync_enabled=False,
    )


@pytest.mark.parametrize(
    ("window", "bucket_seconds", "bucket_count"),
    [("24h", 3_600, 24), ("7d", 21_600, 28), ("30d", 86_400, 30)],
)
def test_statistics_exposes_bounded_zero_filled_windows(
    client: TestClient,
    auth: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    window: str,
    bucket_seconds: int,
    bucket_count: int,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(statistics_application, "utc_now", lambda: now)

    response = client.get(f"/api/v1/metrics/statistics?window={window}", headers=auth)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["window"] == window
    assert payload["generated_at"] == "2026-09-05T12:00:00Z"
    assert payload["ends_at"] == payload["generated_at"]
    assert payload["bucket_seconds"] == bucket_seconds
    assert len(payload["timeline"]) == bucket_count
    assert payload["timeline"][0]["starts_at"] == payload["starts_at"]
    assert all(
        sum(value for key, value in bucket.items() if key != "starts_at") == 0
        for bucket in payload["timeline"]
    )
    assert payload["totals"] == {
        "incidents_started": 0,
        "incidents_resolved": 0,
        "active_incidents": 0,
        "active_critical": 0,
        "acknowledgement_rate": None,
        "resolution_rate": None,
        "mean_time_to_acknowledge_seconds": None,
        "mean_time_to_resolve_seconds": None,
        "deliveries": 0,
        "deliveries_succeeded": 0,
        "deliveries_failed": 0,
        "delivery_success_rate": None,
    }
    assert payload["severities"] == [
        {"severity": "critical", "count": 0},
        {"severity": "warning", "count": 0},
        {"severity": "info", "count": 0},
        {"severity": "unknown", "count": 0},
    ]


def test_statistics_endpoint_reuses_app_scoped_snapshot_until_ttl_expires(
    client: TestClient,
    auth: dict[str, str],
    app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monotonic_clock = [100.0]
    app.state.statistics_snapshot_cache = StatisticsSnapshotCache(
        ttl_seconds=30,
        now=lambda: monotonic_clock[0],
    )
    original_snapshot = statistics_api.statistics_snapshot
    calls = 0

    def counted_snapshot(db, window):
        nonlocal calls
        calls += 1
        return original_snapshot(db, window)

    monkeypatch.setattr(statistics_api, "statistics_snapshot", counted_snapshot)

    first = client.get("/api/v1/metrics/statistics?window=24h", headers=auth)
    second = client.get("/api/v1/metrics/statistics?window=24h", headers=auth)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == first.json()
    assert calls == 1

    monotonic_clock[0] += 30.0
    third = client.get("/api/v1/metrics/statistics?window=24h", headers=auth)

    assert third.status_code == 200
    assert calls == 2


def test_statistics_cache_serves_stale_without_blocking_refresh_followers() -> None:
    monotonic_clock = [100.0]
    cache = StatisticsSnapshotCache(
        ttl_seconds=30,
        stale_ttl_seconds=60,
        now=lambda: monotonic_clock[0],
    )
    cache.put("24h", {"version": "stale"})
    monotonic_clock[0] += 31.0
    refresh_started = Event()
    release_refresh = Event()
    compute_calls = 0

    def slow_refresh() -> dict[str, object]:
        nonlocal compute_calls
        compute_calls += 1
        refresh_started.set()
        if not release_refresh.wait(timeout=2):
            raise RuntimeError("test refresh was not released")
        return {"version": "fresh"}

    with ThreadPoolExecutor(max_workers=2) as executor:
        owner = executor.submit(cache.get_or_compute, "24h", slow_refresh)
        assert refresh_started.wait(timeout=1)
        try:
            follower = executor.submit(
                cache.get_or_compute,
                "24h",
                lambda: pytest.fail("a stale follower must not compute or wait"),
            )
            assert follower.result(timeout=0.5) == {"version": "stale"}
        finally:
            release_refresh.set()
        assert owner.result(timeout=1) == {"version": "fresh"}

    assert compute_calls == 1
    assert cache.get("24h") == {"version": "fresh"}


def test_statistics_cache_falls_back_to_stale_when_refresh_fails() -> None:
    monotonic_clock = [100.0]
    cache = StatisticsSnapshotCache(
        ttl_seconds=30,
        stale_ttl_seconds=60,
        now=lambda: monotonic_clock[0],
    )
    cache.put("24h", {"version": "stale"})
    monotonic_clock[0] += 31.0

    def fail_refresh() -> dict[str, object]:
        raise RuntimeError("database temporarily unavailable")

    assert cache.get_or_compute("24h", fail_refresh) == {"version": "stale"}
    assert cache.get_or_compute("24h", lambda: {"version": "recovered"}) == {"version": "recovered"}


def test_statistics_cache_never_serves_stale_past_its_age_limit() -> None:
    monotonic_clock = [100.0]
    cache = StatisticsSnapshotCache(
        ttl_seconds=30,
        stale_ttl_seconds=60,
        now=lambda: monotonic_clock[0],
    )
    cache.put("24h", {"version": "stale"})
    monotonic_clock[0] = 131.0

    def fail_after_expiry() -> dict[str, object]:
        monotonic_clock[0] = 161.0
        raise RuntimeError("database remained unavailable")

    with pytest.raises(RuntimeError, match="database remained unavailable"):
        cache.get_or_compute("24h", fail_after_expiry)
    assert cache.get("24h") is None


def test_statistics_aggregates_lifecycle_cohorts_and_delivery_receipts(
    client: TestClient,
    auth: dict[str, str],
    app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    starts_at = now - timedelta(hours=24)
    monkeypatch.setattr(statistics_application, "utc_now", lambda: now)

    with app.state.session_factory.begin() as db:
        db.add_all(
            [
                _source("source-alpha", "Alpha", "RU"),
                _source("source-beta", "Beta", None),
                _source("source-idle", "Idle", "EU"),
                _channel("channel-telegram", "Telegram", "telegram"),
                _channel("channel-webhook", "Webhook", "generic_webhook"),
                _channel("channel-idle", "Idle channel", "smtp"),
            ]
        )
        db.add_all(
            [
                _incident(
                    "active-critical",
                    "source-alpha",
                    starts_at=now - timedelta(hours=2),
                    severity="critical",
                    status="acknowledged",
                    acknowledged_at=now - timedelta(minutes=90),
                ),
                _incident(
                    "resolved-warning",
                    "source-alpha",
                    starts_at=now - timedelta(hours=8),
                    severity="warning",
                    status="resolved",
                    resolved_at=now - timedelta(hours=3),
                ),
                _incident(
                    "old-resolved-info",
                    "source-beta",
                    starts_at=now - timedelta(days=2),
                    severity="info",
                    status="resolved",
                    resolved_at=now - timedelta(hours=4),
                ),
                _incident(
                    "old-active-critical",
                    "source-beta",
                    starts_at=now - timedelta(days=40),
                    severity="critical",
                    status="open",
                ),
                _incident(
                    "unknown-status-critical",
                    "source-beta",
                    starts_at=now - timedelta(hours=3),
                    severity="critical",
                    status="future-status",
                ),
                _incident(
                    "skewed-unknown",
                    "source-beta",
                    starts_at=now - timedelta(hours=1),
                    severity="unexpected-severity",
                    status="resolved",
                    acknowledged_at=now - timedelta(hours=2),
                    resolved_at=now - timedelta(hours=2),
                ),
            ]
        )
        db.flush()
        db.add_all(
            [
                _lifecycle(
                    "active-critical-firing",
                    incident_id="active-critical",
                    sequence=1,
                    event_type="firing",
                    occurred_at=now - timedelta(hours=2),
                    starts_at=now - timedelta(hours=2),
                    source_id="source-alpha",
                    severity="critical",
                ),
                _lifecycle(
                    "active-critical-acknowledged",
                    incident_id="active-critical",
                    sequence=2,
                    event_type="acknowledged",
                    occurred_at=now - timedelta(minutes=90),
                ),
                _lifecycle(
                    "resolved-warning-firing",
                    incident_id="resolved-warning",
                    sequence=3,
                    event_type="firing",
                    occurred_at=now - timedelta(hours=8),
                    starts_at=now - timedelta(hours=8),
                    source_id="source-alpha",
                    severity="warning",
                ),
                # Without an explicit starts_at, resolution binds the latest
                # eligible firing cohort.
                _lifecycle(
                    "resolved-warning-resolved",
                    incident_id="resolved-warning",
                    sequence=4,
                    event_type="resolved",
                    occurred_at=now - timedelta(hours=3),
                ),
                # With no eligible firing, this remains a resolved-only cohort.
                _lifecycle(
                    "old-resolved-info-resolved",
                    incident_id="old-resolved-info",
                    sequence=5,
                    event_type="resolved",
                    occurred_at=now - timedelta(hours=4),
                ),
                # Explicit occurrence identity lets an out-of-order resolution
                # converge with its later firing. Its negative duration is clamped.
                _lifecycle(
                    "skewed-unknown-resolved",
                    incident_id="skewed-unknown",
                    sequence=6,
                    event_type="resolved",
                    occurred_at=now - timedelta(hours=2),
                    starts_at=now - timedelta(hours=1),
                ),
                _lifecycle(
                    "skewed-unknown-firing",
                    incident_id="skewed-unknown",
                    sequence=7,
                    event_type="firing",
                    occurred_at=now - timedelta(hours=1),
                    starts_at=now - timedelta(hours=1),
                    source_id="source-beta",
                    severity="unexpected-severity",
                ),
                _receipt(
                    "delivery-at-start",
                    sequence=1,
                    event_type="delivery_succeeded",
                    occurred_at=starts_at,
                    channel_id="channel-webhook",
                    status="succeeded",
                ),
                _receipt(
                    "delivery-succeeded",
                    sequence=2,
                    event_type="delivery_succeeded",
                    occurred_at=now - timedelta(minutes=90),
                    channel_id="channel-telegram",
                    status="succeeded",
                ),
                _receipt(
                    "delivery-retrying",
                    sequence=3,
                    event_type="delivery_failed",
                    occurred_at=now - timedelta(minutes=80),
                    channel_id="channel-telegram",
                    status="retrying",
                ),
                _receipt(
                    "delivery-failed",
                    sequence=4,
                    event_type="delivery_failed",
                    occurred_at=now - timedelta(minutes=70),
                    channel_id="channel-webhook",
                    status="failed",
                ),
                _receipt(
                    "delivery-at-end",
                    sequence=5,
                    event_type="delivery_failed",
                    occurred_at=now,
                    channel_id="channel-webhook",
                    status="failed",
                ),
                _lifecycle(
                    "unrelated-incident-event",
                    incident_id="active-critical",
                    sequence=8,
                    event_type="commented",
                    occurred_at=now - timedelta(minutes=60),
                ),
            ]
        )

    response = client.get("/api/v1/metrics/statistics?window=24h", headers=auth)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["totals"] == {
        "incidents_started": 3,
        "incidents_resolved": 3,
        "active_incidents": 2,
        "active_critical": 2,
        "acknowledgement_rate": 33.3,
        "resolution_rate": 66.7,
        "mean_time_to_acknowledge_seconds": 1_800.0,
        "mean_time_to_resolve_seconds": 9_000.0,
        "deliveries": 4,
        "deliveries_succeeded": 2,
        "deliveries_failed": 2,
        "delivery_success_rate": 50.0,
    }
    assert payload["severities"] == [
        {"severity": "critical", "count": 1},
        {"severity": "warning", "count": 1},
        {"severity": "info", "count": 0},
        {"severity": "unknown", "count": 1},
    ]
    assert payload["sources"] == [
        {"source_id": "source-alpha", "name": "Alpha", "region": "RU", "count": 2},
        {"source_id": "source-beta", "name": "Beta", "region": None, "count": 1},
    ]
    assert payload["channels"] == [
        {
            "channel_id": "channel-telegram",
            "name": "Telegram",
            "kind": "telegram",
            "total": 2,
            "succeeded": 1,
            "failed": 1,
            "success_rate": 50.0,
        },
        {
            "channel_id": "channel-webhook",
            "name": "Webhook",
            "kind": "generic_webhook",
            "total": 2,
            "succeeded": 1,
            "failed": 1,
            "success_rate": 50.0,
        },
    ]
    assert sum(bucket["incidents_started"] for bucket in payload["timeline"]) == 3
    assert sum(bucket["incidents_resolved"] for bucket in payload["timeline"]) == 3
    assert sum(bucket["deliveries_succeeded"] for bucket in payload["timeline"]) == 2
    assert sum(bucket["deliveries_failed"] for bucket in payload["timeline"]) == 2
    # The half-open interval includes the first boundary and excludes generated_at.
    assert payload["timeline"][0]["deliveries_succeeded"] == 1


def test_statistics_preserves_refire_cohorts_and_deterministic_acknowledgements(
    client: TestClient,
    auth: dict[str, str],
    app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    old_start = now - timedelta(hours=20)
    new_start = now - timedelta(hours=2)
    monkeypatch.setattr(statistics_application, "utc_now", lambda: now)

    with app.state.session_factory.begin() as db:
        db.add(_source("source-refire", "Refire source", "EU"))
        db.add(
            _incident(
                "refiring-incident",
                "source-refire",
                # The mutable projection retains only the latest occurrence.
                starts_at=new_start,
                severity="critical",
                status="acknowledged",
                acknowledged_at=now - timedelta(hours=1),
            )
        )
        db.flush()
        # Deliberately insert out of order. Aggregation must use
        # (occurred_at, event_key), not database insertion order.
        db.add_all(
            [
                _lifecycle(
                    "new-acknowledged",
                    incident_id="refiring-incident",
                    sequence=8,
                    event_type="acknowledged",
                    occurred_at=now - timedelta(hours=1),
                ),
                _lifecycle(
                    "old-explicit-resolution",
                    incident_id="refiring-incident",
                    sequence=7,
                    event_type="resolved",
                    occurred_at=now - timedelta(minutes=90),
                    starts_at=old_start,
                ),
                _lifecycle(
                    "stale-old-refresh",
                    incident_id="refiring-incident",
                    sequence=6,
                    event_type="firing",
                    occurred_at=now - timedelta(minutes=100),
                    starts_at=old_start,
                    source_id="source-refire",
                    severity="critical",
                ),
                _lifecycle(
                    "new-firing",
                    incident_id="refiring-incident",
                    sequence=5,
                    event_type="firing",
                    occurred_at=new_start,
                    starts_at=new_start,
                    source_id="source-refire",
                    severity="critical",
                ),
                _lifecycle(
                    "old-second-acknowledgement",
                    incident_id="refiring-incident",
                    sequence=4,
                    event_type="acknowledged",
                    occurred_at=old_start + timedelta(minutes=90),
                ),
                _lifecycle(
                    "old-first-acknowledgement",
                    incident_id="refiring-incident",
                    sequence=3,
                    event_type="acknowledged",
                    occurred_at=old_start + timedelta(hours=1),
                ),
                _lifecycle(
                    "old-refresh",
                    incident_id="refiring-incident",
                    sequence=2,
                    event_type="firing",
                    occurred_at=old_start + timedelta(minutes=10),
                    starts_at=old_start,
                    source_id="source-refire",
                    severity="critical",
                ),
                _lifecycle(
                    "old-firing",
                    incident_id="refiring-incident",
                    sequence=1,
                    event_type="firing",
                    occurred_at=old_start,
                    starts_at=old_start,
                    source_id="source-refire",
                    severity="warning",
                ),
            ]
        )

    response = client.get("/api/v1/metrics/statistics?window=24h", headers=auth)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["totals"] == {
        "incidents_started": 2,
        "incidents_resolved": 1,
        "active_incidents": 1,
        "active_critical": 1,
        "acknowledgement_rate": 100.0,
        "resolution_rate": 50.0,
        "mean_time_to_acknowledge_seconds": 3_600.0,
        "mean_time_to_resolve_seconds": 66_600.0,
        "deliveries": 0,
        "deliveries_succeeded": 0,
        "deliveries_failed": 0,
        "delivery_success_rate": None,
    }
    assert payload["severities"] == [
        {"severity": "critical", "count": 1},
        {"severity": "warning", "count": 1},
        {"severity": "info", "count": 0},
        {"severity": "unknown", "count": 0},
    ]
    assert payload["sources"] == [
        {
            "source_id": "source-refire",
            "name": "Refire source",
            "region": "EU",
            "count": 2,
        }
    ]


def test_future_resolution_transition_does_not_leave_old_cohort_ack_eligible(
    client: TestClient,
    auth: dict[str, str],
    app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    old_start = now - timedelta(hours=6)
    new_start = now - timedelta(hours=2)
    monkeypatch.setattr(statistics_application, "utc_now", lambda: now)

    with app.state.session_factory.begin() as db:
        db.add(_source("clock-skew-source", "Clock skew", "EU"))
        db.add(
            _incident(
                "clock-skew-incident",
                "clock-skew-source",
                starts_at=new_start,
                severity="critical",
                status="acknowledged",
                acknowledged_at=now - timedelta(hours=1),
            )
        )
        db.flush()
        db.add_all(
            [
                _lifecycle(
                    "old-clock-skew-firing",
                    incident_id="clock-skew-incident",
                    sequence=1,
                    event_type="firing",
                    occurred_at=old_start,
                    starts_at=old_start,
                    source_id="clock-skew-source",
                    severity="warning",
                ),
                # The resolution identifies a future refire. It transitions the
                # deterministic projection to resolved even though its firing is
                # observed later because of clock skew.
                _lifecycle(
                    "future-clock-skew-resolution",
                    incident_id="clock-skew-incident",
                    sequence=2,
                    event_type="resolved",
                    occurred_at=now - timedelta(hours=3),
                    starts_at=new_start,
                ),
                _lifecycle(
                    "new-clock-skew-firing",
                    incident_id="clock-skew-incident",
                    sequence=3,
                    event_type="firing",
                    occurred_at=new_start,
                    starts_at=new_start,
                    source_id="clock-skew-source",
                    severity="critical",
                ),
                _lifecycle(
                    "new-clock-skew-acknowledgement",
                    incident_id="clock-skew-incident",
                    sequence=4,
                    event_type="acknowledged",
                    occurred_at=now - timedelta(hours=1),
                ),
            ]
        )

    response = client.get("/api/v1/metrics/statistics?window=24h", headers=auth)

    assert response.status_code == 200, response.text
    totals = response.json()["totals"]
    assert totals["incidents_started"] == 2
    assert totals["incidents_resolved"] == 1
    assert totals["acknowledgement_rate"] == 50.0
    assert totals["mean_time_to_acknowledge_seconds"] == 3_600.0
    assert totals["resolution_rate"] == 50.0
    assert totals["mean_time_to_resolve_seconds"] == 0.0


def test_equal_time_lifecycle_order_converges_by_event_key_across_local_ids(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    occurred_at = now - timedelta(hours=2)
    settings_a = _settings(tmp_path, "event-key-a")
    settings_b = _settings(tmp_path, "event-key-b")
    app_a = create_app(settings_a)
    app_b = create_app(settings_b)

    with (
        TestClient(app_a, base_url="http://testserver"),
        TestClient(app_b, base_url="http://testserver"),
    ):
        for candidate, firing_id, acknowledged_id in (
            (app_a, "z-local-firing", "a-local-acknowledgement"),
            (app_b, "a-local-firing", "z-local-acknowledgement"),
        ):
            with candidate.state.session_factory.begin() as db:
                db.add(_source("stable-source", "Stable source", "EU"))
                db.add(
                    _incident(
                        "stable-incident",
                        "stable-source",
                        starts_at=occurred_at,
                        severity="warning",
                        status="acknowledged",
                        acknowledged_at=occurred_at,
                    )
                )
                db.flush()
                db.add_all(
                    [
                        _lifecycle(
                            firing_id,
                            incident_id="stable-incident",
                            sequence=1,
                            event_type="firing",
                            occurred_at=occurred_at,
                            starts_at=occurred_at,
                            source_id="stable-source",
                            severity="warning",
                            event_key="a-stable-firing",
                        ),
                        _lifecycle(
                            acknowledged_id,
                            incident_id="stable-incident",
                            sequence=2,
                            event_type="acknowledged",
                            occurred_at=occurred_at,
                            event_key="b-stable-acknowledgement",
                        ),
                    ]
                )

        snapshots = []
        for candidate in (app_a, app_b):
            with candidate.state.session_factory() as db:
                snapshots.append(statistics_snapshot(db, "24h", generated_at=now))

    assert snapshots[0] == snapshots[1]
    assert snapshots[0]["totals"]["acknowledgement_rate"] == 100.0
    assert snapshots[0]["totals"]["mean_time_to_acknowledge_seconds"] == 0.0


def test_statistics_uses_one_sqlite_snapshot_across_all_selects(
    client: TestClient,
    app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del client
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    with app.state.session_factory.begin() as db:
        db.add(_source("snapshot-source", "Before commit", "EU"))
        db.add(_channel("snapshot-channel", "Before commit", "generic_webhook"))
        db.add(
            _incident(
                "snapshot-incident",
                "snapshot-source",
                starts_at=now - timedelta(hours=2),
                severity="critical",
                status="open",
            )
        )
        db.flush()
        db.add(
            _lifecycle(
                "snapshot-firing",
                incident_id="snapshot-incident",
                sequence=1,
                event_type="firing",
                occurred_at=now - timedelta(hours=2),
                starts_at=now - timedelta(hours=2),
                source_id="snapshot-source",
                severity="critical",
            )
        )

    original_cohorts = statistics_application._incident_cohorts
    writer_committed = False

    def interleaved_cohorts(db, *, starts_at, ends_at):
        nonlocal writer_committed
        yield from original_cohorts(db, starts_at=starts_at, ends_at=ends_at)
        if writer_committed:
            return
        writer_committed = True
        # WAL permits this writer to commit after the reader's lifecycle SELECT.
        # Every later SELECT in the same statistics call must retain the older view.
        with app.state.session_factory.begin() as writer:
            incident = writer.get(Incident, "snapshot-incident")
            source = writer.get(Source, "snapshot-source")
            channel = writer.get(NotificationChannel, "snapshot-channel")
            assert incident is not None
            assert source is not None
            assert channel is not None
            incident.status = "resolved"
            source.name = "After commit"
            channel.name = "After commit"
            writer.add(
                _receipt(
                    "snapshot-receipt",
                    sequence=1,
                    event_type="delivery_succeeded",
                    occurred_at=now - timedelta(hours=1),
                    channel_id="snapshot-channel",
                    status="succeeded",
                )
            )

    monkeypatch.setattr(statistics_application, "_incident_cohorts", interleaved_cohorts)

    with app.state.session_factory() as reader:
        driver_connection = reader.connection().connection.driver_connection
        snapshot = statistics_snapshot(reader, "24h", generated_at=now)
        assert not driver_connection.in_transaction

    assert writer_committed
    assert snapshot["totals"]["active_incidents"] == 1
    assert snapshot["totals"]["deliveries"] == 0
    assert snapshot["sources"][0]["name"] == "Before commit"
    assert snapshot["channels"] == []

    with app.state.session_factory() as reader:
        refreshed = statistics_snapshot(reader, "24h", generated_at=now)
    assert refreshed["totals"]["active_incidents"] == 0
    assert refreshed["totals"]["deliveries"] == 1
    assert refreshed["sources"][0]["name"] == "After commit"
    assert refreshed["channels"][0]["name"] == "After commit"


def test_delivery_statistics_converge_from_original_receipts_despite_projection_order(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    source_event_id = "delivery-source-event"
    source_event_key = "delivery-source-event-key"
    delivery_id = "shared-delivery"
    channel_id = "shared-channel"
    settings_a = _settings(tmp_path, "statistics-a")
    settings_b = _settings(tmp_path, "statistics-b")
    app_a = create_app(settings_a)
    app_b = create_app(settings_b)

    def receipt(
        receipt_id: str,
        *,
        sequence: int,
        operation: str,
        occurred_at: datetime,
        attempt: int,
        status: str,
    ) -> IncomingClusterEvent:
        payload = {
            "delivery_id": delivery_id,
            "event_id": source_event_id,
            "source_event_key": source_event_key,
            "channel_id": channel_id,
            "subscription_id": None,
            "owner_node_id": "delivery-origin",
            "attempt": attempt,
            "status": status,
            "provider_status": "http_204" if status == "succeeded" else None,
            "error_code": None if status == "succeeded" else "timeout",
            "created_at": (now - timedelta(hours=3)).isoformat(),
            "finished_at": occurred_at.isoformat(),
            "receipt_event_id": receipt_id,
            "receipt_origin_node_id": "delivery-origin",
            "receipt_origin_seq": sequence,
            "receipt_occurred_at": occurred_at.isoformat(),
            "receipt_event_key": f"delivery:{delivery_id}:{attempt}:{status}",
        }
        return IncomingClusterEvent(
            event_id=receipt_id,
            origin_node_id="delivery-origin",
            origin_seq=sequence,
            entity_type="delivery_receipt",
            entity_id=delivery_id,
            operation=operation,
            occurred_at=occurred_at,
            payload=payload,
        )

    failed = receipt(
        "failed-receipt",
        sequence=1,
        operation="delivery_failed",
        occurred_at=now - timedelta(hours=2),
        attempt=1,
        status="retrying",
    )
    succeeded = receipt(
        "succeeded-receipt",
        sequence=2,
        operation="delivery_succeeded",
        occurred_at=now - timedelta(hours=1),
        attempt=2,
        status="succeeded",
    )

    with (
        TestClient(app_a, base_url="http://testserver"),
        TestClient(app_b, base_url="http://testserver"),
    ):
        for candidate in (app_a, app_b):
            with candidate.state.session_factory.begin() as db:
                db.add(_source("delivery-source", "Delivery source", "EU"))
                db.add(_channel(channel_id, "Shared channel", "generic_webhook"))
                db.add(
                    _incident(
                        "delivery-incident",
                        "delivery-source",
                        starts_at=now - timedelta(hours=4),
                        severity="warning",
                        status="open",
                    )
                )
                db.flush()
                source_event = _lifecycle(
                    source_event_id,
                    incident_id="delivery-incident",
                    sequence=1,
                    event_type="firing",
                    occurred_at=now - timedelta(hours=4),
                    starts_at=now - timedelta(hours=4),
                    source_id="delivery-source",
                    severity="warning",
                )
                source_event.event_key = source_event_key
                db.add(source_event)

        # Node A sees terminal success first, so its mutable receipt projection
        # intentionally rejects the late retryable failure. Node B sees causal order.
        with app_a.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [succeeded], settings_a).applied == 1
        with app_a.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [failed], settings_a).applied == 1
        with app_a.state.session_factory.begin() as db:
            duplicate = apply_cluster_events(db, [failed], settings_a)
            assert duplicate.applied == 0
            assert duplicate.duplicates == 1

        with app_b.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [failed], settings_b).applied == 1
        with app_b.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [succeeded], settings_b).applied == 1
        with app_b.state.session_factory.begin() as db:
            duplicate = apply_cluster_events(db, [succeeded], settings_b)
            assert duplicate.applied == 0
            assert duplicate.duplicates == 1

        snapshots = []
        delivery_timeline_types = []
        receipt_ids = []
        for candidate in (app_a, app_b):
            with candidate.state.session_factory() as db:
                snapshots.append(statistics_snapshot(db, "24h", generated_at=now))
                delivery_timeline_types.append(
                    set(
                        db.scalars(
                            select(IncidentEvent.event_type).where(
                                IncidentEvent.event_type.in_(
                                    ("delivery_succeeded", "delivery_failed")
                                )
                            )
                        ).all()
                    )
                )
                receipt_ids.append(
                    set(
                        db.scalars(
                            select(ClusterEvent.event_id).where(
                                ClusterEvent.entity_type == "delivery_receipt"
                            )
                        ).all()
                    )
                )

    # The derived IncidentEvent timelines differ, while original append-only receipt
    # history and therefore the statistics snapshot converge exactly.
    assert delivery_timeline_types == [
        {"delivery_succeeded"},
        {"delivery_succeeded", "delivery_failed"},
    ]
    assert receipt_ids == [
        {"failed-receipt", "succeeded-receipt"},
        {"failed-receipt", "succeeded-receipt"},
    ]
    assert snapshots[0] == snapshots[1]
    assert snapshots[0]["totals"]["deliveries"] == 2
    assert snapshots[0]["totals"]["deliveries_succeeded"] == 1
    assert snapshots[0]["totals"]["deliveries_failed"] == 1
    assert snapshots[0]["totals"]["delivery_success_rate"] == 50.0
    assert snapshots[0]["channels"] == [
        {
            "channel_id": channel_id,
            "name": "Shared channel",
            "kind": "generic_webhook",
            "total": 2,
            "succeeded": 1,
            "failed": 1,
            "success_rate": 50.0,
        }
    ]


@pytest.mark.parametrize(
    ("workload", "expected_resource"),
    [
        ("lifecycle_events", "incident lifecycle event"),
        ("incident_cohorts", "incident ID"),
        ("delivery_receipts", "delivery receipt"),
    ],
)
def test_statistics_rejects_oversized_workloads_without_partial_results(
    client: TestClient,
    auth: dict[str, str],
    app,
    monkeypatch: pytest.MonkeyPatch,
    workload: str,
    expected_resource: str,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(statistics_application, "utc_now", lambda: now)
    if workload == "lifecycle_events":
        monkeypatch.setattr(statistics_application, "_MAX_LIFECYCLE_EVENTS", 1)
    elif workload == "incident_cohorts":
        monkeypatch.setattr(statistics_application, "_MAX_LIFECYCLE_INCIDENTS", 1)
    else:
        monkeypatch.setattr(statistics_application, "_MAX_DELIVERY_RECEIPTS", 1)

    with app.state.session_factory.begin() as db:
        if workload == "delivery_receipts":
            db.add_all(
                [
                    _receipt(
                        "bounded-receipt-1",
                        sequence=1,
                        event_type="delivery_succeeded",
                        occurred_at=now - timedelta(hours=2),
                        channel_id="unused-channel",
                        status="succeeded",
                    ),
                    _receipt(
                        "bounded-receipt-2",
                        sequence=2,
                        event_type="delivery_failed",
                        occurred_at=now - timedelta(hours=1),
                        channel_id="unused-channel",
                        status="failed",
                    ),
                ]
            )
        else:
            db.add(_source("bounded-source", "Bounded source", "EU"))
            incident_count = 2 if workload == "incident_cohorts" else 1
            for index in range(incident_count):
                incident_id = f"bounded-incident-{index}"
                db.add(
                    _incident(
                        incident_id,
                        "bounded-source",
                        starts_at=now - timedelta(hours=index + 2),
                        severity="warning",
                        status="open",
                    )
                )
            db.flush()
            for index in range(incident_count):
                incident_id = f"bounded-incident-{index}"
                occurred_at = now - timedelta(hours=index + 2)
                db.add(
                    _lifecycle(
                        f"bounded-firing-{index}",
                        incident_id=incident_id,
                        sequence=index + 1,
                        event_type="firing",
                        occurred_at=occurred_at,
                        starts_at=occurred_at,
                        source_id="bounded-source",
                        severity="warning",
                    )
                )
            if workload == "lifecycle_events":
                db.add(
                    _lifecycle(
                        "bounded-acknowledgement",
                        incident_id="bounded-incident-0",
                        sequence=2,
                        event_type="acknowledged",
                        occurred_at=now - timedelta(minutes=30),
                    )
                )

    response = client.get("/api/v1/metrics/statistics?window=24h", headers=auth)

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert f"safe {expected_resource} limit (1)" in detail
    assert "totals" not in response.json()


def test_statistics_requires_auth_and_rejects_unbounded_windows(
    client: TestClient, auth: dict[str, str]
) -> None:
    assert client.get("/api/v1/metrics/statistics").status_code == 401
    assert client.get("/api/v1/metrics/statistics?window=90d", headers=auth).status_code == 422


def test_statistics_limits_source_and_channel_activity_to_top_five(
    client: TestClient,
    auth: dict[str, str],
    app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(statistics_application, "utc_now", lambda: now)

    with app.state.session_factory.begin() as db:
        for index in range(7):
            source_id = f"source-{index}"
            channel_id = f"channel-{index}"
            db.add(_source(source_id, f"Source {index}", f"R{index}"))
            db.add(_channel(channel_id, f"Channel {index}", "telegram"))
            for occurrence in range(index + 1):
                db.add(
                    _incident(
                        f"incident-{index}-{occurrence}",
                        source_id,
                        starts_at=now - timedelta(hours=index + 1),
                        severity="warning",
                        status="open",
                    )
                )
            db.flush()
            for occurrence in range(index + 1):
                incident_id = f"incident-{index}-{occurrence}"
                incident_starts_at = now - timedelta(hours=index + 1)
                db.add(
                    _lifecycle(
                        f"firing-{index}-{occurrence}",
                        incident_id=incident_id,
                        sequence=(index * 10) + occurrence + 1,
                        event_type="firing",
                        occurred_at=incident_starts_at,
                        starts_at=incident_starts_at,
                        source_id=source_id,
                        severity="warning",
                    )
                )
            for attempt in range(index + 1):
                db.add(
                    _receipt(
                        f"receipt-{index}-{attempt}",
                        sequence=(index * 10) + attempt + 1,
                        event_type="delivery_succeeded",
                        occurred_at=now - timedelta(minutes=index + 1),
                        channel_id=channel_id,
                        status="succeeded",
                    )
                )

    metadata_queries: list[tuple[str, object]] = []

    def capture_metadata_sql(
        _connection,
        _cursor,
        statement,
        parameters,
        _context,
        _executemany,
    ) -> None:
        normalized_statement = " ".join(statement.lower().split())
        if (
            " from sources " in f" {normalized_statement} "
            or " from notification_channels " in f" {normalized_statement} "
        ):
            metadata_queries.append((normalized_statement, parameters))

    sqlalchemy_event.listen(
        app.state.engine,
        "before_cursor_execute",
        capture_metadata_sql,
    )
    try:
        response = client.get("/api/v1/metrics/statistics", headers=auth)
    finally:
        sqlalchemy_event.remove(
            app.state.engine,
            "before_cursor_execute",
            capture_metadata_sql,
        )

    assert response.status_code == 200, response.text
    payload = response.json()

    assert len(payload["sources"]) == 5
    assert len(payload["channels"]) == 5
    assert [item["source_id"] for item in payload["sources"]] == [
        "source-6",
        "source-5",
        "source-4",
        "source-3",
        "source-2",
    ]
    assert [item["channel_id"] for item in payload["channels"]] == [
        "channel-6",
        "channel-5",
        "channel-4",
        "channel-3",
        "channel-2",
    ]
    assert len(metadata_queries) == 2
    source_query = next(query for query in metadata_queries if " from sources " in f" {query[0]} ")
    channel_query = next(
        query for query in metadata_queries if " from notification_channels " in f" {query[0]} "
    )
    assert "where sources.id in" in source_query[0]
    assert "where notification_channels.id in" in channel_query[0]
    assert len(source_query[1]) == 5
    assert len(channel_query[1]) == 5


def test_statistics_sqlite_plans_use_bounded_and_covering_indexes(
    client: TestClient,
    app,
) -> None:
    del client
    plans = {
        "lifecycle_ids": (
            "EXPLAIN QUERY PLAN "
            "SELECT incident_id FROM incident_events "
            "WHERE event_type IN (?, ?, ?) AND occurred_at >= ? AND occurred_at < ? "
            "LIMIT ?",
            (
                "firing",
                "acknowledged",
                "resolved",
                "2026-09-01",
                "2026-09-06",
                100_001,
            ),
        ),
        "lifecycle_rows": (
            "EXPLAIN QUERY PLAN "
            "SELECT event_key, incident_id, event_type, occurred_at, payload_json "
            "FROM incident_events "
            "WHERE incident_id IN (?, ?) AND event_type IN (?, ?, ?) "
            "AND occurred_at >= ? AND occurred_at < ? "
            "ORDER BY incident_id, occurred_at, event_key LIMIT ?",
            (
                "incident-a",
                "incident-b",
                "firing",
                "acknowledged",
                "resolved",
                "2026-09-01",
                "2026-09-06",
                100_001,
            ),
        ),
        "active": (
            "EXPLAIN QUERY PLAN "
            "SELECT count(*), count(*) FILTER (WHERE severity = ?) FROM incidents "
            "WHERE status IN (?, ?, ?)",
            ("critical", "open", "acknowledged", "silenced"),
        ),
        "receipts": (
            "EXPLAIN QUERY PLAN "
            "SELECT operation, occurred_at, payload_json FROM cluster_events "
            "WHERE entity_type = ? AND operation IN (?, ?) "
            "AND occurred_at >= ? AND occurred_at < ? LIMIT ?",
            (
                "delivery_receipt",
                "delivery_succeeded",
                "delivery_failed",
                "2026-09-01",
                "2026-09-06",
                100_001,
            ),
        ),
    }

    with app.state.engine.connect() as connection:
        details = {
            name: [str(row[3]) for row in connection.exec_driver_sql(statement, parameters).all()]
            for name, (statement, parameters) in plans.items()
        }

    assert any(
        "COVERING INDEX ix_incident_events_type_time_incident" in row
        for row in details["lifecycle_ids"]
    )
    assert any(
        "USING INDEX ix_incident_events_incident_time_key" in row
        for row in details["lifecycle_rows"]
    )
    assert all("TEMP B-TREE FOR ORDER BY" not in row for row in details["lifecycle_rows"])
    assert any("COVERING INDEX ix_incidents_status_severity" in row for row in details["active"])
    assert any(
        "USING INDEX ix_cluster_events_type_operation_time" in row for row in details["receipts"]
    )
    assert all("SCAN " not in row.upper() for query_plan in details.values() for row in query_plan)
