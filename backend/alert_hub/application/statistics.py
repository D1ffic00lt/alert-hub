from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from heapq import nsmallest
from threading import Lock
from time import monotonic
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from alert_hub.domain.events import as_utc, normalize_severity
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    Incident,
    IncidentEvent,
    NotificationChannel,
    Source,
)

type StatisticsWindow = Literal["24h", "7d", "30d"]


@dataclass(frozen=True, slots=True)
class _WindowSpec:
    duration: timedelta
    bucket_seconds: int


@dataclass(slots=True)
class _DeliveryCounts:
    total: int = 0
    succeeded: int = 0
    failed: int = 0


@dataclass(slots=True)
class _IncidentCohort:
    starts_at: datetime
    source_id: str | None = None
    severity: str = "unknown"
    firing_order: tuple[datetime, str] | None = None
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class _StatisticsCacheEntry:
    fresh_until: float
    stale_until: float
    snapshot: dict[str, Any]


class StatisticsWorkloadExceeded(RuntimeError):
    def __init__(self, resource: str, limit: int) -> None:
        self.resource = resource
        self.limit = limit
        super().__init__(
            f"Statistics window exceeds the safe {resource} limit ({limit}); "
            "select a shorter window or reduce event volume"
        )


class StatisticsSnapshotCache:
    """Small process-local cache for concurrent dashboard readers.

    The cache is intentionally app-scoped and bounded to the three supported window
    keys. Copies prevent a response serializer or caller from mutating shared state.
    Independent worker processes may refresh at different moments, which is consistent
    with the endpoint's explicitly eventually consistent semantics.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = 30.0,
        stale_ttl_seconds: float = 60.0,
        now: Callable[[], float] = monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if stale_ttl_seconds < ttl_seconds:
            raise ValueError("stale_ttl_seconds must not be shorter than ttl_seconds")
        self._ttl_seconds = ttl_seconds
        self._stale_ttl_seconds = stale_ttl_seconds
        self._now = now
        self._lock = Lock()
        self._entries: dict[StatisticsWindow, _StatisticsCacheEntry] = {}
        self._refresh_locks = {
            "24h": Lock(),
            "7d": Lock(),
            "30d": Lock(),
        }

    def _get(self, window: StatisticsWindow, *, allow_stale: bool) -> dict[str, Any] | None:
        with self._lock:
            entry = self._entries.get(window)
            if entry is None:
                return None
            now = self._now()
            if entry.stale_until <= now:
                self._entries.pop(window, None)
                return None
            if not allow_stale and entry.fresh_until <= now:
                return None
            return deepcopy(entry.snapshot)

    def get(self, window: StatisticsWindow) -> dict[str, Any] | None:
        return self._get(window, allow_stale=False)

    def put(self, window: StatisticsWindow, snapshot: dict[str, Any]) -> None:
        now = self._now()
        entry = _StatisticsCacheEntry(
            fresh_until=now + self._ttl_seconds,
            stale_until=now + self._stale_ttl_seconds,
            snapshot=deepcopy(snapshot),
        )
        with self._lock:
            self._entries[window] = entry

    def get_or_compute(
        self,
        window: StatisticsWindow,
        compute: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        cached = self.get(window)
        if cached is not None:
            return cached
        stale = self._get(window, allow_stale=True)
        refresh_lock = self._refresh_locks[window]
        if not refresh_lock.acquire(blocking=False):
            # Never park a Starlette worker behind a database scan. A follower can
            # use a bounded-stale snapshot; on a cold miss it computes independently
            # but does not race to replace the refresh owner's cache entry.
            return stale if stale is not None else compute()
        try:
            cached = self.get(window)
            if cached is not None:
                return cached
            try:
                snapshot = compute()
            except Exception:
                # Refreshes can outlive the remaining stale window. Re-read under
                # the cache lock so a failed refresh never serves an over-age entry.
                fallback = self._get(window, allow_stale=True)
                if fallback is not None:
                    return fallback
                raise
            self.put(window, snapshot)
            # ``put`` stores a deep copy, so the factory-owned result is safe to
            # return directly without exposing the shared cache entry.
            return snapshot
        finally:
            refresh_lock.release()


_WINDOWS: dict[StatisticsWindow, _WindowSpec] = {
    "24h": _WindowSpec(timedelta(hours=24), 60 * 60),
    "7d": _WindowSpec(timedelta(days=7), 6 * 60 * 60),
    "30d": _WindowSpec(timedelta(days=30), 24 * 60 * 60),
}
_DELIVERY_SUCCEEDED = "delivery_succeeded"
_DELIVERY_FAILED = "delivery_failed"
_DELIVERY_EVENT_TYPES = (_DELIVERY_SUCCEEDED, _DELIVERY_FAILED)
_INCIDENT_EVENT_TYPES = ("firing", "acknowledged", "resolved")
_SEVERITIES = ("critical", "warning", "info", "unknown")
_TOP_ACTIVITY_LIMIT = 5
_STREAM_BATCH_SIZE = 500
_INCIDENT_ID_BATCH_SIZE = 200
_MAX_LIFECYCLE_INCIDENTS = 20_000
_MAX_LIFECYCLE_EVENTS = 100_000
_MAX_DELIVERY_RECEIPTS = 100_000
_ACTIVE_INCIDENT_STATUSES = ("open", "acknowledged", "silenced")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _percentage(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round((numerator / denominator) * 100, 1)


def _mean_duration_seconds(total: float, count: int) -> float | None:
    if count == 0:
        return None
    return round(total / count, 1)


def _top_activity_ids(counts: Mapping[str, int]) -> list[str]:
    # ``nsmallest`` keeps only five candidates rather than sorting/materializing a
    # second list containing every configured source or channel.
    return nsmallest(
        _TOP_ACTIVITY_LIMIT,
        counts,
        key=lambda entity_id: (-counts[entity_id], entity_id),
    )


def _elapsed_seconds(start: datetime, end: datetime) -> float:
    # Replicated timestamps may reflect clock skew. A skewed row must never make an
    # operational duration negative, even while the cluster is converging.
    return max(0.0, (_as_utc(end) - _as_utc(start)).total_seconds())


def _bucket_index(
    value: datetime,
    *,
    starts_at: datetime,
    ends_at: datetime,
    bucket_seconds: int,
) -> int | None:
    normalized = _as_utc(value)
    if normalized < starts_at or normalized >= ends_at:
        return None
    return int((normalized - starts_at).total_seconds() // bucket_seconds)


def _payload_datetime(payload: dict[str, Any], name: str) -> datetime | None:
    value = payload.get(name)
    if not isinstance(value, (str, datetime)):
        return None
    try:
        return as_utc(value)
    except (TypeError, ValueError):
        return None


def _cohort_key(starts_at: datetime) -> str:
    return _as_utc(starts_at).isoformat()


def _lifecycle_incident_ids(
    db: Session, *, starts_at: datetime, ends_at: datetime
) -> tuple[list[str], int]:
    """Discover relevant IDs through a narrow, strictly capped covering scan."""

    statement = (
        select(IncidentEvent.incident_id)
        .where(
            IncidentEvent.event_type.in_(_INCIDENT_EVENT_TYPES),
            IncidentEvent.occurred_at >= starts_at,
            IncidentEvent.occurred_at < ends_at,
        )
        .limit(_MAX_LIFECYCLE_EVENTS + 1)
        .execution_options(yield_per=_STREAM_BATCH_SIZE)
    )
    rows = db.scalars(statement)
    incident_ids: set[str] = set()
    event_count = 0
    try:
        for incident_id in rows:
            event_count += 1
            if event_count > _MAX_LIFECYCLE_EVENTS:
                raise StatisticsWorkloadExceeded(
                    "incident lifecycle event",
                    _MAX_LIFECYCLE_EVENTS,
                )
            incident_ids.add(incident_id)
            if len(incident_ids) > _MAX_LIFECYCLE_INCIDENTS:
                raise StatisticsWorkloadExceeded(
                    "incident ID",
                    _MAX_LIFECYCLE_INCIDENTS,
                )
    finally:
        rows.close()
    return sorted(incident_ids), event_count


def _incident_cohorts(
    db: Session, *, starts_at: datetime, ends_at: datetime
) -> Iterator[_IncidentCohort]:
    """Rebuild bounded lifecycle cohorts from append-only incident history.

    A narrow temporal-index pass discovers relevant incident IDs and enforces the
    workload cap before JSON is read. Bounded ID batches then use incident/time/key
    order, allowing each incident's state to be discarded before the next one.
    """

    incident_ids, expected_event_count = _lifecycle_incident_ids(
        db,
        starts_at=starts_at,
        ends_at=ends_at,
    )
    processed_event_count = 0

    for offset in range(0, len(incident_ids), _INCIDENT_ID_BATCH_SIZE):
        incident_id_batch = incident_ids[offset : offset + _INCIDENT_ID_BATCH_SIZE]
        metadata_rows = db.execute(
            select(Incident.id, Incident.source_id, Incident.severity).where(
                Incident.id.in_(incident_id_batch)
            )
        ).all()
        metadata_by_incident = {
            incident_id: (source_id, severity) for incident_id, source_id, severity in metadata_rows
        }
        remaining = _MAX_LIFECYCLE_EVENTS - processed_event_count
        statement = (
            select(
                IncidentEvent.event_key,
                IncidentEvent.incident_id,
                IncidentEvent.event_type,
                IncidentEvent.occurred_at,
                IncidentEvent.payload_json,
            )
            .where(
                IncidentEvent.incident_id.in_(incident_id_batch),
                IncidentEvent.event_type.in_(_INCIDENT_EVENT_TYPES),
                IncidentEvent.occurred_at >= starts_at,
                IncidentEvent.occurred_at < ends_at,
            )
            .order_by(
                IncidentEvent.incident_id,
                IncidentEvent.occurred_at,
                IncidentEvent.event_key,
            )
            .limit(remaining + 1)
            .execution_options(yield_per=_STREAM_BATCH_SIZE)
        )
        rows = db.execute(statement)
        current_incident_id: str | None = None
        incident_cohorts: dict[str, _IncidentCohort] = {}
        projection_key: str | None = None
        projection_starts_at: datetime | None = None
        projection_resolved = False

        try:
            for (
                event_key,
                incident_id,
                event_type,
                occurred_at,
                raw_payload,
            ) in rows:
                processed_event_count += 1
                if processed_event_count > _MAX_LIFECYCLE_EVENTS:
                    raise StatisticsWorkloadExceeded(
                        "incident lifecycle event",
                        _MAX_LIFECYCLE_EVENTS,
                    )
                if current_incident_id is None:
                    current_incident_id = incident_id
                elif incident_id != current_incident_id:
                    yield from incident_cohorts.values()
                    current_incident_id = incident_id
                    incident_cohorts = {}
                    projection_key = None
                    projection_starts_at = None
                    projection_resolved = False

                occurred_at = _as_utc(occurred_at)
                payload = raw_payload if isinstance(raw_payload, dict) else {}
                projection_source_id, projection_severity = metadata_by_incident.get(
                    incident_id,
                    (None, "unknown"),
                )

                if event_type == "firing":
                    cohort_starts_at = _payload_datetime(payload, "starts_at") or occurred_at
                    key = _cohort_key(cohort_starts_at)
                    cohort = incident_cohorts.get(key)
                    if cohort is None:
                        cohort = _IncidentCohort(starts_at=cohort_starts_at)
                        incident_cohorts[key] = cohort

                    # The stable logical event key, never the node-local row ID,
                    # breaks equal-time ties on every replica.
                    if cohort.firing_order is None:
                        cohort.firing_order = (occurred_at, event_key)
                        raw_source_id = payload.get("source_id")
                        cohort.source_id = (
                            raw_source_id
                            if isinstance(raw_source_id, str) and raw_source_id
                            else projection_source_id
                        )
                        cohort.severity = normalize_severity(
                            payload.get("severity", projection_severity)
                        )

                    # Mirror project_incident: a newer start or any firing after a
                    # resolved state opens that cohort. A stale refresh cannot steal
                    # acknowledgement eligibility from a newer firing.
                    if (
                        projection_starts_at is None
                        or cohort_starts_at > projection_starts_at
                        or projection_resolved
                    ):
                        projection_key = key
                        projection_starts_at = cohort_starts_at
                        projection_resolved = False
                    continue

                if event_type == "acknowledged":
                    if projection_key is None or projection_resolved:
                        continue
                    cohort = incident_cohorts[projection_key]
                    if cohort.acknowledged_at is None:
                        cohort.acknowledged_at = occurred_at
                    continue

                explicit_starts_at = _payload_datetime(payload, "starts_at")
                if explicit_starts_at is not None:
                    key = _cohort_key(explicit_starts_at)
                    cohort = incident_cohorts.get(key)
                    if cohort is None:
                        cohort = _IncidentCohort(starts_at=explicit_starts_at)
                        incident_cohorts[key] = cohort
                elif projection_key is not None and not projection_resolved:
                    key = projection_key
                    cohort = incident_cohorts[key]
                else:
                    # There is no eligible firing. Keep the resolution visible in
                    # resolved volume without manufacturing a start or duration.
                    key = f"resolved:{event_key}"
                    cohort = _IncidentCohort(starts_at=occurred_at)
                    incident_cohorts[key] = cohort

                if cohort.resolved_at is None:
                    cohort.resolved_at = occurred_at
                if (
                    explicit_starts_at is None
                    or projection_starts_at is None
                    or explicit_starts_at >= projection_starts_at
                ):
                    projection_resolved = True
        finally:
            rows.close()

        yield from incident_cohorts.values()

    if processed_event_count != expected_event_count:
        raise RuntimeError("incident lifecycle changed inside a statistics read snapshot")


@contextmanager
def _consistent_read_snapshot(db: Session) -> Iterator[None]:
    """Pin SQLite reads and promptly release a transaction owned by this call."""

    connection = db.connection()
    if connection.dialect.name != "sqlite":
        yield
        return
    driver_connection = connection.connection.driver_connection
    owns_snapshot = not bool(getattr(driver_connection, "in_transaction", False))
    if owns_snapshot:
        connection.exec_driver_sql("BEGIN")
    try:
        yield
    finally:
        if owns_snapshot:
            # The statistics endpoint's request Session has no pending writes.
            # Rolling it back ends the WAL snapshot immediately without touching a
            # caller-owned transaction when one was already active.
            db.rollback()


def statistics_snapshot(
    db: Session,
    window: StatisticsWindow,
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Aggregate one node's eventually consistent, replicated SQLite projection.

    Historical incident figures are rebuilt from append-only ``IncidentEvent``
    lifecycle cohorts; only the two current-active counters use the mutable
    ``Incident`` projection. Delivery figures read original ``ClusterEvent`` receipt
    history rather than the lossy delivery projection/timeline. Consequently every
    receipt represents an actual attempt outcome: a retryable attempt is intentionally
    counted as failed before a later successful receipt is counted separately. Rates
    and mean durations use firing cohorts whose ``starts_at`` is in the half-open
    window. Source and channel rankings are activity-only top-five lists, keeping the
    response bounded.
    """

    ends_at = _as_utc(generated_at or utc_now())
    with _consistent_read_snapshot(db):
        return _statistics_snapshot(db, window, ends_at=ends_at)


def _statistics_snapshot(
    db: Session,
    window: StatisticsWindow,
    *,
    ends_at: datetime,
) -> dict[str, Any]:
    spec = _WINDOWS[window]
    starts_at = ends_at - spec.duration
    bucket_count = int(spec.duration.total_seconds() // spec.bucket_seconds)
    timeline: list[dict[str, Any]] = [
        {
            "starts_at": starts_at + timedelta(seconds=index * spec.bucket_seconds),
            "incidents_started": 0,
            "incidents_resolved": 0,
            "deliveries_succeeded": 0,
            "deliveries_failed": 0,
        }
        for index in range(bucket_count)
    ]

    incidents_started = 0
    incidents_resolved = 0
    acknowledged_started = 0
    resolved_started = 0
    acknowledgement_duration_total = 0.0
    resolution_duration_total = 0.0
    severity_counts = dict.fromkeys(_SEVERITIES, 0)
    source_counts: defaultdict[str, int] = defaultdict(int)

    for cohort in _incident_cohorts(db, starts_at=starts_at, ends_at=ends_at):
        started_bucket = _bucket_index(
            cohort.starts_at,
            starts_at=starts_at,
            ends_at=ends_at,
            bucket_seconds=spec.bucket_seconds,
        )
        if cohort.firing_order is not None and started_bucket is not None:
            incidents_started += 1
            timeline[started_bucket]["incidents_started"] += 1
            severity_counts[cohort.severity] += 1
            if cohort.source_id is not None:
                source_counts[cohort.source_id] += 1
            if cohort.acknowledged_at is not None:
                acknowledged_started += 1
                acknowledgement_duration_total += _elapsed_seconds(
                    cohort.starts_at, cohort.acknowledged_at
                )
            if cohort.resolved_at is not None:
                resolved_started += 1
                resolution_duration_total += _elapsed_seconds(cohort.starts_at, cohort.resolved_at)

        if cohort.resolved_at is not None:
            resolved_bucket = _bucket_index(
                cohort.resolved_at,
                starts_at=starts_at,
                ends_at=ends_at,
                bucket_seconds=spec.bucket_seconds,
            )
            if resolved_bucket is not None:
                incidents_resolved += 1
                timeline[resolved_bucket]["incidents_resolved"] += 1

    active_incidents, active_critical = db.execute(
        select(
            func.count(),
            func.count().filter(Incident.severity == "critical"),
        )
        .select_from(Incident)
        .where(Incident.status.in_(_ACTIVE_INCIDENT_STATUSES))
    ).one()
    active_incidents = int(active_incidents)
    active_critical = int(active_critical)

    delivery_statement = (
        select(
            ClusterEvent.operation,
            ClusterEvent.occurred_at,
            ClusterEvent.payload_json,
        )
        .where(
            ClusterEvent.entity_type == "delivery_receipt",
            ClusterEvent.operation.in_(_DELIVERY_EVENT_TYPES),
            ClusterEvent.occurred_at >= starts_at,
            ClusterEvent.occurred_at < ends_at,
        )
        .limit(_MAX_DELIVERY_RECEIPTS + 1)
        .execution_options(yield_per=_STREAM_BATCH_SIZE)
    )
    delivery_rows = db.execute(delivery_statement)
    deliveries_succeeded = 0
    deliveries_failed = 0
    channel_counts: defaultdict[str, _DeliveryCounts] = defaultdict(_DeliveryCounts)
    try:
        # ClusterEvent.event_id is the table primary key, so this single-table scan
        # already yields each original receipt exactly once without an unbounded set.
        for receipt_count, (operation, occurred_at, raw_payload) in enumerate(
            delivery_rows,
            start=1,
        ):
            if receipt_count > _MAX_DELIVERY_RECEIPTS:
                raise StatisticsWorkloadExceeded(
                    "delivery receipt",
                    _MAX_DELIVERY_RECEIPTS,
                )
            bucket = _bucket_index(
                occurred_at,
                starts_at=starts_at,
                ends_at=ends_at,
                bucket_seconds=spec.bucket_seconds,
            )
            if bucket is None:
                continue
            succeeded = operation == _DELIVERY_SUCCEEDED
            if succeeded:
                deliveries_succeeded += 1
                timeline[bucket]["deliveries_succeeded"] += 1
            else:
                deliveries_failed += 1
                timeline[bucket]["deliveries_failed"] += 1

            payload = raw_payload if isinstance(raw_payload, dict) else {}
            raw_channel_id = payload.get("channel_id")
            if not isinstance(raw_channel_id, str) or not raw_channel_id:
                continue
            counts = channel_counts[raw_channel_id]
            counts.total += 1
            if succeeded:
                counts.succeeded += 1
            else:
                counts.failed += 1
    finally:
        delivery_rows.close()

    top_source_ids = _top_activity_ids(source_counts)
    source_rows = (
        db.execute(
            select(Source.id, Source.name, Source.region).where(Source.id.in_(top_source_ids))
        ).all()
        if top_source_ids
        else []
    )
    sources = [
        {
            "source_id": source_id,
            "name": name,
            "region": region,
            "count": source_counts[source_id],
        }
        for source_id, name, region in source_rows
    ]
    sources.sort(
        key=lambda item: (-int(item["count"]), str(item["name"]).casefold(), item["source_id"])
    )
    top_channel_ids = nsmallest(
        _TOP_ACTIVITY_LIMIT,
        channel_counts,
        key=lambda channel_id: (-channel_counts[channel_id].total, channel_id),
    )
    channel_rows = (
        db.execute(
            select(
                NotificationChannel.id,
                NotificationChannel.name,
                NotificationChannel.kind,
            ).where(NotificationChannel.id.in_(top_channel_ids))
        ).all()
        if top_channel_ids
        else []
    )
    channels: list[dict[str, Any]] = []
    for channel_id, name, kind in channel_rows:
        counts = channel_counts[channel_id]
        channels.append(
            {
                "channel_id": channel_id,
                "name": name,
                "kind": kind,
                "total": counts.total,
                "succeeded": counts.succeeded,
                "failed": counts.failed,
                "success_rate": _percentage(counts.succeeded, counts.total),
            }
        )
    channels.sort(
        key=lambda item: (-int(item["total"]), str(item["name"]).casefold(), item["channel_id"])
    )
    deliveries = deliveries_succeeded + deliveries_failed
    return {
        "window": window,
        "generated_at": ends_at,
        "starts_at": starts_at,
        "ends_at": ends_at,
        "bucket_seconds": spec.bucket_seconds,
        "totals": {
            "incidents_started": incidents_started,
            "incidents_resolved": incidents_resolved,
            "active_incidents": active_incidents,
            "active_critical": active_critical,
            "acknowledgement_rate": _percentage(acknowledged_started, incidents_started),
            "resolution_rate": _percentage(resolved_started, incidents_started),
            "mean_time_to_acknowledge_seconds": _mean_duration_seconds(
                acknowledgement_duration_total,
                acknowledged_started,
            ),
            "mean_time_to_resolve_seconds": _mean_duration_seconds(
                resolution_duration_total,
                resolved_started,
            ),
            "deliveries": deliveries,
            "deliveries_succeeded": deliveries_succeeded,
            "deliveries_failed": deliveries_failed,
            "delivery_success_rate": _percentage(deliveries_succeeded, deliveries),
        },
        "timeline": timeline,
        "severities": [
            {"severity": severity, "count": severity_counts[severity]} for severity in _SEVERITIES
        ],
        "sources": sources,
        "channels": channels,
    }
