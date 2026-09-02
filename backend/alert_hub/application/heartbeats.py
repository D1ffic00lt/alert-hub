from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.application.incidents import append_cluster_event, ingest_normalized_events
from alert_hub.domain.events import (
    NormalizedEvent,
    as_utc,
    incident_fingerprint,
    normalize_severity,
)
from alert_hub.infrastructure.db.models import HeartbeatState, Incident, IncidentEvent, Source
from alert_hub.settings import Settings


def _heartbeat_labels(source: Source) -> dict[str, Any]:
    config: dict[str, Any] = source.config_json or {}
    configured = config.get("labels")
    labels = (
        {str(key): value for key, value in configured.items()}
        if isinstance(configured, dict)
        else {}
    )
    labels.setdefault("source", source.name)
    labels.setdefault("region", source.region or "unknown")
    return labels


def _restored_event(
    source: Source,
    incident: Incident,
    observed_at: datetime,
) -> NormalizedEvent:
    config: dict[str, Any] = source.config_json or {}
    return NormalizedEvent(
        dedup_key="heartbeat-missed",
        external_event_id=f"heartbeat-observation:{observed_at.isoformat()}:resolved",
        status="resolved",
        title=str(config.get("resolved_title") or f"Heartbeat restored: {source.name}"),
        description=f"Heartbeat from {source.name} resumed",
        severity=normalize_severity(config.get("severity", "critical")),
        starts_at=incident.starts_at,
        ends_at=observed_at,
        labels=_heartbeat_labels(source),
        annotations={"source_kind": "heartbeat"},
    )


def _heartbeat_incident(db: Session, source_id: str) -> Incident | None:
    return db.scalar(
        select(Incident).where(
            Incident.source_id == source_id,
            Incident.fingerprint == incident_fingerprint(source_id, "heartbeat-missed"),
        )
    )


def _ensure_state(db: Session, source: Source) -> HeartbeatState:
    state = db.get(HeartbeatState, source.id)
    if state is None:
        state = HeartbeatState(source_id=source.id, last_received_at=source.created_at)
        db.add(state)
        db.flush()
    return state


def _resolve_from_observation(
    db: Session,
    source: Source,
    state: HeartbeatState,
    settings: Settings,
    observed_at: datetime,
) -> tuple[list[Incident], int]:
    incident = _heartbeat_incident(db, source.id)
    if incident is None or incident.status == "resolved" or observed_at < incident.last_event_at:
        state.missed = bool(incident is not None and incident.status != "resolved")
        return [], 0

    restored = _restored_event(source, incident, observed_at)
    incidents, duplicates = ingest_normalized_events(db, source, [restored], settings)
    state.missed = False
    state.last_event_key = restored.event_key(source.id)
    return incidents, duplicates


def project_heartbeat_observation(
    db: Session,
    source_id: str,
    observed_at: datetime,
    settings: Settings,
) -> tuple[list[Incident], int]:
    """Project the newest replicated heartbeat and resolve an older missed incident."""

    source = db.get(Source, source_id)
    if source is None or source.kind != "heartbeat" or source.deleted_at is not None:
        return [], 0
    observed_at = as_utc(observed_at)
    state = _ensure_state(db, source)
    if observed_at > state.last_received_at:
        state.last_received_at = observed_at
    incidents, duplicates = _resolve_from_observation(
        db,
        source,
        state,
        settings,
        observed_at,
    )
    state.updated_at = max(state.updated_at, observed_at)
    return incidents, duplicates


def record_heartbeat_observation(
    db: Session,
    source: Source,
    settings: Settings,
    observed_at: datetime,
) -> tuple[list[Incident], int]:
    """Append a heartbeat observation so every connected node shares liveness state."""

    observed_at = as_utc(observed_at)
    append_cluster_event(
        db,
        settings,
        entity_type="heartbeat_observation",
        entity_id=source.id,
        operation="observed",
        payload={
            "source_id": source.id,
            "received_at": observed_at.isoformat(),
        },
        occurred_at=observed_at,
    )
    return project_heartbeat_observation(db, source.id, observed_at, settings)


def reconcile_heartbeat_incident(
    db: Session,
    event: IncidentEvent,
    incident: Incident,
    settings: Settings,
) -> None:
    """Keep liveness state correct when incident history and observations arrive out of order."""

    if str(event.payload_json.get("dedup_key") or "") != "heartbeat-missed":
        return
    source = db.get(Source, incident.source_id)
    if source is None or source.kind != "heartbeat":
        return
    state = _ensure_state(db, source)
    if event.event_type == "resolved":
        raw_ends_at = event.payload_json.get("ends_at")
        try:
            observed_at = as_utc(str(raw_ends_at)) if raw_ends_at else event.occurred_at
        except ValueError:
            observed_at = event.occurred_at
        if observed_at > state.last_received_at:
            state.last_received_at = observed_at
        state.missed = False
        state.last_event_key = event.event_key
        state.updated_at = max(state.updated_at, observed_at)
        return

    if event.event_type != "firing":
        return
    if state.last_received_at >= event.occurred_at:
        _resolve_from_observation(
            db,
            source,
            state,
            settings,
            state.last_received_at,
        )
        return
    state.missed = True
    state.last_event_key = event.event_key
    state.updated_at = max(state.updated_at, event.occurred_at)
