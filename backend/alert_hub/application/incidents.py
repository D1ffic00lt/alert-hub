from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from alert_hub.application.notifications import enqueue_notification_event
from alert_hub.domain.events import (
    NormalizedEvent,
    ProjectionEvent,
    incident_fingerprint,
    project_incident,
)
from alert_hub.infrastructure.db.base import new_id, utc_now
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    Incident,
    IncidentEvent,
    Source,
    User,
)
from alert_hub.metrics import INGEST_TOTAL
from alert_hub.settings import Settings


def _json_datetime(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def next_origin_seq(db: Session, node_id: str) -> int:
    current = db.scalar(
        select(func.max(ClusterEvent.origin_seq)).where(ClusterEvent.origin_node_id == node_id)
    )
    return int(current or 0) + 1


def append_cluster_event(
    db: Session,
    settings: Settings,
    *,
    entity_type: str,
    entity_id: str,
    operation: str,
    payload: dict[str, Any],
    occurred_at: datetime | None = None,
    event_id: str | None = None,
) -> ClusterEvent:
    cluster_event = ClusterEvent(
        event_id=event_id or new_id(),
        origin_node_id=settings.node_id,
        origin_seq=next_origin_seq(db, settings.node_id),
        entity_type=entity_type,
        entity_id=entity_id,
        operation=operation,
        occurred_at=occurred_at or utc_now(),
        payload_json=payload,
    )
    db.add(cluster_event)
    db.flush()
    return cluster_event


def incident_projection_id(source_id: str, fingerprint: str) -> str:
    """Return the cluster-wide stable identity for an incident projection."""

    return str(uuid5(NAMESPACE_URL, f"alert-hub:incident:{source_id}:{fingerprint}"))


def reproject_incident(db: Session, incident: Incident) -> None:
    rows = db.scalars(
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.occurred_at, IncidentEvent.id)
    ).all()
    projection = project_incident(
        ProjectionEvent(row.id, row.event_type, row.occurred_at, row.payload_json) for row in rows
    )
    incident.status = projection.status
    if projection.starts_at is not None:
        incident.starts_at = projection.starts_at
    incident.resolved_at = projection.resolved_at
    incident.acknowledged_at = projection.acknowledged_at
    if rows:
        incident.last_event_at = max(row.occurred_at for row in rows)
    metadata_rows = [row for row in rows if row.payload_json.get("title")]
    if metadata_rows:
        metadata = metadata_rows[-1].payload_json
        incident.title = str(metadata.get("title", incident.title))[:1024]
        incident.description = str(metadata.get("description", incident.description))
        incident.severity = str(metadata.get("severity", incident.severity))[:16]
        labels = metadata.get("labels")
        annotations = metadata.get("annotations")
        if isinstance(labels, dict):
            incident.labels_json = labels
        if isinstance(annotations, dict):
            incident.annotations_json = annotations
    if projection.status != "acknowledged":
        incident.acknowledged_by = None
    else:
        for row in reversed(rows):
            if row.event_type == "acknowledged":
                actor = row.payload_json.get("actor_user_id")
                actor_id = str(actor) if actor else None
                incident.acknowledged_by = (
                    actor_id
                    if actor_id is not None and db.get(User, actor_id) is not None
                    else None
                )
                break


def ingest_normalized_events(
    db: Session,
    source: Source,
    events: Iterable[NormalizedEvent],
    settings: Settings,
) -> tuple[list[Incident], int]:
    affected: list[Incident] = []
    duplicates = 0
    for event in events:
        event_key = event.event_key(source.id)
        existing_event = db.scalar(
            select(IncidentEvent).where(IncidentEvent.event_key == event_key)
        )
        if existing_event is not None:
            duplicates += 1
            incident = db.get(Incident, existing_event.incident_id)
            if incident is not None:
                affected.append(incident)
            continue

        fingerprint = incident_fingerprint(source.id, event.dedup_key)
        incident = db.scalar(
            select(Incident).where(
                Incident.source_id == source.id,
                Incident.fingerprint == fingerprint,
            )
        )
        occurred_at = (
            event.ends_at if event.status == "resolved" and event.ends_at else event.starts_at
        )
        if incident is None:
            incident = Incident(
                id=incident_projection_id(source.id, fingerprint),
                source_id=source.id,
                fingerprint=fingerprint,
                title=event.title[:1024],
                description=event.description,
                severity=event.severity,
                status="open",
                labels_json=event.labels,
                annotations_json=event.annotations,
                starts_at=event.starts_at,
                last_event_at=occurred_at,
            )
            db.add(incident)
            db.flush()

        cluster_payload = {
            "event_key": event_key,
            "fingerprint": fingerprint,
            "source_id": source.id,
            "dedup_key": event.dedup_key,
            "status": event.status,
            "title": event.title,
            "description": event.description,
            "severity": event.severity,
            "starts_at": _json_datetime(event.starts_at),
            "ends_at": _json_datetime(event.ends_at),
            "labels": event.labels,
            "annotations": event.annotations,
            "source_url": event.source_url,
            "external_event_id": event.external_event_id,
        }
        cluster_event = append_cluster_event(
            db,
            settings,
            entity_type="incident",
            entity_id=incident.id,
            operation=event.status,
            occurred_at=occurred_at,
            payload=cluster_payload,
        )
        timeline_event = IncidentEvent(
            id=cluster_event.event_id,
            origin_node_id=cluster_event.origin_node_id,
            origin_seq=cluster_event.origin_seq,
            event_key=event_key,
            incident_id=incident.id,
            event_type=event.status,
            occurred_at=occurred_at,
            payload_json=cluster_payload,
        )
        db.add(timeline_event)
        db.flush()

        incident.title = event.title[:1024]
        incident.description = event.description
        incident.severity = event.severity
        incident.labels_json = event.labels
        incident.annotations_json = event.annotations
        incident.last_event_at = max(incident.last_event_at, occurred_at)
        reproject_incident(db, incident)

        enqueue_notification_event(db, timeline_event)
        affected.append(incident)
        INGEST_TOTAL.labels(source_kind=source.kind, status=event.status).inc()
    return affected, duplicates


def append_user_event(
    db: Session,
    incident: Incident,
    event_type: str,
    user_id: str,
    settings: Settings,
    *,
    payload: dict[str, Any] | None = None,
) -> IncidentEvent:
    now = utc_now()
    details = {"actor_user_id": user_id, **(payload or {})}
    digest = hashlib.sha256(
        f"{settings.node_id}\0{incident.id}\0{event_type}\0{now.isoformat()}\0{new_id()}".encode()
    ).hexdigest()
    cluster_event = append_cluster_event(
        db,
        settings,
        entity_type="incident",
        entity_id=incident.id,
        operation=event_type,
        occurred_at=now,
        payload={"event_key": digest, **details},
    )
    timeline_event = IncidentEvent(
        id=cluster_event.event_id,
        origin_node_id=cluster_event.origin_node_id,
        origin_seq=cluster_event.origin_seq,
        event_key=digest,
        incident_id=incident.id,
        event_type=event_type,
        occurred_at=now,
        payload_json=details,
    )
    db.add(timeline_event)
    db.flush()
    enqueue_notification_event(db, timeline_event)
    incident.last_event_at = max(incident.last_event_at, now)
    reproject_incident(db, incident)
    return timeline_event
