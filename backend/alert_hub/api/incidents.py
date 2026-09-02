from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from alert_hub.api.dependencies import current_user, get_db, get_settings
from alert_hub.api.schemas import IncidentActionRequest, IncidentCommentRequest
from alert_hub.application.auth import add_audit
from alert_hub.application.incidents import append_user_event
from alert_hub.infrastructure.db.models import Incident, IncidentEvent, User
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _incident_summary(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "source_id": incident.source_id,
        "source_name": incident.source.name if incident.source else None,
        "fingerprint": incident.fingerprint,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "labels": incident.labels_json,
        "annotations": incident.annotations_json,
        "starts_at": incident.starts_at,
        "last_event_at": incident.last_event_at,
        "resolved_at": incident.resolved_at,
        "acknowledged_at": incident.acknowledged_at,
        "acknowledged_by": incident.acknowledged_by,
    }


def _event_response(event: IncidentEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "origin_node_id": event.origin_node_id,
        "origin_seq": event.origin_seq,
        "event_key": event.event_key,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at,
        "received_at": event.received_at,
        "payload": event.payload_json,
    }


def _incident_or_404(db: Session, incident_id: str) -> Incident:
    incident = db.scalar(
        select(Incident)
        .options(selectinload(Incident.source), selectinload(Incident.events))
        .where(Incident.id == incident_id)
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("")
def list_incidents(
    status_filter: Literal["open", "acknowledged", "resolved", "silenced"] | None = Query(
        default=None, alias="status"
    ),
    severity: Literal["info", "warning", "critical", "unknown"] | None = None,
    source_id: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    predicates = []
    if status_filter:
        predicates.append(Incident.status == status_filter)
    if severity:
        predicates.append(Incident.severity == severity)
    if source_id:
        predicates.append(Incident.source_id == source_id)
    if q:
        pattern = f"%{q.strip()}%"
        predicates.append(or_(Incident.title.ilike(pattern), Incident.description.ilike(pattern)))
    count_query = select(func.count(Incident.id))
    query = select(Incident).options(selectinload(Incident.source))
    if predicates:
        count_query = count_query.where(*predicates)
        query = query.where(*predicates)
    total = int(db.scalar(count_query) or 0)
    incidents = db.scalars(
        query.order_by(Incident.last_event_at.desc(), Incident.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "items": [_incident_summary(incident) for incident in incidents],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{incident_id}")
def incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    incident = _incident_or_404(db, incident_id)
    return {
        **_incident_summary(incident),
        "timeline": [_event_response(event) for event in incident.events],
    }


def _action_response(incident: Incident, event: IncidentEvent | None) -> dict[str, Any]:
    return {
        "incident": _incident_summary(incident),
        "event": _event_response(event) if event else None,
    }


@router.post("/{incident_id}/acknowledge")
def acknowledge_incident(
    incident_id: str,
    payload: IncidentActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    incident = _incident_or_404(db, incident_id)
    if incident.status == "resolved":
        raise HTTPException(status_code=409, detail="Resolved incident cannot be acknowledged")
    event = None
    if incident.status != "acknowledged":
        event = append_user_event(
            db,
            incident,
            "acknowledged",
            user.id,
            settings,
            payload={"reason": payload.reason},
        )
        add_audit(
            db,
            settings,
            "incident_acknowledged",
            actor_user_id=user.id,
            entity_type="incident",
            entity_id=incident.id,
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
    return _action_response(incident, event)


@router.post("/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    payload: IncidentActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    incident = _incident_or_404(db, incident_id)
    event = None
    if incident.status != "resolved":
        event = append_user_event(
            db,
            incident,
            "resolved",
            user.id,
            settings,
            payload={"reason": payload.reason, "starts_at": incident.starts_at.isoformat()},
        )
        add_audit(
            db,
            settings,
            "incident_resolved",
            actor_user_id=user.id,
            entity_type="incident",
            entity_id=incident.id,
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
    return _action_response(incident, event)


@router.post("/{incident_id}/silence")
def silence_incident(
    incident_id: str,
    payload: IncidentActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    incident = _incident_or_404(db, incident_id)
    if incident.status == "resolved":
        raise HTTPException(status_code=409, detail="Resolved incident cannot be silenced")
    event = None
    if incident.status != "silenced":
        event = append_user_event(
            db,
            incident,
            "silenced",
            user.id,
            settings,
            payload={"reason": payload.reason},
        )
        add_audit(
            db,
            settings,
            "incident_silenced",
            actor_user_id=user.id,
            entity_type="incident",
            entity_id=incident.id,
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
    return _action_response(incident, event)


@router.post("/{incident_id}/comments", status_code=201)
def comment_incident(
    incident_id: str,
    payload: IncidentCommentRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    incident = _incident_or_404(db, incident_id)
    event = append_user_event(
        db,
        incident,
        "commented",
        user.id,
        settings,
        payload={"body": payload.body.strip()},
    )
    db.commit()
    return _event_response(event)
