from __future__ import annotations

from typing import Any, Literal, cast
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import String, func, or_, select
from sqlalchemy import cast as sql_cast
from sqlalchemy.orm import Session, load_only, selectinload

from alert_hub.api.dependencies import current_user, get_db, get_settings
from alert_hub.api.schemas import (
    IncidentActionRequest,
    IncidentBulkActionItem,
    IncidentBulkActionRequest,
    IncidentBulkActionResponse,
    IncidentBulkFilters,
    IncidentCommentRequest,
)
from alert_hub.application.auth import add_audit
from alert_hub.application.checks import normalize_check_identifier
from alert_hub.application.incidents import append_user_event
from alert_hub.infrastructure.db.models import Incident, IncidentEvent, Source, User
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

_MAX_RELATED_CHECKS = 200
_MAX_BULK_INCIDENTS = 500


def _related_checks(
    incident: Incident,
    *,
    include_timeline: bool,
) -> tuple[list[dict[str, str]], int]:
    candidates: list[object] = [incident.labels_json.get("check_id")]
    if include_timeline:
        for event in incident.events:
            labels = event.payload_json.get("labels")
            if isinstance(labels, dict):
                candidates.append(labels.get("check_id"))
    check_ids: list[str] = []
    seen: set[str] = set()
    for raw in candidates:
        candidate = normalize_check_identifier(raw)
        if candidate is None:
            continue
        if candidate not in seen:
            seen.add(candidate)
            check_ids.append(candidate)
    total = len(check_ids)
    return [
        {
            "check_id": check_id,
            "href": f"/checks/{quote(check_id, safe='')}",
        }
        for check_id in check_ids[:_MAX_RELATED_CHECKS]
    ], total


def _incident_summary(
    incident: Incident,
    settings: Settings,
    *,
    include_timeline_checks: bool = False,
    compact: bool = False,
) -> dict[str, Any]:
    checks_enabled = settings.checks_enabled
    related_checks, related_checks_total = (
        _related_checks(incident, include_timeline=include_timeline_checks)
        if checks_enabled
        else ([], 0)
    )
    if compact:
        labels = incident.labels_json
        return {
            "id": incident.id,
            "source_id": incident.source_id,
            "source_name": incident.source.name if incident.source else None,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "starts_at": incident.starts_at,
            "last_event_at": incident.last_event_at,
            "resolved_at": incident.resolved_at,
            "acknowledged_at": incident.acknowledged_at,
            "acknowledged_by": incident.acknowledged_by,
            "related_checks": related_checks,
            "related_checks_total": related_checks_total,
            "related_checks_truncated": related_checks_total > len(related_checks),
            "checks_relation_state": "available" if checks_enabled else "disabled",
            "region": labels.get("source_region") or labels.get("region"),
            "target": labels.get("target_name") or labels.get("target"),
            "summary_only": True,
        }
    result = {
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
        "related_checks": related_checks,
        "related_checks_total": related_checks_total,
        "related_checks_truncated": related_checks_total > len(related_checks),
        "checks_relation_state": "available" if checks_enabled else "disabled",
    }
    return result


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


IncidentListStatus = Literal["active", "open", "acknowledged", "resolved", "silenced"]


def _search_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _incident_predicates(
    *,
    status_filter: IncidentListStatus | None,
    severity: Literal["info", "warning", "critical", "unknown"] | None,
    source_id: str | None,
    q: str | None,
) -> list[Any]:
    predicates: list[Any] = []
    if status_filter == "active":
        predicates.append(Incident.status.in_(("open", "acknowledged", "silenced")))
    elif status_filter:
        predicates.append(Incident.status == status_filter)
    if severity:
        predicates.append(Incident.severity == severity)
    if source_id:
        predicates.append(Incident.source_id == source_id)
    normalized_query = q.strip() if q else ""
    if normalized_query:
        pattern = _search_pattern(normalized_query)
        predicates.append(
            or_(
                Incident.title.ilike(pattern, escape="\\"),
                Incident.description.ilike(pattern, escape="\\"),
                sql_cast(Incident.labels_json, String).ilike(pattern, escape="\\"),
                Incident.source.has(Source.name.ilike(pattern, escape="\\")),
            )
        )
    return predicates


def _status_counts(
    db: Session,
    *,
    severity: Literal["info", "warning", "critical", "unknown"] | None,
    source_id: str | None,
    q: str | None,
) -> dict[str, int]:
    predicates = _incident_predicates(
        status_filter=None,
        severity=severity,
        source_id=source_id,
        q=q,
    )
    query = select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    if predicates:
        query = query.where(*predicates)
    by_status = {str(row.status): int(row[1]) for row in db.execute(query)}
    return {
        "active": sum(
            by_status.get(status_name, 0) for status_name in ("open", "acknowledged", "silenced")
        ),
        "open": by_status.get("open", 0),
        "acknowledged": by_status.get("acknowledged", 0),
        "resolved": by_status.get("resolved", 0),
        "silenced": by_status.get("silenced", 0),
        "all": sum(by_status.values()),
    }


@router.get("")
def list_incidents(
    status_filter: IncidentListStatus | None = Query(default=None, alias="status"),
    severity: Literal["info", "warning", "critical", "unknown"] | None = None,
    source_id: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    view: Literal["full", "compact"] = "full",
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    predicates = _incident_predicates(
        status_filter=status_filter,
        severity=severity,
        source_id=source_id,
        q=q,
    )
    counts = _status_counts(db, severity=severity, source_id=source_id, q=q)
    if view == "compact":
        query = select(Incident).options(
            load_only(
                Incident.id,
                Incident.source_id,
                Incident.title,
                Incident.severity,
                Incident.status,
                Incident.labels_json,
                Incident.starts_at,
                Incident.last_event_at,
                Incident.resolved_at,
                Incident.acknowledged_at,
                Incident.acknowledged_by,
            ),
            selectinload(Incident.source).load_only(Source.id, Source.name),
        )
    else:
        query = select(Incident).options(selectinload(Incident.source))
    if predicates:
        query = query.where(*predicates)
    total = counts[status_filter or "all"]
    incidents = db.scalars(
        query.order_by(Incident.last_event_at.desc(), Incident.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "items": [
            _incident_summary(incident, settings, compact=view == "compact")
            for incident in incidents
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
        "counts": counts,
        "bulk_limit": _MAX_BULK_INCIDENTS,
    }


def _bulk_incidents(
    db: Session,
    payload: IncidentBulkActionRequest,
) -> list[Incident | None]:
    if payload.selection_mode == "ids":
        incidents = db.scalars(select(Incident).where(Incident.id.in_(payload.incident_ids))).all()
        by_id = {incident.id: incident for incident in incidents}
        return [by_id.get(incident_id) for incident_id in payload.incident_ids]

    filters = payload.filters or IncidentBulkFilters()
    predicates = _incident_predicates(
        status_filter=filters.status,
        severity=filters.severity,
        source_id=filters.source_id,
        q=filters.q,
    )
    if payload.excluded_incident_ids:
        predicates.append(Incident.id.not_in(payload.excluded_incident_ids))
    query = select(Incident)
    if predicates:
        query = query.where(*predicates)
    incidents = db.scalars(
        query.order_by(Incident.last_event_at.desc(), Incident.id.desc()).limit(
            _MAX_BULK_INCIDENTS + 1
        )
    ).all()
    if len(incidents) > _MAX_BULK_INCIDENTS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "bulk_selection_too_large",
                "message": f"Bulk selection exceeds {_MAX_BULK_INCIDENTS} incidents",
                "limit": _MAX_BULK_INCIDENTS,
            },
        )
    return list(incidents)


@router.post(
    "/bulk-action",
    response_model=IncidentBulkActionResponse,
    responses={
        401: {"description": "Authentication required"},
        207: {
            "model": IncidentBulkActionResponse,
            "description": "Some selected incidents could not be changed",
        },
        422: {"description": "Invalid or oversized incident selection"},
    },
)
def bulk_incident_action(
    payload: IncidentBulkActionRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> IncidentBulkActionResponse:
    incidents = _bulk_incidents(db, payload)
    event_type = {
        "acknowledge": "acknowledged",
        "resolve": "resolved",
        "silence": "silenced",
    }[payload.action]
    audit_action = f"incident_{event_type}"
    results: list[IncidentBulkActionItem] = []
    updated = 0
    unchanged = 0
    failed = 0
    for position, incident in enumerate(incidents):
        if incident is None:
            failed += 1
            results.append(
                IncidentBulkActionItem(
                    incident_id=payload.incident_ids[position],
                    outcome="not_found",
                    status=None,
                    detail="Incident not found",
                )
            )
            continue
        if incident.status == "resolved" and event_type != "resolved":
            failed += 1
            results.append(
                IncidentBulkActionItem(
                    incident_id=incident.id,
                    outcome="conflict",
                    status=cast(Literal["resolved"], incident.status),
                    detail=f"Resolved incident cannot be {event_type}",
                )
            )
            continue
        if incident.status == event_type:
            unchanged += 1
            results.append(
                IncidentBulkActionItem(
                    incident_id=incident.id,
                    outcome="unchanged",
                    status=cast(
                        Literal["open", "acknowledged", "resolved", "silenced"],
                        incident.status,
                    ),
                    detail=None,
                )
            )
            continue
        event_payload: dict[str, Any] = {"reason": payload.reason}
        if event_type == "resolved":
            event_payload["starts_at"] = incident.starts_at.isoformat()
        append_user_event(
            db,
            incident,
            event_type,
            user.id,
            settings,
            payload=event_payload,
        )
        add_audit(
            db,
            settings,
            audit_action,
            actor_user_id=user.id,
            entity_type="incident",
            entity_id=incident.id,
            request_id=getattr(request.state, "request_id", None),
            details={"bulk": True},
        )
        updated += 1
        results.append(
            IncidentBulkActionItem(
                incident_id=incident.id,
                outcome="updated",
                status=cast(
                    Literal["open", "acknowledged", "resolved", "silenced"],
                    incident.status,
                ),
                detail=None,
            )
        )
    if updated:
        db.commit()
    if failed:
        response.status_code = 207
    return IncidentBulkActionResponse(
        action=payload.action,
        selection_mode=payload.selection_mode,
        matched=len(incidents),
        updated=updated,
        unchanged=unchanged,
        failed=failed,
        results=results,
    )


@router.get("/{incident_id}")
def incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    incident = _incident_or_404(db, incident_id)
    return {
        **_incident_summary(incident, settings, include_timeline_checks=True),
        "timeline": [_event_response(event) for event in incident.events],
    }


def _action_response(
    incident: Incident,
    event: IncidentEvent | None,
    settings: Settings,
) -> dict[str, Any]:
    return {
        "incident": _incident_summary(incident, settings),
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
    return _action_response(incident, event, settings)


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
    return _action_response(incident, event, settings)


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
    return _action_response(incident, event, settings)


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
