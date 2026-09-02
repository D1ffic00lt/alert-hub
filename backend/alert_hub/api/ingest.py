from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import get_db, get_settings
from alert_hub.application.auth import add_audit
from alert_hub.application.heartbeats import record_heartbeat_observation
from alert_hub.application.incidents import ingest_normalized_events
from alert_hub.domain.adapters import AdapterError, normalize_alertmanager, normalize_generic
from alert_hub.domain.events import utc_now
from alert_hub.infrastructure.db.models import Incident, Source
from alert_hub.infrastructure.request_security import address_in_cidrs
from alert_hub.metrics import INGEST_ERRORS
from alert_hub.security import constant_time_equal, hash_token
from alert_hub.settings import Settings
from alert_hub.workers.heartbeat import evaluate_heartbeats

router = APIRouter(prefix="/ingest/v1", tags=["ingest"])


def _request_bearer(request: Request) -> str | None:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def authenticated_source(
    request: Request,
    db: Session,
    settings: Settings,
    source_id: str,
    expected_kind: str,
) -> Source:
    source = db.get(Source, source_id)
    token = _request_bearer(request)
    supplied_hash = hash_token(token or "", settings.signing_key, "source")
    expected_hash = source.token_hash if source is not None else "0" * 64
    token_valid = constant_time_equal(expected_hash, supplied_hash)
    source_valid = (
        source is None
        or source.deleted_at is not None
        or not source.enabled
        or source.kind != expected_kind
    )
    allowed_cidrs: list[str] = []
    if source is not None:
        configured = (source.config_json or {}).get("allowed_cidrs", [])
        if isinstance(configured, list):
            allowed_cidrs = [str(item) for item in configured]
    client_ip = getattr(request.state, "client_ip", None)
    cidr_allowed = not allowed_cidrs or address_in_cidrs(client_ip, allowed_cidrs)
    if token is None or source_valid or not token_valid or not cidr_allowed:
        INGEST_ERRORS.labels(source_kind=expected_kind, reason="authentication").inc()
        add_audit(
            db,
            settings,
            "ingest_auth_failed",
            entity_type="source",
            entity_id=source_id,
            request_id=getattr(request.state, "request_id", None),
            details={"client_ip": client_ip, "source_kind": expected_kind},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid source credentials")
    assert source is not None
    return source


async def _json_body(request: Request, settings: Settings, source_kind: str) -> Mapping[str, Any]:
    body = await request.body()
    if len(body) > settings.max_payload_bytes:
        INGEST_ERRORS.labels(source_kind=source_kind, reason="payload_too_large").inc()
        raise HTTPException(status_code=413, detail="Payload too large")
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        INGEST_ERRORS.labels(source_kind=source_kind, reason="invalid_json").inc()
        raise HTTPException(status_code=400, detail="Request body must be valid JSON") from exc
    if not isinstance(value, Mapping):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")
    return value


def _result(incidents: list[Incident], duplicates: int) -> dict[str, Any]:
    unique_ids = list(dict.fromkeys(incident.id for incident in incidents))
    return {
        "accepted": len(incidents) - duplicates,
        "duplicates": duplicates,
        "incident_ids": unique_ids,
    }


@router.post("/alertmanager/{source_id}")
async def ingest_alertmanager(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    source = authenticated_source(request, db, settings, source_id, "alertmanager")
    payload = await _json_body(request, settings, source.kind)
    try:
        events = normalize_alertmanager(payload)
    except AdapterError as exc:
        INGEST_ERRORS.labels(source_kind=source.kind, reason="adapter").inc()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    incidents, duplicates = ingest_normalized_events(db, source, events, settings)
    db.commit()
    return _result(incidents, duplicates)


@router.post("/events/{source_id}")
async def ingest_generic(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    source = authenticated_source(request, db, settings, source_id, "generic_json")
    payload = await _json_body(request, settings, source.kind)
    try:
        event = normalize_generic(payload)
    except (AdapterError, ValueError) as exc:
        INGEST_ERRORS.labels(source_kind=source.kind, reason="adapter").inc()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    incidents, duplicates = ingest_normalized_events(db, source, [event], settings)
    db.commit()
    return _result(incidents, duplicates)


@router.post("/heartbeat/{source_id}")
async def ingest_heartbeat(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    source = authenticated_source(request, db, settings, source_id, "heartbeat")
    body = await request.body()
    if len(body) > settings.max_payload_bytes:
        raise HTTPException(status_code=413, detail="Payload too large")
    now = utc_now()
    # This also makes heartbeat semantics correct when the optional scheduler is disabled.
    evaluate_heartbeats(db, settings, now=now)
    incidents, duplicates = record_heartbeat_observation(db, source, settings, now)
    db.commit()
    return {"received_at": now, **_result(incidents, duplicates)}
