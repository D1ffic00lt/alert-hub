from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import admin_user, get_db, get_settings
from alert_hub.api.schemas import (
    SourceCreate,
    SourceCreatedResponse,
    SourceKind,
    SourcePatch,
    SourceResponse,
)
from alert_hub.application.auth import add_audit
from alert_hub.application.incidents import append_cluster_event, ingest_normalized_events
from alert_hub.domain.events import NormalizedEvent, utc_now
from alert_hub.domain.heartbeats import heartbeat_window
from alert_hub.infrastructure.db.models import HeartbeatState, Source, User
from alert_hub.infrastructure.request_security import normalize_cidrs
from alert_hub.security import hash_token, random_token
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/sources", tags=["sources"])


def _allowed_cidrs(source: Source) -> list[str]:
    config = source.config_json or {}
    raw = config.get("allowed_cidrs", [])
    if not isinstance(raw, list):
        return []
    try:
        return normalize_cidrs(raw)
    except ValueError:
        return []


def _source_config(config: dict[str, Any], allowed_cidrs: list[str]) -> dict[str, Any]:
    normalized = dict(config)
    normalized["allowed_cidrs"] = list(allowed_cidrs)
    return normalized


def source_response(source: Source) -> SourceResponse:
    return SourceResponse(
        id=source.id,
        name=source.name,
        kind=cast(SourceKind, source.kind),
        enabled=source.enabled,
        region=source.region,
        config=source.config_json,
        allowed_cidrs=_allowed_cidrs(source),
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


def source_path(source: Source) -> str:
    suffix = {
        "alertmanager": "alertmanager",
        "generic_json": "events",
        "heartbeat": "heartbeat",
    }[source.kind]
    return f"/ingest/v1/{suffix}/{source.id}"


def source_webhook_url(source: Source, settings: Settings, request: Request) -> str:
    if settings.public_api_url:
        origin = settings.public_api_url.rstrip("/")
    elif settings.trusted_origins:
        origin = settings.trusted_origins[0].rstrip("/")
    else:
        origin = str(request.base_url).rstrip("/")
    return f"{origin}{source_path(source)}"


def source_example(source: Source, token: str, webhook_url: str) -> str:
    if source.kind == "alertmanager":
        return (
            "receivers:\n"
            f"  - name: {source.name!r}\n"
            "    webhook_configs:\n"
            f"      - url: {webhook_url}\n"
            "        send_resolved: true\n"
            "        http_config:\n"
            "          authorization:\n"
            "            type: Bearer\n"
            f"            credentials: {token}\n"
        )
    if source.kind == "heartbeat":
        return (
            "curl --fail --silent --show-error -X POST "
            "--connect-timeout 5 --max-time 10 "
            f"-H 'Authorization: Bearer {token}' {webhook_url}"
        )
    example_starts_at = source.created_at.isoformat().replace("+00:00", "Z")
    return (
        "curl --fail --silent --show-error --connect-timeout 5 --max-time 10 "
        f"-H 'Authorization: Bearer {token}' "
        "-H 'Content-Type: application/json' "
        f"{webhook_url} --data-binary "
        f'\'{{"schema_version":1,"external_event_id":"example-1",'
        f'"dedup_key":"example","status":"firing","title":"Example alert",'
        f'"starts_at":"{example_starts_at}"}}\''
    )


def _cluster_payload(source: Source) -> dict[str, Any]:
    return {
        "name": source.name,
        "kind": source.kind,
        "enabled": source.enabled,
        "region": source.region,
        "config": source.config_json,
        "token_hash": source.token_hash,
        "created_at": source.created_at.isoformat(),
        "updated_at": source.updated_at.isoformat(),
        "deleted_at": source.deleted_at.isoformat() if source.deleted_at else None,
    }


@router.get("", response_model=list[SourceResponse])
def list_sources(
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
) -> list[SourceResponse]:
    del user
    sources = db.scalars(
        select(Source).where(Source.deleted_at.is_(None)).order_by(Source.name, Source.id)
    ).all()
    return [source_response(item) for item in sources]


@router.post("", response_model=SourceCreatedResponse, status_code=201)
def create_source(
    payload: SourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> SourceCreatedResponse:
    raw_token = random_token(32)
    source = Source(
        name=payload.name.strip(),
        kind=payload.kind,
        enabled=payload.enabled,
        region=payload.region,
        config_json=_source_config(payload.config, payload.allowed_cidrs),
        token_hash=hash_token(raw_token, settings.signing_key, "source"),
    )
    db.add(source)
    db.flush()
    if source.kind == "heartbeat":
        db.add(HeartbeatState(source_id=source.id, last_received_at=utc_now()))
    append_cluster_event(
        db,
        settings,
        entity_type="source",
        entity_id=source.id,
        operation="upsert",
        payload=_cluster_payload(source),
    )
    add_audit(
        db,
        settings,
        "source_created",
        actor_user_id=user.id,
        entity_type="source",
        entity_id=source.id,
        request_id=getattr(request.state, "request_id", None),
        details={"kind": source.kind},
    )
    db.commit()
    base = source_response(source).model_dump()
    webhook_url = source_webhook_url(source, settings, request)
    return SourceCreatedResponse(
        **base,
        token=raw_token,
        webhook_url=webhook_url,
        example=source_example(source, raw_token, webhook_url),
    )


def _active_source(db: Session, source_id: str) -> Source:
    source = db.get(Source, source_id)
    if source is None or source.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Source not found")
    return source


@router.patch("/{source_id}", response_model=SourceResponse)
def update_source(
    source_id: str,
    payload: SourcePatch,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> SourceResponse:
    source = _active_source(db, source_id)
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes:
        source.name = changes["name"].strip()
    if "enabled" in changes:
        source.enabled = changes["enabled"]
    if "region" in changes:
        source.region = changes["region"]
    if changes.get("config") is not None:
        if source.kind == "heartbeat":
            try:
                heartbeat_window(changes["config"])
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        allowed_cidrs = changes.get("allowed_cidrs")
        if allowed_cidrs is None:
            allowed_cidrs = _allowed_cidrs(source)
        source.config_json = _source_config(changes["config"], allowed_cidrs)
    elif changes.get("allowed_cidrs") is not None:
        source.config_json = _source_config(
            source.config_json or {},
            changes["allowed_cidrs"],
        )
    source.updated_at = utc_now()
    append_cluster_event(
        db,
        settings,
        entity_type="source",
        entity_id=source.id,
        operation="upsert",
        payload=_cluster_payload(source),
    )
    add_audit(
        db,
        settings,
        "source_updated",
        actor_user_id=user.id,
        entity_type="source",
        entity_id=source.id,
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changes)},
    )
    db.commit()
    return source_response(source)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_source(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> None:
    source = _active_source(db, source_id)
    source.enabled = False
    source.deleted_at = utc_now()
    source.updated_at = source.deleted_at
    append_cluster_event(
        db,
        settings,
        entity_type="source",
        entity_id=source.id,
        operation="tombstone",
        payload=_cluster_payload(source),
    )
    add_audit(
        db,
        settings,
        "source_deleted",
        actor_user_id=user.id,
        entity_type="source",
        entity_id=source.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()


@router.post("/{source_id}/rotate-token", response_model=SourceCreatedResponse)
def rotate_source_token(
    source_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> SourceCreatedResponse:
    source = _active_source(db, source_id)
    raw_token = random_token(32)
    source.token_hash = hash_token(raw_token, settings.signing_key, "source")
    source.updated_at = utc_now()
    append_cluster_event(
        db,
        settings,
        entity_type="source",
        entity_id=source.id,
        operation="rotate_token",
        payload=_cluster_payload(source),
    )
    add_audit(
        db,
        settings,
        "source_token_rotated",
        actor_user_id=user.id,
        entity_type="source",
        entity_id=source.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    webhook_url = source_webhook_url(source, settings, request)
    return SourceCreatedResponse(
        **source_response(source).model_dump(),
        token=raw_token,
        webhook_url=webhook_url,
        example=source_example(source, raw_token, webhook_url),
    )


@router.post("/{source_id}/test")
def test_source(
    source_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    del user
    source = _active_source(db, source_id)
    now = utc_now()
    test_event = NormalizedEvent(
        external_event_id=f"ui-test-{now.isoformat()}",
        dedup_key=f"source-test-{now.isoformat()}",
        status="firing",
        title=f"Test event from {source.name}",
        description="Created by the Alert Hub source test action",
        severity="info",
        starts_at=now,
        labels={"test": "true", "source": source.name},
        annotations={"generated_by": "source_test"},
    )
    incidents, duplicates = ingest_normalized_events(db, source, [test_event], settings)
    db.commit()
    return {
        "accepted": 1,
        "duplicates": duplicates,
        "incident_id": incidents[0].id,
    }
