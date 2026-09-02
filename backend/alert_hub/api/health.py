from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import get_db, get_settings
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    Delivery,
    Incident,
    Node,
    NotificationChannel,
    Outbox,
)
from alert_hub.infrastructure.vapid import VapidConfigurationError, vapid_public_key
from alert_hub.metrics import BUILD_INFO, DB_ERRORS, INCIDENTS_OPEN, OUTBOX_PENDING
from alert_hub.settings import Settings

router = APIRouter(tags=["operations"])


def _valid_vapid_subject(value: str) -> bool:
    """Validate the contact URI passed to the VAPID provider without network I/O."""

    if not value or value != value.strip() or any(character.isspace() for character in value):
        return False
    try:
        parsed = urlsplit(value)
        parsed_port = parsed.port
    except ValueError:
        return False
    if parsed.fragment or parsed_port == 0:
        return False
    if parsed.scheme == "mailto":
        address = parsed.path
        local, separator, domain = address.rpartition("@")
        return (
            not parsed.netloc
            and not parsed.query
            and separator == "@"
            and "@" not in local
            and bool(local)
            and (domain == "localhost" or "." in domain)
        )
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and parsed.port is None
        and parsed.path == ""
        and not parsed.query
    )


def _web_push_capability(settings: Settings, enabled_channels: int) -> dict[str, Any]:
    issues: list[str] = []
    if not settings.notify_enabled:
        issues.append("notification_worker_disabled")

    sender_configured = settings.vapid_private_key_file is not None
    if not sender_configured:
        issues.append("missing_vapid_private_key")
    else:
        try:
            # This validates readable P-256 private material and, when supplied,
            # the canonical public key plus its pairing with the private key.
            vapid_public_key(settings)
        except VapidConfigurationError:
            issues.append("invalid_vapid_key_material")
    if not _valid_vapid_subject(settings.vapid_subject):
        issues.append("invalid_vapid_subject")

    if enabled_channels == 0:
        capability_status = "not_configured"
    elif not settings.notify_enabled:
        capability_status = "worker_disabled"
    elif issues:
        capability_status = "misconfigured"
    else:
        capability_status = "configured"
    return {
        "status": capability_status,
        "enabled_channels": enabled_channels,
        "worker_enabled": settings.notify_enabled,
        "sender_configured": sender_configured
        and not any(issue.startswith(("missing_vapid_", "invalid_vapid_")) for issue in issues),
        "issues": issues,
    }


@router.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
def ready(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    try:
        db.execute(select(1))
    except SQLAlchemyError:
        DB_ERRORS.labels(operation="readiness").inc()
        return JSONResponse(
            status_code=503,
            content={"status": "unavailable", "node_id": settings.node_id, "database": "down"},
        )
    return JSONResponse(content={"status": "ok", "node_id": settings.node_id, "database": "ok"})


@router.get("/health/deep")
def deep(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    db.execute(select(1))
    sync_worker = getattr(request.app.state, "peer_sync_worker", None)
    peer_snapshot = sync_worker.status_snapshot() if sync_worker is not None else {}
    peers = (
        {
            "status": (
                "ok"
                if peer_snapshot and all(bool(item["up"]) for item in peer_snapshot.values())
                else "degraded"
            ),
            "items": peer_snapshot,
        }
        if sync_worker is not None
        else {"status": "not_configured", "items": {}}
    )
    enabled_channels = int(
        db.scalar(
            select(func.count(NotificationChannel.id)).where(
                NotificationChannel.enabled.is_(True),
                NotificationChannel.deleted_at.is_(None),
            )
        )
        or 0
    )
    enabled_web_push_channels = int(
        db.scalar(
            select(func.count(NotificationChannel.id)).where(
                NotificationChannel.kind == "web_push",
                NotificationChannel.enabled.is_(True),
                NotificationChannel.deleted_at.is_(None),
            )
        )
        or 0
    )
    web_push = _web_push_capability(settings, enabled_web_push_channels)
    pending_notifications = int(
        db.scalar(
            select(func.count(Outbox.id)).where(
                Outbox.topic == "notification_event",
                Outbox.completed_at.is_(None),
            )
        )
        or 0
    )
    failed_deliveries = int(
        db.scalar(select(func.count(Delivery.id)).where(Delivery.status == "failed")) or 0
    )
    if not settings.notify_enabled:
        channel_status = "worker_disabled"
    elif enabled_channels == 0:
        channel_status = "not_configured"
    elif enabled_web_push_channels and web_push["status"] != "configured":
        channel_status = "misconfigured"
    else:
        # A configured provider is not called "healthy" until a delivery proves it.
        channel_status = "configured"

    return {
        "status": "ok",
        "node_id": settings.node_id,
        "region": settings.node_region,
        "roles": settings.enabled_roles(),
        "database": "ok",
        "nodes_known": int(db.scalar(select(func.count(Node.id))) or 0),
        "cluster_events": int(db.scalar(select(func.count(ClusterEvent.event_id))) or 0),
        "open_incidents": int(
            db.scalar(select(func.count(Incident.id)).where(Incident.status != "resolved")) or 0
        ),
        # Remote peer/channel failures are informational and never change local readiness.
        "peers": peers,
        "channels": {
            "status": channel_status,
            "enabled": enabled_channels,
            "outbox_pending": pending_notifications,
            "failed_delivery_records": failed_deliveries,
            "providers": {"web_push": web_push},
        },
    }


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    INCIDENTS_OPEN.set(
        int(db.scalar(select(func.count(Incident.id)).where(Incident.status != "resolved")) or 0)
    )
    OUTBOX_PENDING.set(
        int(db.scalar(select(func.count(Outbox.id)).where(Outbox.completed_at.is_(None))) or 0)
    )
    BUILD_INFO.info(
        {
            "version": settings.software_version,
            "node_id": settings.node_id,
            "region": settings.node_region,
        }
    )
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
