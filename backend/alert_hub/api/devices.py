from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_session, get_db, get_settings
from alert_hub.application.auth import (
    add_audit,
    disable_session_push_subscriptions,
    session_cluster_payload,
)
from alert_hub.application.incidents import append_cluster_event
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import PushSubscription
from alert_hub.infrastructure.db.models import Session as AuthSession
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


@router.get("")
def list_devices(
    db: Session = Depends(get_db),
    auth_session: AuthSession = Depends(current_session),
) -> list[dict[str, Any]]:
    sessions = db.scalars(
        select(AuthSession)
        .where(
            AuthSession.user_id == auth_session.user_id,
            AuthSession.revoked_at.is_(None),
        )
        .order_by(AuthSession.last_used_at.desc(), AuthSession.id)
    ).all()
    subscriptions = db.scalars(
        select(PushSubscription)
        .where(
            PushSubscription.user_id == auth_session.user_id,
            PushSubscription.disabled_at.is_(None),
        )
        .order_by(PushSubscription.created_at.desc(), PushSubscription.id)
    ).all()
    subscriptions_by_session: dict[str, PushSubscription] = {}
    for candidate in subscriptions:
        if candidate.session_id is not None:
            subscriptions_by_session.setdefault(candidate.session_id, candidate)

    device_rows: list[dict[str, Any]] = []
    for item in sessions:
        subscription = subscriptions_by_session.get(item.id)
        device_rows.append(
            {
                "id": item.id,
                "session_id": item.id,
                "device_name": item.device_name,
                "name": item.device_name,
                "current": item.id == auth_session.id,
                "is_current": item.id == auth_session.id,
                "push_enabled": subscription is not None,
                "push_subscription_id": subscription.id if subscription is not None else None,
                "user_agent": subscription.user_agent if subscription is not None else None,
                "platform": (
                    subscription.user_agent if subscription is not None else "Browser session"
                ),
                "location": "Unknown location",
                "created_at": item.created_at,
                "last_used_at": item.last_used_at,
                "expires_at": item.expires_at,
                "absolute_expires_at": item.absolute_expires_at,
            }
        )
    return device_rows


@router.delete("/{device_id}/sessions", status_code=status.HTTP_204_NO_CONTENT)
def revoke_device_session(
    device_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    auth_session: AuthSession = Depends(current_session),
) -> None:
    target = db.get(AuthSession, device_id)
    if target is None or target.user_id != auth_session.user_id:
        raise HTTPException(status_code=404, detail="Device session not found")
    newly_revoked = target.revoked_at is None
    if newly_revoked:
        target.revoked_at = utc_now()
        append_cluster_event(
            db,
            settings,
            entity_type="session",
            entity_id=target.id,
            operation="revoke",
            payload=session_cluster_payload(target),
        )
        add_audit(
            db,
            settings,
            "session_revoked",
            actor_user_id=auth_session.user_id,
            entity_type="session",
            entity_id=target.id,
            request_id=getattr(request.state, "request_id", None),
            details={
                "device_name": target.device_name,
                "self_revocation": target.id == auth_session.id,
            },
        )
    disabled_subscription_ids = disable_session_push_subscriptions(
        db,
        target.id,
        settings,
        disabled_at=target.revoked_at,
    )
    if newly_revoked or disabled_subscription_ids:
        db.commit()
