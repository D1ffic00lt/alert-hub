from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_session, get_db, get_settings
from alert_hub.application.auth import add_audit, session_cluster_payload
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
        select(PushSubscription).where(
            PushSubscription.user_id == auth_session.user_id,
            PushSubscription.disabled_at.is_(None),
        )
    ).all()
    subscriptions_by_device = {item.device_name: item for item in subscriptions}
    return [
        {
            "id": item.id,
            "session_id": item.id,
            "device_name": item.device_name,
            "name": item.device_name,
            "current": item.id == auth_session.id,
            "is_current": item.id == auth_session.id,
            "push_enabled": item.device_name in subscriptions_by_device,
            "push_subscription_id": (
                subscriptions_by_device[item.device_name].id
                if item.device_name in subscriptions_by_device
                else None
            ),
            "user_agent": (
                subscriptions_by_device[item.device_name].user_agent
                if item.device_name in subscriptions_by_device
                else None
            ),
            "platform": (
                subscriptions_by_device[item.device_name].user_agent
                if item.device_name in subscriptions_by_device
                else "Browser session"
            ),
            "location": "Unknown location",
            "created_at": item.created_at,
            "last_used_at": item.last_used_at,
            "expires_at": item.expires_at,
            "absolute_expires_at": item.absolute_expires_at,
        }
        for item in sessions
    ]


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
    if target.revoked_at is None:
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
        db.commit()
