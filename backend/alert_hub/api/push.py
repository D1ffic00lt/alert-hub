from __future__ import annotations

import base64
import binascii
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_user, get_db, get_envelope_cipher, get_settings
from alert_hub.application.auth import add_audit
from alert_hub.application.incidents import append_cluster_event
from alert_hub.application.notifications import push_subscription_payload
from alert_hub.infrastructure.db.base import new_id, utc_now
from alert_hub.infrastructure.db.models import PushSubscription, User
from alert_hub.infrastructure.encryption import EncryptionError, EnvelopeCipher
from alert_hub.infrastructure.url_safety import UnsafeURL, validate_webhook_url
from alert_hub.infrastructure.vapid import VapidConfigurationError, vapid_public_key
from alert_hub.security import constant_time_equal
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/push", tags=["push"])


class PushKeys(BaseModel):
    p256dh: str = Field(min_length=16, max_length=512)
    auth: str = Field(min_length=8, max_length=256)


class PushSubscriptionCreate(BaseModel):
    endpoint: str = Field(min_length=12, max_length=4_096)
    keys: PushKeys
    device_name: str = Field(default="Installed PWA", min_length=1, max_length=255)
    user_agent: str | None = Field(default=None, max_length=1_024)
    expirationTime: float | None = None


def _decode_key(value: str, name: str, minimum: int, maximum: int) -> None:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail=f"{name} must be base64url encoded") from exc
    if not minimum <= len(decoded) <= maximum:
        raise HTTPException(status_code=422, detail=f"{name} has an invalid decoded length")


def _context(subscription_id: str, field: str) -> str:
    return f"push_subscription:{subscription_id}:{field}"


def _decrypt_endpoint(subscription: PushSubscription, cipher: EnvelopeCipher) -> str | None:
    try:
        return cipher.decrypt(
            subscription.endpoint,
            context=_context(subscription.id, "endpoint"),
        ).decode()
    except (EncryptionError, UnicodeDecodeError):
        return None


def _response(subscription: PushSubscription) -> dict[str, Any]:
    return {
        "id": subscription.id,
        "device_name": subscription.device_name,
        "user_agent": subscription.user_agent,
        "created_at": subscription.created_at,
        "last_success_at": subscription.last_success_at,
        "enabled": subscription.disabled_at is None,
        "disabled_at": subscription.disabled_at,
    }


@router.get("/vapid-public-key")
def get_vapid_public_key(
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, str]:
    del user
    try:
        public_key = vapid_public_key(settings)
    except VapidConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"public_key": public_key, "vapid_public_key": public_key}


@router.get("/subscriptions")
def list_push_subscriptions(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> list[dict[str, Any]]:
    subscriptions = db.scalars(
        select(PushSubscription)
        .where(PushSubscription.user_id == user.id)
        .order_by(PushSubscription.created_at.desc())
    ).all()
    return [_response(subscription) for subscription in subscriptions]


@router.post("/subscriptions", status_code=201)
def create_push_subscription(
    payload: PushSubscriptionCreate,
    request: Request,
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    try:
        endpoint = validate_webhook_url(payload.endpoint, allow_http=False, allow_private=False)
    except UnsafeURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _decode_key(payload.keys.p256dh, "p256dh", 32, 128)
    _decode_key(payload.keys.auth, "auth", 8, 64)

    subscription = None
    candidates = db.scalars(
        select(PushSubscription).where(PushSubscription.user_id == user.id)
    ).all()
    for candidate in candidates:
        current_endpoint = _decrypt_endpoint(candidate, cipher)
        if current_endpoint is not None and constant_time_equal(current_endpoint, endpoint):
            subscription = candidate
            break
    created = subscription is None
    if subscription is None:
        subscription = PushSubscription(
            id=new_id(),
            user_id=user.id,
            device_name=payload.device_name.strip(),
            endpoint=b"",
            p256dh=b"",
            auth=b"",
            user_agent=payload.user_agent,
        )
        db.add(subscription)
    subscription.device_name = payload.device_name.strip()
    subscription.endpoint = cipher.encrypt(
        endpoint.encode(), context=_context(subscription.id, "endpoint")
    )
    subscription.p256dh = cipher.encrypt(
        payload.keys.p256dh.encode(), context=_context(subscription.id, "p256dh")
    )
    subscription.auth = cipher.encrypt(
        payload.keys.auth.encode(), context=_context(subscription.id, "auth")
    )
    subscription.user_agent = payload.user_agent
    subscription.disabled_at = None
    db.flush()
    append_cluster_event(
        db,
        settings,
        entity_type="push_subscription",
        entity_id=subscription.id,
        operation="upsert",
        payload=push_subscription_payload(subscription),
    )
    add_audit(
        db,
        settings,
        "push_subscription_created" if created else "push_subscription_updated",
        actor_user_id=user.id,
        entity_type="push_subscription",
        entity_id=subscription.id,
        request_id=getattr(request.state, "request_id", None),
        details={"device_name": subscription.device_name},
    )
    db.commit()
    return _response(subscription)


@router.delete("/subscriptions/{subscription_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_push_subscription(
    subscription_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> None:
    subscription = db.get(PushSubscription, subscription_id)
    if subscription is None or subscription.user_id != user.id:
        raise HTTPException(status_code=404, detail="Push subscription not found")
    if subscription.disabled_at is None:
        subscription.disabled_at = utc_now()
        append_cluster_event(
            db,
            settings,
            entity_type="push_subscription",
            entity_id=subscription.id,
            operation="tombstone",
            payload=push_subscription_payload(subscription),
        )
        add_audit(
            db,
            settings,
            "push_subscription_disabled",
            actor_user_id=user.id,
            entity_type="push_subscription",
            entity_id=subscription.id,
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
