from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import admin_user, get_db, get_envelope_cipher, get_settings
from alert_hub.application.auth import add_audit
from alert_hub.application.incidents import append_cluster_event
from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
    ProviderRegistry,
    push_subscription_payload,
)
from alert_hub.infrastructure.db.base import new_id, utc_now
from alert_hub.infrastructure.db.models import (
    Delivery,
    NotificationChannel,
    NotificationRoute,
    PushSubscription,
    User,
)
from alert_hub.infrastructure.encryption import EncryptionError, EnvelopeCipher
from alert_hub.infrastructure.notifications import build_provider_registry
from alert_hub.infrastructure.notifications.secrets import (
    decrypt_channel_config,
    decrypt_push_subscription,
)
from alert_hub.infrastructure.notifications.smtp_templates import (
    SMTPTemplateError,
    normalize_smtp_template_config,
)
from alert_hub.infrastructure.url_safety import UnsafeURL, validate_headers, validate_webhook_url
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/channels", tags=["channels"])

ChannelKind = Literal["web_push", "telegram", "smtp", "generic_webhook"]
_SECRET_KEYS = {
    "api_key",
    "auth",
    "authorization",
    "bot_token",
    "credential",
    "credentials",
    "hmac_secret",
    "password",
    "private_key",
    "secret",
    "token",
}


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    kind: ChannelKind
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    eligible_regions: list[str] = Field(default_factory=list, max_length=100)
    eligible_node_ids: list[str] = Field(default_factory=list, max_length=100)


class ChannelPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    eligible_regions: list[str] | None = Field(default=None, max_length=100)
    eligible_node_ids: list[str] | None = Field(default=None, max_length=100)


def _redacted_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "***"
    hostname = parsed.hostname or ""
    if parsed.port:
        hostname = f"{hostname}:{parsed.port}"
    path = "/***" if parsed.path and parsed.path != "/" else "/"
    return urlunsplit((parsed.scheme, hostname, path, "", ""))


def _redact(value: Any, *, key: str = "") -> Any:
    lowered = key.lower()
    if lowered == "headers" and isinstance(value, dict):
        return {str(name): "***" for name in value}
    if lowered in _SECRET_KEYS or any(
        marker in lowered for marker in ("password", "secret", "token")
    ):
        return "***" if value is not None and value != "" else value
    if lowered == "url" and isinstance(value, str):
        return _redacted_url(value)
    if isinstance(value, dict):
        return {
            str(child_key): _redact(item, key=str(child_key)) for child_key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _normalize_config(kind: str, config: dict[str, Any], settings: Settings) -> dict[str, Any]:
    normalized = dict(config)
    if kind == "generic_webhook":
        if normalized.get("url"):
            try:
                normalized["url"] = validate_webhook_url(
                    str(normalized["url"]),
                    allow_http=settings.allow_http_webhooks,
                    allow_private=settings.allow_private_webhooks,
                )
                normalized["headers"] = validate_headers(normalized.get("headers"))
            except UnsafeURL as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif kind == "smtp":
        try:
            normalized = normalize_smtp_template_config(normalized)
        except SMTPTemplateError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if normalized.get("port") is not None:
            try:
                port = int(normalized["port"])
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="SMTP port must be an integer") from exc
            if not 1 <= port <= 65_535:
                raise HTTPException(status_code=422, detail="SMTP port is outside the valid range")
            normalized["port"] = port
        if normalized.get("port") is not None or "tls" in normalized:
            tls_mode = str(normalized.get("tls") or "starttls").lower()
            tls_mode = {"ssl": "implicit", "smtps": "implicit"}.get(tls_mode, tls_mode)
            if tls_mode not in {"starttls", "implicit"}:
                raise HTTPException(
                    status_code=422,
                    detail="SMTP TLS mode must be starttls or implicit",
                )
            normalized["tls"] = tls_mode
    return normalized


def _decrypt_config(channel: NotificationChannel, cipher: EnvelopeCipher) -> dict[str, Any]:
    return decrypt_channel_config(channel, cipher)


def _eligibility(regions: list[str], nodes: list[str]) -> dict[str, list[str]]:
    return {
        "regions": list(dict.fromkeys(item.strip() for item in regions if item.strip())),
        "node_ids": list(dict.fromkeys(item.strip() for item in nodes if item.strip())),
    }


def _delivery_stats(db: Session, channel_id: str) -> tuple[int, int, float | None]:
    since = utc_now() - timedelta(hours=24)
    total = int(
        db.scalar(
            select(func.count(Delivery.id)).where(
                Delivery.channel_id == channel_id,
                Delivery.created_at >= since,
            )
        )
        or 0
    )
    succeeded = int(
        db.scalar(
            select(func.count(Delivery.id)).where(
                Delivery.channel_id == channel_id,
                Delivery.created_at >= since,
                Delivery.status.in_(("succeeded", "success", "delivered")),
            )
        )
        or 0
    )
    return total, succeeded, round((succeeded / total) * 100, 1) if total else None


def _response(
    db: Session,
    channel: NotificationChannel,
    cipher: EnvelopeCipher,
) -> dict[str, Any]:
    config_available = True
    try:
        config = _decrypt_config(channel, cipher)
    except EncryptionError:
        config = {}
        config_available = False
    delivery_total, delivery_success, success_rate = _delivery_stats(db, channel.id)
    eligibility = channel.eligible_nodes_or_regions or {}
    regions = [str(item) for item in eligibility.get("regions", [])]
    nodes = [str(item) for item in eligibility.get("node_ids", [])]
    eligible_label = ", ".join([*regions, *nodes]) or "All nodes"
    route_names = [
        route.name
        for route in db.scalars(
            select(NotificationRoute)
            .where(NotificationRoute.enabled.is_(True))
            .order_by(NotificationRoute.priority, NotificationRoute.id)
        ).all()
        if channel.id in route.channel_ids
    ]
    if not channel.enabled:
        health = "paused"
    elif not config_available:
        health = "configuration_error"
    elif delivery_total == 0:
        health = "not_exercised"
    elif delivery_success == delivery_total:
        health = "healthy"
    else:
        health = "degraded"
    return {
        "id": channel.id,
        "name": channel.name,
        "kind": channel.kind,
        "enabled": channel.enabled,
        "health": health,
        "config": _redact(config),
        "configured_fields": sorted(config),
        "config_available": config_available,
        "eligible_regions": regions,
        "eligible_node_ids": nodes,
        "eligible": eligible_label,
        "route": ", ".join(route_names) if route_names else None,
        "route_names": route_names,
        "deliveries_24h": delivery_total,
        "delivered_24h": delivery_success,
        "delivery_success_24h": delivery_success,
        "success_rate": success_rate,
        "created_at": channel.created_at,
        "updated_at": channel.updated_at,
    }


def _channel_or_404(db: Session, channel_id: str) -> NotificationChannel:
    channel = db.get(NotificationChannel, channel_id)
    if channel is None or channel.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    return channel


def _replicated_payload(channel: NotificationChannel) -> dict[str, Any]:
    return {
        "name": channel.name,
        "kind": channel.kind,
        "enabled": channel.enabled,
        "encrypted_config": base64.b64encode(channel.encrypted_config).decode(),
        "eligible_nodes_or_regions": channel.eligible_nodes_or_regions,
        "created_at": channel.created_at.isoformat(),
        "updated_at": channel.updated_at.isoformat(),
        "deleted_at": channel.deleted_at.isoformat() if channel.deleted_at else None,
    }


@router.get("")
def list_channels(
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    user: User = Depends(admin_user),
) -> list[dict[str, Any]]:
    del user
    channels = db.scalars(
        select(NotificationChannel)
        .where(NotificationChannel.deleted_at.is_(None))
        .order_by(NotificationChannel.name, NotificationChannel.id)
    ).all()
    return [_response(db, channel, cipher) for channel in channels]


@router.post("", status_code=201)
def create_channel(
    payload: ChannelCreate,
    request: Request,
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    config = _normalize_config(payload.kind, payload.config, settings)
    channel_id = new_id()
    channel = NotificationChannel(
        id=channel_id,
        name=payload.name.strip(),
        kind=payload.kind,
        enabled=payload.enabled,
        encrypted_config=cipher.encrypt_json(config, context=f"channel:{channel_id}:config"),
        eligible_nodes_or_regions=_eligibility(payload.eligible_regions, payload.eligible_node_ids),
    )
    db.add(channel)
    db.flush()
    append_cluster_event(
        db,
        settings,
        entity_type="notification_channel",
        entity_id=channel.id,
        operation="upsert",
        payload=_replicated_payload(channel),
    )
    add_audit(
        db,
        settings,
        "channel_created",
        actor_user_id=user.id,
        entity_type="notification_channel",
        entity_id=channel.id,
        request_id=getattr(request.state, "request_id", None),
        details={"kind": channel.kind},
    )
    db.commit()
    return _response(db, channel, cipher)


def _merge_config(current: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    merged = dict(current)
    for key, value in changes.items():
        if value == "***" and key in current:
            continue
        if isinstance(value, dict) and isinstance(current.get(key), dict):
            merged[key] = _merge_config(current[key], value)
        else:
            merged[key] = value
    return merged


@router.patch("/{channel_id}")
def update_channel(
    channel_id: str,
    payload: ChannelPatch,
    request: Request,
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    channel = _channel_or_404(db, channel_id)
    changes = payload.model_dump(exclude_unset=True)
    if payload.name is not None:
        channel.name = payload.name.strip()
    if payload.enabled is not None:
        channel.enabled = payload.enabled
    if payload.config is not None:
        current = _decrypt_config(channel, cipher)
        config = _normalize_config(channel.kind, _merge_config(current, payload.config), settings)
        channel.encrypted_config = cipher.encrypt_json(
            config, context=f"channel:{channel.id}:config"
        )
    current_eligibility = channel.eligible_nodes_or_regions or {}
    if payload.eligible_regions is not None or payload.eligible_node_ids is not None:
        channel.eligible_nodes_or_regions = _eligibility(
            payload.eligible_regions
            if payload.eligible_regions is not None
            else list(current_eligibility.get("regions", [])),
            payload.eligible_node_ids
            if payload.eligible_node_ids is not None
            else list(current_eligibility.get("node_ids", [])),
        )
    channel.updated_at = utc_now()
    append_cluster_event(
        db,
        settings,
        entity_type="notification_channel",
        entity_id=channel.id,
        operation="upsert",
        payload=_replicated_payload(channel),
    )
    add_audit(
        db,
        settings,
        "channel_updated",
        actor_user_id=user.id,
        entity_type="notification_channel",
        entity_id=channel.id,
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changes)},
    )
    db.commit()
    return _response(db, channel, cipher)


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(
    channel_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> None:
    channel = _channel_or_404(db, channel_id)
    channel.enabled = False
    channel.deleted_at = utc_now()
    channel.updated_at = channel.deleted_at
    append_cluster_event(
        db,
        settings,
        entity_type="notification_channel",
        entity_id=channel.id,
        operation="tombstone",
        payload=_replicated_payload(channel),
    )
    add_audit(
        db,
        settings,
        "channel_deleted",
        actor_user_id=user.id,
        entity_type="notification_channel",
        entity_id=channel.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()


def _missing_fields(kind: str, config: dict[str, Any]) -> list[str]:
    required = {
        "web_push": [],
        "telegram": ["bot_token", "chat_id"],
        "smtp": ["host", "port", "from", "to"],
        "generic_webhook": ["url"],
    }[kind]
    return [
        field
        for field in required
        if config.get(field) is None or config.get(field) == "" or config.get(field) == []
    ]


@router.post("/{channel_id}/test")
async def test_channel(
    channel_id: str,
    request: Request,
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    channel = _channel_or_404(db, channel_id)
    config = _decrypt_config(channel, cipher)
    missing = _missing_fields(channel.kind, config)
    active_subscriptions = 0
    if channel.kind == "web_push":
        active_subscriptions = int(
            db.scalar(
                select(func.count(PushSubscription.id)).where(
                    PushSubscription.disabled_at.is_(None)
                )
            )
            or 0
        )
        if active_subscriptions == 0:
            missing.append("active_push_subscription")
    add_audit(
        db,
        settings,
        "channel_test_requested",
        actor_user_id=user.id,
        entity_type="notification_channel",
        entity_id=channel.id,
        request_id=getattr(request.state, "request_id", None),
        details={"kind": channel.kind, "configured": not missing},
    )
    db.commit()
    if missing:
        add_audit(
            db,
            settings,
            "channel_test_rejected",
            actor_user_id=user.id,
            entity_type="notification_channel",
            entity_id=channel.id,
            request_id=getattr(request.state, "request_id", None),
            details={"kind": channel.kind, "reason": "not_configured"},
        )
        db.commit()
        return {
            "ok": False,
            "attempted": False,
            "status": "not_configured",
            "missing_fields": missing,
            "detail": "Channel configuration is incomplete; no provider request was made",
        }

    registry: ProviderRegistry = getattr(
        request.app.state,
        "notification_providers",
        None,
    ) or build_provider_registry(settings)
    provider = registry.get(channel.kind)
    message = NotificationMessage(
        event_id=new_id(),
        event_type="firing",
        incident_id="channel-test",
        source_id="channel-test",
        title=f"{settings.app_name} test notification",
        body=f"Test delivery from node {settings.node_name}.",
        severity="info",
        status="open",
        occurred_at=utc_now(),
        app_name=settings.app_name,
        labels={"test": "true", "node_id": settings.node_id},
        annotations={},
        incident_url=settings.public_api_url,
    )
    subscriptions: list[PushSubscription | None]
    if channel.kind == "web_push":
        subscriptions = list(
            db.scalars(
                select(PushSubscription)
                .where(PushSubscription.disabled_at.is_(None))
                .order_by(PushSubscription.id)
            ).all()
        )
    else:
        subscriptions = [None]

    outcomes: list[dict[str, Any]] = []
    gone_subscriptions: list[PushSubscription] = []
    for subscription in subscriptions:
        if provider is None:
            result = DeliveryResult(
                "permanent",
                "unsupported_provider",
                "unsupported_provider",
            )
        else:
            endpoint = p256dh = auth = None
            if subscription is not None:
                try:
                    endpoint, p256dh, auth = decrypt_push_subscription(subscription, cipher)
                except EncryptionError:
                    result = DeliveryResult(
                        "permanent",
                        "configuration_error",
                        "decrypt_failed",
                    )
                else:
                    target = DeliveryTarget(
                        channel_id=channel.id,
                        channel_kind=channel.kind,
                        config=config,
                        subscription_id=subscription.id,
                        endpoint=endpoint,
                        p256dh=p256dh,
                        auth=auth,
                    )
                    try:
                        result = await provider.send(message, target)
                    except Exception:
                        result = DeliveryResult(
                            "retryable",
                            "transport_error",
                            "provider_unavailable",
                        )
            else:
                target = DeliveryTarget(
                    channel_id=channel.id,
                    channel_kind=channel.kind,
                    config=config,
                )
                try:
                    result = await provider.send(message, target)
                except Exception:
                    result = DeliveryResult(
                        "retryable",
                        "transport_error",
                        "provider_unavailable",
                    )
        if result.outcome == "gone" and subscription is not None:
            subscription.disabled_at = utc_now()
            gone_subscriptions.append(subscription)
        outcomes.append(
            {
                "subscription_id": subscription.id if subscription is not None else None,
                "outcome": result.outcome,
                "provider_status": result.provider_status,
                "error_code": result.error_code,
            }
        )

    for subscription in gone_subscriptions:
        append_cluster_event(
            db,
            settings,
            entity_type="push_subscription",
            entity_id=subscription.id,
            operation="tombstone",
            payload=push_subscription_payload(subscription),
            occurred_at=subscription.disabled_at,
        )
    succeeded = sum(item["outcome"] == "succeeded" for item in outcomes)
    overall = (
        "succeeded"
        if succeeded == len(outcomes)
        else ("partial_failure" if succeeded else str(outcomes[0]["outcome"]))
    )
    add_audit(
        db,
        settings,
        "channel_test_completed",
        actor_user_id=user.id,
        entity_type="notification_channel",
        entity_id=channel.id,
        request_id=getattr(request.state, "request_id", None),
        details={
            "kind": channel.kind,
            "status": overall,
            "attempted": len(outcomes),
            "succeeded": succeeded,
        },
    )
    db.commit()
    return {
        "ok": succeeded == len(outcomes),
        "attempted": True,
        "status": overall,
        "missing_fields": [],
        "outcomes": outcomes,
        "detail": f"{succeeded} of {len(outcomes)} test deliveries succeeded",
    }
