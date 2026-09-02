from __future__ import annotations

import base64
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.infrastructure.db.models import (
    Delivery,
    Incident,
    IncidentEvent,
    Outbox,
    PushSubscription,
)

DeliveryOutcome = Literal["succeeded", "retryable", "permanent", "gone"]


@dataclass(frozen=True, slots=True)
class NotificationMessage:
    event_id: str
    event_type: str
    incident_id: str
    source_id: str
    title: str
    body: str
    severity: str
    status: str
    occurred_at: datetime
    app_name: str = "Alert Hub"
    labels: Mapping[str, Any] = field(default_factory=dict)
    annotations: Mapping[str, Any] = field(default_factory=dict)
    incident_url: str | None = None

    def provider_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "incident_id": self.incident_id,
            "source_id": self.source_id,
            "app_name": self.app_name,
            "title": self.title,
            "description": self.body,
            "severity": self.severity,
            "status": self.status,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "labels": dict(self.labels),
            "annotations": dict(self.annotations),
            "incident_url": self.incident_url,
        }


@dataclass(frozen=True, slots=True)
class DeliveryTarget:
    channel_id: str
    channel_kind: str
    config: Mapping[str, Any] = field(repr=False)
    subscription_id: str | None = None
    endpoint: str | None = field(default=None, repr=False)
    p256dh: str | None = field(default=None, repr=False)
    auth: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    outcome: DeliveryOutcome
    provider_status: str
    error_code: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.outcome == "succeeded"


class NotificationProvider(Protocol):
    async def send(
        self, message: NotificationMessage, target: DeliveryTarget
    ) -> DeliveryResult: ...


class ProviderRegistry:
    def __init__(self, providers: Mapping[str, NotificationProvider]) -> None:
        self._providers = dict(providers)

    def get(self, kind: str) -> NotificationProvider | None:
        return self._providers.get(kind)


def enqueue_notification_event(db: Session, event: IncidentEvent) -> Outbox | None:
    """Create exactly one durable local work item for a firing/resolved timeline event."""

    if event.event_type not in {"firing", "resolved"}:
        return None
    existing = db.get(Outbox, event.id)
    if existing is not None:
        return existing
    existing = db.scalar(
        select(Outbox).where(
            Outbox.payload_json["event_id"].as_string() == event.id,
        )
    )
    if existing is not None:
        return existing
    item = Outbox(
        id=event.id,
        topic="notification_event",
        payload_json={"event_id": event.id, "incident_id": event.incident_id},
        available_at=event.received_at,
    )
    db.add(item)
    return item


def deterministic_delivery_id(
    event_identity: str,
    channel_id: str,
    subscription_id: str | None,
) -> str:
    identity = f"alert_hub:delivery:{event_identity}:{channel_id}:{subscription_id or '-'}"
    return str(uuid5(NAMESPACE_URL, identity))


def retry_delay_seconds(attempt: int, base_seconds: float, cap_seconds: float) -> float:
    if attempt < 1:
        raise ValueError("attempt must be at least one")
    if base_seconds <= 0 or cap_seconds <= 0:
        raise ValueError("retry delays must be positive")
    return min(cap_seconds, base_seconds * (2.0 ** (attempt - 1)))


def message_from_event(
    event: IncidentEvent,
    incident: Incident,
    *,
    public_api_url: str | None = None,
    app_name: str = "Alert Hub",
) -> NotificationMessage:
    incident_url = (
        f"{public_api_url.rstrip('/')}/incidents/{incident.id}" if public_api_url else None
    )
    event_labels = event.payload_json.get("labels")
    event_annotations = event.payload_json.get("annotations")
    return NotificationMessage(
        event_id=event.id,
        event_type=event.event_type,
        incident_id=incident.id,
        source_id=incident.source_id,
        title=str(event.payload_json.get("title") or incident.title),
        body=str(event.payload_json.get("description") or incident.description),
        severity=str(event.payload_json.get("severity") or incident.severity),
        status=event.event_type,
        occurred_at=event.occurred_at,
        app_name=app_name,
        labels=event_labels if isinstance(event_labels, dict) else incident.labels_json,
        annotations=(
            event_annotations if isinstance(event_annotations, dict) else incident.annotations_json
        ),
        incident_url=incident_url,
    )


def delivery_receipt_payload(
    delivery: Delivery,
    *,
    source_event_key: str,
) -> dict[str, Any]:
    return {
        "delivery_id": delivery.id,
        "event_id": delivery.event_id,
        "source_event_key": source_event_key,
        "channel_id": delivery.channel_id,
        "subscription_id": delivery.subscription_id,
        "owner_node_id": delivery.owner_node_id,
        "attempt": delivery.attempt,
        "status": delivery.status,
        "provider_status": delivery.provider_status,
        "error_code": delivery.error_code,
        "created_at": delivery.created_at.isoformat(),
        "finished_at": delivery.finished_at.isoformat() if delivery.finished_at else None,
    }


def push_subscription_payload(subscription: PushSubscription) -> dict[str, Any]:
    """Return the encrypted, replication-safe representation of a subscription."""

    return {
        "user_id": subscription.user_id,
        "device_name": subscription.device_name,
        "endpoint": base64.b64encode(subscription.endpoint).decode(),
        "p256dh": base64.b64encode(subscription.p256dh).decode(),
        "auth": base64.b64encode(subscription.auth).decode(),
        "user_agent": subscription.user_agent,
        "created_at": subscription.created_at.isoformat(),
        "disabled_at": (subscription.disabled_at.isoformat() if subscription.disabled_at else None),
    }


def apply_delivery_receipt(db: Session, payload: Mapping[str, Any]) -> bool:
    """Project a replicated receipt without allowing late failures to regress success."""

    delivery_id = str(payload.get("delivery_id") or "")
    channel_id = str(payload.get("channel_id") or "")
    source_event_key = str(payload.get("source_event_key") or "")
    source_event_id = str(payload.get("event_id") or payload.get("source_event_id") or "")
    source_event = None
    if source_event_key:
        source_event = db.scalar(
            select(IncidentEvent).where(IncidentEvent.event_key == source_event_key)
        )
    if source_event is None and source_event_id:
        source_event = db.get(IncidentEvent, source_event_id)
    if not delivery_id or source_event is None or not channel_id:
        return False
    existing = db.get(Delivery, delivery_id)
    status = str(payload.get("status") or "pending")
    if existing is not None and existing.status == "succeeded" and status != "succeeded":
        return False
    if existing is None:
        from alert_hub.infrastructure.db.models import NotificationChannel

        if db.get(NotificationChannel, channel_id) is None:
            return False
        existing = Delivery(
            id=delivery_id,
            event_id=source_event.id,
            channel_id=channel_id,
            subscription_id=(
                str(payload["subscription_id"]) if payload.get("subscription_id") else None
            ),
            owner_node_id=str(payload.get("owner_node_id") or "unknown"),
            attempt=int(payload.get("attempt") or 0),
            status=status,
        )
        db.add(existing)
    else:
        existing.owner_node_id = str(payload.get("owner_node_id") or existing.owner_node_id)
        existing.attempt = max(existing.attempt, int(payload.get("attempt") or 0))
        existing.status = status
    existing.provider_status = _safe_status(payload.get("provider_status"))
    existing.error_code = _safe_status(payload.get("error_code"))
    if payload.get("finished_at"):
        with suppress(ValueError):
            existing.finished_at = datetime.fromisoformat(
                str(payload["finished_at"]).replace("Z", "+00:00")
            )
    _apply_delivery_timeline(db, payload, existing)
    # A dependency replay can project a receipt that is also present later in the
    # same sync page. Flush here so a second projection in this unit of work sees
    # the delivery and timeline rows instead of scheduling duplicate INSERTs.
    db.flush()
    return True


def _apply_delivery_timeline(
    db: Session,
    payload: Mapping[str, Any],
    delivery: Delivery,
) -> None:
    receipt_event_id = str(payload.get("receipt_event_id") or "")
    origin_node_id = str(payload.get("receipt_origin_node_id") or "")
    try:
        origin_seq = int(payload.get("receipt_origin_seq") or 0)
    except (TypeError, ValueError):
        return
    if not receipt_event_id or not origin_node_id or origin_seq < 1:
        return
    if db.get(IncidentEvent, receipt_event_id) is not None:
        return
    source_event = db.get(IncidentEvent, delivery.event_id)
    if source_event is None:
        return
    try:
        occurred_at = datetime.fromisoformat(
            str(payload.get("receipt_occurred_at") or payload.get("finished_at")).replace(
                "Z", "+00:00"
            )
        )
    except (TypeError, ValueError):
        occurred_at = source_event.received_at
    event_type = "delivery_succeeded" if delivery.status == "succeeded" else "delivery_failed"
    db.add(
        IncidentEvent(
            id=receipt_event_id,
            origin_node_id=origin_node_id[:128],
            origin_seq=origin_seq,
            event_key=str(
                payload.get("receipt_event_key")
                or f"delivery:{delivery.id}:{delivery.attempt}:{delivery.status}"
            )[:128],
            incident_id=source_event.incident_id,
            event_type=event_type,
            occurred_at=occurred_at,
            payload_json={
                "delivery_id": delivery.id,
                "channel_id": delivery.channel_id,
                "subscription_id": delivery.subscription_id,
                "owner_node_id": delivery.owner_node_id,
                "attempt": delivery.attempt,
                "status": delivery.status,
                "provider_status": delivery.provider_status,
                "error_code": delivery.error_code,
                "source_event_id": delivery.event_id,
            },
        )
    )


def _safe_status(value: object) -> str | None:
    if value is None:
        return None
    return str(value).replace("\r", " ").replace("\n", " ")[:255]
