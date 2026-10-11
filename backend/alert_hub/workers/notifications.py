from __future__ import annotations

import asyncio
import logging
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from alert_hub.application.auth import (
    disable_push_subscription,
    disable_session_push_subscriptions,
    eligible_push_subscriptions,
    push_subscription_session_state,
    push_subscription_state_requires_tombstone,
)
from alert_hub.application.incidents import append_cluster_event
from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
    ProviderRegistry,
    apply_delivery_receipt,
    delivery_rank,
    delivery_receipt_payload,
    deterministic_delivery_id,
    message_from_event,
    notification_route_rules,
    push_subscription_payload,
    retry_delay_seconds,
    should_deliver_notification,
    update_notification_backlog_metrics,
)
from alert_hub.domain.routing import select_channel_ids
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    Delivery,
    Incident,
    IncidentEvent,
    NotificationChannel,
    Outbox,
    PushSubscription,
)
from alert_hub.infrastructure.encryption import EncryptionError, EnvelopeCipher
from alert_hub.infrastructure.notifications.registry import build_provider_registry
from alert_hub.infrastructure.notifications.secrets import (
    decrypt_channel_config,
    decrypt_push_subscription,
)
from alert_hub.metrics import (
    DELIVERY_FAILURES,
    DELIVERY_TOTAL,
    NOTIFICATION_WORKER_ERRORS,
    NOTIFICATION_WORKER_PROGRESS,
    NOTIFICATION_WORKER_UP,
)
from alert_hub.settings import Settings

logger = logging.getLogger("alert_hub.notifications")


@dataclass(slots=True)
class NotificationWorkerStatus:
    enabled: bool
    running: bool = False
    last_progress_at: float = 0.0
    last_error_type: str | None = None
    failures: int = 0

    def progress(self) -> None:
        self.last_progress_at = utc_now().timestamp()
        self.last_error_type = None
        NOTIFICATION_WORKER_PROGRESS.set(self.last_progress_at)

    def snapshot(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "running": self.running,
            "last_progress_timestamp": self.last_progress_at,
            "last_error_type": self.last_error_type,
            "failures": self.failures,
        }


def _log_worker_failure(exc: Exception, *, stage: str, item_id: str | None = None) -> None:
    frames = traceback.extract_tb(exc.__traceback__)
    frame = frames[-1] if frames else None
    # SQLAlchemy exception text can contain SQL bind values. Keep type and final
    # frame without logging provider credentials, statements, or parameters.
    logger.error(
        "notification_worker_failed",
        extra={
            "event": "notification_worker_failed",
            "scope": stage,
            "item_id": item_id,
            "exception_type": type(exc).__name__,
            "exception_frame": (
                f"{frame.filename}:{frame.lineno}:{frame.name}" if frame else "unavailable"
            ),
        },
    )
    NOTIFICATION_WORKER_ERRORS.labels(stage=stage).inc()


@dataclass(frozen=True, slots=True)
class _TargetDescriptor:
    channel_id: str
    subscription_id: str | None = None


@dataclass(frozen=True, slots=True)
class _TargetProgress:
    terminal: bool
    available_at: datetime | None = None
    error_code: str | None = None


class NotificationOutboxProcessor:
    """Restart-safe notification dispatcher with short database transactions."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: Settings,
        cipher: EnvelopeCipher | None,
        providers: ProviderRegistry | None = None,
        *,
        now: Callable[[], datetime] = utc_now,
        status: NotificationWorkerStatus | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._cipher = cipher
        self._providers = providers or build_provider_registry(settings)
        self._now = now
        self._status = status

    async def run_once(self) -> int:
        item_ids = self._claim_batch()
        for item_id in item_ids:
            try:
                await self._process_item(item_id)
            except Exception as exc:
                _log_worker_failure(exc, stage="item", item_id=item_id)
                self._release_item(
                    item_id,
                    available_at=self._now()
                    + timedelta(seconds=self._settings.notification_retry_base_seconds),
                    error_code="worker_error",
                )
            if self._status is not None:
                self._status.progress()
        self._update_pending_metric()
        return len(item_ids)

    def _claim_batch(self) -> list[str]:
        now = self._now()
        stale_before = now - timedelta(seconds=self._settings.notification_lock_seconds)
        with self._session_factory.begin() as db:
            items = db.scalars(
                select(Outbox)
                .where(
                    Outbox.topic == "notification_event",
                    Outbox.completed_at.is_(None),
                    Outbox.available_at <= now,
                    or_(Outbox.locked_at.is_(None), Outbox.locked_at < stale_before),
                )
                .order_by(Outbox.available_at, Outbox.id)
                .limit(self._settings.notification_batch_size)
            ).all()
            for item in items:
                item.locked_at = now
                item.attempt += 1
            return [item.id for item in items]

    async def _process_item(self, item_id: str) -> None:
        prepared = self._prepare_targets(item_id)
        if prepared is None:
            return
        event_id, targets = prepared
        if not targets:
            self._complete_item(item_id)
            return

        progress: list[_TargetProgress] = []
        for descriptor in targets:
            progress.append(await self._process_target(event_id, descriptor))
            if self._status is not None:
                self._status.progress()
        pending = [item for item in progress if not item.terminal]
        if not pending:
            errors = sorted({item.error_code for item in progress if item.error_code})
            self._complete_item(item_id, error_code=",".join(errors) or None)
            return
        next_attempts = [item.available_at for item in pending if item.available_at is not None]
        available_at = min(next_attempts) if next_attempts else self._now()
        errors = sorted({item.error_code for item in pending if item.error_code})
        self._release_item(
            item_id,
            available_at=available_at,
            error_code=",".join(errors) or None,
        )

    def _prepare_targets(self, item_id: str) -> tuple[str, list[_TargetDescriptor]] | None:
        with self._session_factory() as db:
            item = db.get(Outbox, item_id)
            if item is None or item.completed_at is not None:
                return None
            event_id = str(item.payload_json.get("event_id") or "")
            event = db.get(IncidentEvent, event_id)
            if event is None:
                self._complete_item(item_id, error_code="event_unavailable")
                return None
            if not should_deliver_notification(event):
                return event.id, []
            incident = db.get(Incident, event.incident_id)
            if incident is None:
                self._complete_item(item_id, error_code="incident_unavailable")
                return None

            routes = notification_route_rules(db)
            selected_ids = select_channel_ids(
                routes,
                source_id=incident.source_id,
                severity=incident.severity,
                labels=incident.labels_json,
            )
            if not selected_ids:
                return event.id, []
            channels = db.scalars(
                select(NotificationChannel).where(
                    NotificationChannel.id.in_(selected_ids),
                    NotificationChannel.enabled.is_(True),
                    NotificationChannel.deleted_at.is_(None),
                )
            ).all()
            channels_by_id = {channel.id: channel for channel in channels}
            active_subscriptions = eligible_push_subscriptions(
                db,
                self._settings,
                now=self._now(),
            )
            db.commit()
            targets: list[_TargetDescriptor] = []
            for channel_id in selected_ids:
                channel = channels_by_id.get(channel_id)
                if channel is None:
                    continue
                if channel.kind == "web_push":
                    targets.extend(
                        _TargetDescriptor(channel.id, subscription.id)
                        for subscription in active_subscriptions
                    )
                else:
                    targets.append(_TargetDescriptor(channel.id))
            return event.id, targets

    async def _process_target(
        self, event_id: str, descriptor: _TargetDescriptor
    ) -> _TargetProgress:
        now = self._now()
        no_eligible_node = False
        with self._session_factory() as db:
            event = db.get(IncidentEvent, event_id)
            channel = db.get(NotificationChannel, descriptor.channel_id)
            if event is None or channel is None or not channel.enabled:
                return _TargetProgress(True, error_code="target_unavailable")
            delivery_id = deterministic_delivery_id(
                event.event_key,
                descriptor.channel_id,
                descriptor.subscription_id,
            )
            existing = db.get(Delivery, delivery_id)
            if existing is not None and existing.status in {
                "succeeded",
                "failed",
                "gone",
            }:
                return _TargetProgress(True, error_code=existing.error_code)

            rank, has_eligible_node = self._delivery_rank(db, event.event_key, channel)
            if not has_eligible_node:
                no_eligible_node = True
            elif rank is None:
                return _TargetProgress(True)
            elif rank > 0:
                # A local timeout cannot fence the current owner. Promoting every
                # rendezvous rank after a delay lets all partitions call the
                # provider for the same deterministic delivery. Keep the durable
                # work queued until the rank-zero receipt arrives instead.
                return _TargetProgress(
                    False,
                    now
                    + timedelta(
                        seconds=max(
                            self._settings.notification_failover_base_seconds,
                            self._settings.notification_poll_seconds,
                        )
                    ),
                    "awaiting_owner_receipt",
                )

        if no_eligible_node:
            return self._defer_no_eligible_node(
                delivery_id,
                event_id,
                descriptor,
            )

        obsolete, historical = self._backlog_policy(event_id)
        if obsolete is not None:
            return self._skip_historical_delivery(delivery_id, event_id, descriptor, obsolete)
        if historical:
            # A still-active old incident remains notifiable. Pace its individual
            # provider calls so restart recovery cannot burst through the backlog.
            await asyncio.sleep(self._settings.notification_backlog_spacing_seconds)
            obsolete, _ = self._backlog_policy(event_id)
            if obsolete is not None:
                return self._skip_historical_delivery(delivery_id, event_id, descriptor, obsolete)

        delivery = self._begin_delivery(delivery_id, event_id, descriptor)
        if delivery is None:
            return _TargetProgress(True, error_code="target_unavailable")
        if delivery.status in {"succeeded", "failed", "gone"}:
            return _TargetProgress(True, error_code=delivery.error_code)
        attempt = delivery.attempt
        try:
            message, target = self._provider_input(event_id, descriptor)
        except EncryptionError:
            result = DeliveryResult("permanent", "configuration_error", "decrypt_failed")
        else:
            provider = self._providers.get(target.channel_kind)
            if provider is None:
                result = DeliveryResult(
                    "permanent",
                    "unsupported_provider",
                    "unsupported_provider",
                )
            else:
                try:
                    result = await provider.send(message, target)
                except Exception:
                    result = DeliveryResult(
                        "retryable",
                        "transport_error",
                        "provider_unavailable",
                    )
        return self._record_result(delivery_id, descriptor, result, attempt)

    def _backlog_policy(self, event_id: str) -> tuple[str | None, bool]:
        with self._session_factory() as db:
            event = db.get(IncidentEvent, event_id)
            if event is None:
                return None, False
            historical = (self._now() - event.occurred_at).total_seconds() > (
                self._settings.notification_backlog_age_seconds
            )
            if not historical:
                return None, False
            latest = db.scalar(
                select(IncidentEvent)
                .where(
                    IncidentEvent.incident_id == event.incident_id,
                    IncidentEvent.event_type.in_(["firing", "resolved"]),
                )
                .order_by(IncidentEvent.occurred_at.desc(), IncidentEvent.event_key.desc())
                .limit(1)
            )
            if latest is not None and latest.id != event.id:
                return "backlog_superseded", True
            if event.event_type == "resolved":
                return "backlog_expired_recovery", True
            return None, True

    def _skip_historical_delivery(
        self, delivery_id: str, event_id: str, descriptor: _TargetDescriptor, reason: str
    ) -> _TargetProgress:
        with self._session_factory.begin() as db:
            delivery = db.get(Delivery, delivery_id)
            if delivery is not None and delivery.status in {"succeeded", "failed", "gone"}:
                return _TargetProgress(True, error_code=delivery.error_code)
            if delivery is None:
                delivery = Delivery(
                    id=delivery_id,
                    event_id=event_id,
                    channel_id=descriptor.channel_id,
                    subscription_id=descriptor.subscription_id,
                    owner_node_id=self._settings.node_id,
                    attempt=0,
                    status="failed",
                )
                db.add(delivery)
            delivery.status = "failed"
            delivery.provider_status = "policy_skipped"
            delivery.error_code = reason
            delivery.finished_at = self._now()
            db.flush()
            self._append_receipt(db, delivery)
        return _TargetProgress(True, error_code=reason)

    def _delivery_rank(
        self,
        db: Session,
        event_identity: str,
        channel: NotificationChannel,
    ) -> tuple[int | None, bool]:
        return delivery_rank(db, self._settings, event_identity, channel)

    def _defer_no_eligible_node(
        self,
        delivery_id: str,
        event_id: str,
        descriptor: _TargetDescriptor,
    ) -> _TargetProgress:
        now = self._now()
        with self._session_factory.begin() as db:
            delivery = db.get(Delivery, delivery_id)
            if delivery is None:
                delivery = Delivery(
                    id=delivery_id,
                    event_id=event_id,
                    channel_id=descriptor.channel_id,
                    subscription_id=descriptor.subscription_id,
                    owner_node_id="unassigned",
                    attempt=0,
                    status="retrying",
                    provider_status="eligibility_wait",
                    error_code="no_eligible_node",
                    finished_at=now,
                )
                db.add(delivery)
                db.flush()
                self._append_receipt(db, delivery)
            elif delivery.status == "succeeded":
                return _TargetProgress(True)
            else:
                delivery.owner_node_id = "unassigned"
                delivery.status = "retrying"
                delivery.provider_status = "eligibility_wait"
                delivery.error_code = "no_eligible_node"
                delivery.finished_at = now
        return _TargetProgress(
            False,
            now + timedelta(seconds=self._settings.notification_retry_max_seconds),
            "no_eligible_node",
        )

    def _begin_delivery(
        self,
        delivery_id: str,
        event_id: str,
        descriptor: _TargetDescriptor,
    ) -> Delivery | None:
        with self._session_factory.begin() as db:
            channel = db.get(NotificationChannel, descriptor.channel_id)
            event = db.get(IncidentEvent, event_id)
            if channel is None or event is None:
                return None
            delivery = db.get(Delivery, delivery_id)
            if delivery is None:
                delivery = Delivery(
                    id=delivery_id,
                    event_id=event_id,
                    channel_id=descriptor.channel_id,
                    subscription_id=descriptor.subscription_id,
                    owner_node_id=self._settings.node_id,
                    attempt=0,
                    status="pending",
                )
                db.add(delivery)
            if delivery.status in {"succeeded", "failed", "gone"}:
                return delivery
            delivery.owner_node_id = self._settings.node_id
            delivery.attempt += 1
            delivery.status = "sending"
            delivery.provider_status = None
            delivery.error_code = None
            delivery.finished_at = None
            db.flush()
            self._append_receipt(db, delivery, occurred_at=self._now())
            db.expunge(delivery)
            return delivery

    def _provider_input(
        self,
        event_id: str,
        descriptor: _TargetDescriptor,
    ) -> tuple[NotificationMessage, DeliveryTarget]:
        if self._cipher is None:
            raise EncryptionError("notification secret storage is unavailable")
        with self._session_factory() as db:
            event = db.get(IncidentEvent, event_id)
            channel = db.get(NotificationChannel, descriptor.channel_id)
            if event is None or channel is None:
                raise EncryptionError("notification target disappeared")
            incident = db.get(Incident, event.incident_id)
            if incident is None:
                raise EncryptionError("notification incident disappeared")
            config = decrypt_channel_config(channel, self._cipher)
            endpoint = p256dh = auth = None
            if descriptor.subscription_id is not None:
                subscription = db.get(PushSubscription, descriptor.subscription_id)
                if subscription is None or subscription.disabled_at is not None:
                    raise EncryptionError("push subscription is unavailable")
                observed_at = self._now()
                session_state = push_subscription_session_state(
                    db,
                    subscription,
                    now=observed_at,
                )
                if session_state != "active":
                    if push_subscription_state_requires_tombstone(session_state):
                        if subscription.session_id is not None:
                            disable_session_push_subscriptions(
                                db,
                                subscription.session_id,
                                self._settings,
                                disabled_at=observed_at,
                            )
                        else:
                            disable_push_subscription(
                                db,
                                subscription,
                                self._settings,
                                disabled_at=observed_at,
                            )
                        db.commit()
                    raise EncryptionError("push subscription owner or session is unavailable")
                endpoint, p256dh, auth = decrypt_push_subscription(
                    subscription,
                    self._cipher,
                )
            message = message_from_event(
                event,
                incident,
                public_api_url=self._settings.public_ui_url or self._settings.public_api_url,
                app_name=self._settings.app_name,
            )
            target = DeliveryTarget(
                channel_id=channel.id,
                channel_kind=channel.kind,
                config=config,
                subscription_id=descriptor.subscription_id,
                endpoint=endpoint,
                p256dh=p256dh,
                auth=auth,
            )
            return message, target

    def _record_result(
        self,
        delivery_id: str,
        descriptor: _TargetDescriptor,
        result: DeliveryResult,
        attempt: int,
    ) -> _TargetProgress:
        now = self._now()
        retryable = result.outcome == "retryable" and (
            attempt < self._settings.notification_max_attempts
        )
        with self._session_factory.begin() as db:
            delivery = db.get(Delivery, delivery_id)
            if delivery is None:
                return _TargetProgress(True, error_code="delivery_unavailable")
            delivery.provider_status = _safe_provider_value(result.provider_status)
            delivery.error_code = _safe_provider_value(result.error_code)
            delivery.finished_at = now
            if result.outcome == "succeeded":
                delivery.status = "succeeded"
            elif result.outcome == "gone":
                delivery.status = "gone"
                if descriptor.subscription_id is not None:
                    subscription = db.get(PushSubscription, descriptor.subscription_id)
                    if subscription is not None and subscription.disabled_at is None:
                        subscription.disabled_at = now
                        append_cluster_event(
                            db,
                            self._settings,
                            entity_type="push_subscription",
                            entity_id=subscription.id,
                            operation="tombstone",
                            payload=push_subscription_payload(subscription),
                            occurred_at=now,
                        )
            elif retryable:
                delivery.status = "retrying"
            else:
                delivery.status = "failed"
                if result.outcome == "retryable":
                    delivery.error_code = "max_attempts"
            self._append_receipt(db, delivery)

        DELIVERY_TOTAL.labels(
            channel_kind=self._channel_kind(descriptor.channel_id),
            status=delivery.status,
        ).inc()
        if delivery.status in {"failed", "gone"}:
            DELIVERY_FAILURES.labels(channel_kind=self._channel_kind(descriptor.channel_id)).inc()
        if not retryable:
            return _TargetProgress(True, error_code=delivery.error_code)
        delay = retry_delay_seconds(
            attempt,
            self._settings.notification_retry_base_seconds,
            self._settings.notification_retry_max_seconds,
        )
        return _TargetProgress(
            False,
            now + timedelta(seconds=delay),
            delivery.error_code,
        )

    def _append_receipt(
        self,
        db: Session,
        delivery: Delivery,
        *,
        occurred_at: datetime | None = None,
    ) -> None:
        receipt_id = str(
            uuid5(
                NAMESPACE_URL,
                (
                    "alert-hub:receipt:"
                    f"{delivery.id}:{delivery.owner_node_id}:"
                    f"{delivery.attempt}:{delivery.status}"
                ),
            )
        )
        if db.get(ClusterEvent, receipt_id) is not None:
            return
        source_event = db.get(IncidentEvent, delivery.event_id)
        if source_event is None:
            return
        payload = delivery_receipt_payload(
            delivery,
            source_event_key=source_event.event_key,
        )
        operation = {
            "sending": "delivery_attempted",
            "succeeded": "delivery_succeeded",
        }.get(delivery.status, "delivery_failed")
        cluster_event = append_cluster_event(
            db,
            self._settings,
            entity_type="delivery_receipt",
            entity_id=delivery.id,
            operation=operation,
            payload=payload,
            occurred_at=occurred_at or delivery.finished_at,
            event_id=receipt_id,
        )
        replicated_payload = {
            **payload,
            "receipt_event_id": cluster_event.event_id,
            "receipt_origin_node_id": cluster_event.origin_node_id,
            "receipt_origin_seq": cluster_event.origin_seq,
            "receipt_occurred_at": cluster_event.occurred_at.isoformat(),
            "receipt_event_key": (
                f"delivery:{delivery.id}:{delivery.owner_node_id}:"
                f"{delivery.attempt}:{delivery.status}"
            ),
        }
        # append_cluster_event flushes its initial payload. Assign a fresh mapping
        # so SQLAlchemy persists the receipt metadata added after that flush.
        cluster_event.payload_json = replicated_payload
        apply_delivery_receipt(db, replicated_payload)

    def _channel_kind(self, channel_id: str) -> str:
        with self._session_factory() as db:
            channel = db.get(NotificationChannel, channel_id)
            return channel.kind if channel is not None else "unknown"

    def _complete_item(self, item_id: str, *, error_code: str | None = None) -> None:
        with self._session_factory.begin() as db:
            item = db.get(Outbox, item_id)
            if item is None:
                return
            item.completed_at = self._now()
            item.locked_at = None
            item.last_error = error_code

    def _release_item(
        self,
        item_id: str,
        *,
        available_at: datetime,
        error_code: str | None,
    ) -> None:
        with self._session_factory.begin() as db:
            item = db.get(Outbox, item_id)
            if item is None or item.completed_at is not None:
                return
            item.available_at = available_at
            item.locked_at = None
            item.last_error = error_code

    def _update_pending_metric(self) -> None:
        with self._session_factory() as db:
            update_notification_backlog_metrics(db, self._settings)


def _safe_provider_value(value: str | None) -> str | None:
    if value is None:
        return None
    return value.replace("\r", " ").replace("\n", " ")[:255]


async def notification_worker_loop(
    session_factory: sessionmaker[Session],
    settings: Settings,
    cipher: EnvelopeCipher | None,
    providers: ProviderRegistry | None = None,
    *,
    status: NotificationWorkerStatus | None = None,
) -> None:
    """Run the durable notification processor until its task is cancelled."""

    status = status or NotificationWorkerStatus(enabled=True)
    processor = NotificationOutboxProcessor(
        session_factory,
        settings,
        cipher,
        providers,
        status=status,
    )
    failures = 0
    status.running = True
    NOTIFICATION_WORKER_UP.set(1)
    try:
        while True:
            try:
                processed = await processor.run_once()
            except Exception as exc:
                failures += 1
                status.failures += 1
                status.last_error_type = type(exc).__name__
                _log_worker_failure(exc, stage="iteration")
                await asyncio.sleep(
                    retry_delay_seconds(
                        min(failures, 10),
                        settings.notification_retry_base_seconds,
                        min(30.0, settings.notification_retry_max_seconds),
                    )
                )
            else:
                failures = 0
                status.progress()
                # Always yield, including a permanently busy queue, for clean
                # cancellation and independent HTTP/peer/heartbeat processing.
                await asyncio.sleep(settings.notification_poll_seconds if processed == 0 else 0)
    finally:
        status.running = False
        NOTIFICATION_WORKER_UP.set(0)


async def notification_worker_supervisor(
    session_factory: sessionmaker[Session],
    settings: Settings,
    cipher: EnvelopeCipher | None,
    providers: ProviderRegistry | None = None,
    *,
    status: NotificationWorkerStatus,
) -> None:
    """Restart unexpected task exits without an unbounded tight restart loop."""
    failures = 0
    while True:
        try:
            await notification_worker_loop(
                session_factory, settings, cipher, providers, status=status
            )
            raise RuntimeError("notification worker exited unexpectedly")
        except Exception as exc:
            failures += 1
            status.running = False
            NOTIFICATION_WORKER_UP.set(0)
            status.failures += 1
            status.last_error_type = type(exc).__name__
            _log_worker_failure(exc, stage="supervisor")
            await asyncio.sleep(
                retry_delay_seconds(
                    min(failures, 10),
                    settings.notification_retry_base_seconds,
                    min(30.0, settings.notification_retry_max_seconds),
                )
            )
