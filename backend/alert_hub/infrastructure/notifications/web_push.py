from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pywebpush import WebPushException, webpush  # type: ignore[import-untyped]

from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
)


@dataclass(frozen=True, slots=True)
class WebPushResponse:
    status_code: int


class WebPushTransportError(Exception):
    pass


class WebPushTransportTimeout(Exception):
    pass


class WebPushTransport(Protocol):
    async def send(
        self,
        subscription: dict[str, object],
        payload: str,
        *,
        private_key_path: Path,
        subject: str,
        ttl_seconds: int,
        timeout_seconds: float,
    ) -> WebPushResponse: ...


class PyWebPushTransport:
    async def send(
        self,
        subscription: dict[str, object],
        payload: str,
        *,
        private_key_path: Path,
        subject: str,
        ttl_seconds: int,
        timeout_seconds: float,
    ) -> WebPushResponse:
        return await asyncio.to_thread(
            self._send_sync,
            subscription,
            payload,
            private_key_path,
            subject,
            ttl_seconds,
            timeout_seconds,
        )

    @staticmethod
    def _send_sync(
        subscription: dict[str, object],
        payload: str,
        private_key_path: Path,
        subject: str,
        ttl_seconds: int,
        timeout_seconds: float,
    ) -> WebPushResponse:
        try:
            response = webpush(
                subscription_info=subscription,
                data=payload,
                vapid_private_key=str(private_key_path),
                vapid_claims={"sub": subject},
                ttl=ttl_seconds,
                timeout=timeout_seconds,
            )
        except WebPushException as exc:
            status_code = exc.response.status_code if exc.response is not None else 0
            if status_code:
                return WebPushResponse(status_code=status_code)
            raise WebPushTransportError from exc
        except TimeoutError as exc:
            raise WebPushTransportTimeout from exc
        except OSError as exc:
            raise WebPushTransportError from exc
        return WebPushResponse(status_code=int(getattr(response, "status_code", 201)))


class WebPushProvider:
    def __init__(
        self,
        transport: WebPushTransport,
        *,
        private_key_path: Path | None,
        subject: str,
        ttl_seconds: int,
        timeout_seconds: float,
    ) -> None:
        self._transport = transport
        self._private_key_path = private_key_path
        self._subject = subject
        self._ttl_seconds = ttl_seconds
        self._timeout_seconds = timeout_seconds

    async def send(self, message: NotificationMessage, target: DeliveryTarget) -> DeliveryResult:
        if self._private_key_path is None:
            return DeliveryResult("permanent", "not_configured", "missing_vapid_key")
        if not target.endpoint or not target.p256dh or not target.auth:
            return DeliveryResult("permanent", "not_configured", "missing_subscription")
        state = "RESOLVED" if message.event_type == "resolved" else "FIRING"
        app_name = message.app_name.replace("\r", " ").replace("\n", " ").strip()
        detail = message.body or message.title
        body = message.title if detail == message.title else f"{message.title} — {detail}"
        payload = json.dumps(
            {
                "title": f"{app_name} · {state}",
                "body": body,
                "tag": f"incident-{message.incident_id}",
                "renotify": message.event_type == "firing",
                "data": {
                    "url": message.incident_url or f"/incidents/{message.incident_id}",
                    "incident_id": message.incident_id,
                    "event_id": message.event_id,
                },
                "severity": message.severity,
                "status": "resolved" if message.event_type == "resolved" else "firing",
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )
        subscription: dict[str, object] = {
            "endpoint": target.endpoint,
            "keys": {"p256dh": target.p256dh, "auth": target.auth},
        }
        try:
            response = await self._transport.send(
                subscription,
                payload,
                private_key_path=self._private_key_path,
                subject=self._subject,
                ttl_seconds=self._ttl_seconds,
                timeout_seconds=self._timeout_seconds,
            )
        except WebPushTransportTimeout:
            return DeliveryResult("retryable", "timeout", "provider_timeout")
        except WebPushTransportError:
            return DeliveryResult("retryable", "transport_error", "provider_unavailable")
        if 200 <= response.status_code < 300:
            return DeliveryResult("succeeded", f"http_{response.status_code}")
        if response.status_code in {404, 410}:
            return DeliveryResult("gone", f"http_{response.status_code}", "subscription_gone")
        if response.status_code in {408, 409, 425, 429} or response.status_code >= 500:
            return DeliveryResult("retryable", f"http_{response.status_code}", "provider_retryable")
        return DeliveryResult("permanent", f"http_{response.status_code}", "provider_rejected")
