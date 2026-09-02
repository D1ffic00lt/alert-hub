from __future__ import annotations

import html
import json
from urllib.parse import quote

from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
)
from alert_hub.infrastructure.notifications.http import (
    HTTPTransport,
    HTTPTransportError,
    HTTPTransportTimeout,
    classify_http_status,
)


class TelegramProvider:
    def __init__(self, transport: HTTPTransport, *, timeout_seconds: float) -> None:
        self._transport = transport
        self._timeout_seconds = timeout_seconds

    async def send(self, message: NotificationMessage, target: DeliveryTarget) -> DeliveryResult:
        token = str(target.config.get("bot_token") or "")
        chat_id = str(target.config.get("chat_id") or "")
        if not token or not chat_id:
            return DeliveryResult("permanent", "not_configured", "missing_credentials")
        title = html.escape(message.title)
        body = html.escape(message.body)
        severity = html.escape(message.severity.upper())
        state = "RESOLVED" if message.event_type == "resolved" else "FIRING"
        app_name = html.escape(message.app_name)
        text = f"<b>{app_name} · {html.escape(state)} · {severity}</b>\n<b>{title}</b>"
        if body:
            text += f"\n{body}"
        if message.incident_url:
            text += f'\n<a href="{html.escape(message.incident_url, quote=True)}">Open incident</a>'
        payload = json.dumps(
            {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            separators=(",", ":"),
        ).encode()
        url = f"https://api.telegram.org/bot{quote(token, safe=':')}/sendMessage"
        try:
            response = await self._transport.post(
                url,
                headers={"Content-Type": "application/json"},
                content=payload,
                timeout_seconds=self._timeout_seconds,
            )
        except HTTPTransportTimeout:
            return DeliveryResult("retryable", "timeout", "provider_timeout")
        except HTTPTransportError:
            return DeliveryResult("retryable", "transport_error", "provider_unavailable")
        outcome = classify_http_status(response.status_code)
        error_code = None if outcome == "succeeded" else f"http_{response.status_code}"
        return DeliveryResult(outcome, f"http_{response.status_code}", error_code)
