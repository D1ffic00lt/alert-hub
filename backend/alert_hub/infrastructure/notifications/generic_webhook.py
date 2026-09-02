from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import socket

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
from alert_hub.infrastructure.url_safety import (
    Resolver,
    UnsafeURL,
    validate_headers,
    validate_webhook_url,
)


class GenericWebhookProvider:
    def __init__(
        self,
        transport: HTTPTransport,
        *,
        timeout_seconds: float,
        allow_http: bool = False,
        allow_private: bool = False,
        resolver: Resolver = socket.getaddrinfo,
    ) -> None:
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self._allow_http = allow_http
        self._allow_private = allow_private
        self._resolver = resolver

    async def send(self, message: NotificationMessage, target: DeliveryTarget) -> DeliveryResult:
        try:
            # getaddrinfo is blocking on common platforms. Resolve in a worker thread so one
            # unhealthy DNS server cannot freeze this node's single async application worker.
            url = await asyncio.to_thread(
                validate_webhook_url,
                str(target.config.get("url") or ""),
                allow_http=self._allow_http,
                allow_private=self._allow_private,
                require_resolution=not self._allow_private,
                resolver=self._resolver,
            )
            configured_headers = validate_headers(target.config.get("headers"))
        except UnsafeURL:
            return DeliveryResult("permanent", "rejected", "unsafe_destination")
        body = json.dumps(
            message.provider_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Alert-Hub/notification",
            **configured_headers,
        }
        secret = target.config.get("hmac_secret")
        if secret:
            signature = hmac.new(str(secret).encode(), body, hashlib.sha256).hexdigest()
            header_name = str(target.config.get("signature_header") or "X-Alert-Hub-Signature")
            try:
                validate_headers({header_name: signature})
            except UnsafeURL:
                return DeliveryResult("permanent", "rejected", "invalid_signature_header")
            headers[header_name] = f"sha256={signature}"
        try:
            response = await self._transport.post(
                url,
                headers=headers,
                content=body,
                timeout_seconds=self._timeout_seconds,
            )
        except HTTPTransportTimeout:
            return DeliveryResult("retryable", "timeout", "provider_timeout")
        except HTTPTransportError:
            return DeliveryResult("retryable", "transport_error", "provider_unavailable")
        outcome = classify_http_status(response.status_code)
        error_code = None if outcome == "succeeded" else f"http_{response.status_code}"
        return DeliveryResult(outcome, f"http_{response.status_code}", error_code)
