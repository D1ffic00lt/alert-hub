from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from pywebpush import WebPushException, webpush  # type: ignore[import-untyped]
from requests import PreparedRequest, Session
from requests.adapters import HTTPAdapter
from requests.exceptions import InvalidURL, RequestException, Timeout
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import connection as urllib3_connection

from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
)
from alert_hub.infrastructure.url_safety import Resolver, UnsafeURL, validate_webhook_url


@dataclass(frozen=True, slots=True)
class WebPushResponse:
    status_code: int


class WebPushTransportError(Exception):
    pass


class WebPushTransportTimeout(Exception):
    pass


class _PinnedHTTPSConnection(HTTPSConnection):
    """Open TLS to one validated address while retaining the original TLS hostname."""

    def __init__(
        self,
        *args: Any,
        pinned_addresses: tuple[str, ...],
        **kwargs: Any,
    ) -> None:
        self._pinned_addresses = pinned_addresses
        super().__init__(*args, **kwargs)

    def _new_conn(self) -> socket.socket:
        last_error: OSError | None = None
        for address in self._pinned_addresses:
            try:
                return urllib3_connection.create_connection(
                    (address, int(self.port or 443)),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except OSError as exc:
                last_error = exc
        if isinstance(last_error, TimeoutError):
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out (connect timeout={self.timeout})",
            ) from last_error
        raise NewConnectionError(
            self,
            f"Failed to connect to a validated address for {self.host}",
        ) from last_error


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedHTTPSAdapter(HTTPAdapter):
    """Build a one-origin pool that cannot perform a second hostname lookup."""

    def __init__(
        self,
        hostname: str,
        port: int,
        pinned_addresses: tuple[str, ...],
    ) -> None:
        super().__init__(max_retries=0)
        self._hostname = hostname
        self._port = port
        self._pinned_addresses = pinned_addresses
        self._pinned_pool: _PinnedHTTPSConnectionPool | None = None

    def get_connection_with_tls_context(
        self,
        request: PreparedRequest,
        verify: bool | str | None,
        proxies: Mapping[str, str] | None = None,
        cert: str | tuple[str, str] | None = None,
    ) -> HTTPSConnectionPool:
        parsed = urlsplit(request.url or "")
        request_port = parsed.port or 443
        if (
            parsed.scheme != "https"
            or parsed.hostname != self._hostname
            or request_port != self._port
        ):
            raise InvalidURL("Web Push request escaped its validated HTTPS origin")
        if proxies and any(proxies.values()):
            raise InvalidURL("Web Push proxying is disabled for address-pinned delivery")
        _, pool_kwargs = self.build_connection_pool_key_attributes(
            request,
            True if verify is None else verify,
            cert,
        )
        if self._pinned_pool is not None:
            self._pinned_pool.close()
        self._pinned_pool = _PinnedHTTPSConnectionPool(
            self._hostname,
            self._port,
            pinned_addresses=self._pinned_addresses,
            **pool_kwargs,
        )
        return self._pinned_pool

    def close(self) -> None:
        if self._pinned_pool is not None:
            self._pinned_pool.close()
            self._pinned_pool = None
        super().close()


def _pinned_session(endpoint: str, pinned_addresses: tuple[str, ...]) -> Session:
    parsed = urlsplit(endpoint)
    hostname = parsed.hostname
    if parsed.scheme != "https" or hostname is None or not pinned_addresses:
        raise WebPushTransportError
    session = Session()
    # Environment proxies would terminate TLS elsewhere and invalidate address pinning.
    session.trust_env = False
    # pywebpush does not expose allow_redirects; zero prevents a redirect request.
    session.max_redirects = 0
    session.mount(
        "https://",
        _PinnedHTTPSAdapter(hostname, parsed.port or 443, pinned_addresses),
    )
    return session


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
        pinned_addresses: tuple[str, ...],
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
        pinned_addresses: tuple[str, ...] = (),
    ) -> WebPushResponse:
        return await asyncio.to_thread(
            self._send_sync,
            subscription,
            payload,
            private_key_path,
            subject,
            ttl_seconds,
            timeout_seconds,
            pinned_addresses,
        )

    @staticmethod
    def _send_sync(
        subscription: dict[str, object],
        payload: str,
        private_key_path: Path,
        subject: str,
        ttl_seconds: int,
        timeout_seconds: float,
        pinned_addresses: tuple[str, ...] = (),
    ) -> WebPushResponse:
        endpoint = str(subscription.get("endpoint") or "")
        session = _pinned_session(endpoint, pinned_addresses) if pinned_addresses else None
        try:
            response = webpush(
                subscription_info=subscription,
                data=payload,
                vapid_private_key=str(private_key_path),
                vapid_claims={"sub": subject},
                ttl=ttl_seconds,
                timeout=timeout_seconds,
                requests_session=session,
            )
        except WebPushException as exc:
            status_code = exc.response.status_code if exc.response is not None else 0
            if status_code:
                return WebPushResponse(status_code=status_code)
            raise WebPushTransportError from exc
        except (TimeoutError, Timeout) as exc:
            raise WebPushTransportTimeout from exc
        except (OSError, RequestException) as exc:
            raise WebPushTransportError from exc
        finally:
            if session is not None:
                session.close()
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
        resolver: Resolver = socket.getaddrinfo,
    ) -> None:
        self._transport = transport
        self._private_key_path = private_key_path
        self._subject = subject
        self._ttl_seconds = ttl_seconds
        self._timeout_seconds = timeout_seconds
        self._resolver = resolver

    async def send(self, message: NotificationMessage, target: DeliveryTarget) -> DeliveryResult:
        if self._private_key_path is None:
            return DeliveryResult("permanent", "not_configured", "missing_vapid_key")
        if not target.endpoint or not target.p256dh or not target.auth:
            return DeliveryResult("permanent", "not_configured", "missing_subscription")
        resolved_addresses: list[str] = []

        def capture_resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
            answers = list(self._resolver(*args, **kwargs))
            resolved_addresses.extend(str(answer[4][0]) for answer in answers if answer[4])
            return answers

        try:
            # Resolution is blocking on common platforms. Perform the final SSRF and
            # address selection immediately before provider I/O without stalling the
            # application's event loop. The transport connects only to these validated
            # addresses while preserving the hostname for HTTP and TLS verification.
            endpoint = await asyncio.to_thread(
                validate_webhook_url,
                target.endpoint,
                allow_http=False,
                allow_private=False,
                require_resolution=True,
                resolver=capture_resolver,
            )
        except UnsafeURL:
            return DeliveryResult("permanent", "rejected", "unsafe_destination")
        if not resolved_addresses:
            literal_hostname = urlsplit(endpoint).hostname
            if literal_hostname is None:
                return DeliveryResult("permanent", "rejected", "unsafe_destination")
            resolved_addresses.append(literal_hostname)
        pinned_addresses = tuple(dict.fromkeys(resolved_addresses))
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
            "endpoint": endpoint,
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
                pinned_addresses=pinned_addresses,
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
