from __future__ import annotations

import asyncio
import base64
import json
import socket
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pywebpush import WebPushException
from sqlalchemy import func, select
from starlette.requests import Request

from alert_hub.api.stream import _stream_claims, stream
from alert_hub.application.incidents import append_cluster_event
from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
)
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import ClusterEvent, PushSubscription
from alert_hub.infrastructure.db.models import Session as AuthSession
from alert_hub.infrastructure.notifications import http as http_module
from alert_hub.infrastructure.notifications import web_push as web_push_module
from alert_hub.infrastructure.notifications.http import (
    HTTPTransportError,
    HTTPTransportTimeout,
    HttpxTransport,
    classify_http_status,
)
from alert_hub.infrastructure.notifications.web_push import (
    PyWebPushTransport,
    WebPushProvider,
    WebPushResponse,
    WebPushTransportError,
    WebPushTransportTimeout,
)
from alert_hub.infrastructure.vapid import VapidConfigurationError, vapid_public_key
from alert_hub.security import encode_access_token
from alert_hub.settings import Settings


def _message(*, event_type: str = "firing") -> NotificationMessage:
    return NotificationMessage(
        event_id="event-coverage-edge",
        event_type=event_type,
        incident_id="incident-coverage-edge",
        source_id="source-coverage-edge",
        title="Database latency",
        body="Latency crossed the threshold",
        severity="critical",
        status="resolved" if event_type == "resolved" else "firing",
        occurred_at=utc_now(),
        app_name="Alert Hub",
        labels={"service": "database"},
    )


def _subscription_target(
    *,
    endpoint: str = "https://1.1.1.1/push/device",
    p256dh: str = "public-key",
    auth: str = "auth-secret",
) -> DeliveryTarget:
    return DeliveryTarget(
        channel_id="web-push",
        channel_kind="web_push",
        config={},
        subscription_id="subscription-coverage-edge",
        endpoint=endpoint,
        p256dh=p256dh,
        auth=auth,
    )


def _public_key(private_key: ec.EllipticCurvePrivateKey) -> str:
    encoded = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode()


class _RecordingWebPushTransport:
    def __init__(
        self,
        response: WebPushResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response or WebPushResponse(201)
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def send(
        self,
        subscription: dict[str, object],
        payload: str,
        **kwargs: Any,
    ) -> WebPushResponse:
        self.calls.append(
            {
                "subscription": subscription,
                "payload": json.loads(payload),
                "kwargs": kwargs,
            }
        )
        if self.error is not None:
            raise self.error
        return self.response


def test_vapid_public_key_sources_and_key_type_validation(
    settings: Settings,
    tmp_path: Path,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = _public_key(private_key)
    direct = settings.model_copy(update={"vapid_public_key": f"  {public_key}  "})
    assert vapid_public_key(direct) == public_key

    public_path = tmp_path / "vapid-public.key"
    public_path.write_text(f"  {public_key}\n", encoding="utf-8")
    from_file = settings.model_copy(
        update={"vapid_public_key": None, "vapid_public_key_file": public_path}
    )
    assert vapid_public_key(from_file) == public_key

    public_path.write_text(" \n", encoding="utf-8")
    with pytest.raises(VapidConfigurationError, match="public key file is empty"):
        vapid_public_key(from_file)

    unreadable = settings.model_copy(
        update={"vapid_public_key": None, "vapid_public_key_file": tmp_path}
    )
    with pytest.raises(VapidConfigurationError, match="unable to read VAPID public key file"):
        vapid_public_key(unreadable)

    missing = settings.model_copy(
        update={
            "vapid_public_key": None,
            "vapid_public_key_file": None,
            "vapid_private_key_file": None,
        }
    )
    with pytest.raises(VapidConfigurationError, match="VAPID key is not configured"):
        vapid_public_key(missing)


def test_explicit_vapid_public_key_is_valid_and_matches_private_key(
    settings: Settings,
    tmp_path: Path,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_path = tmp_path / "vapid-private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_key = _public_key(private_key)
    matching = settings.model_copy(
        update={"vapid_public_key": public_key, "vapid_private_key_file": private_path}
    )
    assert vapid_public_key(matching) == public_key

    mismatched = matching.model_copy(
        update={"vapid_public_key": _public_key(ec.generate_private_key(ec.SECP256R1()))}
    )
    with pytest.raises(VapidConfigurationError, match="public and private keys do not match"):
        vapid_public_key(mismatched)

    malformed = settings.model_copy(update={"vapid_public_key": "not+canonical/base64=="})
    with pytest.raises(VapidConfigurationError, match="canonical unpadded base64url"):
        vapid_public_key(malformed)

    invalid_point = base64.urlsafe_b64encode(b"\x04" + (b"\x00" * 64)).rstrip(b"=").decode()
    invalid = settings.model_copy(update={"vapid_public_key": invalid_point})
    with pytest.raises(VapidConfigurationError, match="uncompressed P-256 point"):
        vapid_public_key(invalid)


@pytest.mark.parametrize("key_kind", ["malformed", "rsa", "wrong_curve"])
def test_vapid_private_key_rejects_invalid_material(
    settings: Settings,
    tmp_path: Path,
    key_kind: str,
) -> None:
    private_path = tmp_path / f"{key_kind}.pem"
    if key_kind == "malformed":
        private_path.write_bytes(b"not a PEM private key")
    elif key_kind == "rsa":
        private_path.write_bytes(
            rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    else:
        private_path.write_bytes(
            ec.generate_private_key(ec.SECP384R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    configured = settings.model_copy(
        update={
            "vapid_public_key": None,
            "vapid_public_key_file": None,
            "vapid_private_key_file": private_path,
        }
    )

    expected = (
        "unable to load VAPID private key"
        if key_kind == "malformed"
        else "VAPID private key must use the P-256 curve"
    )
    with pytest.raises(VapidConfigurationError, match=expected):
        vapid_public_key(configured)


def test_vapid_private_key_derives_uncompressed_p256_public_key(
    settings: Settings,
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "p256.pem"
    private_path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    configured = settings.model_copy(
        update={
            "vapid_public_key": None,
            "vapid_public_key_file": None,
            "vapid_private_key_file": private_path,
        }
    )

    encoded = vapid_public_key(configured)
    decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    assert len(decoded) == 65
    assert decoded[0] == 4


def test_pywebpush_transport_maps_library_failures_without_exposing_details(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "unused-vapid.pem"
    captured: dict[str, Any] = {}

    def accepted(**kwargs: Any) -> object:
        captured.update(kwargs)
        return SimpleNamespace(status_code=202)

    monkeypatch.setattr(web_push_module, "webpush", accepted)
    response = asyncio.run(
        PyWebPushTransport().send(
            {"endpoint": "https://push.example.test/device", "keys": {}},
            "{}",
            private_key_path=private_path,
            subject="mailto:operator@example.invalid",
            ttl_seconds=120,
            timeout_seconds=2.5,
            pinned_addresses=("1.1.1.1",),
        )
    )
    assert response == WebPushResponse(202)
    assert captured["vapid_private_key"] == str(private_path)
    assert captured["vapid_claims"] == {"sub": "mailto:operator@example.invalid"}
    assert captured["ttl"] == 120
    assert captured["timeout"] == 2.5
    pinned_session = captured["requests_session"]
    assert pinned_session.trust_env is False
    assert pinned_session.max_redirects == 0

    def gone(**kwargs: Any) -> object:
        del kwargs
        response = SimpleNamespace(status_code=410, text="credential=must-not-escape")
        raise WebPushException("credential=must-not-escape", response=response)

    monkeypatch.setattr(web_push_module, "webpush", gone)
    assert PyWebPushTransport._send_sync(
        {}, "{}", private_path, "mailto:test@example.invalid", 60, 1
    ) == WebPushResponse(410)

    failures: list[tuple[Exception, type[Exception]]] = [
        (WebPushException("credential=must-not-escape"), WebPushTransportError),
        (TimeoutError("credential=must-not-escape"), WebPushTransportTimeout),
        (OSError("credential=must-not-escape"), WebPushTransportError),
    ]
    for source_error, expected_error in failures:

        def failed(
            _source_error: Exception = source_error,
            **kwargs: Any,
        ) -> object:
            del kwargs
            raise _source_error

        monkeypatch.setattr(web_push_module, "webpush", failed)
        with pytest.raises(expected_error) as raised:
            PyWebPushTransport._send_sync(
                {}, "{}", private_path, "mailto:test@example.invalid", 60, 1
            )
        assert "must-not-escape" not in str(raised.value)


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (200, DeliveryResult("succeeded", "http_200")),
        (410, DeliveryResult("gone", "http_410", "subscription_gone")),
        (408, DeliveryResult("retryable", "http_408", "provider_retryable")),
        (409, DeliveryResult("retryable", "http_409", "provider_retryable")),
        (425, DeliveryResult("retryable", "http_425", "provider_retryable")),
        (429, DeliveryResult("retryable", "http_429", "provider_retryable")),
        (503, DeliveryResult("retryable", "http_503", "provider_retryable")),
        (400, DeliveryResult("permanent", "http_400", "provider_rejected")),
    ],
)
def test_web_push_provider_classifies_provider_statuses(
    status_code: int,
    expected: DeliveryResult,
    tmp_path: Path,
) -> None:
    provider = WebPushProvider(
        _RecordingWebPushTransport(WebPushResponse(status_code)),
        private_key_path=tmp_path / "unused-vapid.pem",
        subject="mailto:test@example.invalid",
        ttl_seconds=60,
        timeout_seconds=1,
    )
    assert asyncio.run(provider.send(_message(), _subscription_target())) == expected


@pytest.mark.parametrize(
    ("endpoint", "p256dh", "auth"),
    [
        ("", "public-key", "auth-secret"),
        ("https://push.example.test/device", "", "auth-secret"),
        ("https://push.example.test/device", "public-key", ""),
    ],
)
def test_web_push_provider_rejects_incomplete_subscriptions_without_transport(
    endpoint: str,
    p256dh: str,
    auth: str,
    tmp_path: Path,
) -> None:
    transport = _RecordingWebPushTransport()
    provider = WebPushProvider(
        transport,
        private_key_path=tmp_path / "unused-vapid.pem",
        subject="mailto:test@example.invalid",
        ttl_seconds=60,
        timeout_seconds=1,
    )

    result = asyncio.run(
        provider.send(
            _message(),
            _subscription_target(endpoint=endpoint, p256dh=p256dh, auth=auth),
        )
    )

    assert result == DeliveryResult("permanent", "not_configured", "missing_subscription")
    assert transport.calls == []


def test_web_push_provider_payload_safety_and_transport_failures(tmp_path: Path) -> None:
    transport = _RecordingWebPushTransport()
    private_path = tmp_path / "unused-vapid.pem"
    provider = WebPushProvider(
        transport,
        private_key_path=private_path,
        subject="mailto:test@example.invalid",
        ttl_seconds=90,
        timeout_seconds=1.5,
    )
    message = _message(event_type="resolved")
    message = NotificationMessage(
        event_id=message.event_id,
        event_type=message.event_type,
        incident_id=message.incident_id,
        source_id=message.source_id,
        title=message.title,
        body="",
        severity=message.severity,
        status=message.status,
        occurred_at=message.occurred_at,
        app_name=" Alert\r\nHub ",
        labels=message.labels,
    )

    result = asyncio.run(provider.send(message, _subscription_target()))

    assert result == DeliveryResult("succeeded", "http_201")
    call = transport.calls[0]
    payload = call["payload"]
    assert payload["title"] == "Alert  Hub · RESOLVED"
    assert payload["body"] == "Database latency"
    assert payload["renotify"] is False
    assert payload["data"] == {
        "url": "/incidents/incident-coverage-edge",
        "incident_id": "incident-coverage-edge",
        "event_id": "event-coverage-edge",
    }
    assert call["subscription"]["keys"] == {
        "p256dh": "public-key",
        "auth": "auth-secret",
    }
    assert call["kwargs"] == {
        "private_key_path": private_path,
        "subject": "mailto:test@example.invalid",
        "ttl_seconds": 90,
        "timeout_seconds": 1.5,
        "pinned_addresses": ("1.1.1.1",),
    }

    for error, expected in [
        (
            WebPushTransportTimeout("credential=must-not-escape"),
            DeliveryResult("retryable", "timeout", "provider_timeout"),
        ),
        (
            WebPushTransportError("credential=must-not-escape"),
            DeliveryResult("retryable", "transport_error", "provider_unavailable"),
        ),
    ]:
        failed = WebPushProvider(
            _RecordingWebPushTransport(error=error),
            private_key_path=private_path,
            subject="mailto:test@example.invalid",
            ttl_seconds=90,
            timeout_seconds=1.5,
        )
        failure = asyncio.run(failed.send(message, _subscription_target()))
        assert failure == expected
        assert "must-not-escape" not in repr(failure)

    unconfigured = WebPushProvider(
        _RecordingWebPushTransport(),
        private_key_path=None,
        subject="mailto:test@example.invalid",
        ttl_seconds=90,
        timeout_seconds=1.5,
    )
    assert asyncio.run(unconfigured.send(message, _subscription_target())) == DeliveryResult(
        "permanent", "not_configured", "missing_vapid_key"
    )


def test_web_push_provider_revalidates_endpoint_before_transport(tmp_path: Path) -> None:
    def private_resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", 443))]

    transport = _RecordingWebPushTransport()
    provider = WebPushProvider(
        transport,
        private_key_path=tmp_path / "unused-vapid.pem",
        subject="mailto:test@example.invalid",
        ttl_seconds=60,
        timeout_seconds=1,
        resolver=private_resolver,
    )

    result = asyncio.run(
        provider.send(
            _message(),
            _subscription_target(endpoint="https://push.example.test/device"),
        )
    )

    assert result == DeliveryResult("permanent", "rejected", "unsafe_destination")
    assert transport.calls == []


def test_web_push_provider_pins_the_validated_dns_answers(tmp_path: Path) -> None:
    resolver_calls = 0

    def public_resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        nonlocal resolver_calls
        del args, kwargs
        resolver_calls += 1
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ]

    transport = _RecordingWebPushTransport()
    provider = WebPushProvider(
        transport,
        private_key_path=tmp_path / "unused-vapid.pem",
        subject="mailto:test@example.invalid",
        ttl_seconds=60,
        timeout_seconds=1,
        resolver=public_resolver,
    )

    result = asyncio.run(
        provider.send(
            _message(),
            _subscription_target(endpoint="https://push.example.test/device"),
        )
    )

    assert result == DeliveryResult("succeeded", "http_201")
    assert resolver_calls == 1
    assert transport.calls[0]["kwargs"]["pinned_addresses"] == ("1.1.1.1", "8.8.8.8")


def test_pinned_web_push_connection_never_resolves_the_original_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected_to: list[tuple[str, int]] = []
    returned_socket = socket.socket()

    def connect(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
        del args, kwargs
        connected_to.append(address)
        return returned_socket

    monkeypatch.setattr(web_push_module.urllib3_connection, "create_connection", connect)
    connection = web_push_module._PinnedHTTPSConnection(
        host="push.example.test",
        port=443,
        timeout=1,
        pinned_addresses=("1.1.1.1",),
    )
    try:
        assert connection._new_conn() is returned_socket
        assert connection.host == "push.example.test"
        assert connected_to == [("1.1.1.1", 443)]
    finally:
        returned_socket.close()


@dataclass
class _FakeHTTPResponse:
    status_code: int
    closed: bool = False

    async def aclose(self) -> None:
        self.closed = True


def test_httpx_transport_streams_only_status_and_maps_redacted_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeHTTPResponse(204)
    clients: list[Any] = []

    class FakeAsyncClient:
        next_error: Exception | None = None

        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            self.sent: list[tuple[object, bool]] = []
            clients.append(self)

        async def __aenter__(self) -> FakeAsyncClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        def build_request(
            self,
            method: str,
            url: str,
            *,
            headers: dict[str, str],
            content: bytes,
        ) -> object:
            return (method, url, headers, content)

        async def send(self, request: object, *, stream: bool) -> _FakeHTTPResponse:
            self.sent.append((request, stream))
            if self.next_error is not None:
                raise self.next_error
            return response

    monkeypatch.setattr(http_module.httpx, "AsyncClient", FakeAsyncClient)
    transport = HttpxTransport()
    result = asyncio.run(
        transport.post(
            "https://hooks.example.test/alert",
            headers={"Authorization": "Bearer must-not-escape"},
            content=b'{"credential":"must-not-escape"}',
            timeout_seconds=2.5,
        )
    )

    assert result.status_code == 204
    assert response.closed is True
    assert clients[0].kwargs["follow_redirects"] is False
    assert clients[0].kwargs["trust_env"] is False
    assert clients[0].kwargs["timeout"].connect == 2.5
    assert clients[0].sent[0][1] is True

    for source_error, expected_error in [
        (httpx.ReadTimeout("credential=must-not-escape"), HTTPTransportTimeout),
        (httpx.ConnectError("credential=must-not-escape"), HTTPTransportError),
    ]:
        FakeAsyncClient.next_error = source_error
        with pytest.raises(expected_error) as raised:
            asyncio.run(
                transport.post(
                    "https://hooks.example.test/alert",
                    headers={},
                    content=b"{}",
                    timeout_seconds=1,
                )
            )
        assert "must-not-escape" not in str(raised.value)


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (200, "succeeded"),
        (299, "succeeded"),
        (408, "retryable"),
        (409, "retryable"),
        (425, "retryable"),
        (429, "retryable"),
        (500, "retryable"),
        (599, "retryable"),
        (300, "permanent"),
        (400, "permanent"),
        (600, "permanent"),
    ],
)
def test_http_delivery_classification_boundaries(status_code: int, expected: str) -> None:
    assert classify_http_status(status_code) == expected


@pytest.mark.parametrize(
    ("session_state", "expected_revoke_events"),
    [
        ("sliding_expired", 1),
        ("absolute_expired", 1),
        ("disabled_user", 1),
        ("already_revoked", 0),
    ],
)
def test_refresh_expiry_and_revocation_are_fail_closed_and_idempotent(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
    settings: Settings,
    session_state: str,
    expected_revoke_events: int,
) -> None:
    raw_refresh = client.cookies.get(settings.refresh_cookie_name)
    assert raw_refresh is not None
    push_response = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json={
            "endpoint": f"https://1.1.1.1/push/{session_state}",
            "keys": {
                "p256dh": _public_key(ec.generate_private_key(ec.SECP256R1())),
                "auth": base64.urlsafe_b64encode(b"a" * 16).rstrip(b"=").decode(),
            },
            "device_name": "expiring browser",
        },
    )
    assert push_response.status_code == 201, push_response.text
    now = utc_now()
    with app.state.session_factory.begin() as db:
        auth_session = db.scalar(select(AuthSession))
        assert auth_session is not None
        session_id = auth_session.id
        if session_state == "sliding_expired":
            auth_session.expires_at = now - timedelta(seconds=1)
        elif session_state == "absolute_expired":
            auth_session.absolute_expires_at = now - timedelta(seconds=1)
        elif session_state == "disabled_user":
            auth_session.user.disabled_at = now
        else:
            auth_session.revoked_at = now

    request_headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": auth["X-CSRF-Token"],
    }
    first = client.post("/api/v1/auth/refresh", headers=request_headers)
    second = client.post("/api/v1/auth/refresh", headers=request_headers)
    assert first.status_code == second.status_code == 401
    assert first.json()["detail"] == "Refresh session expired or revoked"

    with app.state.session_factory() as db:
        persisted = db.get(AuthSession, session_id)
        assert persisted is not None
        assert persisted.revoked_at is not None
        revoke_count = db.scalar(
            select(func.count(ClusterEvent.event_id)).where(
                ClusterEvent.entity_type == "session",
                ClusterEvent.entity_id == session_id,
                ClusterEvent.operation == "revoke",
            )
        )
        push_subscription = db.get(PushSubscription, push_response.json()["id"])
        assert push_subscription is not None
        assert push_subscription.disabled_at is not None
        push_tombstone_count = db.scalar(
            select(func.count(ClusterEvent.event_id)).where(
                ClusterEvent.entity_type == "push_subscription",
                ClusterEvent.entity_id == push_subscription.id,
                ClusterEvent.operation == "tombstone",
            )
        )
    assert revoke_count == expected_revoke_events
    assert push_tombstone_count == 1


def _stream_request(
    app: Any,
    *,
    token: str | None = None,
    cookie: str | None = None,
    receive: Any | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    if cookie is not None:
        headers.append((b"cookie", f"alert_hub_stream={cookie}".encode()))

    async def default_receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/stream",
            "raw_path": b"/api/v1/stream",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
            "app": app,
        },
        receive=receive or default_receive,
    )


def test_sse_authentication_rejects_missing_invalid_and_unknown_sessions(
    client: TestClient,
    app: Any,
    settings: Settings,
) -> None:
    del client
    with app.state.session_factory() as db:
        with pytest.raises(HTTPException, match="Stream authentication required"):
            _stream_claims(_stream_request(app), db, settings)
        with pytest.raises(HTTPException, match="Stream token expired or invalid"):
            _stream_claims(_stream_request(app, token="malformed"), db, settings)

        unknown_session_token = encode_access_token(
            "missing-user",
            "missing-session",
            settings.signing_key,
            60,
        )
        with pytest.raises(HTTPException, match="Stream session unavailable"):
            _stream_claims(_stream_request(app, token=unknown_session_token), db, settings)


def test_sse_stream_emits_changes_keepalives_and_stops_on_disconnect(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
    settings: Settings,
) -> None:
    del auth
    token = client.cookies.get(settings.stream_cookie_name)
    assert token is not None
    settings.sse_poll_seconds = 0
    settings.sse_keepalive_seconds = 0

    async def disconnected() -> dict[str, object]:
        return {"type": "http.disconnect"}

    async def exercise_stream() -> None:
        keepalive_response = stream(_stream_request(app, token=token))
        ready = await anext(keepalive_response.body_iterator)
        keepalive = await anext(keepalive_response.body_iterator)
        assert '"type":"ready"' in ready
        assert keepalive.startswith(": keepalive ")
        await keepalive_response.body_iterator.aclose()

        event_response = stream(_stream_request(app, token=token))
        await anext(event_response.body_iterator)
        with app.state.session_factory.begin() as db:
            event = append_cluster_event(
                db,
                settings,
                entity_type="coverage_edge",
                entity_id="stream",
                operation="created",
                payload={"safe": True},
            )
            event_id = event.event_id
        update = await anext(event_response.body_iterator)
        assert '"type":"cluster_event"' in update
        assert f'"event_id":"{event_id}"' in update
        assert '"entity_type":"coverage_edge"' in update
        assert '"operation":"created"' in update
        await event_response.body_iterator.aclose()

        disconnected_response = stream(_stream_request(app, token=token, receive=disconnected))
        await anext(disconnected_response.body_iterator)
        with pytest.raises(StopAsyncIteration):
            await anext(disconnected_response.body_iterator)

    asyncio.run(exercise_stream())


def test_sse_stream_rechecks_revocation_after_connection(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
    settings: Settings,
) -> None:
    del auth
    token = client.cookies.get(settings.stream_cookie_name)
    assert token is not None
    settings.sse_poll_seconds = 0

    async def exercise_stream() -> None:
        response = stream(_stream_request(app, token=token))
        await anext(response.body_iterator)
        with app.state.session_factory.begin() as db:
            auth_session = db.scalar(select(AuthSession))
            assert auth_session is not None
            auth_session.revoked_at = utc_now()
        with pytest.raises(StopAsyncIteration):
            await anext(response.body_iterator)

    asyncio.run(exercise_stream())
