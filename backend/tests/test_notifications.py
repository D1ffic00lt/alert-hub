from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
    ProviderRegistry,
    enqueue_notification_event,
)
from alert_hub.domain.routing import (
    LabelMatcher,
    NodeCandidate,
    RouteRule,
    eligible_node_ids,
    rank_delivery_nodes,
    select_channel_ids,
)
from alert_hub.infrastructure.db.base import Base, new_id
from alert_hub.infrastructure.db.models import (
    Delivery,
    Incident,
    IncidentEvent,
    Node,
    NotificationChannel,
    NotificationRoute,
    Outbox,
    PushSubscription,
    Source,
)
from alert_hub.infrastructure.db.session import initialize_database
from alert_hub.infrastructure.notifications.generic_webhook import GenericWebhookProvider
from alert_hub.infrastructure.notifications.http import (
    HTTPResponse,
    HTTPTransportError,
    HTTPTransportTimeout,
)
from alert_hub.infrastructure.notifications.smtp import (
    SmtplibTransport,
    SMTPPermanentError,
    SMTPProvider,
    SMTPRetryableError,
)
from alert_hub.infrastructure.notifications.telegram import TelegramProvider
from alert_hub.infrastructure.notifications.web_push import (
    WebPushProvider,
    WebPushResponse,
)
from alert_hub.infrastructure.url_safety import UnsafeURL, validate_webhook_url
from alert_hub.workers.notifications import NotificationOutboxProcessor


class _SequenceProvider:
    def __init__(self, *results: DeliveryResult) -> None:
        self._results = list(results)
        self.calls: list[tuple[NotificationMessage, DeliveryTarget]] = []

    async def send(
        self,
        message: NotificationMessage,
        target: DeliveryTarget,
    ) -> DeliveryResult:
        self.calls.append((message, target))
        return self._results.pop(0)


class _HTTPTransport:
    def __init__(
        self,
        response: HTTPResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response or HTTPResponse(204)
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes,
        timeout_seconds: float,
    ) -> HTTPResponse:
        self.calls.append(
            {
                "url": url,
                "headers": headers,
                "content": content,
                "timeout_seconds": timeout_seconds,
            }
        )
        if self.error is not None:
            raise self.error
        return self.response


class _WebPushTransport:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.payloads: list[dict[str, Any]] = []

    async def send(
        self,
        subscription: dict[str, object],
        payload: str,
        **kwargs: Any,
    ) -> WebPushResponse:
        del subscription, kwargs
        self.payloads.append(json.loads(payload))
        return WebPushResponse(self.status_code)


class _SMTPTransport:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.messages: list[EmailMessage] = []

    async def send(
        self,
        config: dict[str, Any],
        message: EmailMessage,
        *,
        timeout_seconds: float,
    ) -> None:
        del config, timeout_seconds
        self.messages.append(message)
        if self.error is not None:
            raise self.error


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _message() -> NotificationMessage:
    return NotificationMessage(
        event_id="event-1",
        event_type="firing",
        incident_id="incident-1",
        source_id="source-1",
        title="Database latency",
        body="Latency crossed the threshold",
        severity="critical",
        status="firing",
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        app_name="Northstar Ops",
        labels={"service": "db"},
    )


def _public_resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]


def test_generic_webhook_signs_canonical_payload_and_classifies_failures() -> None:
    transport = _HTTPTransport(HTTPResponse(202))
    provider = GenericWebhookProvider(
        transport,
        timeout_seconds=3,
        resolver=_public_resolver,
    )
    target = DeliveryTarget(
        channel_id="channel-1",
        channel_kind="generic_webhook",
        config={
            "url": "https://hooks.example.test/alert",
            "hmac_secret": "signing-secret",
        },
    )

    result = asyncio.run(provider.send(_message(), target))

    assert result == DeliveryResult("succeeded", "http_202")
    body = transport.calls[0]["content"]
    signature = hmac.new(b"signing-secret", body, hashlib.sha256).hexdigest()
    assert transport.calls[0]["headers"]["X-Alert-Hub-Signature"] == f"sha256={signature}"
    webhook_payload = json.loads(body)
    assert webhook_payload["event_id"] == "event-1"
    assert webhook_payload["app_name"] == "Northstar Ops"

    timeout = GenericWebhookProvider(
        _HTTPTransport(error=HTTPTransportTimeout()),
        timeout_seconds=1,
        resolver=_public_resolver,
    )
    assert asyncio.run(timeout.send(_message(), target)).outcome == "retryable"
    rejected = GenericWebhookProvider(
        _HTTPTransport(HTTPResponse(400)),
        timeout_seconds=1,
        resolver=_public_resolver,
    )
    assert asyncio.run(rejected.send(_message(), target)).outcome == "permanent"


def test_webhook_send_time_dns_validation_fails_closed() -> None:
    def unresolved(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        return []

    transport = _HTTPTransport()
    provider = GenericWebhookProvider(
        transport,
        timeout_seconds=1,
        resolver=unresolved,
    )
    target = DeliveryTarget(
        channel_id="channel-1",
        channel_kind="generic_webhook",
        config={"url": "https://unresolved.example.test/hook"},
    )
    result = asyncio.run(provider.send(_message(), target))
    assert result == DeliveryResult("permanent", "rejected", "unsafe_destination")
    assert transport.calls == []

    for unsafe_address in ("10.0.0.5", "169.254.169.254", "127.0.0.1"):

        def unsafe_resolver(
            *args: Any,
            _address: str = unsafe_address,
            **kwargs: Any,
        ) -> list[tuple[Any, ...]]:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_address, 443))]

        with pytest.raises(UnsafeURL):
            validate_webhook_url(
                "https://hooks.example.test/path",
                require_resolution=True,
                resolver=unsafe_resolver,
            )


def test_telegram_escapes_html_and_never_returns_bot_token() -> None:
    transport = _HTTPTransport(HTTPResponse(200))
    provider = TelegramProvider(transport, timeout_seconds=2)
    message = replace(
        _message(),
        title="<b>database</b>",
        body="5 < 7 & paging",
    )
    token = "123456:bot-secret-never-return"
    target = DeliveryTarget(
        channel_id="telegram",
        channel_kind="telegram",
        config={"bot_token": token, "chat_id": "42"},
    )
    result = asyncio.run(provider.send(message, target))
    payload = json.loads(transport.calls[0]["content"])
    assert result == DeliveryResult("succeeded", "http_200")
    assert "Northstar Ops" in payload["text"]
    assert "&lt;b&gt;database&lt;/b&gt;" in payload["text"]
    assert "5 &lt; 7 &amp; paging" in payload["text"]
    assert token not in repr(result)

    failed = TelegramProvider(
        _HTTPTransport(error=HTTPTransportError(f"request failed for {token}")),
        timeout_seconds=2,
    )
    failure = asyncio.run(failed.send(message, target))
    assert failure == DeliveryResult(
        "retryable",
        "transport_error",
        "provider_unavailable",
    )
    assert token not in repr(failure)


def test_smtp_provider_classifies_configuration_and_transport_errors() -> None:
    config = {
        "host": "smtp.example.test",
        "port": 587,
        "from": "alerts@example.test",
        "to": ["operator@example.test"],
    }
    success_transport = _SMTPTransport()
    success = SMTPProvider(success_transport, timeout_seconds=3)
    result = asyncio.run(
        success.send(
            _message(),
            DeliveryTarget("smtp", "smtp", config),
        )
    )
    assert result == DeliveryResult("succeeded", "accepted")
    assert success_transport.messages[0]["To"] == "operator@example.test"
    assert success_transport.messages[0]["From"] == "Northstar Ops <alerts@example.test>"
    assert str(success_transport.messages[0]["Subject"]) == (
        "[Northstar Ops] [FIRING] [CRITICAL] Database latency"
    )
    assert success_transport.messages[0].get_content().rstrip("\n") == (
        "Latency crossed the threshold"
    )

    missing = asyncio.run(
        success.send(_message(), DeliveryTarget("smtp", "smtp", {"host": "smtp"}))
    )
    assert missing.outcome == "permanent"
    invalid_tls = asyncio.run(
        success.send(
            _message(),
            DeliveryTarget("smtp", "smtp", {**config, "tls": "plaintext"}),
        )
    )
    assert invalid_tls.error_code == "invalid_tls_mode"
    retry = SMTPProvider(
        _SMTPTransport(SMTPRetryableError()),
        timeout_seconds=3,
    )
    assert asyncio.run(retry.send(_message(), DeliveryTarget("smtp", "smtp", config))).outcome == (
        "retryable"
    )
    permanent = SMTPProvider(
        _SMTPTransport(SMTPPermanentError()),
        timeout_seconds=3,
    )
    assert (
        asyncio.run(permanent.send(_message(), DeliveryTarget("smtp", "smtp", config))).outcome
        == "permanent"
    )


def test_smtp_provider_renders_custom_templates_deterministically() -> None:
    transport = _SMTPTransport()
    provider = SMTPProvider(transport, timeout_seconds=3)
    message = replace(
        _message(),
        incident_url="https://alerts.example.test/incidents/incident-1",
        annotations={"runbook": "db-latency"},
    )
    config = {
        "host": "smtp.example.test",
        "port": 587,
        "from": "alerts@example.test",
        "to": ["operator@example.test"],
        "subject_template": "{{state}} · {{severity}} · {{title}} · {{incident_id}}",
        "body_template": (
            "{{description}}\nURL={{incident_url}}\nlabels={{labels}}\n"
            "annotations={{annotations}}\nat={{occurred_at}}"
        ),
    }

    result = asyncio.run(provider.send(message, DeliveryTarget("smtp", "smtp", config)))

    assert result == DeliveryResult("succeeded", "accepted")
    email = transport.messages[0]
    assert str(email["Subject"]) == "FIRING · critical · Database latency · incident-1"
    assert email.get_content().rstrip("\n") == (
        "Latency crossed the threshold\n"
        "URL=https://alerts.example.test/incidents/incident-1\n"
        'labels={"service":"db"}\n'
        'annotations={"runbook":"db-latency"}\n'
        "at=2026-01-01T00:00:00Z"
    )


def test_smtp_provider_rejects_unknown_templates_and_flattens_header_values() -> None:
    invalid_transport = _SMTPTransport()
    provider = SMTPProvider(invalid_transport, timeout_seconds=3)
    config = {
        "host": "smtp.example.test",
        "port": 587,
        "from": "alerts@example.test",
        "to": ["operator@example.test"],
    }

    unknown = asyncio.run(
        provider.send(
            _message(),
            DeliveryTarget(
                "smtp",
                "smtp",
                {**config, "subject_template": "{{unknown_placeholder}}"},
            ),
        )
    )
    injected_template = asyncio.run(
        provider.send(
            _message(),
            DeliveryTarget(
                "smtp",
                "smtp",
                {**config, "subject_template": "Alert\r\nBcc: attacker@example.test"},
            ),
        )
    )
    assert unknown == DeliveryResult("permanent", "not_configured", "invalid_template")
    assert injected_template == DeliveryResult("permanent", "not_configured", "invalid_template")
    assert invalid_transport.messages == []

    safe_transport = _SMTPTransport()
    safe_provider = SMTPProvider(safe_transport, timeout_seconds=3)
    message = replace(_message(), body="threshold crossed\r\nBcc: attacker@example.test")
    result = asyncio.run(
        safe_provider.send(
            message,
            DeliveryTarget("smtp", "smtp", {**config, "subject_template": "{{body}}"}),
        )
    )
    assert result == DeliveryResult("succeeded", "accepted")
    assert "\r" not in str(safe_transport.messages[0]["Subject"])
    assert "\n" not in str(safe_transport.messages[0]["Subject"])
    assert safe_transport.messages[0]["Bcc"] is None


def test_smtplib_transport_uses_starttls_and_implicit_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    instances: list[Any] = []

    class FakeClient:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.started_tls = False
            self.login_args: tuple[str, str] | None = None
            self.sent = False
            instances.append(self)

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def starttls(self, *, context: Any) -> None:
            assert context is not None
            self.started_tls = True

        def login(self, username: str, password: str) -> None:
            self.login_args = (username, password)

        def send_message(self, message: EmailMessage) -> None:
            del message
            self.sent = True

    import alert_hub.infrastructure.notifications.smtp as smtp_module

    monkeypatch.setattr(smtp_module.smtplib, "SMTP", FakeClient)
    monkeypatch.setattr(smtp_module.smtplib, "SMTP_SSL", FakeClient)
    email = EmailMessage()
    email["From"] = "alerts@example.test"
    email["To"] = "operator@example.test"
    email.set_content("test")
    base = {
        "host": "smtp.example.test",
        "port": 587,
        "username": "operator",
        "password": "secret",
    }

    SmtplibTransport._send_sync({**base, "tls": "starttls"}, email, 4)
    assert instances[-1].started_tls is True
    assert instances[-1].login_args == ("operator", "secret")
    assert instances[-1].sent is True

    SmtplibTransport._send_sync({**base, "tls": "implicit"}, email, 4)
    assert instances[-1].started_tls is False
    assert instances[-1].sent is True


@pytest.mark.parametrize("status_code", [404, 410])
def test_web_push_marks_gone_subscriptions(status_code: int) -> None:
    transport = _WebPushTransport(status_code)
    provider = WebPushProvider(
        transport,
        private_key_path=Path("/unused/test-vapid.pem"),
        subject="mailto:test@example.invalid",
        ttl_seconds=60,
        timeout_seconds=1,
    )
    target = DeliveryTarget(
        channel_id="push",
        channel_kind="web_push",
        config={},
        subscription_id="subscription",
        endpoint="https://push.example.test/device",
        p256dh="key",
        auth="auth",
    )
    assert asyncio.run(provider.send(_message(), target)).outcome == "gone"
    assert transport.payloads[0]["title"] == "Northstar Ops · FIRING"
    assert transport.payloads[0]["body"].startswith("Database latency — ")


def test_ordered_route_matching_and_node_eligibility() -> None:
    routes = [
        RouteRule(
            route_id="first",
            priority=10,
            severity_filter=frozenset({"critical"}),
            label_matchers=(LabelMatcher("service", "=", "db"),),
            channel_ids=("push",),
            continue_matching=True,
        ),
        RouteRule(
            route_id="second",
            priority=20,
            source_filter=frozenset({"source-1"}),
            channel_ids=("telegram", "push"),
        ),
        RouteRule(route_id="ignored", priority=30, channel_ids=("smtp",)),
    ]
    assert select_channel_ids(
        routes,
        source_id="source-1",
        severity="critical",
        labels={"service": "db"},
    ) == ["push", "telegram"]

    candidates = [
        NodeCandidate("eu-notify", "eu", frozenset({"notify"})),
        NodeCandidate("us-notify", "us", frozenset({"notify"})),
        NodeCandidate("eu-ingest", "eu", frozenset({"ingest"})),
    ]
    assert eligible_node_ids(candidates, {"regions": ["eu"]}) == ["eu-notify"]


def _initialize_processor_database(app: Any, settings: Any) -> None:
    Base.metadata.create_all(app.state.engine)
    initialize_database(app.state.engine, app.state.session_factory, settings)


def _seed_event(
    app: Any,
    settings: Any,
    *,
    now: datetime,
    event_id: str | None = None,
    channel_id: str | None = None,
) -> tuple[str, str]:
    event_id = event_id or new_id()
    channel_id = channel_id or new_id()
    source_id = new_id()
    incident_id = new_id()
    cipher = app.state.envelope_cipher
    with app.state.session_factory.begin() as db:
        db.add(
            Source(
                id=source_id,
                name="Test source",
                kind="generic_json",
                token_hash="not-a-real-token",
            )
        )
        db.flush()
        incident = Incident(
            id=incident_id,
            source_id=source_id,
            fingerprint="f" * 64,
            title="Current resolved title",
            description="Current state",
            severity="warning",
            status="resolved",
            labels_json={"service": "db"},
            annotations_json={},
            starts_at=now,
            last_event_at=now,
            resolved_at=now,
        )
        db.add(incident)
        db.flush()
        event = IncidentEvent(
            id=event_id,
            origin_node_id="remote-origin",
            origin_seq=1,
            event_key=f"event-{event_id}",
            incident_id=incident_id,
            event_type="firing",
            occurred_at=now,
            received_at=now,
            payload_json={
                "title": "Original firing title",
                "description": "Original firing body",
                "severity": "critical",
            },
        )
        db.add(event)
        channel = NotificationChannel(
            id=channel_id,
            name="Webhook",
            kind="generic_webhook",
            enabled=True,
            encrypted_config=cipher.encrypt_json(
                {"url": "https://1.1.1.1/hook", "hmac_secret": "secret"},
                context=f"channel:{channel_id}:config",
            ),
            eligible_nodes_or_regions={},
        )
        db.add(channel)
        db.add(
            NotificationRoute(
                id=new_id(),
                name="All critical",
                priority=0,
                severity_filter=["warning"],
                channel_ids=[channel_id],
            )
        )
        db.flush()
        enqueue_notification_event(db, event)
    return event_id, channel_id


def test_worker_records_delivery_timeline_and_preserves_event_snapshot(
    app: Any, settings: Any
) -> None:
    _initialize_processor_database(app, settings)
    now = datetime(2026, 2, 1, tzinfo=UTC)
    event_id, _ = _seed_event(app, settings, now=now)
    provider = _SequenceProvider(DeliveryResult("succeeded", "http_204"))
    processor = NotificationOutboxProcessor(
        app.state.session_factory,
        settings,
        app.state.envelope_cipher,
        ProviderRegistry({"generic_webhook": provider}),
        now=_Clock(now),
    )

    assert asyncio.run(processor.run_once()) == 1

    assert len(provider.calls) == 1
    message, target = provider.calls[0]
    assert message.status == "firing"
    assert message.title == "Original firing title"
    assert target.config["hmac_secret"] == "secret"
    with app.state.session_factory() as db:
        delivery = db.query(Delivery).one()
        assert delivery.status == "succeeded"
        assert db.get(Outbox, event_id).completed_at is not None
        timeline = db.query(IncidentEvent).filter_by(event_type="delivery_succeeded").one()
        assert timeline.payload_json["delivery_id"] == delivery.id


def test_worker_retries_after_restart_without_duplicate_delivery(app: Any, settings: Any) -> None:
    _initialize_processor_database(app, settings)
    now = datetime(2026, 2, 2, tzinfo=UTC)
    event_id, _ = _seed_event(app, settings, now=now)
    clock = _Clock(now)
    provider = _SequenceProvider(
        DeliveryResult("retryable", "timeout", "provider_timeout"),
        DeliveryResult("succeeded", "http_204"),
    )
    registry = ProviderRegistry({"generic_webhook": provider})
    first_process = NotificationOutboxProcessor(
        app.state.session_factory,
        settings,
        app.state.envelope_cipher,
        registry,
        now=clock,
    )
    assert asyncio.run(first_process.run_once()) == 1
    with app.state.session_factory() as db:
        assert db.query(Delivery).one().status == "retrying"
        assert db.get(Outbox, event_id).completed_at is None

    clock.value += timedelta(seconds=settings.notification_retry_base_seconds)
    restarted = NotificationOutboxProcessor(
        app.state.session_factory,
        settings,
        app.state.envelope_cipher,
        registry,
        now=clock,
    )
    assert asyncio.run(restarted.run_once()) == 1
    with app.state.session_factory() as db:
        deliveries = db.query(Delivery).all()
        assert len(deliveries) == 1
        assert deliveries[0].attempt == 2
        assert deliveries[0].status == "succeeded"
        types = {event.event_type for event in db.query(IncidentEvent).all()}
        assert {"delivery_failed", "delivery_succeeded"} <= types
    assert len(provider.calls) == 2


def test_secondary_node_waits_then_takes_over(app: Any, settings: Any) -> None:
    _initialize_processor_database(app, settings)
    now = datetime(2026, 2, 3, tzinfo=UTC)
    event_id = new_id()
    candidates = [
        NodeCandidate(settings.node_id, settings.node_region, frozenset({"notify"})),
        NodeCandidate("peer-node", "peer", frozenset({"notify"})),
    ]
    while True:
        channel_id = new_id()
        ranking = rank_delivery_nodes(f"event-{event_id}", channel_id, candidates, {})
        if ranking.index(settings.node_id) == 1:
            break
    with app.state.session_factory.begin() as db:
        db.add(
            Node(
                id="peer-node",
                name="Peer",
                region="peer",
                enabled_roles=["notify"],
            )
        )
    _seed_event(
        app,
        settings,
        now=now,
        event_id=event_id,
        channel_id=channel_id,
    )
    provider = _SequenceProvider(DeliveryResult("succeeded", "http_204"))
    clock = _Clock(now)
    processor = NotificationOutboxProcessor(
        app.state.session_factory,
        settings,
        app.state.envelope_cipher,
        ProviderRegistry({"generic_webhook": provider}),
        now=clock,
    )

    assert asyncio.run(processor.run_once()) == 1
    assert provider.calls == []
    clock.value += timedelta(seconds=settings.notification_failover_base_seconds)
    assert asyncio.run(processor.run_once()) == 1
    assert len(provider.calls) == 1


def test_no_eligible_delivery_remains_visible_and_queued(app: Any, settings: Any) -> None:
    _initialize_processor_database(app, settings)
    now = datetime(2026, 2, 4, tzinfo=UTC)
    event_id, channel_id = _seed_event(app, settings, now=now)
    with app.state.session_factory.begin() as db:
        channel = db.get(NotificationChannel, channel_id)
        channel.eligible_nodes_or_regions = {"regions": ["missing-region"]}
    provider = _SequenceProvider(DeliveryResult("succeeded", "http_204"))
    processor = NotificationOutboxProcessor(
        app.state.session_factory,
        settings,
        app.state.envelope_cipher,
        ProviderRegistry({"generic_webhook": provider}),
        now=_Clock(now),
    )

    assert asyncio.run(processor.run_once()) == 1
    assert provider.calls == []
    with app.state.session_factory() as db:
        delivery = db.query(Delivery).one()
        assert delivery.status == "retrying"
        assert delivery.owner_node_id == "unassigned"
        assert delivery.error_code == "no_eligible_node"
        outbox = db.get(Outbox, event_id)
        assert outbox.completed_at is None
        assert outbox.last_error == "no_eligible_node"


def test_route_crud_and_live_web_push_test_disables_gone_subscription(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
) -> None:
    channel = client.post(
        "/api/v1/channels",
        headers=auth,
        json={"name": "Browser push", "kind": "web_push", "config": {}},
    )
    assert channel.status_code == 201, channel.text
    route = client.post(
        "/api/v1/routes",
        headers=auth,
        json={
            "name": "Critical browser route",
            "priority": 10,
            "severity_filter": ["critical"],
            "label_matchers": [{"name": "service", "operator": "=~", "value": "api|db"}],
            "channel_ids": [channel.json()["id"]],
        },
    )
    assert route.status_code == 201, route.text
    patched = client.patch(
        f"/api/v1/routes/{route.json()['id']}",
        headers=auth,
        json={"continue_matching": True},
    )
    assert patched.status_code == 200
    assert patched.json()["continue_matching"] is True

    endpoint = "https://1.1.1.1/push/test-device"
    subscription = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json={
            "endpoint": endpoint,
            "keys": {
                "p256dh": base64.urlsafe_b64encode(os.urandom(65)).rstrip(b"=").decode(),
                "auth": base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode(),
            },
            "device_name": "gone browser",
        },
    )
    assert subscription.status_code == 201, subscription.text
    app.state.notification_providers = ProviderRegistry(
        {"web_push": _SequenceProvider(DeliveryResult("gone", "http_410", "subscription_gone"))}
    )
    tested = client.post(f"/api/v1/channels/{channel.json()['id']}/test", headers=auth)
    assert tested.status_code == 200
    assert tested.json()["attempted"] is True
    assert tested.json()["outcomes"][0]["outcome"] == "gone"
    assert endpoint not in tested.text
    with app.state.session_factory() as db:
        assert db.get(PushSubscription, subscription.json()["id"]).disabled_at is not None

    deleted = client.delete(f"/api/v1/routes/{route.json()['id']}", headers=auth)
    assert deleted.status_code == 204
    assert client.get("/api/v1/routes", headers=auth).json() == []
