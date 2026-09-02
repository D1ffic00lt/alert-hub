from __future__ import annotations

import asyncio
import base64
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from alert_hub.api.stream import stream as stream_endpoint
from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
    ProviderRegistry,
)
from alert_hub.infrastructure.db.models import ClusterEvent, NotificationChannel, PushSubscription
from alert_hub.infrastructure.db.models import Session as AuthSession
from alert_hub.main import create_app
from alert_hub.settings import Settings


class _SuccessfulProvider:
    def __init__(self) -> None:
        self.targets: list[DeliveryTarget] = []

    async def send(
        self,
        message: NotificationMessage,
        target: DeliveryTarget,
    ) -> DeliveryResult:
        del message
        self.targets.append(target)
        return DeliveryResult("succeeded", "accepted")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _browser_p256dh() -> str:
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return _b64url(
        public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


def _push_payload(endpoint: str, *, device_name: str) -> dict[str, object]:
    return {
        "endpoint": endpoint,
        "keys": {"p256dh": _browser_p256dh(), "auth": _b64url(os.urandom(16))},
        "device_name": device_name,
        "user_agent": f"{device_name} user agent",
    }


def test_channel_crud_encrypts_and_redacts_secrets(
    client: TestClient, auth: dict[str, str], app
) -> None:
    raw_token = "telegram-token-that-must-never-leak"
    created = client.post(
        "/api/v1/channels",
        headers=auth,
        json={
            "name": "Operator Telegram",
            "kind": "telegram",
            "config": {"bot_token": raw_token, "chat_id": "123456"},
            "eligible_regions": ["eu"],
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert raw_token not in created.text
    assert body["health"] == "not_exercised"
    assert body["success_rate"] is None
    assert body["deliveries_24h"] == 0
    assert body["delivered_24h"] == 0
    assert body["route"] is None
    assert body["route_names"] == []
    assert body["config"]["bot_token"] == "***"
    assert body["config"]["chat_id"] == "123456"
    assert body["eligible_regions"] == ["eu"]

    with app.state.session_factory() as db:
        channel = db.get(NotificationChannel, body["id"])
        assert channel is not None
        assert raw_token.encode() not in channel.encrypted_config
        decrypted = app.state.envelope_cipher.decrypt_json(
            channel.encrypted_config, context=f"channel:{channel.id}:config"
        )
        assert decrypted["bot_token"] == raw_token

    updated = client.patch(
        f"/api/v1/channels/{body['id']}",
        headers=auth,
        json={"config": {"bot_token": "***", "chat_id": "654321"}},
    )
    assert updated.status_code == 200, updated.text
    assert raw_token not in updated.text
    with app.state.session_factory() as db:
        channel = db.get(NotificationChannel, body["id"])
        assert channel is not None
        decrypted = app.state.envelope_cipher.decrypt_json(
            channel.encrypted_config, context=f"channel:{channel.id}:config"
        )
        assert decrypted == {"bot_token": raw_token, "chat_id": "654321"}

    provider = _SuccessfulProvider()
    app.state.notification_providers = ProviderRegistry({"telegram": provider})
    tested = client.post(f"/api/v1/channels/{body['id']}/test", headers=auth)
    assert tested.status_code == 200
    assert tested.json()["status"] == "succeeded"
    assert tested.json()["attempted"] is True
    assert tested.json()["ok"] is True
    assert provider.targets[0].config["bot_token"] == raw_token
    assert raw_token not in tested.text

    listing = client.get("/api/v1/channels", headers=auth)
    assert listing.status_code == 200
    assert len(listing.json()) == 1
    assert raw_token not in listing.text

    deleted = client.delete(f"/api/v1/channels/{body['id']}", headers=auth)
    assert deleted.status_code == 204
    assert client.get("/api/v1/channels", headers=auth).json() == []


def test_generic_webhook_channel_blocks_ssrf(client: TestClient, auth: dict[str, str]) -> None:
    for url in ("http://example.com/hook", "https://127.0.0.1/hook"):
        response = client.post(
            "/api/v1/channels",
            headers=auth,
            json={
                "name": "Unsafe webhook",
                "kind": "generic_webhook",
                "config": {"url": url},
            },
        )
        assert response.status_code == 422, response.text

    safe = client.post(
        "/api/v1/channels",
        headers=auth,
        json={
            "name": "Safe webhook",
            "kind": "generic_webhook",
            "config": {
                "url": "https://1.1.1.1/notify?key=secret-query",
                "headers": {"Authorization": "Bearer hidden"},
            },
        },
    )
    assert safe.status_code == 201, safe.text
    assert "secret-query" not in safe.text
    assert "Bearer hidden" not in safe.text
    assert safe.json()["config"]["headers"]["Authorization"] == "***"


def test_smtp_template_config_is_validated_on_create_and_patch(
    client: TestClient,
    auth: dict[str, str],
) -> None:
    base_config = {
        "host": "smtp.example.test",
        "port": 587,
        "tls": "starttls",
        "from": "alerts@example.test",
        "to": ["operator@example.test"],
    }
    created = client.post(
        "/api/v1/channels",
        headers=auth,
        json={
            "name": "Templated email",
            "kind": "smtp",
            "config": {
                **base_config,
                "subject_template": "{{state}} {{severity_upper}} {{title}}",
                "body_template": "{{body}}{{incident_link}}",
            },
        },
    )
    assert created.status_code == 201, created.text
    channel_id = created.json()["id"]
    assert created.json()["config"]["subject_template"] == (
        "{{state}} {{severity_upper}} {{title}}"
    )

    for template in ("{{unknown_placeholder}}", "Alert\r\nBcc: attacker@example.test"):
        invalid_create = client.post(
            "/api/v1/channels",
            headers=auth,
            json={
                "name": "Invalid email",
                "kind": "smtp",
                "config": {**base_config, "subject_template": template},
            },
        )
        assert invalid_create.status_code == 422, invalid_create.text

        invalid_patch = client.patch(
            f"/api/v1/channels/{channel_id}",
            headers=auth,
            json={"config": {"subject_template": template}},
        )
        assert invalid_patch.status_code == 422, invalid_patch.text

    malformed_body = client.patch(
        f"/api/v1/channels/{channel_id}",
        headers=auth,
        json={"config": {"body_template": "{{title.__class__}}"}},
    )
    assert malformed_body.status_code == 422, malformed_body.text

    reset = client.patch(
        f"/api/v1/channels/{channel_id}",
        headers=auth,
        json={"config": {"subject_template": None, "body_template": None}},
    )
    assert reset.status_code == 200, reset.text
    assert "subject_template" not in reset.json()["config"]
    assert "body_template" not in reset.json()["config"]


def test_push_subscription_vapid_devices_and_tombstone(
    client: TestClient,
    auth: dict[str, str],
    app,
    settings,
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
    settings.vapid_private_key_file = private_path
    key_response = client.get("/api/v1/push/vapid-public-key", headers=auth)
    assert key_response.status_code == 200, key_response.text
    assert len(base64.urlsafe_b64decode(key_response.json()["public_key"] + "==")) == 65

    endpoint = "https://1.1.1.1/push/device?credential=never-return-this"
    payload = {
        "endpoint": endpoint,
        "keys": {"p256dh": _browser_p256dh(), "auth": _b64url(os.urandom(16))},
        "device_name": "pytest",
        "user_agent": "pytest browser",
    }
    first = client.post("/api/v1/push/subscriptions", headers=auth, json=payload)
    second = client.post("/api/v1/push/subscriptions", headers=auth, json=payload)
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["id"] == second.json()["id"]
    assert endpoint not in first.text

    with app.state.session_factory() as db:
        subscriptions = db.query(PushSubscription).all()
        assert len(subscriptions) == 1
        assert endpoint.encode() not in subscriptions[0].endpoint
        session = db.scalar(select(AuthSession))
        assert session is not None
        assert subscriptions[0].session_id == session.id

    assert first.json()["session_id"] == subscriptions[0].session_id

    devices = client.get("/api/v1/devices", headers=auth)
    assert devices.status_code == 200
    assert len(devices.json()) == 1
    assert devices.json()[0]["current"] is True
    assert devices.json()[0]["push_enabled"] is True

    removed = client.delete(f"/api/v1/push/subscriptions/{first.json()['id']}", headers=auth)
    assert removed.status_code == 204
    subscriptions = client.get("/api/v1/push/subscriptions", headers=auth).json()
    assert subscriptions[0]["enabled"] is False


def test_duplicate_device_names_keep_push_bound_to_the_correct_session(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    first = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json=_push_payload("https://1.1.1.1/push/first-session", device_name="first platform"),
    )
    assert first.status_code == 201, first.text

    second_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "a-strong-test-password",
            "device_name": "pytest",
        },
    )
    assert second_login.status_code == 200, second_login.text
    second_body = second_login.json()
    second_auth = {
        "Authorization": f"Bearer {second_body['access_token']}",
        "X-CSRF-Token": second_body["csrf_token"],
    }
    second = client.post(
        "/api/v1/push/subscriptions",
        headers=second_auth,
        json=_push_payload("https://1.1.1.1/push/second-session", device_name="second platform"),
    )
    assert second.status_code == 201, second.text

    first_view = client.get("/api/v1/devices", headers=auth)
    second_view = client.get("/api/v1/devices", headers=second_auth)
    assert first_view.status_code == second_view.status_code == 200
    first_current = next(item for item in first_view.json() if item["current"])
    second_current = next(item for item in second_view.json() if item["current"])
    assert first_current["push_subscription_id"] == first.json()["id"]
    assert second_current["push_subscription_id"] == second.json()["id"]
    assert first_current["id"] != second_current["id"]

    revoked = client.delete(
        f"/api/v1/devices/{second_current['id']}/sessions",
        headers=auth,
    )
    assert revoked.status_code == 204, revoked.text
    with app.state.session_factory() as db:
        first_subscription = db.get(PushSubscription, first.json()["id"])
        second_subscription = db.get(PushSubscription, second.json()["id"])
        second_session = db.get(AuthSession, second_current["id"])
        assert first_subscription is not None and first_subscription.disabled_at is None
        assert second_subscription is not None and second_subscription.disabled_at is not None
        assert second_session is not None and second_session.revoked_at is not None
        tombstone = db.scalar(
            select(ClusterEvent).where(
                ClusterEvent.entity_type == "push_subscription",
                ClusterEvent.entity_id == second_subscription.id,
                ClusterEvent.operation == "tombstone",
            )
        )
        assert tombstone is not None
        assert tombstone.payload_json["session_id"] == second_session.id


def test_changed_keys_for_an_active_endpoint_create_a_new_subscription_generation(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    endpoint = "https://1.1.1.1/push/key-rotation"
    first = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json=_push_payload(endpoint, device_name="before key rotation"),
    )
    second = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json=_push_payload(endpoint, device_name="after key rotation"),
    )
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] != second.json()["id"]
    assert first.json()["session_id"] == second.json()["session_id"]

    with app.state.session_factory() as db:
        old_generation = db.get(PushSubscription, first.json()["id"])
        new_generation = db.get(PushSubscription, second.json()["id"])
        assert old_generation is not None and old_generation.disabled_at is not None
        assert new_generation is not None and new_generation.disabled_at is None
        tombstone = db.scalar(
            select(ClusterEvent).where(
                ClusterEvent.entity_type == "push_subscription",
                ClusterEvent.entity_id == old_generation.id,
                ClusterEvent.operation == "tombstone",
            )
        )
        assert tombstone is not None


def test_logout_disables_every_push_subscription_linked_to_the_session(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    subscription_ids: list[str] = []
    for suffix in ("primary", "rotated"):
        response = client.post(
            "/api/v1/push/subscriptions",
            headers=auth,
            json=_push_payload(
                f"https://1.1.1.1/push/logout-{suffix}",
                device_name=f"{suffix} endpoint",
            ),
        )
        assert response.status_code == 201, response.text
        subscription_ids.append(response.json()["id"])

    logged_out = client.post(
        "/api/v1/auth/logout",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": auth["X-CSRF-Token"],
        },
    )
    assert logged_out.status_code == 204, logged_out.text

    with app.state.session_factory() as db:
        subscriptions = [db.get(PushSubscription, item) for item in subscription_ids]
        assert all(item is not None and item.disabled_at is not None for item in subscriptions)
        session_ids = {item.session_id for item in subscriptions if item is not None}
        assert len(session_ids) == 1
        session_id = session_ids.pop()
        assert session_id is not None
        session = db.get(AuthSession, session_id)
        assert session is not None and session.revoked_at is not None
        tombstone_count = len(
            db.scalars(
                select(ClusterEvent).where(
                    ClusterEvent.entity_type == "push_subscription",
                    ClusterEvent.operation == "tombstone",
                )
            ).all()
        )
        assert tombstone_count == 2


def test_existing_browser_endpoint_gets_a_new_id_after_login_to_a_new_session(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    endpoint = "https://1.1.1.1/push/persistent-browser-endpoint"
    first = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json=_push_payload(endpoint, device_name="old platform label"),
    )
    assert first.status_code == 201, first.text
    old_session_id = first.json()["session_id"]
    assert (
        client.post(
            "/api/v1/auth/logout",
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": auth["X-CSRF-Token"],
            },
        ).status_code
        == 204
    )

    login = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "a-strong-test-password"},
    )
    assert login.status_code == 200, login.text
    login_body = login.json()
    new_auth = {"Authorization": f"Bearer {login_body['access_token']}"}
    rebound = client.post(
        "/api/v1/push/subscriptions",
        headers=new_auth,
        json=_push_payload(endpoint, device_name="new platform label"),
    )
    assert rebound.status_code == 201, rebound.text
    assert rebound.json()["id"] != first.json()["id"]
    assert rebound.json()["session_id"] != old_session_id
    assert rebound.json()["enabled"] is True

    with app.state.session_factory() as db:
        subscription = db.get(PushSubscription, rebound.json()["id"])
        previous_subscription = db.get(PushSubscription, first.json()["id"])
        assert subscription is not None
        assert subscription.session_id == rebound.json()["session_id"]
        assert subscription.disabled_at is None
        assert previous_subscription is not None
        assert previous_subscription.session_id == old_session_id
        assert previous_subscription.disabled_at is not None
        old_session = db.get(AuthSession, old_session_id)
        assert old_session is not None and old_session.revoked_at is not None
        tombstone = db.scalar(
            select(ClusterEvent).where(
                ClusterEvent.entity_type == "push_subscription",
                ClusterEvent.entity_id == previous_subscription.id,
                ClusterEvent.operation == "tombstone",
            )
        )
        assert tombstone is not None


def test_legacy_unbound_push_is_not_attributed_to_a_session(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    created = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json=_push_payload("https://1.1.1.1/push/legacy", device_name="pytest"),
    )
    assert created.status_code == 201, created.text
    with app.state.session_factory.begin() as db:
        subscription = db.get(PushSubscription, created.json()["id"])
        assert subscription is not None
        subscription.session_id = None

    single_session = client.get("/api/v1/devices", headers=auth)
    assert single_session.status_code == 200
    assert single_session.json()[0]["push_subscription_id"] is None
    assert single_session.json()[0]["push_enabled"] is False

    second_login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "a-strong-test-password",
            "device_name": "pytest",
        },
    )
    assert second_login.status_code == 200, second_login.text
    ambiguous = client.get("/api/v1/devices", headers=auth)
    assert ambiguous.status_code == 200
    assert len(ambiguous.json()) == 2
    assert all(item["push_enabled"] is False for item in ambiguous.json())


@pytest.mark.parametrize(
    ("p256dh", "auth_key", "detail"),
    [
        (_browser_p256dh() + "=", _b64url(os.urandom(16)), "canonical unpadded base64url"),
        (_b64url(b"\x04" + (b"\x00" * 63)), _b64url(os.urandom(16)), "invalid decoded length"),
        (
            _b64url(b"\x04" + (b"\x00" * 64)),
            _b64url(os.urandom(16)),
            "valid uncompressed P-256 public key",
        ),
        (_browser_p256dh(), _b64url(os.urandom(15)), "invalid decoded length"),
        (_browser_p256dh(), _b64url(os.urandom(16)) + "=", "canonical unpadded base64url"),
    ],
)
def test_push_subscription_rejects_non_browser_key_material(
    client: TestClient,
    auth: dict[str, str],
    p256dh: str,
    auth_key: str,
    detail: str,
) -> None:
    response = client.post(
        "/api/v1/push/subscriptions",
        headers=auth,
        json={
            "endpoint": "https://1.1.1.1/push/invalid-device",
            "keys": {"p256dh": p256dh, "auth": auth_key},
        },
    )

    assert response.status_code == 422, response.text
    assert detail in response.text


def test_device_session_revocation_audit_and_summary(
    client: TestClient, auth: dict[str, str]
) -> None:
    login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "a-strong-test-password",
            "device_name": "second browser",
        },
    )
    assert login.status_code == 200, login.text
    devices = client.get("/api/v1/devices", headers=auth).json()
    assert len(devices) == 2
    second = next(item for item in devices if not item["current"])
    revoked = client.delete(f"/api/v1/devices/{second['id']}/sessions", headers=auth)
    assert revoked.status_code == 204
    assert len(client.get("/api/v1/devices", headers=auth).json()) == 1

    audit = client.get("/api/v1/audit", headers=auth)
    assert audit.status_code == 200
    actions = {item["action_code"] for item in audit.json()["items"]}
    assert "session_revoked" in actions
    assert "login_succeeded" in actions

    summary = client.get("/api/v1/metrics/summary", headers=auth)
    assert summary.status_code == 200
    assert summary.json()["open"] == 0
    assert summary.json()["delivery_rate"] is None
    reachability = client.get("/api/v1/metrics/reachability", headers=auth)
    assert reachability.json()["status"] == "not_configured"


def test_auth_sets_dedicated_stream_cookie(client: TestClient, auth: dict[str, str]) -> None:
    del auth
    assert client.cookies.get("alert_hub_stream")


def test_only_double_submit_cookie_is_browser_readable(
    client: TestClient, auth: dict[str, str]
) -> None:
    del auth
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "a-strong-test-password",
            "device_name": "cookie attribute test",
        },
    )
    assert response.status_code == 200, response.text
    cookies = {
        header.partition("=")[0]: header for header in response.headers.get_list("set-cookie")
    }

    assert "HttpOnly" in cookies["alert_hub_refresh"]
    assert "HttpOnly" in cookies["alert_hub_stream"]
    assert "HttpOnly" not in cookies["alert_hub_csrf"]
    assert "SameSite=strict" in cookies["alert_hub_csrf"]
    assert "Path=/" in cookies["alert_hub_csrf"]
    body = response.json()
    refresh_token = response.cookies["alert_hub_refresh"]
    csrf_token = response.cookies["alert_hub_csrf"]
    assert csrf_token == body["csrf_token"]
    assert len({body["access_token"], refresh_token, csrf_token}) == 3


def test_stream_cookie_authenticates_initial_sse_event(
    client: TestClient, auth: dict[str, str], app
) -> None:
    del auth
    token = client.cookies.get("alert_hub_stream")
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/stream",
            "raw_path": b"/api/v1/stream",
            "query_string": b"",
            "headers": [(b"cookie", f"alert_hub_stream={token}".encode())],
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
            "app": app,
        }
    )
    response = stream_endpoint(request)

    async def first_event() -> str:
        value = await anext(response.body_iterator)
        await response.body_iterator.aclose()
        return value

    value = asyncio.run(first_event())
    assert "data:" in value
    assert '"type":"ready"' in value


def test_production_startup_requires_master_key(tmp_path: Path) -> None:
    settings = Settings(
        environment="production",
        database_url=f"sqlite:///{tmp_path / 'production.db'}",
        auto_create_schema=False,
        signing_key="production-signing-key-4SRfMvKz7pX2b9Qa",
        cluster_secret="production-cluster-key-8TyD3wHn6LcP5rVe",
        bootstrap_token="production-bootstrap",
        cookie_secure=True,
        public_api_url="https://hub.example",
        trusted_origins=["https://hub.example"],
        heartbeat_scan_seconds=0,
    )
    with pytest.raises(RuntimeError, match="MASTER_ENCRYPTION_KEY_FILE"):
        create_app(settings)
