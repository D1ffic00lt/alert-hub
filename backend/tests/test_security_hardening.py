from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from alert_hub.api import auth as auth_api
from alert_hub.application.sync import IncomingClusterEvent
from alert_hub.infrastructure.db.models import AuditLog
from alert_hub.infrastructure.rate_limit import LocalRateLimiter
from alert_hub.infrastructure.request_security import (
    address_in_cidrs,
    normalize_cidrs,
    resolve_client_ip,
)
from alert_hub.main import _validate_production_settings, create_app
from alert_hub.metrics import CLOCK_SKEW_SUSPECTED
from alert_hub.security import DUMMY_PASSWORD_HASH, password_needs_rehash
from alert_hub.settings import Settings
from alert_hub.workers.sync import clock_skew_exceeds_threshold, record_clock_skew


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _request(peer: str, headers: dict[str, str] | None = None) -> Request:
    raw_headers = [
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": raw_headers,
            "client": (peer, 12345),
            "server": ("hub.example", 443),
        }
    )


def _bootstrap(client: TestClient, token: str = "bootstrap-test-token") -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": token,
            "username": "admin",
            "password": "a-strong-test-password",
            "device_name": "security-test",
        },
    )
    assert response.status_code == 201, response.text
    return {
        "Authorization": f"Bearer {response.json()['access_token']}",
        "X-CSRF-Token": response.json()["csrf_token"],
    }


def _event(origin: str, occurred_at: datetime) -> IncomingClusterEvent:
    return IncomingClusterEvent(
        event_id=f"event-{origin}-{occurred_at.timestamp()}",
        origin_node_id=origin,
        origin_seq=1,
        entity_type="security-test",
        entity_id="entity",
        operation="upsert",
        occurred_at=occurred_at,
        payload={},
    )


def test_client_ip_resolver_ignores_spoofing_and_walks_only_trusted_hops() -> None:
    trusted = ["10.0.0.0/8", "127.0.0.1/32"]

    untrusted = _request("198.51.100.9", {"X-Forwarded-For": "203.0.113.8"})
    assert resolve_client_ip(untrusted, trusted) == "198.51.100.9"

    chained = _request(
        "10.0.0.3",
        {"X-Forwarded-For": "203.0.113.8, 10.0.0.2"},
    )
    assert resolve_client_ip(chained, trusted) == "203.0.113.8"

    injected_leftmost = _request(
        "10.0.0.3",
        {"X-Forwarded-For": "192.0.2.44, 203.0.113.8"},
    )
    assert resolve_client_ip(injected_leftmost, trusted) == "203.0.113.8"

    malformed = _request("10.0.0.3", {"X-Forwarded-For": "not-an-ip"})
    assert resolve_client_ip(malformed, trusted) == "10.0.0.3"

    forwarded = _request(
        "10.0.0.3",
        {"Forwarded": 'for="[2001:db8::12]:4711";proto=https, for=10.0.0.2'},
    )
    assert resolve_client_ip(forwarded, trusted) == "2001:db8::12"


def test_cidrs_are_canonical_and_invalid_values_fail_closed() -> None:
    assert normalize_cidrs(["10.2.3.4/8", "10.0.0.0/8", "2001:db8::3/64"]) == [
        "10.0.0.0/8",
        "2001:db8::/64",
    ]
    assert address_in_cidrs("10.9.8.7", ["10.0.0.0/8"])
    assert not address_in_cidrs("not-an-ip", ["10.0.0.0/8"])
    parsed = Settings(
        trusted_proxy_cidrs=["10.2.3.4/8"],
        peer_allowed_cidrs=["2001:db8::4/64"],
    )
    assert parsed.trusted_proxy_cidrs == ["10.0.0.0/8"]
    assert parsed.peer_allowed_cidrs == ["2001:db8::/64"]
    with pytest.raises(ValueError, match="invalid CIDR"):
        normalize_cidrs(["10.0.0.0/99"])
    with pytest.raises(ValueError, match="invalid CIDR"):
        Settings(peer_allowed_cidrs=["not-a-network"])


def test_local_rate_limiter_boundaries_cleanup_and_capacity_are_deterministic() -> None:
    clock = _Clock()
    limiter = LocalRateLimiter(max_keys=2, cleanup_interval_seconds=5, clock=clock)

    assert limiter.check("login", "one", limit=2, window_seconds=10).allowed
    assert limiter.check("login", "one", limit=2, window_seconds=10).allowed
    denied = limiter.check("login", "one", limit=2, window_seconds=10)
    assert not denied.allowed
    assert denied.retry_after == 10

    clock.advance(9.1)
    assert limiter.check("login", "one", limit=2, window_seconds=10).retry_after == 1
    clock.advance(0.9)
    assert limiter.check("login", "one", limit=2, window_seconds=10).allowed

    limiter.check("login", "two", limit=1, window_seconds=10)
    limiter.check("login", "three", limit=1, window_seconds=10)
    assert limiter.size == 2
    assert not limiter.check("login", "four", limit=1, window_seconds=10).allowed
    clock.advance(10)
    assert limiter.cleanup() == 0


def test_http_rate_limits_run_before_argon_source_auth_and_bootstrap_work(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hardened = settings.model_copy(
        update={
            "bootstrap_rate_limit_attempts": 1,
            "login_rate_limit_attempts": 1,
            "ingest_rate_limit_attempts": 1,
        }
    )
    app = create_app(hardened)
    calls: list[str] = []
    original_verify = auth_api.verify_password

    def observed_verify(password_hash: str, password: str) -> bool:
        calls.append(password_hash)
        return original_verify(password_hash, password)

    monkeypatch.setattr(auth_api, "verify_password", observed_verify)
    with TestClient(app, base_url="http://testserver", client=("127.0.0.1", 50000)) as client:
        auth = _bootstrap(client)
        second_bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": "bootstrap-test-token",
                "username": "other",
                "password": "another-strong-password",
            },
        )
        assert second_bootstrap.status_code == 429
        assert int(second_bootstrap.headers["Retry-After"]) >= 1

        missing = client.post(
            "/api/v1/auth/login",
            json={"username": "missing", "password": "wrong", "device_name": "test"},
        )
        assert missing.status_code == 401
        assert calls == [DUMMY_PASSWORD_HASH]
        limited_login = client.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://testserver"},
            json={"username": "missing", "password": "wrong", "device_name": "test"},
        )
        assert limited_login.status_code == 429
        assert limited_login.headers["Access-Control-Allow-Origin"] == "http://testserver"
        assert calls == [DUMMY_PASSWORD_HASH]

        source = client.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "limited", "kind": "generic_json"},
        ).json()
        ingest_url = f"/ingest/v1/events/{source['id']}"
        first_ingest = client.post(
            ingest_url,
            headers={"Authorization": "Bearer wrong"},
            json={"status": "firing", "title": "rejected"},
        )
        assert first_ingest.status_code == 401
        limited_ingest = client.post(
            f"{ingest_url}-rotated-attacker-id",
            headers={"Authorization": f"Bearer {source['token']}"},
            json={"status": "firing", "title": "must not parse"},
        )
        assert limited_ingest.status_code == 429

        with app.state.session_factory() as db:
            actions = set(db.scalars(select(AuditLog.action)).all())
        assert {
            "bootstrap_rate_limited",
            "login_rate_limited",
            "ingest_rate_limited",
        }.issubset(actions)

    assert not password_needs_rehash(DUMMY_PASSWORD_HASH)


def test_chunked_ingest_stops_reading_as_soon_as_payload_limit_is_exceeded(
    settings: Settings,
) -> None:
    app = create_app(settings.model_copy(update={"max_payload_bytes": 1_024}))
    with TestClient(app, base_url="http://testserver") as client:
        auth = _bootstrap(client)
        created = client.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "chunked", "kind": "generic_json"},
        )
        assert created.status_code == 201, created.text
        source = created.json()

        async def send_chunked() -> tuple[httpx.Response, list[int]]:
            consumed: list[int] = []

            async def body() -> Any:
                for chunk in (b"{" + b"x" * 699, b"y" * 700, b"never-consumed"):
                    consumed.append(len(chunk))
                    yield chunk

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as async_client:
                response = await async_client.post(
                    f"/ingest/v1/events/{source['id']}",
                    headers={
                        "Authorization": f"Bearer {source['token']}",
                        "X-Request-ID": "chunked-too-large",
                    },
                    content=body(),
                )
            return response, consumed

        response, consumed = asyncio.run(send_chunked())

    assert response.request.headers["Transfer-Encoding"] == "chunked"
    assert "Content-Length" not in response.request.headers
    assert response.status_code == 413
    assert response.json() == {"detail": "Payload too large"}
    assert response.headers["X-Request-ID"] == "chunked-too-large"
    assert consumed == [700, 700]


def test_ingest_body_limit_preserves_valid_chunked_and_regular_requests(
    settings: Settings,
) -> None:
    app = create_app(settings.model_copy(update={"max_payload_bytes": 1_024}))
    with TestClient(app, base_url="http://testserver") as client:
        auth = _bootstrap(client)
        created = client.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "body-limit", "kind": "generic_json"},
        )
        assert created.status_code == 201, created.text
        source = created.json()
        url = f"/ingest/v1/events/{source['id']}"
        source_auth = {"Authorization": f"Bearer {source['token']}"}

        async def send_chunked() -> httpx.Response:
            payload = json.dumps(
                {
                    "external_event_id": "chunked-valid",
                    "dedup_key": "chunked-valid",
                    "status": "firing",
                    "title": "Valid chunked body",
                }
            ).encode()

            async def body() -> Any:
                yield payload[:17]
                yield payload[17:]

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as async_client:
                return await async_client.post(url, headers=source_auth, content=body())

        chunked = asyncio.run(send_chunked())
        regular = client.post(
            url,
            headers=source_auth,
            json={
                "external_event_id": "regular-valid",
                "dedup_key": "regular-valid",
                "status": "firing",
                "title": "Valid regular body",
            },
        )
        regular_too_large = client.post(url, headers=source_auth, content=b"x" * 1_025)

    assert chunked.request.headers["Transfer-Encoding"] == "chunked"
    assert chunked.status_code == 200, chunked.text
    assert regular.status_code == 200, regular.text
    assert regular_too_large.status_code == 413
    assert regular_too_large.json() == {"detail": "Payload too large"}


def test_refresh_requires_exact_origin_and_authenticated_responses_are_partitioned(
    client: TestClient,
    auth: dict[str, str],
) -> None:
    me = client.get("/api/v1/auth/me", headers=auth)
    assert me.status_code == 200
    assert me.headers["X-Alert-Hub-Cache-Partition"]
    assert "X-Alert-Hub-Cache-Partition" in me.headers["Vary"]

    csrf = auth["X-CSRF-Token"]
    missing = client.post("/api/v1/auth/refresh", headers={"X-CSRF-Token": csrf})
    wrong = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://evil.example", "X-CSRF-Token": csrf},
    )
    trailing = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://testserver/", "X-CSRF-Token": csrf},
    )
    mismatched = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://testserver", "X-CSRF-Token": f"{csrf}-wrong"},
    )
    assert missing.status_code == wrong.status_code == trailing.status_code == 403
    assert mismatched.status_code == 403

    exact = client.post(
        "/api/v1/auth/refresh",
        headers={"Origin": "http://testserver", "X-CSRF-Token": csrf},
    )
    assert exact.status_code == 200, exact.text
    assert exact.headers["Cache-Control"] == "private, no-store"
    assert exact.headers["X-Alert-Hub-Cache-Partition"]

    refreshed_csrf = exact.json()["csrf_token"]
    missing_logout_origin = client.post(
        "/api/v1/auth/logout",
        headers={"X-CSRF-Token": refreshed_csrf},
    )
    assert missing_logout_origin.status_code == 403
    logout = client.post(
        "/api/v1/auth/logout",
        headers={"Origin": "http://testserver", "X-CSRF-Token": refreshed_csrf},
    )
    assert logout.status_code == 204

    preflight = client.options(
        "/api/v1/auth/me",
        headers={
            "Origin": "http://testserver",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Alert-Hub-Cache-Partition",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["Access-Control-Allow-Origin"] == "http://testserver"


def test_source_allowed_cidrs_are_normalized_enforced_and_non_oracular(
    settings: Settings,
) -> None:
    app = create_app(settings)
    payload = {
        "external_event_id": "cidr-event",
        "dedup_key": "cidr-test",
        "status": "firing",
        "title": "CIDR test",
    }
    with TestClient(app, base_url="http://testserver", client=("127.0.0.1", 50000)) as client:
        auth = _bootstrap(client)
        created = client.post(
            "/api/v1/sources",
            headers=auth,
            json={
                "name": "restricted",
                "kind": "generic_json",
                "allowed_cidrs": ["203.0.113.42/24", "203.0.113.0/24"],
            },
        )
        assert created.status_code == 201, created.text
        source = created.json()
        assert source["allowed_cidrs"] == ["203.0.113.0/24"]
        assert source["config"]["allowed_cidrs"] == ["203.0.113.0/24"]
        url = f"/ingest/v1/events/{source['id']}"

        allowed = client.post(
            url,
            headers={
                "Authorization": f"Bearer {source['token']}",
                "X-Forwarded-For": "203.0.113.55",
            },
            json=payload,
        )
        denied = client.post(
            url,
            headers={
                "Authorization": f"Bearer {source['token']}",
                "X-Forwarded-For": "198.51.100.5",
            },
            json={**payload, "external_event_id": "denied"},
        )
        bad_token = client.post(
            url,
            headers={
                "Authorization": "Bearer wrong",
                "X-Forwarded-For": "203.0.113.55",
            },
            json={**payload, "external_event_id": "bad-token"},
        )
        assert allowed.status_code == 200, allowed.text
        assert denied.status_code == bad_token.status_code == 401
        assert denied.json() == bad_token.json() == {"detail": "Invalid source credentials"}

        invalid_patch = client.patch(
            f"/api/v1/sources/{source['id']}",
            headers=auth,
            json={"allowed_cidrs": ["invalid"]},
        )
        assert invalid_patch.status_code == 422
        cleared = client.patch(
            f"/api/v1/sources/{source['id']}",
            headers=auth,
            json={"allowed_cidrs": []},
        )
        assert cleared.status_code == 200
        assert cleared.json()["allowed_cidrs"] == []
        assert cleared.json()["config"]["allowed_cidrs"] == []


def test_peer_cidr_auth_and_rate_failures_are_audited_without_secrets(
    settings: Settings,
) -> None:
    cluster_secret = settings.cluster_secret
    hardened = settings.model_copy(
        update={
            "peer_allowed_cidrs": ["10.0.0.0/8"],
            "peer_rate_limit_attempts": 2,
        }
    )
    app = create_app(hardened)
    path = "/internal/v1/sync/cursors"
    with TestClient(app, base_url="http://testserver", client=("127.0.0.1", 50000)) as client:
        failed_auth = client.get(
            path,
            headers={"Authorization": "Bearer never-log-me", "X-Forwarded-For": "10.0.0.5"},
        )
        allowed = client.get(
            path,
            headers={
                "Authorization": f"Bearer {cluster_secret}",
                "X-Forwarded-For": "10.0.0.5",
            },
        )
        limited = client.get(
            path,
            headers={
                "Authorization": f"Bearer {cluster_secret}",
                "X-Forwarded-For": "10.0.0.5",
            },
        )
        disallowed = client.get(
            path,
            headers={
                "Authorization": f"Bearer {cluster_secret}",
                "X-Forwarded-For": "203.0.113.9",
            },
        )
        assert failed_auth.status_code == 401
        assert allowed.status_code == 200
        assert limited.status_code == 429
        assert int(limited.headers["Retry-After"]) >= 1
        assert disallowed.status_code == 403

        with app.state.session_factory() as db:
            rows = db.scalars(
                select(AuditLog).where(
                    AuditLog.action.in_(
                        ["cluster_auth_failed", "cluster_rate_limited", "cluster_peer_denied"]
                    )
                )
            ).all()
        assert {row.action for row in rows} == {
            "cluster_auth_failed",
            "cluster_rate_limited",
            "cluster_peer_denied",
        }
        serialized = json.dumps([row.details_json for row in rows])
        assert cluster_secret not in serialized
        assert "never-log-me" not in serialized


def _production_settings(tmp_path: Path, **updates: Any) -> Settings:
    master_key = tmp_path / "master-key"
    master_key.write_bytes(b"m" * 32)
    values: dict[str, Any] = {
        "environment": "production",
        "database_url": f"sqlite:///{tmp_path / 'production.db'}",
        "auto_create_schema": False,
        "signing_key": "sV9!kQ2@pL7#xR4$wT8%zN5&cD1*eF6+",
        "cluster_secret": "gH3!uJ8@bM2#qW7$rY4%vC9&nK5*aP1+",
        "master_encryption_key_file": master_key,
        "cookie_secure": True,
        "public_api_url": "https://hub.example",
        "trusted_origins": ["https://hub.example"],
        "peer_allowed_cidrs": ["10.0.0.0/8"],
    }
    values.update(updates)
    return Settings(**values)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"cookie_secure": False}, "COOKIE_SECURE"),
        ({"public_api_url": "http://hub.example"}, "exact HTTPS"),
        ({"public_api_url": "https://hub.example/path"}, "exact HTTPS"),
        ({"public_api_url": "https://127.0.0.1"}, "exact HTTPS"),
        ({"grafana_url": "http://grafana.example/d/ops"}, "GRAFANA_URL"),
        ({"trusted_origins": ["http://hub.example"]}, "use HTTPS"),
        ({"trusted_origins": ["https://other.example"]}, "must be present"),
        ({"cookie_domain": "other.example"}, "COOKIE_DOMAIN"),
        ({"peer_allowed_cidrs": []}, "PEER_ALLOWED_CIDRS"),
        (
            {"peer_urls": ["https://peer.example"]},
            "literal RFC 1918 or ULA",
        ),
        (
            {"peer_urls": ["https://203.0.113.10:8080"]},
            "literal RFC 1918 or ULA",
        ),
        (
            {
                "cluster_secret": "sV9!kQ2@pL7#xR4$wT8%zN5&cD1*eF6+",
            },
            "distinct",
        ),
        ({"signing_key": "too-short"}, "high entropy"),
        ({"cluster_previous_secret": "old"}, "previous cluster secret must be high entropy"),
        ({"master_encryption_key_file": None}, "MASTER_ENCRYPTION_KEY_FILE"),
    ],
)
def test_production_startup_invariants(
    tmp_path: Path,
    updates: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(RuntimeError, match=message):
        _validate_production_settings(_production_settings(tmp_path, **updates))


def test_valid_production_settings_and_unsafe_origin_cookie_shapes(tmp_path: Path) -> None:
    settings = _production_settings(
        tmp_path,
        peer_urls=["http://10.42.0.2:8080", "http://[fd42::2]:8080"],
    )
    _validate_production_settings(settings)
    app = create_app(settings)
    app.state.engine.dispose()

    with pytest.raises(ValueError, match="wildcards"):
        Settings(trusted_origins=["*"])
    with pytest.raises(ValueError, match="path"):
        Settings(trusted_origins=["https://hub.example/path"])
    with pytest.raises(ValueError, match="COOKIE_DOMAIN"):
        Settings(cookie_domain="localhost")
    with pytest.raises(ValueError, match="node URLs"):
        Settings(public_api_url="ftp://hub.example")
    with pytest.raises(ValueError, match="wildcards"):
        Settings(peer_urls=["https://*.peer.example"])


def test_clock_skew_threshold_and_metric_are_observable() -> None:
    observed_at = datetime(2026, 9, 2, 12, tzinfo=UTC)
    assert not clock_skew_exceeds_threshold(observed_at + timedelta(seconds=300), observed_at, 300)
    assert clock_skew_exceeds_threshold(observed_at + timedelta(seconds=301), observed_at, 300)

    suspected = record_clock_skew(
        [
            _event("skewed-origin", observed_at - timedelta(seconds=301)),
            _event("healthy-origin", observed_at + timedelta(seconds=5)),
        ],
        peer_node_id="security-peer",
        observed_at=observed_at,
        threshold_seconds=300,
    )
    assert suspected == {"skewed-origin": True, "healthy-origin": False}
    assert CLOCK_SKEW_SUSPECTED.labels(peer_node_id="security-peer")._value.get() == 1
    record_clock_skew(
        [_event("later-healthy-origin", observed_at)],
        peer_node_id="security-peer",
        observed_at=observed_at,
        threshold_seconds=300,
        already_suspected=True,
    )
    assert CLOCK_SKEW_SUSPECTED.labels(peer_node_id="security-peer")._value.get() == 1
