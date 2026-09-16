from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import AuditLog, ServiceToken


def _create_token(client: TestClient, auth: dict[str, str]) -> dict[str, object]:
    response = client.post(
        "/api/v1/service-tokens",
        headers=auth,
        json={"name": "Codex MCP", "expires_in_days": 30},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_service_token_is_one_time_read_only_and_audited(client, app, auth) -> None:
    created = _create_token(client, auth)
    raw_token = str(created["token"])
    token_id = str(created["id"])
    assert raw_token.startswith(f"ahs_{token_id}.")
    assert created["scopes"] == ["mcp:read"]

    listed = client.get("/api/v1/service-tokens", headers=auth)
    assert listed.status_code == 200, listed.text
    assert listed.json()[0]["id"] == token_id
    assert "token" not in listed.json()[0]

    service_auth = {"Authorization": f"Bearer {raw_token}"}
    incidents = client.get("/api/v1/incidents", headers=service_auth)
    assert incidents.status_code == 200, incidents.text
    assert incidents.json()["items"] == []
    summary = client.get("/api/v1/metrics/summary", headers=service_auth)
    assert summary.status_code == 200, summary.text

    mutation = client.post(
        "/api/v1/incidents/not-present/comments",
        headers=service_auth,
        json={"body": "must not be accepted"},
    )
    assert mutation.status_code == 403
    assert mutation.json()["detail"] == "Service token is read-only"

    admin_read = client.get("/api/v1/sources", headers=service_auth)
    assert admin_read.status_code == 403
    assert admin_read.json()["detail"] == "Service token cannot access this endpoint"

    with app.state.session_factory() as db:
        stored = db.get(ServiceToken, token_id)
        assert stored is not None
        assert stored.token_hash not in raw_token
        assert raw_token not in str(stored.token_hash)
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.action == "service_token_created",
                AuditLog.entity_id == token_id,
            )
        )
        assert audit is not None
        assert raw_token not in str(audit.details_json)

    revoked = client.delete(f"/api/v1/service-tokens/{token_id}", headers=auth)
    assert revoked.status_code == 204, revoked.text
    denied = client.get("/api/v1/incidents", headers=service_auth)
    assert denied.status_code == 401

    active = client.get("/api/v1/service-tokens", headers=auth)
    assert active.status_code == 200
    assert active.json() == []
    all_tokens = client.get("/api/v1/service-tokens?include_revoked=true", headers=auth)
    assert all_tokens.status_code == 200
    assert all_tokens.json()[0]["revoked_at"] is not None


def test_expired_and_malformed_service_tokens_fail_closed(client, app, auth) -> None:
    created = _create_token(client, auth)
    service_auth = {"Authorization": f"Bearer {created['token']}"}

    with app.state.session_factory.begin() as db:
        stored = db.get(ServiceToken, str(created["id"]))
        assert stored is not None
        stored.expires_at = utc_now() - timedelta(seconds=1)

    expired = client.get("/api/v1/incidents", headers=service_auth)
    assert expired.status_code == 401
    malformed = client.get(
        "/api/v1/incidents",
        headers={"Authorization": "Bearer ahs_not-a-uuid.secret"},
    )
    assert malformed.status_code == 401
    assert malformed.json()["detail"] == "Invalid service token"
