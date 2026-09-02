from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from alert_hub.main import create_app
from alert_hub.settings import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        auto_create_schema=True,
        node_id="test-node",
        node_name="Test node",
        node_region="test",
        signing_key="test-signing-key-with-enough-entropy",
        cluster_secret="test-cluster-key-with-enough-entropy",
        bootstrap_token="bootstrap-test-token",
        cookie_secure=False,
        trusted_origins=["http://testserver"],
        # TestClient uses a non-IP peer label; focused tests exercise the CIDR boundary.
        peer_allowed_cidrs=[],
        heartbeat_scan_seconds=0,
    )


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app, base_url="http://testserver") as test_client:
        yield test_client


@pytest.fixture
def auth(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": "bootstrap-test-token",
            "username": "admin",
            "password": "a-strong-test-password",
            "device_name": "pytest",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return {
        "Authorization": f"Bearer {body['access_token']}",
        "X-CSRF-Token": body["csrf_token"],
    }
