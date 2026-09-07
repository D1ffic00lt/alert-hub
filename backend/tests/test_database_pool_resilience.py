from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from alert_hub.api.dependencies import get_db
from alert_hub.api.stream import stream
from alert_hub.main import create_app
from alert_hub.settings import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'pool.db'}",
        auto_create_schema=True,
        node_id="pool-node",
        node_name="Pool node",
        node_region="test",
        signing_key="test-signing-key-with-enough-entropy",
        cluster_secret="test-cluster-key-with-enough-entropy",
        bootstrap_token="bootstrap-test-token",
        cookie_secure=False,
        trusted_origins=["http://testserver"],
        peer_allowed_cidrs=[],
        heartbeat_scan_seconds=0,
        notify_enabled=False,
        database_public_read_limit=8,
    )


def _stream_request(app: Any, token: str) -> Request:
    return Request(
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


def test_bootstrap_wave_keeps_health_responsive_with_open_sse_connections(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    app = create_app(settings)
    release = threading.Event()
    started = threading.Condition()
    active_holders = 0

    @app.get("/test/db-hold")
    def hold_database_connection(db: Session = Depends(get_db)) -> dict[str, bool]:
        nonlocal active_holders
        db.execute(select(1))
        with started:
            active_holders += 1
            started.notify_all()
        release.wait(timeout=3)
        return {"ok": True}

    with TestClient(app, base_url="http://testserver") as client:
        authenticated = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": "bootstrap-test-token",
                "username": "admin",
                "password": "a-strong-test-password",
                "device_name": "pool-test",
            },
        )
        assert authenticated.status_code == 201, authenticated.text
        stream_token = client.cookies.get(settings.stream_cookie_name)
        assert stream_token is not None
        streams = [stream(_stream_request(app, stream_token)) for _ in range(3)]

        async def open_streams() -> None:
            for response in streams:
                ready = await anext(response.body_iterator)
                assert '"type":"ready"' in ready

        asyncio.run(open_streams())

        with ThreadPoolExecutor(max_workers=24) as executor:
            requests = [executor.submit(client.get, "/test/db-hold") for _ in range(20)]
            with started:
                assert started.wait_for(
                    lambda: active_holders == settings.database_public_read_limit,
                    timeout=2,
                )

            health_started = time.monotonic()
            assert client.get("/health/live").status_code == 200
            assert client.get("/health/ready").status_code == 200
            assert time.monotonic() - health_started < 1.0

            worker_started = time.monotonic()
            with app.state.session_factory() as worker_db:
                worker_db.execute(select(1))
            assert time.monotonic() - worker_started < 1.0

            release.set()
            assert [future.result(timeout=3).status_code for future in requests] == [200] * 20

        async def close_streams() -> None:
            for response in streams:
                await response.body_iterator.aclose()

        asyncio.run(close_streams())
        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "alert_hub_db_pool_events_total" in metrics.text
        assert "alert_hub_db_pool_connections" in metrics.text
        assert "alert_hub_db_pool_acquire_seconds" in metrics.text
        assert "alert_hub_db_pool_acquire_timeouts_total" in metrics.text


def test_database_pool_requires_reserved_priority_capacity(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with_settings = settings.model_dump()
    with_settings["database_public_read_limit"] = (
        settings.database_pool_size + settings.database_max_overflow
    )

    try:
        Settings(**with_settings)
    except ValueError as exc:
        assert "DATABASE_PUBLIC_READ_LIMIT" in str(exc)
    else:
        raise AssertionError("database pool validation unexpectedly accepted no reserved capacity")


def test_public_read_queue_times_out_cleanly_and_increments_metrics(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.node_id = "pool-timeout-node"
    settings.database_public_read_limit = 1
    settings.database_public_queue_timeout_seconds = 0.1
    app = create_app(settings)
    holder_started = threading.Event()
    release = threading.Event()

    @app.get("/test/db-timeout")
    def hold_database_connection(db: Session = Depends(get_db)) -> dict[str, bool]:
        db.execute(select(1))
        holder_started.set()
        release.wait(timeout=2)
        return {"ok": True}

    with TestClient(app, base_url="http://testserver") as client:
        with ThreadPoolExecutor(max_workers=1) as executor:
            holder = executor.submit(client.get, "/test/db-timeout")
            assert holder_started.wait(timeout=1)
            timed_out = client.get("/test/db-timeout")
            assert timed_out.status_code == 503
            assert timed_out.headers["Retry-After"] == "1"
            assert timed_out.json() == {"detail": "Database is busy; retry shortly"}
            release.set()
            assert holder.result(timeout=2).status_code == 200

        metrics = client.get("/metrics")
        assert (
            "alert_hub_db_pool_acquire_timeouts_total"
            '{lane="public_read",node_id="pool-timeout-node"} 1.0' in metrics.text
        )
