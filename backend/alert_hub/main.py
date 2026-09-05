from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from urllib.parse import urlsplit
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from alert_hub import __version__
from alert_hub.api import (
    application_settings,
    audit,
    auth,
    channels,
    cluster,
    devices,
    health,
    incidents,
    ingest,
    metrics_api,
    prometheus,
    push,
    routes,
    sources,
    stream,
)
from alert_hub.application.auth import add_audit, ensure_bootstrap_token
from alert_hub.application.sync import register_local_node_event
from alert_hub.infrastructure.db.session import (
    create_db_engine,
    create_session_factory,
    initialize_database,
)
from alert_hub.infrastructure.encryption import build_envelope_cipher
from alert_hub.infrastructure.logging import configure_logging
from alert_hub.infrastructure.notifications.registry import build_provider_registry
from alert_hub.infrastructure.rate_limit import LocalRateLimiter
from alert_hub.infrastructure.request_security import resolve_client_ip
from alert_hub.settings import Settings, get_settings
from alert_hub.workers.heartbeat import heartbeat_loop
from alert_hub.workers.notifications import notification_worker_loop
from alert_hub.workers.sync import PeerSyncWorker

logger = logging.getLogger("alert_hub")
_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_PRIVATE_PEER_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


class _IngestPayloadTooLarge(Exception):
    pass


class _IngestBodyLimitMiddleware:
    """Stop reading an ingest body as soon as its cumulative chunks exceed the limit."""

    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or not scope["path"].startswith("/ingest/v1/")
        ):
            await self.app(scope, receive, send)
            return

        total_size = 0
        response_started = False

        async def receive_with_limit() -> Message:
            nonlocal total_size
            message = await receive()
            if message["type"] == "http.request":
                total_size += len(message.get("body", b""))
                if total_size > self.max_body_size:
                    raise _IngestPayloadTooLarge
            return message

        async def send_with_state(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive_with_limit, send_with_state)
        except _IngestPayloadTooLarge:
            if response_started:
                raise
            response = JSONResponse(status_code=413, content={"detail": "Payload too large"})
            await response(scope, receive, send)


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return True
    candidate = host.rstrip(".").lower()
    if candidate == "localhost" or candidate.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _is_private_peer_host(host: str | None) -> bool:
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return any(address in network for network in _PRIVATE_PEER_NETWORKS)


def _peer_origin_uses_permitted_transport(origin: str) -> bool:
    parsed = urlsplit(origin)
    return parsed.scheme == "https" or (
        parsed.scheme == "http" and _is_private_peer_host(parsed.hostname)
    )


def _secret_is_weak(value: str, insecure_values: set[str]) -> bool:
    return value in insecure_values or len(value.encode()) < 32 or len(set(value)) < 12


def _validate_production_settings(settings: Settings) -> None:
    if settings.environment != "production":
        return
    insecure = {
        "development-only-change-me",
        "development-cluster-secret-change-me",
    }
    secrets = (settings.signing_key, settings.cluster_secret)
    if any(_secret_is_weak(value, insecure) for value in secrets):
        raise RuntimeError("Production signing and cluster secrets must be high entropy")
    if settings.signing_key == settings.cluster_secret:
        raise RuntimeError("Production signing and cluster secrets must be distinct")
    if settings.cluster_previous_secret in {settings.signing_key, settings.cluster_secret}:
        raise RuntimeError("The previous cluster secret must be distinct from active secrets")
    if settings.cluster_previous_secret and _secret_is_weak(
        settings.cluster_previous_secret, insecure
    ):
        raise RuntimeError("The previous cluster secret must be high entropy")
    if settings.auto_create_schema:
        raise RuntimeError("AUTO_CREATE_SCHEMA must be disabled in production; use Alembic")
    if not settings.cookie_secure:
        raise RuntimeError("COOKIE_SECURE must be enabled in production")
    if settings.master_encryption_key_file is None:
        raise RuntimeError("MASTER_ENCRYPTION_KEY_FILE is required in production")
    if not settings.public_api_url:
        raise RuntimeError("PUBLIC_API_URL is required in production")
    if settings.grafana_url and urlsplit(settings.grafana_url).scheme != "https":
        raise RuntimeError("GRAFANA_URL must use HTTPS in production")
    public_url = urlsplit(settings.public_api_url)
    if (
        public_url.scheme != "https"
        or public_url.path not in {"", "/"}
        or _is_loopback_host(public_url.hostname)
    ):
        raise RuntimeError("PUBLIC_API_URL must be an exact HTTPS origin in production")
    if not settings.trusted_origins:
        raise RuntimeError("At least one exact TRUSTED_ORIGIN is required in production")
    if any(
        urlsplit(origin).scheme != "https" or _is_loopback_host(urlsplit(origin).hostname)
        for origin in settings.trusted_origins
    ):
        raise RuntimeError("TRUSTED_ORIGINS must use HTTPS in production")
    public_origin = f"https://{public_url.netloc.lower()}"
    if public_origin not in settings.trusted_origins:
        raise RuntimeError("PUBLIC_API_URL origin must be present in TRUSTED_ORIGINS")
    if settings.cookie_domain:
        hosts = [urlsplit(origin).hostname or "" for origin in settings.trusted_origins]
        if any(
            host != settings.cookie_domain and not host.endswith(f".{settings.cookie_domain}")
            for host in hosts
        ):
            raise RuntimeError("COOKIE_DOMAIN must contain every trusted origin host")
    if settings.sync_enabled and not settings.peer_allowed_cidrs:
        raise RuntimeError("PEER_ALLOWED_CIDRS is required when sync is enabled in production")
    if settings.sync_enabled or settings.peer_urls:
        if not settings.private_peer_url:
            raise RuntimeError(
                "PEER_PUBLIC_URL is required when sync is enabled or PEER_URLS are configured"
            )
        if not _peer_origin_uses_permitted_transport(settings.private_peer_url):
            raise RuntimeError(
                "PEER_PUBLIC_URL must use HTTPS, except HTTP is allowed for a literal RFC 1918 "
                "or ULA address"
            )
    insecure_peer_urls = [
        url for url in settings.peer_urls if not _peer_origin_uses_permitted_transport(url)
    ]
    if insecure_peer_urls:
        raise RuntimeError(
            "PEER_URLS must use HTTPS, except HTTP is allowed for literal RFC 1918 or ULA addresses"
        )


def _rate_limit_policy(
    request: Request,
    settings: Settings,
) -> tuple[str, str, int, float, str] | None:
    if request.method != "POST" and not request.url.path.startswith("/internal/"):
        return None
    client_ip = getattr(request.state, "client_ip", None) or "unresolved"
    path = request.url.path
    if request.method == "POST" and path == "/api/v1/auth/login":
        return (
            "login",
            client_ip,
            settings.login_rate_limit_attempts,
            settings.login_rate_limit_window_seconds,
            "login_rate_limited",
        )
    if request.method == "POST" and path == "/api/v1/auth/bootstrap":
        return (
            "bootstrap",
            client_ip,
            settings.bootstrap_rate_limit_attempts,
            settings.bootstrap_rate_limit_window_seconds,
            "bootstrap_rate_limited",
        )
    if request.method == "POST" and path.startswith("/ingest/v1/"):
        return (
            "ingest",
            client_ip,
            settings.ingest_rate_limit_attempts,
            settings.ingest_rate_limit_window_seconds,
            "ingest_rate_limited",
        )
    if path.startswith("/internal/"):
        return (
            "cluster",
            client_ip,
            settings.peer_rate_limit_attempts,
            settings.peer_rate_limit_window_seconds,
            "cluster_rate_limited",
        )
    return None


def _append_vary(response: Response, value: str) -> None:
    headers = response.headers
    existing = [item.strip() for item in headers.get("Vary", "").split(",") if item.strip()]
    if value not in existing:
        headers["Vary"] = ", ".join([*existing, value])


def _request_id(request: Request) -> str:
    candidate = request.headers.get("x-request-id", "").strip()
    if _REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return str(uuid4())


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or get_settings()
    configure_logging(runtime_settings.log_level, runtime_settings.log_format)
    _validate_production_settings(runtime_settings)
    engine = create_db_engine(runtime_settings)
    session_factory = create_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        initialize_database(engine, session_factory, runtime_settings)
        with session_factory.begin() as db:
            ensure_bootstrap_token(db, runtime_settings)
            register_local_node_event(db, runtime_settings)
        heartbeat_task: asyncio.Task[None] | None = None
        notification_task: asyncio.Task[None] | None = None
        sync_task: asyncio.Task[None] | None = None
        sync_worker: PeerSyncWorker | None = None
        if runtime_settings.ingest_enabled and runtime_settings.heartbeat_scan_seconds > 0:
            heartbeat_task = asyncio.create_task(
                heartbeat_loop(session_factory, runtime_settings),
                name="heartbeat-evaluator",
            )
        if runtime_settings.sync_enabled and runtime_settings.peer_urls:
            sync_worker = PeerSyncWorker(session_factory, runtime_settings)
            sync_task = asyncio.create_task(sync_worker.run(), name="peer-sync")
        if runtime_settings.notify_enabled:
            notification_task = asyncio.create_task(
                notification_worker_loop(
                    session_factory,
                    runtime_settings,
                    app.state.envelope_cipher,
                    app.state.notification_providers,
                ),
                name="notification-outbox",
            )
        app.state.peer_sync_worker = sync_worker
        yield
        if notification_task is not None:
            notification_task.cancel()
            with suppress(asyncio.CancelledError):
                await notification_task
        if sync_task is not None:
            sync_task.cancel()
            with suppress(asyncio.CancelledError):
                await sync_task
        if heartbeat_task is not None:
            heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat_task
        engine.dispose()

    app = FastAPI(
        title=runtime_settings.app_name,
        version=runtime_settings.software_version or __version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    app.state.settings = runtime_settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.envelope_cipher = build_envelope_cipher(runtime_settings)
    app.state.notification_providers = build_provider_registry(runtime_settings)
    app.state.rate_limiter = LocalRateLimiter(
        max_keys=runtime_settings.rate_limit_max_keys,
        cleanup_interval_seconds=runtime_settings.rate_limit_cleanup_interval_seconds,
    )

    # Register this before the HTTP request-context middleware. Starlette inserts
    # later middleware on the outside, so early 413 responses still receive the
    # normal request ID, security headers, and structured request log entry.
    app.add_middleware(
        _IngestBodyLimitMiddleware,
        max_body_size=runtime_settings.max_payload_bytes,
    )

    @app.middleware("http")
    async def request_context(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        started = time.monotonic()
        request_id = _request_id(request)
        request.state.request_id = request_id
        request.state.client_ip = resolve_client_ip(request, runtime_settings.trusted_proxy_cidrs)

        def finish_response(
            response: Response,
            *,
            event: str = "http_request_completed",
            include_exception: bool = False,
        ) -> Response:
            response.headers["X-Request-ID"] = request_id
            session_id = getattr(request.state, "session_id", None)
            cache_partition = response.headers.get("X-Alert-Hub-Cache-Partition") or session_id
            if cache_partition:
                response.headers["X-Alert-Hub-Cache-Partition"] = cache_partition
                _append_vary(response, "X-Alert-Hub-Cache-Partition")
                response.headers.setdefault("Cache-Control", "private")
            if request.url.path.startswith("/api/v1/auth") or response.status_code >= 400:
                response.headers["Cache-Control"] = "private, no-store"
            context = {
                "event": event,
                "request_id": request_id,
                "node_id": runtime_settings.node_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }
            if include_exception:
                logger.exception(event, extra=context)
            else:
                logger.info(event, extra=context)
            return response

        policy = _rate_limit_policy(request, runtime_settings)
        if policy is not None:
            scope, key, limit, window_seconds, audit_action = policy
            decision = app.state.rate_limiter.check(
                scope,
                key,
                limit=limit,
                window_seconds=window_seconds,
            )
            if not decision.allowed:
                try:
                    with session_factory.begin() as db:
                        add_audit(
                            db,
                            runtime_settings,
                            audit_action,
                            request_id=request_id,
                            details={
                                "client_ip": request.state.client_ip,
                                "path": request.url.path,
                                "scope": scope,
                            },
                        )
                except Exception:
                    logger.exception(
                        "request_rate_limit_audit_failed",
                        extra={
                            "event": "request_rate_limit_audit_failed",
                            "request_id": request_id,
                            "node_id": runtime_settings.node_id,
                            "scope": scope,
                        },
                    )
                return finish_response(
                    JSONResponse(
                        status_code=429,
                        content={"detail": "Too many requests"},
                        headers={"Retry-After": str(decision.retry_after)},
                    )
                )
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                parsed_content_length = int(content_length)
            except ValueError:
                return finish_response(
                    JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
                )
            if parsed_content_length < 0:
                return finish_response(
                    JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
                )
            if parsed_content_length > runtime_settings.max_payload_bytes:
                return finish_response(
                    JSONResponse(status_code=413, content={"detail": "Payload too large"})
                )
        if request.url.path.startswith("/ingest/") and not runtime_settings.ingest_enabled:
            return finish_response(
                JSONResponse(status_code=503, content={"detail": "Ingest role disabled"})
            )
        if request.url.path.startswith("/internal/") and not runtime_settings.sync_enabled:
            return finish_response(
                JSONResponse(status_code=503, content={"detail": "Sync role disabled"})
            )
        try:
            response = await call_next(request)
        except Exception:
            return finish_response(
                JSONResponse(status_code=500, content={"detail": "Internal server error"}),
                event="http_request_failed",
                include_exception=True,
            )
        return finish_response(response)

    # CORS is registered after the request boundary so it remains the outermost
    # middleware and also covers early 4xx/429 security responses.
    if runtime_settings.trusted_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=runtime_settings.trusted_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-CSRF-Token",
                "X-Request-ID",
                "X-Alert-Hub-Cache-Partition",
            ],
            expose_headers=["X-Request-ID", "X-Alert-Hub-Cache-Partition"],
        )

    app.include_router(auth.router)
    app.include_router(incidents.router)
    app.include_router(sources.router)
    app.include_router(channels.router)
    app.include_router(routes.router)
    app.include_router(push.router)
    app.include_router(devices.router)
    app.include_router(audit.router)
    app.include_router(application_settings.router)
    app.include_router(metrics_api.router)
    app.include_router(prometheus.router)
    app.include_router(stream.router)
    app.include_router(ingest.router)
    app.include_router(cluster.internal_router)
    app.include_router(cluster.public_router)
    app.include_router(health.router)
    return app


app = create_app()


def run() -> None:
    runtime_settings = get_settings()
    configure_logging(runtime_settings.log_level, runtime_settings.log_format)
    uvicorn.run(
        "alert_hub.main:app",
        host=runtime_settings.backend_host,
        port=runtime_settings.backend_port,
        workers=1,
        access_log=False,
        log_config=None,
        log_level=runtime_settings.log_level.lower(),
    )


if __name__ == "__main__":
    run()
