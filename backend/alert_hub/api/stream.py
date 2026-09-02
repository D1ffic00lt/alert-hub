from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import ClusterEvent
from alert_hub.infrastructure.db.models import Session as AuthSession
from alert_hub.security import TokenError, decode_access_token
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1", tags=["stream"])


def _stream_claims(request: Request, db: Session, settings: Settings) -> dict[str, Any]:
    authorization = request.headers.get("authorization", "")
    scheme, _, bearer = authorization.partition(" ")
    token = bearer if scheme.lower() == "bearer" and bearer else None
    token = token or request.cookies.get(settings.stream_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Stream authentication required")
    try:
        claims = decode_access_token(token, settings.signing_key)
    except TokenError as exc:
        raise HTTPException(status_code=401, detail="Stream token expired or invalid") from exc
    auth_session = db.scalar(
        select(AuthSession).where(
            AuthSession.id == claims["sid"],
            AuthSession.user_id == claims["sub"],
        )
    )
    now = utc_now()
    if (
        auth_session is None
        or auth_session.revoked_at is not None
        or auth_session.expires_at <= now
        or auth_session.absolute_expires_at <= now
        or auth_session.user.disabled_at is not None
    ):
        raise HTTPException(status_code=401, detail="Stream session unavailable")
    return claims


def _event_snapshot(db: Session) -> tuple[int, ClusterEvent | None]:
    count = int(db.scalar(select(func.count(ClusterEvent.event_id))) or 0)
    latest = db.scalar(
        select(ClusterEvent).order_by(ClusterEvent.received_at.desc(), ClusterEvent.event_id.desc())
    )
    return count, latest


def _sse_data(value: dict[str, Any]) -> str:
    return f"data: {json.dumps(value, separators=(',', ':'), default=str)}\n\n"


@router.get("/stream")
def stream(request: Request) -> StreamingResponse:
    settings: Settings = request.app.state.settings
    session_factory = request.app.state.session_factory
    with session_factory() as db:
        claims = _stream_claims(request, db, settings)
        initial_count, initial_event = _event_snapshot(db)

    async def events() -> AsyncIterator[str]:
        last_count = initial_count
        last_keepalive = time.monotonic()
        yield "retry: 5000\n" + _sse_data(
            {
                "type": "ready",
                "event_count": initial_count,
                "latest_event_id": initial_event.event_id if initial_event else None,
            }
        )
        while int(time.time()) < int(claims["exp"]):
            await asyncio.sleep(settings.sse_poll_seconds)
            if await request.is_disconnected():
                break
            with session_factory() as db:
                current_count, latest = _event_snapshot(db)
                auth_session = db.get(AuthSession, claims["sid"])
                if auth_session is None or auth_session.revoked_at is not None:
                    break
            if current_count != last_count:
                last_count = current_count
                yield _sse_data(
                    {
                        "type": "cluster_event",
                        "event_count": current_count,
                        "event_id": latest.event_id if latest else None,
                        "entity_type": latest.entity_type if latest else None,
                        "operation": latest.operation if latest else None,
                        "occurred_at": latest.occurred_at.isoformat() if latest else None,
                    }
                )
                last_keepalive = time.monotonic()
            elif time.monotonic() - last_keepalive >= settings.sse_keepalive_seconds:
                yield f": keepalive {int(time.time())}\n\n"
                last_keepalive = time.monotonic()

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
