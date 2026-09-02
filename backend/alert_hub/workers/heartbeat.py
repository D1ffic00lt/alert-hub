from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from alert_hub.application.incidents import ingest_normalized_events
from alert_hub.domain.events import NormalizedEvent, normalize_severity, utc_now
from alert_hub.domain.heartbeats import heartbeat_window
from alert_hub.infrastructure.db.models import HeartbeatState, Source
from alert_hub.metrics import HEARTBEAT_EVALUATION_ERRORS
from alert_hub.settings import Settings

logger = logging.getLogger("alert_hub.heartbeat")


def _source_event(
    source: Source, status: str, starts_at: datetime, now: datetime
) -> NormalizedEvent:
    config: dict[str, Any] = source.config_json or {}
    labels = {str(k): v for k, v in (config.get("labels") or {}).items()}
    labels.setdefault("source", source.name)
    labels.setdefault("region", source.region or "unknown")
    title = str(config.get("title") or f"Heartbeat missed: {source.name}")
    return NormalizedEvent(
        dedup_key="heartbeat-missed",
        status=status,  # type: ignore[arg-type]
        title=title,
        description=f"No heartbeat received from {source.name} within the configured window",
        severity=normalize_severity(config.get("severity", "critical")),
        starts_at=starts_at,
        ends_at=now if status == "resolved" else None,
        labels=labels,
        annotations={"source_kind": "heartbeat"},
        external_event_id=f"heartbeat:{starts_at.isoformat()}:{status}",
    )


def evaluate_heartbeats(db: Session, settings: Settings, *, now: datetime | None = None) -> int:
    current = now or utc_now()
    fired = 0
    sources = db.scalars(
        select(Source).where(
            Source.kind == "heartbeat",
            Source.enabled.is_(True),
            Source.deleted_at.is_(None),
        )
    ).all()
    for source in sources:
        state = db.get(HeartbeatState, source.id)
        if state is None:
            state = HeartbeatState(source_id=source.id, last_received_at=source.created_at)
            db.add(state)
            db.flush()
        config = source.config_json or {}
        try:
            interval, grace = heartbeat_window(config)
        except ValueError:
            HEARTBEAT_EVALUATION_ERRORS.labels(reason="invalid_config").inc()
            logger.warning(
                "heartbeat_source_skipped",
                extra={
                    "event": "heartbeat_source_skipped",
                    "source_id": source.id,
                    "reason": "invalid_config",
                },
            )
            continue
        deadline = state.last_received_at + timedelta(seconds=interval + grace)
        if not state.missed and current > deadline:
            event = _source_event(source, "firing", deadline, current)
            _, duplicates = ingest_normalized_events(db, source, [event], settings)
            state.missed = True
            state.last_event_key = event.event_key(source.id)
            fired += int(duplicates == 0)
    return fired


async def heartbeat_loop(session_factory: sessionmaker[Session], settings: Settings) -> None:
    while True:
        await asyncio.sleep(settings.heartbeat_scan_seconds)
        try:
            with session_factory.begin() as db:
                evaluate_heartbeats(db, settings)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            HEARTBEAT_EVALUATION_ERRORS.labels(reason="worker_error").inc()
            logger.exception(
                "heartbeat_evaluation_failed",
                extra={
                    "event": "heartbeat_evaluation_failed",
                    "exception_type": type(exc).__name__,
                },
            )
            # The next tick retries from durable state.
            continue
