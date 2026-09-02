from __future__ import annotations

import os
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session as DbSession

from alert_hub.application.incidents import append_cluster_event
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import AuditLog, Session, User
from alert_hub.security import encode_access_token, hash_token, random_token
from alert_hub.settings import Settings


@dataclass(slots=True)
class IssuedSession:
    access_token: str
    refresh_token: str
    csrf_token: str
    session: Session


def session_cluster_payload(session: Session) -> dict[str, object]:
    """Serialize replicated session state without exposing the refresh token."""

    return {
        "user_id": session.user_id,
        "refresh_token_hash": session.refresh_token_hash,
        "device_name": session.device_name,
        "created_at": session.created_at.isoformat(),
        "last_used_at": session.last_used_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "absolute_expires_at": session.absolute_expires_at.isoformat(),
        "revoked_at": session.revoked_at.isoformat() if session.revoked_at else None,
    }


def ensure_bootstrap_token(db: DbSession, settings: Settings) -> str | None:
    if db.scalar(select(func.count(User.id))) != 0:
        return None
    if settings.bootstrap_token:
        return settings.bootstrap_token
    path = Path(settings.bootstrap_token_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = path.read_text(encoding="utf-8").strip()
        if current:
            return current
    except FileNotFoundError:
        pass
    token = random_token(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        target.write(token)
        target.write("\n")
    return token


def read_bootstrap_token(settings: Settings) -> str | None:
    if settings.bootstrap_token:
        return settings.bootstrap_token
    try:
        return Path(settings.bootstrap_token_file).read_text(encoding="utf-8").strip() or None
    except FileNotFoundError:
        return None


def invalidate_bootstrap_token(settings: Settings) -> None:
    if settings.bootstrap_token:
        return
    with suppress(FileNotFoundError):
        Path(settings.bootstrap_token_file).unlink()


def acquire_bootstrap_write_lock(db: DbSession) -> None:
    if db.get_bind().dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))


def issue_session(
    db: DbSession,
    user: User,
    device_name: str,
    settings: Settings,
) -> IssuedSession:
    now = utc_now()
    raw_refresh = random_token(48)
    absolute = now + timedelta(days=settings.refresh_absolute_days)
    session = Session(
        user_id=user.id,
        refresh_token_hash=hash_token(raw_refresh, settings.signing_key, "refresh"),
        device_name=device_name[:255] or "Unknown device",
        created_at=now,
        last_used_at=now,
        expires_at=min(now + timedelta(days=settings.refresh_sliding_days), absolute),
        absolute_expires_at=absolute,
    )
    db.add(session)
    db.flush()
    append_cluster_event(
        db,
        settings,
        entity_type="session",
        entity_id=session.id,
        operation="issued",
        payload=session_cluster_payload(session),
    )
    access = encode_access_token(
        user.id,
        session.id,
        settings.signing_key,
        settings.access_token_ttl_seconds,
    )
    return IssuedSession(access, raw_refresh, random_token(24), session)


def rotate_session(db: DbSession, raw_refresh: str, settings: Settings) -> IssuedSession | None:
    token_hash = hash_token(raw_refresh, settings.signing_key, "refresh")
    session = db.scalar(select(Session).where(Session.refresh_token_hash == token_hash))
    now = utc_now()
    if (
        session is None
        or session.revoked_at is not None
        or session.expires_at <= now
        or session.absolute_expires_at <= now
        or session.user.disabled_at is not None
    ):
        if session is not None and session.revoked_at is None:
            session.revoked_at = now
            append_cluster_event(
                db,
                settings,
                entity_type="session",
                entity_id=session.id,
                operation="revoke",
                payload=session_cluster_payload(session),
            )
        return None
    new_refresh = random_token(48)
    session.refresh_token_hash = hash_token(new_refresh, settings.signing_key, "refresh")
    session.last_used_at = now
    session.expires_at = min(
        now + timedelta(days=settings.refresh_sliding_days), session.absolute_expires_at
    )
    append_cluster_event(
        db,
        settings,
        entity_type="session",
        entity_id=session.id,
        operation="rotate",
        payload=session_cluster_payload(session),
    )
    access = encode_access_token(
        session.user_id,
        session.id,
        settings.signing_key,
        settings.access_token_ttl_seconds,
    )
    return IssuedSession(access, new_refresh, random_token(24), session)


def add_audit(
    db: DbSession,
    settings: Settings,
    action: str,
    *,
    actor_user_id: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    request_id: str | None = None,
    details: dict[str, object] | None = None,
) -> None:
    db.add(
        AuditLog(
            node_id=settings.node_id,
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            request_id=request_id,
            details_json=details or {},
        )
    )
