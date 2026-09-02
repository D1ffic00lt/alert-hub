from __future__ import annotations

from collections.abc import Iterator
from typing import cast

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.application.auth import add_audit
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import Session as AuthSession
from alert_hub.infrastructure.db.models import User
from alert_hub.infrastructure.encryption import EnvelopeCipher
from alert_hub.infrastructure.request_security import address_in_cidrs
from alert_hub.security import TokenError, constant_time_equal, decode_access_token, hash_token
from alert_hub.settings import Settings


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as db:
        yield db


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def current_session(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthSession:
    try:
        claims = decode_access_token(_bearer_token(request), settings.signing_key)
    except (TokenError, HTTPException) as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
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
    ):
        raise HTTPException(status_code=401, detail="Session revoked")
    user = auth_session.user
    if user is None or user.disabled_at is not None:
        raise HTTPException(status_code=401, detail="User unavailable")
    request.state.session_id = auth_session.id
    return auth_session


def current_user(auth_session: AuthSession = Depends(current_session)) -> User:
    return auth_session.user


def session_from_refresh_cookie(
    request: Request,
    db: Session,
    settings: Settings,
) -> AuthSession | None:
    raw_refresh = request.cookies.get(settings.refresh_cookie_name)
    if not raw_refresh:
        return None
    token_hash = hash_token(raw_refresh, settings.signing_key, "refresh")
    auth_session = db.scalar(
        select(AuthSession).where(AuthSession.refresh_token_hash == token_hash)
    )
    now = utc_now()
    if (
        auth_session is None
        or auth_session.revoked_at is not None
        or auth_session.expires_at <= now
        or auth_session.absolute_expires_at <= now
        or auth_session.user.disabled_at is not None
    ):
        return None
    return auth_session


def get_envelope_cipher(request: Request) -> EnvelopeCipher:
    cipher: EnvelopeCipher | None = request.app.state.envelope_cipher
    if cipher is None:
        raise HTTPException(
            status_code=503,
            detail="Secret storage is unavailable; configure MASTER_ENCRYPTION_KEY_FILE",
        )
    return cipher


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


def require_cookie_csrf(request: Request, settings: Settings) -> None:
    origins = request.headers.getlist("origin")
    if len(origins) != 1 or origins[0] not in settings.trusted_origins:
        raise HTTPException(status_code=403, detail="Untrusted request origin")
    csrf_cookie = request.cookies.get(settings.csrf_cookie_name, "")
    csrf_headers = request.headers.getlist("x-csrf-token")
    csrf_header = csrf_headers[0] if len(csrf_headers) == 1 else ""
    if not csrf_cookie or not csrf_header or not constant_time_equal(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def require_cluster_auth(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    client_ip = getattr(request.state, "client_ip", None)
    if settings.peer_allowed_cidrs and not address_in_cidrs(client_ip, settings.peer_allowed_cidrs):
        add_audit(
            db,
            settings,
            "cluster_peer_denied",
            request_id=getattr(request.state, "request_id", None),
            details={"client_ip": client_ip},
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Cluster peer is not allowed")
    try:
        token = _bearer_token(request)
    except HTTPException:
        add_audit(
            db,
            settings,
            "cluster_auth_failed",
            request_id=getattr(request.state, "request_id", None),
            details={"client_ip": client_ip},
        )
        db.commit()
        raise
    allowed = constant_time_equal(token, settings.cluster_secret)
    if settings.cluster_previous_secret:
        allowed = allowed or constant_time_equal(token, settings.cluster_previous_secret)
    if not allowed:
        add_audit(
            db,
            settings,
            "cluster_auth_failed",
            request_id=getattr(request.state, "request_id", None),
            details={"client_ip": client_ip},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid cluster bearer token")
