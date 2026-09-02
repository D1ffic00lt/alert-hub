from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_user, get_db, get_settings, require_cookie_csrf
from alert_hub.api.schemas import AuthResponse, BootstrapRequest, LoginRequest, UserResponse
from alert_hub.application.auth import (
    IssuedSession,
    acquire_bootstrap_write_lock,
    add_audit,
    invalidate_bootstrap_token,
    issue_session,
    read_bootstrap_token,
    rotate_session,
    session_cluster_payload,
)
from alert_hub.application.incidents import append_cluster_event
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import Session as AuthSession
from alert_hub.infrastructure.db.models import User
from alert_hub.security import (
    DUMMY_PASSWORD_HASH,
    constant_time_equal,
    hash_password,
    verify_password,
)
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _set_auth_cookies(response: Response, issued: IssuedSession, settings: Settings) -> None:
    response.headers["X-Alert-Hub-Cache-Partition"] = issued.session.id
    response.set_cookie(
        settings.refresh_cookie_name,
        issued.refresh_token,
        httponly=True,
        max_age=settings.refresh_absolute_days * 86_400,
        path="/api/v1/auth",
        secure=settings.cookie_secure,
        samesite="strict",
        domain=settings.cookie_domain,
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        issued.csrf_token,
        httponly=False,
        max_age=settings.refresh_absolute_days * 86_400,
        path="/",
        secure=settings.cookie_secure,
        samesite="strict",
        domain=settings.cookie_domain,
    )
    response.set_cookie(
        settings.stream_cookie_name,
        issued.access_token,
        httponly=True,
        max_age=settings.access_token_ttl_seconds,
        path="/api/v1/stream",
        secure=settings.cookie_secure,
        samesite="strict",
        domain=settings.cookie_domain,
    )


def _auth_response(issued: IssuedSession, settings: Settings) -> AuthResponse:
    return AuthResponse(
        access_token=issued.access_token,
        expires_in=settings.access_token_ttl_seconds,
        csrf_token=issued.csrf_token,
        user=UserResponse.model_validate(issued.session.user),
    )


@router.post("/bootstrap", response_model=AuthResponse, status_code=201)
def bootstrap(
    payload: BootstrapRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthResponse:
    acquire_bootstrap_write_lock(db)
    if db.scalar(select(func.count(User.id))) != 0:
        raise HTTPException(status_code=409, detail="Bootstrap has already completed")
    expected = read_bootstrap_token(settings)
    if expected is None or not constant_time_equal(payload.bootstrap_token, expected):
        add_audit(
            db,
            settings,
            "bootstrap_failed",
            request_id=getattr(request.state, "request_id", None),
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid bootstrap token")
    user = User(
        username=payload.username.strip(),
        password_hash=hash_password(payload.password),
        is_admin=True,
    )
    db.add(user)
    db.flush()
    issued = issue_session(db, user, payload.device_name, settings)
    append_cluster_event(
        db,
        settings,
        entity_type="user",
        entity_id=user.id,
        operation="bootstrap",
        payload={
            "username": user.username,
            "password_hash": user.password_hash,
            "is_admin": True,
            "created_at": user.created_at.isoformat(),
        },
    )
    add_audit(
        db,
        settings,
        "bootstrap_completed",
        actor_user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    invalidate_bootstrap_token(settings)
    _set_auth_cookies(response, issued, settings)
    return _auth_response(issued, settings)


@router.get("/bootstrap/status")
def bootstrap_status(db: Session = Depends(get_db)) -> dict[str, bool]:
    required = db.scalar(select(func.count(User.id))) == 0
    return {
        "required": required,
        "bootstrap_required": required,
        "needs_bootstrap": required,
        "enabled": required,
    }


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthResponse:
    user = db.scalar(select(User).where(User.username == payload.username.strip()))
    password_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    password_valid = verify_password(password_hash, payload.password)
    if user is None or user.disabled_at is not None or not password_valid:
        add_audit(
            db,
            settings,
            "login_failed",
            request_id=getattr(request.state, "request_id", None),
            details={"username": payload.username.strip()},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    issued = issue_session(db, user, payload.device_name, settings)
    add_audit(
        db,
        settings,
        "login_succeeded",
        actor_user_id=user.id,
        entity_type="session",
        entity_id=issued.session.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    _set_auth_cookies(response, issued, settings)
    return _auth_response(issued, settings)


@router.post("/refresh", response_model=AuthResponse)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthResponse:
    require_cookie_csrf(request, settings)
    raw_refresh = request.cookies.get(settings.refresh_cookie_name)
    if not raw_refresh:
        raise HTTPException(status_code=401, detail="Refresh session missing")
    issued = rotate_session(db, raw_refresh, settings)
    if issued is None:
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh session expired or revoked")
    add_audit(
        db,
        settings,
        "session_refreshed",
        actor_user_id=issued.session.user_id,
        entity_type="session",
        entity_id=issued.session.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
    _set_auth_cookies(response, issued, settings)
    return _auth_response(issued, settings)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    require_cookie_csrf(request, settings)
    raw_refresh = request.cookies.get(settings.refresh_cookie_name)
    if raw_refresh:
        from alert_hub.security import hash_token

        token_hash = hash_token(raw_refresh, settings.signing_key, "refresh")
        session = db.scalar(select(AuthSession).where(AuthSession.refresh_token_hash == token_hash))
        if session and session.revoked_at is None:
            session.revoked_at = utc_now()
            append_cluster_event(
                db,
                settings,
                entity_type="session",
                entity_id=session.id,
                operation="revoke",
                payload=session_cluster_payload(session),
            )
            add_audit(
                db,
                settings,
                "logout",
                actor_user_id=session.user_id,
                entity_type="session",
                entity_id=session.id,
                request_id=getattr(request.state, "request_id", None),
            )
            db.commit()
    response.delete_cookie(
        settings.refresh_cookie_name,
        path="/api/v1/auth",
        domain=settings.cookie_domain,
    )
    response.delete_cookie(
        settings.csrf_cookie_name,
        path="/",
        domain=settings.cookie_domain,
    )
    response.delete_cookie(
        settings.stream_cookie_name,
        path="/api/v1/stream",
        domain=settings.cookie_domain,
    )


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(current_user)) -> User:
    return user
