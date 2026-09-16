from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import admin_user, get_db, get_settings
from alert_hub.api.schemas import (
    ServiceTokenCreate,
    ServiceTokenCreatedResponse,
    ServiceTokenResponse,
)
from alert_hub.application.auth import (
    add_audit,
    issue_service_token,
    service_token_cluster_payload,
)
from alert_hub.application.incidents import append_cluster_event
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import ServiceToken, User
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/service-tokens", tags=["service-tokens"])


def _response(token: ServiceToken) -> dict[str, Any]:
    return {
        "id": token.id,
        "user_id": token.user_id,
        "name": token.name,
        "scopes": token.scopes_json,
        "created_at": token.created_at,
        "expires_at": token.expires_at,
        "revoked_at": token.revoked_at,
    }


@router.get("", response_model=list[ServiceTokenResponse])
def list_service_tokens(
    include_revoked: bool = Query(default=False),
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
) -> list[dict[str, Any]]:
    del user
    query = select(ServiceToken)
    if not include_revoked:
        query = query.where(ServiceToken.revoked_at.is_(None))
    tokens = db.scalars(query.order_by(ServiceToken.created_at.desc(), ServiceToken.id)).all()
    return [_response(token) for token in tokens]


@router.post("", response_model=ServiceTokenCreatedResponse, status_code=status.HTTP_201_CREATED)
def create_service_token(
    payload: ServiceTokenCreate,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Service token name cannot be blank")
    issued = issue_service_token(db, user, name, payload.expires_in_days, settings)
    add_audit(
        db,
        settings,
        "service_token_created",
        actor_user_id=user.id,
        entity_type="service_token",
        entity_id=issued.token.id,
        request_id=getattr(request.state, "request_id", None),
        details={"name": issued.token.name, "scopes": issued.token.scopes_json},
    )
    db.commit()
    return {**_response(issued.token), "token": issued.raw_token}


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_service_token(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> None:
    token = db.get(ServiceToken, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Service token not found")
    if token.revoked_at is not None:
        return
    token.revoked_at = utc_now()
    append_cluster_event(
        db,
        settings,
        entity_type="service_token",
        entity_id=token.id,
        operation="tombstone",
        payload=service_token_cluster_payload(token),
    )
    add_audit(
        db,
        settings,
        "service_token_revoked",
        actor_user_id=user.id,
        entity_type="service_token",
        entity_id=token.id,
        request_id=getattr(request.state, "request_id", None),
        details={"name": token.name},
    )
    db.commit()
