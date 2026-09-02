from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import admin_user, get_db
from alert_hub.infrastructure.db.models import AuditLog, User

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


def _safe_details(value: Any, *, key: str = "") -> Any:
    lowered = key.lower()
    if any(
        marker in lowered
        for marker in ("password", "secret", "token", "authorization", "cookie", "credential")
    ):
        return "***"
    if isinstance(value, dict):
        return {str(child): _safe_details(item, key=str(child)) for child, item in value.items()}
    if isinstance(value, list):
        return [_safe_details(item) for item in value]
    return value


def _tone(action: str) -> str:
    if any(marker in action for marker in ("failed", "denied", "error")):
        return "danger"
    if any(marker in action for marker in ("deleted", "disabled", "revoked", "rotated")):
        return "warning"
    if any(marker in action for marker in ("created", "completed", "succeeded", "bootstrap")):
        return "success"
    return "neutral"


@router.get("")
def list_audit_log(
    q: str | None = Query(default=None, max_length=200),
    action: str | None = Query(default=None, max_length=128),
    node_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    del user
    predicates = []
    if action:
        predicates.append(AuditLog.action == action)
    if node_id:
        predicates.append(AuditLog.node_id == node_id)
    if q:
        pattern = f"%{q.strip()}%"
        predicates.append(
            or_(
                AuditLog.action.ilike(pattern),
                AuditLog.entity_type.ilike(pattern),
                AuditLog.entity_id.ilike(pattern),
                AuditLog.node_id.ilike(pattern),
                User.username.ilike(pattern),
            )
        )
    count_query = select(func.count(AuditLog.id)).outerjoin(User, User.id == AuditLog.actor_user_id)
    query = select(AuditLog, User.username).outerjoin(User, User.id == AuditLog.actor_user_id)
    if predicates:
        count_query = count_query.where(*predicates)
        query = query.where(*predicates)
    rows = db.execute(
        query.order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc()).offset(offset).limit(limit)
    ).all()
    items = []
    for entry, username in rows:
        details = _safe_details(entry.details_json or {})
        entity = " ".join(item for item in (entry.entity_type, entry.entity_id) if item is not None)
        detail = entity or "System operation"
        if details:
            detail = f"{detail} · {json.dumps(details, sort_keys=True, ensure_ascii=False)}"
        items.append(
            {
                "id": entry.id,
                "action": entry.action.replace("_", " ").title(),
                "action_code": entry.action,
                "detail": detail,
                "actor": username or "system",
                "actor_user_id": entry.actor_user_id,
                "node": entry.node_id,
                "node_id": entry.node_id,
                "at": entry.occurred_at,
                "occurred_at": entry.occurred_at,
                "tone": _tone(entry.action),
                "entity_type": entry.entity_type,
                "entity_id": entry.entity_id,
                "request_id": entry.request_id,
                "details": details,
            }
        )
    return {
        "items": items,
        "total": int(db.scalar(count_query) or 0),
        "limit": limit,
        "offset": offset,
    }
