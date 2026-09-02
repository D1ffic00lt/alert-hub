from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import admin_user, get_db, get_settings
from alert_hub.application.auth import add_audit
from alert_hub.application.incidents import append_cluster_event
from alert_hub.domain.routing import LabelMatcher
from alert_hub.infrastructure.db.base import new_id
from alert_hub.infrastructure.db.models import (
    ClusterEvent,
    NotificationChannel,
    NotificationRoute,
    User,
)
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/routes", tags=["notification-routes"])


class RouteMatcherInput(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    operator: str = Field(default="equals", min_length=1, max_length=32)
    value: str = Field(default="", max_length=1_024)

    @field_validator("name", "operator")
    @classmethod
    def strip_required(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("value must not be blank")
        return stripped

    def normalized(self) -> dict[str, str]:
        try:
            return LabelMatcher(
                name=self.name,
                operator=self.operator,
                value=self.value,
            ).as_dict()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


class RouteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    priority: int = Field(default=0, ge=-1_000_000, le=1_000_000)
    source_filter: list[str] = Field(default_factory=list, max_length=100)
    severity_filter: list[str] = Field(default_factory=list, max_length=20)
    label_matchers: list[RouteMatcherInput] = Field(default_factory=list, max_length=100)
    channel_ids: list[str] = Field(default_factory=list, max_length=100)
    continue_matching: bool = False


class RoutePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=-1_000_000, le=1_000_000)
    source_filter: list[str] | None = Field(default=None, max_length=100)
    severity_filter: list[str] | None = Field(default=None, max_length=20)
    label_matchers: list[RouteMatcherInput] | None = Field(default=None, max_length=100)
    channel_ids: list[str] | None = Field(default=None, max_length=100)
    continue_matching: bool | None = None


def _unique_strings(values: list[str], *, field_name: str) -> list[str]:
    normalized: list[str] = []
    for value in values:
        item = value.strip()
        if not item:
            raise HTTPException(status_code=422, detail=f"{field_name} cannot contain blanks")
        if item not in normalized:
            normalized.append(item)
    return normalized


def _validate_channels(db: Session, channel_ids: list[str]) -> list[str]:
    normalized = _unique_strings(channel_ids, field_name="channel_ids")
    if not normalized:
        return []
    available = set(
        db.scalars(
            select(NotificationChannel.id).where(
                NotificationChannel.id.in_(normalized),
                NotificationChannel.deleted_at.is_(None),
            )
        ).all()
    )
    missing = [channel_id for channel_id in normalized if channel_id not in available]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={"message": "Unknown notification channel", "channel_ids": missing},
        )
    return normalized


def _latest_route_event(db: Session, route_id: str) -> ClusterEvent | None:
    return db.scalar(
        select(ClusterEvent)
        .where(
            ClusterEvent.entity_type == "notification_route",
            ClusterEvent.entity_id == route_id,
        )
        .order_by(ClusterEvent.occurred_at.desc(), ClusterEvent.event_id.desc())
        .limit(1)
    )


def _is_deleted(db: Session, route: NotificationRoute) -> bool:
    latest = _latest_route_event(db, route.id)
    return latest is not None and latest.operation == "tombstone"


def _route_or_404(db: Session, route_id: str) -> NotificationRoute:
    route = db.get(NotificationRoute, route_id)
    if route is None or _is_deleted(db, route):
        raise HTTPException(status_code=404, detail="Notification route not found")
    return route


def _response(route: NotificationRoute) -> dict[str, Any]:
    return {
        "id": route.id,
        "name": route.name,
        "enabled": route.enabled,
        "priority": route.priority,
        "source_filter": route.source_filter,
        "severity_filter": route.severity_filter,
        "label_matchers": route.label_matchers,
        "channel_ids": route.channel_ids,
        "continue_matching": route.continue_matching,
    }


def _replicated_payload(route: NotificationRoute) -> dict[str, Any]:
    return _response(route)


@router.get("")
def list_routes(
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
) -> list[dict[str, Any]]:
    del user
    rows = db.scalars(
        select(NotificationRoute).order_by(NotificationRoute.priority, NotificationRoute.id)
    ).all()
    return [_response(route) for route in rows if not _is_deleted(db, route)]


@router.get("/{route_id}")
def get_route(
    route_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    del user
    return _response(_route_or_404(db, route_id))


@router.post("", status_code=status.HTTP_201_CREATED)
def create_route(
    payload: RouteCreate,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    route = NotificationRoute(
        id=new_id(),
        name=payload.name.strip(),
        enabled=payload.enabled,
        priority=payload.priority,
        source_filter=_unique_strings(payload.source_filter, field_name="source_filter"),
        severity_filter=_unique_strings(
            payload.severity_filter,
            field_name="severity_filter",
        ),
        label_matchers=[matcher.normalized() for matcher in payload.label_matchers],
        channel_ids=_validate_channels(db, payload.channel_ids),
        continue_matching=payload.continue_matching,
    )
    db.add(route)
    db.flush()
    append_cluster_event(
        db,
        settings,
        entity_type="notification_route",
        entity_id=route.id,
        operation="upsert",
        payload=_replicated_payload(route),
    )
    add_audit(
        db,
        settings,
        "notification_route_created",
        actor_user_id=user.id,
        entity_type="notification_route",
        entity_id=route.id,
        request_id=getattr(request.state, "request_id", None),
        details={"channel_count": len(route.channel_ids)},
    )
    db.commit()
    return _response(route)


@router.patch("/{route_id}")
def update_route(
    route_id: str,
    payload: RoutePatch,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    route = _route_or_404(db, route_id)
    changes = payload.model_dump(exclude_unset=True)
    if payload.name is not None:
        route.name = payload.name.strip()
    if payload.enabled is not None:
        route.enabled = payload.enabled
    if payload.priority is not None:
        route.priority = payload.priority
    if payload.source_filter is not None:
        route.source_filter = _unique_strings(
            payload.source_filter,
            field_name="source_filter",
        )
    if payload.severity_filter is not None:
        route.severity_filter = _unique_strings(
            payload.severity_filter,
            field_name="severity_filter",
        )
    if payload.label_matchers is not None:
        route.label_matchers = [matcher.normalized() for matcher in payload.label_matchers]
    if payload.channel_ids is not None:
        route.channel_ids = _validate_channels(db, payload.channel_ids)
    if payload.continue_matching is not None:
        route.continue_matching = payload.continue_matching
    append_cluster_event(
        db,
        settings,
        entity_type="notification_route",
        entity_id=route.id,
        operation="upsert",
        payload=_replicated_payload(route),
    )
    add_audit(
        db,
        settings,
        "notification_route_updated",
        actor_user_id=user.id,
        entity_type="notification_route",
        entity_id=route.id,
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changes)},
    )
    db.commit()
    return _response(route)


@router.delete("/{route_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_route(
    route_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> None:
    route = _route_or_404(db, route_id)
    route.enabled = False
    route.channel_ids = []
    append_cluster_event(
        db,
        settings,
        entity_type="notification_route",
        entity_id=route.id,
        operation="tombstone",
        payload=_replicated_payload(route),
    )
    add_audit(
        db,
        settings,
        "notification_route_deleted",
        actor_user_id=user.id,
        entity_type="notification_route",
        entity_id=route.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.commit()
