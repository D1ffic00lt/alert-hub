from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_user, get_db, get_settings, require_cluster_auth
from alert_hub.api.schemas import SyncQueryRequest
from alert_hub.application.sync import (
    IncomingClusterEvent,
    apply_cluster_events,
    cluster_cursor,
)
from alert_hub.infrastructure.db.models import ClusterEvent, Node, User
from alert_hub.metrics import SYNC_EVENTS
from alert_hub.settings import Settings

internal_router = APIRouter(
    prefix="/internal/v1",
    tags=["cluster-internal"],
    dependencies=[Depends(require_cluster_auth)],
)
public_router = APIRouter(prefix="/api/v1/cluster", tags=["cluster"])


def _cursor_map(db: Session) -> dict[str, int]:
    return cluster_cursor(db)


def _cluster_event(event: ClusterEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "origin_node_id": event.origin_node_id,
        "origin_seq": event.origin_seq,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "operation": event.operation,
        "occurred_at": event.occurred_at,
        "payload": event.payload_json,
    }


@internal_router.get("/sync/cursors")
def sync_cursors(db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"cursor": _cursor_map(db)}


@internal_router.post("/sync/events/query")
def query_sync_events(
    payload: SyncQueryRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    limit = min(payload.limit or settings.sync_page_size, settings.sync_page_size)
    query = select(ClusterEvent)
    if payload.cursor:
        known_origins = list(payload.cursor)
        conditions = [
            ClusterEvent.origin_node_id.not_in(known_origins),
            *[
                (ClusterEvent.origin_node_id == node_id) & (ClusterEvent.origin_seq > sequence)
                for node_id, sequence in payload.cursor.items()
            ],
        ]
        query = query.where(or_(*conditions))
    events = db.scalars(
        query.order_by(
            # The cursor advances independently for each origin by origin_seq.  The
            # page order must therefore preserve that sequence within every origin;
            # ordering by the caller-controlled occurred_at could otherwise return
            # seq=2 before seq=1 and make seq=1 permanently invisible on the next
            # request.  Sorting by sequence first also interleaves origins instead of
            # draining one origin completely before serving the next one.
            ClusterEvent.origin_seq,
            ClusterEvent.origin_node_id,
            ClusterEvent.event_id,
        ).limit(limit + 1)
    ).all()
    has_more = len(events) > limit
    page = events[:limit]
    SYNC_EVENTS.labels(direction="outbound", result="served").inc(len(page))
    next_cursor = dict(payload.cursor)
    for event in page:
        next_cursor[event.origin_node_id] = max(
            next_cursor.get(event.origin_node_id, 0), event.origin_seq
        )
    return {
        "events": [_cluster_event(event) for event in page],
        "cursor": next_cursor,
        "has_more": has_more,
    }


class ApplyEventsRequest(BaseModel):
    events: list[IncomingClusterEvent] = Field(max_length=1_000)


@internal_router.post("/sync/events/apply")
def apply_sync_events(
    payload: ApplyEventsRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, int]:
    """Idempotently persist remote history and update local projections."""

    result = apply_cluster_events(db, payload.events, settings)
    db.commit()
    SYNC_EVENTS.labels(direction="inbound", result="applied").inc(result.applied)
    SYNC_EVENTS.labels(direction="inbound", result="duplicate").inc(result.duplicates)
    return {"applied": result.applied, "duplicates": result.duplicates}


@internal_router.get("/nodes/health")
def internal_node_health(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    db.execute(select(1))
    return {
        "status": "ok",
        "node_id": settings.node_id,
        "region": settings.node_region,
        "software_version": settings.software_version,
        "cursor": _cursor_map(db),
    }


def _node_response(node: Node) -> dict[str, Any]:
    return {
        "id": node.id,
        "name": node.name,
        "region": node.region,
        "public_api_url": node.public_api_url,
        "private_peer_url": node.private_peer_url,
        "enabled_roles": node.enabled_roles,
        "created_at": node.created_at,
        "last_seen_at": node.last_seen_at,
        "software_version": node.software_version,
    }


@public_router.get("/nodes")
def cluster_nodes(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> list[dict[str, Any]]:
    del user
    return [_node_response(node) for node in db.scalars(select(Node).order_by(Node.id)).all()]


@public_router.get("/status")
def cluster_status(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    nodes = db.scalars(select(Node).order_by(Node.id)).all()
    return {
        "nodes": [_node_response(node) for node in nodes],
        "cursor": _cursor_map(db),
        "cluster_event_count": int(db.scalar(select(func.count(ClusterEvent.event_id))) or 0),
    }
