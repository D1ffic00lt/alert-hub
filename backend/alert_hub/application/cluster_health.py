from __future__ import annotations

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.application.incidents import append_cluster_event, ingest_normalized_events
from alert_hub.domain.events import NormalizedEvent, as_utc, incident_fingerprint
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import Incident, Node, Source
from alert_hub.settings import Settings

CLUSTER_API_HEALTH_SOURCE_ID = str(uuid5(NAMESPACE_URL, "alert-hub:source:cluster-api-health"))
CLUSTER_API_HEALTH_SOURCE_NAME = "Cluster API health"
CLUSTER_API_HEALTH_SOURCE_KIND = "generic_json"
PEER_OFFLINE_FAILURE_THRESHOLD = 3


def _source_payload(source: Source) -> dict[str, object]:
    return {
        "name": source.name,
        "kind": source.kind,
        "enabled": source.enabled,
        "region": source.region,
        "config": source.config_json,
        "token_hash": source.token_hash,
        "created_at": source.created_at.isoformat(),
        "updated_at": source.updated_at.isoformat(),
        "deleted_at": None,
    }


def ensure_cluster_api_health_source(db: Session, settings: Settings) -> Source:
    source = db.get(Source, CLUSTER_API_HEALTH_SOURCE_ID)
    if source is not None:
        return source
    now = utc_now()
    source = Source(
        id=CLUSTER_API_HEALTH_SOURCE_ID,
        name=CLUSTER_API_HEALTH_SOURCE_NAME,
        kind=CLUSTER_API_HEALTH_SOURCE_KIND,
        enabled=False,
        region=None,
        config_json={"allowed_cidrs": [], "system_managed": True},
        # The system source is disabled for public ingest, so this value can never
        # authenticate a request. It only satisfies the replicated Source schema.
        token_hash="0" * 64,
        created_at=now,
        updated_at=now,
    )
    db.add(source)
    db.flush()
    append_cluster_event(
        db,
        settings,
        entity_type="source",
        entity_id=source.id,
        operation="upsert",
        payload=_source_payload(source),
        occurred_at=now,
    )
    return source


def node_api_alert_dedup_key(node_id: str) -> str:
    return f"cluster-node-api-down:{node_id}"


def _node_api_incident(db: Session, node_id: str) -> Incident | None:
    fingerprint = incident_fingerprint(
        CLUSTER_API_HEALTH_SOURCE_ID,
        node_api_alert_dedup_key(node_id),
    )
    return db.scalar(
        select(Incident).where(
            Incident.source_id == CLUSTER_API_HEALTH_SOURCE_ID,
            Incident.fingerprint == fingerprint,
        )
    )


def _labels(node: Node) -> dict[str, str]:
    return {
        "alertname": "AlertHubNodeApiDown",
        "component": "alert-hub-api",
        "node_id": node.id,
        "source_region": node.region,
        "target": node.name,
        "target_name": node.name,
    }


def record_node_api_down(
    db: Session,
    node: Node,
    settings: Settings,
    *,
    failure_count: int,
    observed_at: datetime | None = None,
) -> bool:
    """Open one durable incident after peer health reaches the offline threshold."""

    if not node.api_down_alert_enabled:
        return False
    existing = _node_api_incident(db, node.id)
    if existing is not None and existing.status != "resolved":
        return False
    now = as_utc(observed_at or utc_now())
    source = ensure_cluster_api_health_source(db, settings)
    ingest_normalized_events(
        db,
        source,
        [
            NormalizedEvent(
                dedup_key=node_api_alert_dedup_key(node.id),
                status="firing",
                title=f"API unavailable: {node.name}",
                description=(
                    f"Node {node.name} ({node.region}) failed {failure_count} consecutive "
                    "authenticated peer health checks."
                ),
                severity="critical",
                starts_at=now,
                labels=_labels(node),
                annotations={
                    "observer_node_id": settings.node_id,
                    "failure_count": failure_count,
                },
                external_event_id=(f"node-api-down:{node.id}:{settings.node_id}:{now.isoformat()}"),
            )
        ],
        settings,
    )
    return True


def resolve_node_api_alert(
    db: Session,
    node: Node,
    settings: Settings,
    *,
    reason: str,
    observed_at: datetime | None = None,
) -> bool:
    incident = _node_api_incident(db, node.id)
    if incident is None or incident.status == "resolved":
        return False
    source = db.get(Source, CLUSTER_API_HEALTH_SOURCE_ID)
    if source is None:
        return False
    now = as_utc(observed_at or utc_now())
    ingest_normalized_events(
        db,
        source,
        [
            NormalizedEvent(
                dedup_key=node_api_alert_dedup_key(node.id),
                status="resolved",
                title=f"API unavailable: {node.name}",
                description=reason,
                severity="critical",
                starts_at=incident.starts_at,
                ends_at=now,
                labels=_labels(node),
                annotations={"observer_node_id": settings.node_id, "resolution_reason": reason},
                external_event_id=(
                    f"node-api-recovered:{node.id}:{settings.node_id}:{now.isoformat()}"
                ),
            )
        ],
        settings,
    )
    return True


def set_node_api_down_alert(
    db: Session,
    node: Node,
    enabled: bool,
    settings: Settings,
) -> bool:
    changed = node.api_down_alert_enabled != enabled
    if not changed:
        return False
    node.api_down_alert_enabled = enabled
    append_cluster_event(
        db,
        settings,
        entity_type="node_api_alert_setting",
        entity_id=node.id,
        operation="upsert",
        payload={"enabled": enabled},
    )
    if not enabled:
        resolve_node_api_alert(
            db,
            node,
            settings,
            reason="API-down monitoring was disabled by an operator.",
        )
    return True
