from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from alert_hub.application.heartbeats import (
    project_heartbeat_observation,
    reconcile_heartbeat_incident,
)
from alert_hub.application.incidents import (
    append_cluster_event,
    incident_projection_id,
    reproject_incident,
)
from alert_hub.application.notifications import apply_delivery_receipt, enqueue_notification_event
from alert_hub.domain.events import as_utc
from alert_hub.domain.monitoring import normalize_grafana_url, normalize_job_globs
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import (
    ApplicationSetting,
    AuditLog,
    ClusterEvent,
    HeartbeatState,
    Incident,
    IncidentEvent,
    Node,
    NotificationChannel,
    NotificationRoute,
    PrometheusDatasource,
    PushSubscription,
    Source,
    SyncCursor,
    User,
)
from alert_hub.infrastructure.db.models import Session as AuthSession
from alert_hub.infrastructure.request_security import normalize_cidrs
from alert_hub.settings import Settings


class IncomingClusterEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128)
    origin_node_id: str = Field(min_length=1, max_length=128)
    origin_seq: int = Field(ge=1)
    entity_type: str = Field(min_length=1, max_length=64)
    entity_id: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=64)
    occurred_at: datetime
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ApplyResult:
    applied: int
    duplicates: int


def cluster_cursor(db: Session) -> dict[str, int]:
    rows = db.execute(
        select(ClusterEvent.origin_node_id, func.max(ClusterEvent.origin_seq)).group_by(
            ClusterEvent.origin_node_id
        )
    ).all()
    return {node_id: int(sequence) for node_id, sequence in rows}


def peer_cursor(db: Session, peer_node_id: str) -> dict[str, int]:
    rows = db.scalars(select(SyncCursor).where(SyncCursor.peer_node_id == peer_node_id)).all()
    return {row.origin_node_id: row.origin_seq for row in rows}


def advance_peer_cursor(
    db: Session,
    peer_node_id: str,
    candidates: Mapping[str, int],
) -> dict[str, int]:
    """Advance only across contiguous history, never across a missing sequence."""

    for origin_node_id, candidate in candidates.items():
        row = db.scalar(
            select(SyncCursor).where(
                SyncCursor.peer_node_id == peer_node_id,
                SyncCursor.origin_node_id == origin_node_id,
            )
        )
        current = row.origin_seq if row is not None else 0
        if candidate <= current:
            continue
        present = int(
            db.scalar(
                select(func.count(ClusterEvent.event_id)).where(
                    ClusterEvent.origin_node_id == origin_node_id,
                    ClusterEvent.origin_seq > current,
                    ClusterEvent.origin_seq <= candidate,
                )
            )
            or 0
        )
        if present != candidate - current:
            continue
        if row is None:
            row = SyncCursor(
                peer_node_id=peer_node_id,
                origin_node_id=origin_node_id,
                origin_seq=candidate,
            )
            db.add(row)
        else:
            row.origin_seq = candidate
            row.updated_at = utc_now()
    db.flush()
    return peer_cursor(db, peer_node_id)


def _event_order(event: ClusterEvent) -> tuple[datetime, str]:
    return (as_utc(event.occurred_at), event.event_id)


def _latest_entity_event(db: Session, entity_type: str, entity_id: str) -> ClusterEvent | None:
    events = db.scalars(
        select(ClusterEvent).where(
            ClusterEvent.entity_type == entity_type,
            ClusterEvent.entity_id == entity_id,
        )
    ).all()
    return max(events, key=_event_order, default=None)


def _payload_datetime(
    payload: Mapping[str, Any],
    name: str,
    *,
    default: datetime | None = None,
) -> datetime | None:
    value = payload.get(name)
    if value in {None, ""}:
        return default
    try:
        return as_utc(str(value))
    except (TypeError, ValueError):
        return default


def _decode_blob(payload: Mapping[str, Any], name: str) -> bytes | None:
    value = payload.get(name)
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None


def node_cluster_payload(node: Node) -> dict[str, Any]:
    return {
        "name": node.name,
        "region": node.region,
        "public_api_url": node.public_api_url,
        "private_peer_url": node.private_peer_url,
        "enabled_roles": node.enabled_roles,
        "created_at": node.created_at.isoformat(),
        "software_version": node.software_version,
    }


def register_local_node_event(db: Session, settings: Settings) -> None:
    node = db.get(Node, settings.node_id)
    if node is None:
        return
    payload = node_cluster_payload(node)
    latest = _latest_entity_event(db, "node", node.id)
    if latest is not None and latest.operation == "upsert" and latest.payload_json == payload:
        return
    append_cluster_event(
        db,
        settings,
        entity_type="node",
        entity_id=node.id,
        operation="upsert",
        payload=payload,
    )


def _project_node(db: Session, entity_id: str) -> None:
    event = _latest_entity_event(db, "node", entity_id)
    if event is None:
        return
    payload = event.payload_json
    node = db.get(Node, entity_id)
    created_at = _payload_datetime(payload, "created_at", default=event.occurred_at)
    if node is None:
        node = Node(
            id=entity_id,
            name=str(payload.get("name") or entity_id)[:255],
            region=str(payload.get("region") or "unknown")[:128],
            enabled_roles=list(payload.get("enabled_roles") or []),
            created_at=created_at or event.occurred_at,
        )
        db.add(node)
    node.name = str(payload.get("name") or node.name)[:255]
    node.region = str(payload.get("region") or node.region)[:128]
    node.public_api_url = str(payload["public_api_url"]) if payload.get("public_api_url") else None
    node.private_peer_url = (
        str(payload["private_peer_url"]) if payload.get("private_peer_url") else None
    )
    roles = payload.get("enabled_roles")
    node.enabled_roles = [str(role) for role in roles] if isinstance(roles, list) else []
    node.software_version = str(payload.get("software_version") or "unknown")[:64]
    node.last_seen_at = max(node.last_seen_at or event.occurred_at, event.occurred_at)


def _record_bootstrap_conflict(
    db: Session,
    settings: Settings,
    events: Sequence[ClusterEvent],
) -> None:
    entity_ids = sorted({event.entity_id for event in events})
    if len(entity_ids) < 2:
        return
    conflict_id = str(
        uuid5(
            NAMESPACE_URL,
            "alert-hub:bootstrap-conflict:" + ":".join(sorted(event.event_id for event in events)),
        )
    )
    conflict_at = max(event.occurred_at for event in events)
    if db.get(AuditLog, conflict_id) is None:
        db.add(
            AuditLog(
                id=conflict_id,
                occurred_at=conflict_at,
                node_id=settings.node_id,
                action="bootstrap_conflict_detected",
                entity_type="user",
                details_json={
                    "user_ids": entity_ids,
                    "event_ids": sorted(event.event_id for event in events),
                    "requires_manual_resolution": True,
                },
            )
        )
    # A split-brain bootstrap must stop authentication until an operator resolves it.
    for user_id in entity_ids:
        user = db.get(User, user_id)
        if user is not None and user.disabled_at is None:
            user.disabled_at = conflict_at


def _project_user(db: Session, entity_id: str, settings: Settings) -> None:
    bootstrap_events = db.scalars(
        select(ClusterEvent).where(
            ClusterEvent.entity_type == "user",
            ClusterEvent.operation == "bootstrap",
        )
    ).all()
    _record_bootstrap_conflict(db, settings, bootstrap_events)
    if len({event.entity_id for event in bootstrap_events}) > 1:
        return
    event = _latest_entity_event(db, "user", entity_id)
    if event is None:
        return
    payload = event.payload_json
    username = str(payload.get("username") or "").strip()
    password_hash = str(payload.get("password_hash") or "")
    if not username or not password_hash:
        return
    user = db.get(User, entity_id)
    if user is None:
        existing_username = db.scalar(select(User).where(User.username == username))
        if existing_username is not None and existing_username.id != entity_id:
            _record_bootstrap_conflict(db, settings, bootstrap_events)
            return
        user = User(
            id=entity_id,
            username=username[:255],
            password_hash=password_hash,
            is_admin=bool(payload.get("is_admin", False)),
            created_at=_payload_datetime(payload, "created_at", default=event.occurred_at)
            or event.occurred_at,
        )
        db.add(user)
    else:
        user.username = username[:255]
        user.password_hash = password_hash
        user.is_admin = bool(payload.get("is_admin", user.is_admin))
        user.disabled_at = _payload_datetime(payload, "disabled_at")
    db.flush()
    _replay_user_dependencies(db, entity_id, settings)


def _session_events_for_user(db: Session, user_id: str) -> list[ClusterEvent]:
    return [
        event
        for event in db.scalars(
            select(ClusterEvent).where(ClusterEvent.entity_type == "session")
        ).all()
        if str(event.payload_json.get("user_id") or "") == user_id
    ]


def _push_events_for_session(db: Session, session_id: str) -> list[ClusterEvent]:
    return [
        event
        for event in db.scalars(
            select(ClusterEvent).where(ClusterEvent.entity_type == "push_subscription")
        ).all()
        if str(event.payload_json.get("session_id") or "") == session_id
    ]


def _project_session(db: Session, entity_id: str) -> None:
    events = sorted(
        db.scalars(
            select(ClusterEvent).where(
                ClusterEvent.entity_type == "session",
                ClusterEvent.entity_id == entity_id,
            )
        ).all(),
        key=_event_order,
    )
    if not events:
        return
    state: dict[str, Any] = {}
    revoked_at: datetime | None = None
    for event in events:
        # Revocation is terminal. A delayed rotation can carry a stale null
        # revoked_at value, but it must never make the session usable again.
        state.update(
            (key, value) for key, value in event.payload_json.items() if key != "revoked_at"
        )
        candidate_revoked_at = _payload_datetime(event.payload_json, "revoked_at")
        if candidate_revoked_at is None and event.operation in {"revoke", "tombstone"}:
            candidate_revoked_at = event.occurred_at
        if candidate_revoked_at is not None and (
            revoked_at is None or candidate_revoked_at < revoked_at
        ):
            revoked_at = candidate_revoked_at
    user_id = str(state.get("user_id") or "")
    refresh_hash = str(state.get("refresh_token_hash") or "")
    if not user_id or not refresh_hash or db.get(User, user_id) is None:
        return
    latest = events[-1]
    created_at = _payload_datetime(state, "created_at", default=latest.occurred_at)
    last_used_at = _payload_datetime(state, "last_used_at", default=created_at)
    expires_at = _payload_datetime(state, "expires_at", default=last_used_at)
    absolute = _payload_datetime(state, "absolute_expires_at", default=expires_at)
    if created_at is None or last_used_at is None or expires_at is None or absolute is None:
        return
    auth_session = db.get(AuthSession, entity_id)
    if auth_session is None:
        auth_session = AuthSession(
            id=entity_id,
            user_id=user_id,
            refresh_token_hash=refresh_hash,
            device_name=str(state.get("device_name") or "Unknown device")[:255],
            created_at=created_at,
            last_used_at=last_used_at,
            expires_at=expires_at,
            absolute_expires_at=absolute,
        )
        db.add(auth_session)
    auth_session.user_id = user_id
    auth_session.refresh_token_hash = refresh_hash
    auth_session.device_name = str(state.get("device_name") or "Unknown device")[:255]
    auth_session.created_at = created_at
    auth_session.last_used_at = last_used_at
    auth_session.expires_at = expires_at
    auth_session.absolute_expires_at = absolute
    auth_session.revoked_at = revoked_at
    # A user projection can replay this session before the same sync page reaches
    # its explicit session event.  Flush the newly created row so the second
    # projection resolves it instead of queuing a duplicate INSERT.
    db.flush()
    for push_event in _push_events_for_session(db, entity_id):
        _project_push_subscription(db, push_event.entity_id)


def _project_source(db: Session, entity_id: str, settings: Settings) -> None:
    event = _latest_entity_event(db, "source", entity_id)
    if event is None:
        return
    payload = event.payload_json
    kind = str(payload.get("kind") or "")
    token_hash = str(payload.get("token_hash") or "")
    if not kind or not token_hash:
        return
    raw_config = payload.get("config")
    config = dict(raw_config) if isinstance(raw_config, dict) else {}
    raw_allowed_cidrs = config.get("allowed_cidrs", [])
    if not isinstance(raw_allowed_cidrs, list):
        return
    try:
        config["allowed_cidrs"] = normalize_cidrs(raw_allowed_cidrs)
    except ValueError:
        return
    created_at = _payload_datetime(payload, "created_at", default=event.occurred_at)
    updated_at = _payload_datetime(payload, "updated_at", default=event.occurred_at)
    source = db.get(Source, entity_id)
    if source is None:
        source = Source(
            id=entity_id,
            name=str(payload.get("name") or entity_id)[:255],
            kind=kind[:32],
            token_hash=token_hash,
            created_at=created_at or event.occurred_at,
            updated_at=updated_at or event.occurred_at,
        )
        db.add(source)
    source.name = str(payload.get("name") or source.name)[:255]
    source.kind = kind[:32]
    source.enabled = bool(payload.get("enabled", True)) and event.operation != "tombstone"
    source.region = str(payload["region"])[:128] if payload.get("region") else None
    source.config_json = config
    source.token_hash = token_hash
    source.updated_at = updated_at or event.occurred_at
    source.deleted_at = (
        _payload_datetime(payload, "deleted_at", default=event.occurred_at)
        if event.operation == "tombstone" or payload.get("deleted_at")
        else None
    )
    db.flush()
    if source.kind == "heartbeat" and db.get(HeartbeatState, source.id) is None:
        db.add(HeartbeatState(source_id=source.id, last_received_at=source.created_at))
        # Persist the projection inside this transaction so a heartbeat
        # observation later in the same sync page resolves this identity
        # instead of queuing a second row with the same primary key.
        db.flush()
    # An incident can arrive on a relay before the source that owns it.
    for incident_event in db.scalars(
        select(ClusterEvent).where(ClusterEvent.entity_type == "incident")
    ).all():
        if str(incident_event.payload_json.get("source_id") or "") == entity_id:
            _project_incident_event(db, incident_event, settings)


def _project_channel(db: Session, entity_id: str) -> None:
    event = _latest_entity_event(db, "notification_channel", entity_id)
    if event is None:
        return
    payload = event.payload_json
    encrypted_config = _decode_blob(payload, "encrypted_config")
    if encrypted_config is None:
        return
    created_at = _payload_datetime(payload, "created_at", default=event.occurred_at)
    updated_at = _payload_datetime(payload, "updated_at", default=event.occurred_at)
    channel = db.get(NotificationChannel, entity_id)
    if channel is None:
        channel = NotificationChannel(
            id=entity_id,
            name=str(payload.get("name") or entity_id)[:255],
            kind=str(payload.get("kind") or "generic_webhook")[:32],
            encrypted_config=encrypted_config,
            created_at=created_at or event.occurred_at,
            updated_at=updated_at or event.occurred_at,
        )
        db.add(channel)
    channel.name = str(payload.get("name") or channel.name)[:255]
    channel.kind = str(payload.get("kind") or channel.kind)[:32]
    channel.enabled = bool(payload.get("enabled", True)) and event.operation != "tombstone"
    channel.encrypted_config = encrypted_config
    eligibility = payload.get("eligible_nodes_or_regions")
    channel.eligible_nodes_or_regions = dict(eligibility) if isinstance(eligibility, dict) else {}
    channel.updated_at = updated_at or event.occurred_at
    channel.deleted_at = (
        _payload_datetime(payload, "deleted_at", default=event.occurred_at)
        if event.operation == "tombstone" or payload.get("deleted_at")
        else None
    )
    db.flush()
    _replay_delivery_receipts(db, channel_id=entity_id)


def _project_notification_route(db: Session, entity_id: str) -> None:
    event = _latest_entity_event(db, "notification_route", entity_id)
    if event is None:
        return
    payload = event.payload_json
    route = db.get(NotificationRoute, entity_id)
    if route is None:
        route = NotificationRoute(
            id=entity_id,
            name=str(payload.get("name") or entity_id)[:255],
        )
        db.add(route)
    route.name = str(payload.get("name") or route.name)[:255]
    route.enabled = bool(payload.get("enabled", True)) and event.operation != "tombstone"
    route.priority = int(payload.get("priority") or 0)
    sources = payload.get("source_filter")
    severities = payload.get("severity_filter")
    matchers = payload.get("label_matchers")
    channels = payload.get("channel_ids")
    route.source_filter = [str(item) for item in sources] if isinstance(sources, list) else []
    route.severity_filter = (
        [str(item) for item in severities] if isinstance(severities, list) else []
    )
    route.label_matchers = (
        [dict(item) for item in matchers if isinstance(item, dict)]
        if isinstance(matchers, list)
        else []
    )
    route.channel_ids = (
        [str(item) for item in channels]
        if isinstance(channels, list) and event.operation != "tombstone"
        else []
    )
    route.continue_matching = bool(payload.get("continue_matching", False))


def _project_prometheus_datasource(db: Session, entity_id: str) -> None:
    event = _latest_entity_event(db, "prometheus_datasource", entity_id)
    if event is None:
        return
    datasource = db.get(PrometheusDatasource, entity_id)
    if event.operation == "tombstone":
        if datasource is not None:
            db.delete(datasource)
            db.flush()
        return
    payload = event.payload_json
    encrypted_value = payload.get("encrypted_credentials")
    encrypted_credentials = (
        _decode_blob(payload, "encrypted_credentials") if encrypted_value is not None else None
    )
    if encrypted_value is not None and encrypted_credentials is None:
        return
    name = str(payload.get("name") or "").strip()
    url = str(payload.get("url") or "").strip()
    if not name or not url:
        return
    created_at = _payload_datetime(payload, "created_at", default=event.occurred_at)
    updated_at = _payload_datetime(payload, "updated_at", default=event.occurred_at)
    if datasource is None:
        datasource = PrometheusDatasource(
            id=entity_id,
            name=name[:255],
            url=url[:2048],
            created_at=created_at or event.occurred_at,
            updated_at=updated_at or event.occurred_at,
        )
        db.add(datasource)
    datasource.name = name[:255]
    datasource.url = url[:2048]
    datasource.node_id = str(payload["node_id"])[:128] if payload.get("node_id") else None
    datasource.region = str(payload["region"])[:128] if payload.get("region") else None
    label_mode = str(payload.get("reachability_label_mode") or "canonical")
    datasource.reachability_label_mode = (
        label_mode if label_mode in {"canonical", "server"} else "canonical"
    )
    datasource.enabled = bool(payload.get("enabled", True))
    datasource.encrypted_credentials = encrypted_credentials
    datasource.updated_at = updated_at or event.occurred_at


def _project_application_setting(db: Session, entity_id: str) -> None:
    event = _latest_entity_event(db, "application_setting", entity_id)
    if event is None or event.operation == "tombstone":
        return
    payload = event.payload_json
    try:
        grafana_url = normalize_grafana_url(payload.get("grafana_url"), https_only=True)
        key_job_globs = normalize_job_globs(
            payload.get("key_job_globs"), field_name="key_job_globs"
        )
        alert_hub_job_globs = normalize_job_globs(
            payload.get("alert_hub_job_globs"), field_name="alert_hub_job_globs"
        )
    except ValueError:
        return
    created_at = _payload_datetime(payload, "created_at", default=event.occurred_at)
    updated_at = _payload_datetime(payload, "updated_at", default=event.occurred_at)
    stored = db.get(ApplicationSetting, entity_id)
    if stored is None:
        stored = ApplicationSetting(
            id=entity_id,
            grafana_url=grafana_url,
            key_job_globs=key_job_globs,
            alert_hub_job_globs=alert_hub_job_globs,
            created_at=created_at or event.occurred_at,
            updated_at=updated_at or event.occurred_at,
        )
        db.add(stored)
        return
    stored.grafana_url = grafana_url
    stored.key_job_globs = key_job_globs
    stored.alert_hub_job_globs = alert_hub_job_globs
    stored.updated_at = updated_at or event.occurred_at


def _push_events_for_user(db: Session, user_id: str) -> list[ClusterEvent]:
    return [
        event
        for event in db.scalars(
            select(ClusterEvent).where(ClusterEvent.entity_type == "push_subscription")
        ).all()
        if str(event.payload_json.get("user_id") or "") == user_id
    ]


def _project_push_subscription(db: Session, entity_id: str) -> None:
    events = db.scalars(
        select(ClusterEvent).where(
            ClusterEvent.entity_type == "push_subscription",
            ClusterEvent.entity_id == entity_id,
        )
    ).all()
    state_events = [event for event in events if event.operation in {"upsert", "tombstone"}]
    if not state_events:
        return
    bound_state_events = [event for event in state_events if event.payload_json.get("session_id")]
    if bound_state_events:
        # Once a subscription is bound to an authenticated session, an old
        # pre-migration upsert must not erase that binding or revive a tombstone.
        effective_state_events = [
            event
            for event in state_events
            if event.operation == "tombstone" or event.payload_json.get("session_id")
        ]
        configuration_event = max(bound_state_events, key=_event_order)
    else:
        effective_state_events = state_events
        configuration_event = max(state_events, key=_event_order)
    payload = configuration_event.payload_json
    user_id = str(payload.get("user_id") or "")
    endpoint = _decode_blob(payload, "endpoint")
    p256dh = _decode_blob(payload, "p256dh")
    auth = _decode_blob(payload, "auth")
    if (
        not user_id
        or db.get(User, user_id) is None
        or endpoint is None
        or p256dh is None
        or auth is None
    ):
        return
    requested_session_id = str(payload.get("session_id") or "") or None
    linked_session = db.get(AuthSession, requested_session_id) if requested_session_id else None
    if requested_session_id is not None and (
        linked_session is None or linked_session.user_id != user_id
    ):
        # A subscription may arrive through another origin before the session it
        # references. Keep the event and replay it when session projection catches
        # up instead of weakening the foreign key into a legacy, unbound endpoint.
        return
    session_id = requested_session_id
    created_at = _payload_datetime(
        payload,
        "created_at",
        default=configuration_event.occurred_at,
    )
    subscription = db.get(PushSubscription, entity_id)
    if subscription is None:
        subscription = PushSubscription(
            id=entity_id,
            user_id=user_id,
            session_id=session_id,
            device_name=str(payload.get("device_name") or "Installed PWA")[:255],
            endpoint=endpoint,
            p256dh=p256dh,
            auth=auth,
            created_at=created_at or configuration_event.occurred_at,
        )
        db.add(subscription)
    subscription.user_id = user_id
    subscription.session_id = session_id
    subscription.device_name = str(payload.get("device_name") or subscription.device_name)[:255]
    subscription.endpoint = endpoint
    subscription.p256dh = p256dh
    subscription.auth = auth
    subscription.user_agent = (
        str(payload["user_agent"])[:1024] if payload.get("user_agent") else None
    )
    last_success_at: datetime | None = None
    for history_event in events:
        candidate = _payload_datetime(history_event.payload_json, "last_success_at")
        if candidate is not None and (last_success_at is None or candidate > last_success_at):
            last_success_at = candidate
    if last_success_at is not None and (
        subscription.last_success_at is None or subscription.last_success_at < last_success_at
    ):
        subscription.last_success_at = last_success_at
    removal_events = [
        event
        for event in effective_state_events
        if event.operation == "tombstone" or event.payload_json.get("disabled_at")
    ]
    disabled_at: datetime | None = None
    if removal_events:
        # Subscription IDs are immutable generations. Once one generation is
        # removed, no delayed upsert may resurrect it; re-registration gets a
        # fresh ID instead.
        removal_event = min(removal_events, key=_event_order)
        disabled_at = _payload_datetime(
            removal_event.payload_json,
            "disabled_at",
            default=removal_event.occurred_at,
        )
    if requested_session_id is None:
        disabled_at = disabled_at or configuration_event.occurred_at
    if linked_session is not None and linked_session.revoked_at is not None:
        disabled_at = disabled_at or linked_session.revoked_at
    subscription.disabled_at = disabled_at
    db.flush()
    _replay_delivery_receipts(db, subscription_id=entity_id)


def _incident_anchor(db: Session, event: ClusterEvent) -> tuple[str, str] | None:
    source_id = str(event.payload_json.get("source_id") or "")
    fingerprint = str(event.payload_json.get("fingerprint") or "")
    if source_id and fingerprint:
        return source_id, fingerprint
    related = sorted(
        db.scalars(
            select(ClusterEvent).where(
                ClusterEvent.entity_type == "incident",
                ClusterEvent.entity_id == event.entity_id,
            )
        ).all(),
        key=_event_order,
    )
    for candidate in related:
        source_id = str(candidate.payload_json.get("source_id") or "")
        fingerprint = str(candidate.payload_json.get("fingerprint") or "")
        if source_id and fingerprint:
            return source_id, fingerprint
    return None


def _merge_incident(db: Session, canonical: Incident, duplicate: Incident) -> None:
    rows = db.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == duplicate.id)).all()
    for row in rows:
        existing = db.scalar(
            select(IncidentEvent).where(
                IncidentEvent.event_key == row.event_key,
                IncidentEvent.id != row.id,
            )
        )
        if existing is None:
            row.incident_id = canonical.id
        else:
            db.delete(row)
    db.flush()
    db.delete(duplicate)
    db.flush()


def _canonical_incident(
    db: Session,
    event: ClusterEvent,
    source_id: str,
    fingerprint: str,
) -> Incident | None:
    if db.get(Source, source_id) is None:
        return None
    canonical_id = incident_projection_id(source_id, fingerprint)
    canonical = db.get(Incident, canonical_id)
    existing = db.scalar(
        select(Incident).where(
            Incident.source_id == source_id,
            Incident.fingerprint == fingerprint,
        )
    )
    payload = event.payload_json
    starts_at = _payload_datetime(payload, "starts_at", default=event.occurred_at)
    if canonical is None and existing is not None and existing.id != canonical_id:
        canonical = Incident(
            id=canonical_id,
            source_id=source_id,
            fingerprint=fingerprint,
            title=existing.title,
            description=existing.description,
            severity=existing.severity,
            status=existing.status,
            labels_json=existing.labels_json,
            annotations_json=existing.annotations_json,
            starts_at=existing.starts_at,
            last_event_at=existing.last_event_at,
            resolved_at=existing.resolved_at,
            acknowledged_at=existing.acknowledged_at,
            acknowledged_by=existing.acknowledged_by,
        )
        db.add(canonical)
        db.flush()
        _merge_incident(db, canonical, existing)
    elif canonical is None:
        canonical = Incident(
            id=canonical_id,
            source_id=source_id,
            fingerprint=fingerprint,
            title=str(payload.get("title") or "Replicated incident")[:1024],
            description=str(payload.get("description") or ""),
            severity=str(payload.get("severity") or "unknown")[:16],
            status="open",
            labels_json=(
                dict(payload["labels"]) if isinstance(payload.get("labels"), dict) else {}
            ),
            annotations_json=(
                dict(payload["annotations"]) if isinstance(payload.get("annotations"), dict) else {}
            ),
            starts_at=starts_at or event.occurred_at,
            last_event_at=event.occurred_at,
        )
        db.add(canonical)
        db.flush()
    if existing is not None and existing.id != canonical.id:
        _merge_incident(db, canonical, existing)
    return canonical


def _project_incident_event(db: Session, event: ClusterEvent, settings: Settings) -> None:
    anchor = _incident_anchor(db, event)
    if anchor is None:
        return
    source_id, fingerprint = anchor
    incident = _canonical_incident(db, event, source_id, fingerprint)
    if incident is None:
        return
    event_key = str(event.payload_json.get("event_key") or event.event_id)
    existing = db.scalar(select(IncidentEvent).where(IncidentEvent.event_key == event_key))
    if existing is None:
        existing = IncidentEvent(
            id=event.event_id,
            origin_node_id=event.origin_node_id,
            origin_seq=event.origin_seq,
            event_key=event_key[:128],
            incident_id=incident.id,
            event_type=event.operation[:32],
            occurred_at=event.occurred_at,
            payload_json=dict(event.payload_json),
        )
        db.add(existing)
        db.flush()
    elif existing.incident_id != incident.id:
        duplicate_incident = db.get(Incident, existing.incident_id)
        if duplicate_incident is not None:
            _merge_incident(db, incident, duplicate_incident)
    reproject_incident(db, incident)
    reconcile_heartbeat_incident(db, existing, incident, settings)
    enqueue_notification_event(db, existing)
    db.flush()
    _replay_delivery_receipts(
        db,
        event_id=existing.id,
        event_key=existing.event_key,
    )


def _project_delivery_receipt(db: Session, event: ClusterEvent) -> None:
    payload = event.payload_json
    channel_id = str(payload.get("channel_id") or "")
    subscription_id = str(payload.get("subscription_id") or "")
    if not channel_id or db.get(NotificationChannel, channel_id) is None:
        return
    if subscription_id and db.get(PushSubscription, subscription_id) is None:
        return
    apply_delivery_receipt(db, payload)


def _project_heartbeat_observation(
    db: Session,
    event: ClusterEvent,
    settings: Settings,
) -> None:
    observed_at = _payload_datetime(
        event.payload_json,
        "received_at",
        default=event.occurred_at,
    )
    if observed_at is None:
        return
    project_heartbeat_observation(db, event.entity_id, observed_at, settings)


def _replay_delivery_receipts(
    db: Session,
    *,
    event_id: str | None = None,
    event_key: str | None = None,
    channel_id: str | None = None,
    subscription_id: str | None = None,
) -> None:
    events = db.scalars(
        select(ClusterEvent).where(ClusterEvent.entity_type == "delivery_receipt")
    ).all()
    for event in events:
        payload = event.payload_json
        payload_event_id = str(payload.get("event_id") or payload.get("source_event_id") or "")
        payload_event_key = str(payload.get("source_event_key") or "")
        if event_id is not None or event_key is not None:
            matches_id = event_id is not None and payload_event_id == event_id
            matches_key = event_key is not None and payload_event_key == event_key
            if not matches_id and not matches_key:
                continue
        if channel_id is not None and str(payload.get("channel_id") or "") != channel_id:
            continue
        if (
            subscription_id is not None
            and str(payload.get("subscription_id") or "") != subscription_id
        ):
            continue
        _project_delivery_receipt(db, event)


def _replay_user_dependencies(db: Session, user_id: str, settings: Settings) -> None:
    del settings
    for event in _session_events_for_user(db, user_id):
        _project_session(db, event.entity_id)
    for event in _push_events_for_user(db, user_id):
        _project_push_subscription(db, event.entity_id)


def _project_event(db: Session, event: ClusterEvent, settings: Settings) -> None:
    if event.entity_type == "node":
        _project_node(db, event.entity_id)
    elif event.entity_type == "user":
        _project_user(db, event.entity_id, settings)
    elif event.entity_type == "session":
        _project_session(db, event.entity_id)
    elif event.entity_type == "source":
        _project_source(db, event.entity_id, settings)
    elif event.entity_type == "incident":
        _project_incident_event(db, event, settings)
    elif event.entity_type == "notification_channel":
        _project_channel(db, event.entity_id)
    elif event.entity_type == "notification_route":
        _project_notification_route(db, event.entity_id)
    elif event.entity_type == "prometheus_datasource":
        _project_prometheus_datasource(db, event.entity_id)
    elif event.entity_type == "application_setting":
        _project_application_setting(db, event.entity_id)
    elif event.entity_type == "push_subscription":
        _project_push_subscription(db, event.entity_id)
    elif event.entity_type == "delivery_receipt":
        _project_delivery_receipt(db, event)
    elif event.entity_type == "heartbeat_observation":
        _project_heartbeat_observation(db, event, settings)


def apply_cluster_events(
    db: Session,
    incoming_events: Iterable[IncomingClusterEvent],
    settings: Settings,
) -> ApplyResult:
    """Persist original history and idempotently rebuild application projections."""

    applied_events: list[ClusterEvent] = []
    duplicates = 0
    for incoming in incoming_events:
        existing = db.scalar(
            select(ClusterEvent.event_id).where(
                or_(
                    ClusterEvent.event_id == incoming.event_id,
                    (ClusterEvent.origin_node_id == incoming.origin_node_id)
                    & (ClusterEvent.origin_seq == incoming.origin_seq),
                )
            )
        )
        if existing is not None:
            duplicates += 1
            continue
        event = ClusterEvent(
            event_id=incoming.event_id,
            origin_node_id=incoming.origin_node_id,
            origin_seq=incoming.origin_seq,
            entity_type=incoming.entity_type,
            entity_id=incoming.entity_id,
            operation=incoming.operation,
            occurred_at=as_utc(incoming.occurred_at),
            payload_json=incoming.payload,
        )
        db.add(event)
        db.flush()
        applied_events.append(event)

    priorities = {
        "node": 0,
        "user": 1,
        "source": 2,
        "session": 3,
        "notification_channel": 3,
        "notification_route": 3,
        "prometheus_datasource": 3,
        "application_setting": 3,
        "push_subscription": 4,
        "incident": 5,
        "heartbeat_observation": 6,
        "delivery_receipt": 7,
    }
    for event in sorted(
        applied_events,
        key=lambda item: (priorities.get(item.entity_type, 10), *_event_order(item)),
    ):
        _project_event(db, event, settings)
        # A later event in this page may project the same entity again.  Flush
        # each projection boundary so primary-key lookups resolve rows added by
        # the previous event while keeping the whole page in one transaction.
        db.flush()
    return ApplyResult(applied=len(applied_events), duplicates=duplicates)
