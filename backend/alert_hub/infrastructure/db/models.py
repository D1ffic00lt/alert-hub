from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from alert_hub.infrastructure.db.base import Base, UTCDateTime, new_id, utc_now


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    region: Mapped[str] = mapped_column(String(128), index=True)
    public_api_url: Mapped[str | None] = mapped_column(String(2048))
    private_peer_url: Mapped[str | None] = mapped_column(String(2048))
    enabled_roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    software_version: Mapped[str] = mapped_column(String(64), default="unknown")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    sessions: Mapped[list[Session]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    device_name: Mapped[str] = mapped_column(String(255), default="Unknown device")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    last_used_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    absolute_expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    user: Mapped[User] = relationship(back_populates="sessions")


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    region: Mapped[str | None] = mapped_column(String(128), index=True)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    token_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), index=True)

    incidents: Mapped[list[Incident]] = relationship(back_populates="source")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("source_id", "fingerprint", name="uq_incidents_source_fingerprint"),
        Index("ix_incidents_status_last_event", "status", "last_event_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(
        ForeignKey("sources.id", ondelete="RESTRICT"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    labels_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    annotations_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    starts_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_event_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    acknowledged_by: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    source: Mapped[Source] = relationship(back_populates="incidents")
    events: Mapped[list[IncidentEvent]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvent.occurred_at, IncidentEvent.id",
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    __table_args__ = (
        UniqueConstraint("origin_node_id", "origin_seq", name="uq_incident_events_origin_seq"),
        UniqueConstraint("event_key", name="uq_incident_events_event_key"),
        Index("ix_incident_events_incident_time", "incident_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    origin_node_id: Mapped[str] = mapped_column(String(128), index=True)
    origin_seq: Mapped[int] = mapped_column(Integer)
    event_key: Mapped[str] = mapped_column(String(128))
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    incident: Mapped[Incident] = relationship(back_populates="events")


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    encrypted_config: Mapped[bytes] = mapped_column(LargeBinary)
    eligible_nodes_or_regions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class NotificationRoute(Base):
    __tablename__ = "notification_routes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=0, index=True)
    source_filter: Mapped[list[str]] = mapped_column(JSON, default=list)
    severity_filter: Mapped[list[str]] = mapped_column(JSON, default=list)
    label_matchers: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    channel_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    continue_matching: Mapped[bool] = mapped_column(Boolean, default=False)


class PushSubscription(Base):
    __tablename__ = "push_subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    device_name: Mapped[str] = mapped_column(String(255))
    endpoint: Mapped[bytes] = mapped_column(LargeBinary)
    p256dh: Mapped[bytes] = mapped_column(LargeBinary)
    auth: Mapped[bytes] = mapped_column(LargeBinary)
    user_agent: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Delivery(Base):
    __tablename__ = "deliveries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(
        ForeignKey("incident_events.id", ondelete="CASCADE"), index=True
    )
    channel_id: Mapped[str] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True
    )
    subscription_id: Mapped[str | None] = mapped_column(
        ForeignKey("push_subscriptions.id", ondelete="CASCADE")
    )
    owner_node_id: Mapped[str] = mapped_column(String(128), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), index=True)
    provider_status: Mapped[str | None] = mapped_column(String(255))
    error_code: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Outbox(Base):
    __tablename__ = "outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    topic: Mapped[str] = mapped_column(String(64), index=True)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    available_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    locked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), index=True)
    last_error: Mapped[str | None] = mapped_column(Text)


class SyncCursor(Base):
    __tablename__ = "sync_cursors"
    __table_args__ = (UniqueConstraint("peer_node_id", "origin_node_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    peer_node_id: Mapped[str] = mapped_column(String(128), index=True)
    origin_node_id: Mapped[str] = mapped_column(String(128), index=True)
    origin_seq: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class ClusterEvent(Base):
    __tablename__ = "cluster_events"
    __table_args__ = (
        UniqueConstraint("origin_node_id", "origin_seq", name="uq_cluster_events_origin_seq"),
        Index("ix_cluster_events_origin_cursor", "origin_node_id", "origin_seq"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    origin_node_id: Mapped[str] = mapped_column(String(128))
    origin_seq: Mapped[int] = mapped_column(Integer)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(128), index=True)
    operation: Mapped[str] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, index=True)
    node_id: Mapped[str] = mapped_column(String(128), index=True)
    actor_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(128), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(128))
    request_id: Mapped[str | None] = mapped_column(String(128))
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class PrometheusDatasource(Base):
    __tablename__ = "prometheus_datasources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(2048))
    node_id: Mapped[str | None] = mapped_column(String(128), index=True)
    region: Mapped[str | None] = mapped_column(String(128), index=True)
    encrypted_credentials: Mapped[bytes | None] = mapped_column(LargeBinary)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)


class HeartbeatState(Base):
    __tablename__ = "heartbeat_state"

    source_id: Mapped[str] = mapped_column(
        ForeignKey("sources.id", ondelete="CASCADE"), primary_key=True
    )
    last_received_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now)
    missed: Mapped[bool] = mapped_column(Boolean, default=False)
    last_event_key: Mapped[str | None] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utc_now, onupdate=utc_now)
