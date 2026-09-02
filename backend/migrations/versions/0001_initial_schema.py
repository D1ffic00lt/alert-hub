"""Create the Alert Hub MVP schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-01

This revision is an immutable snapshot.  Keep it independent from the live ORM
metadata so later model changes cannot silently rewrite fresh installations.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "nodes",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("region", sa.String(length=128), nullable=False),
        sa.Column("public_api_url", sa.String(length=2048), nullable=True),
        sa.Column("private_peer_url", sa.String(length=2048), nullable=True),
        sa.Column("enabled_roles", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("software_version", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_nodes"),
    )
    op.create_index("ix_nodes_region", "nodes", ["region"], unique=False)

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_sessions_user_id_users", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
    )
    op.create_index(
        "ix_sessions_refresh_token_hash", "sessions", ["refresh_token_hash"], unique=True
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"], unique=False)

    op.create_table(
        "sources",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("region", sa.String(length=128), nullable=True),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_sources"),
    )
    op.create_index("ix_sources_deleted_at", "sources", ["deleted_at"], unique=False)
    op.create_index("ix_sources_enabled", "sources", ["enabled"], unique=False)
    op.create_index("ix_sources_kind", "sources", ["kind"], unique=False)
    op.create_index("ix_sources_region", "sources", ["region"], unique=False)

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=1024), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("labels_json", sa.JSON(), nullable=False),
        sa.Column("annotations_json", sa.JSON(), nullable=False),
        sa.Column("starts_at", sa.DateTime(), nullable=False),
        sa.Column("last_event_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(
            ["acknowledged_by"],
            ["users.id"],
            name="fk_incidents_acknowledged_by_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name="fk_incidents_source_id_sources",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incidents"),
        sa.UniqueConstraint("source_id", "fingerprint", name="uq_incidents_source_fingerprint"),
    )
    op.create_index("ix_incidents_fingerprint", "incidents", ["fingerprint"], unique=False)
    op.create_index("ix_incidents_last_event_at", "incidents", ["last_event_at"], unique=False)
    op.create_index("ix_incidents_severity", "incidents", ["severity"], unique=False)
    op.create_index("ix_incidents_source_id", "incidents", ["source_id"], unique=False)
    op.create_index("ix_incidents_status", "incidents", ["status"], unique=False)
    op.create_index(
        "ix_incidents_status_last_event",
        "incidents",
        ["status", "last_event_at"],
        unique=False,
    )

    op.create_table(
        "incident_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("origin_node_id", sa.String(length=128), nullable=False),
        sa.Column("origin_seq", sa.Integer(), nullable=False),
        sa.Column("event_key", sa.String(length=128), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name="fk_incident_events_incident_id_incidents",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incident_events"),
        sa.UniqueConstraint("event_key", name="uq_incident_events_event_key"),
        sa.UniqueConstraint("origin_node_id", "origin_seq", name="uq_incident_events_origin_seq"),
    )
    op.create_index(
        "ix_incident_events_event_type", "incident_events", ["event_type"], unique=False
    )
    op.create_index(
        "ix_incident_events_incident_id", "incident_events", ["incident_id"], unique=False
    )
    op.create_index(
        "ix_incident_events_incident_time",
        "incident_events",
        ["incident_id", "occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_incident_events_occurred_at", "incident_events", ["occurred_at"], unique=False
    )
    op.create_index(
        "ix_incident_events_origin_node_id",
        "incident_events",
        ["origin_node_id"],
        unique=False,
    )

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("encrypted_config", sa.LargeBinary(), nullable=False),
        sa.Column("eligible_nodes_or_regions", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_notification_channels"),
    )
    op.create_index(
        "ix_notification_channels_kind", "notification_channels", ["kind"], unique=False
    )

    op.create_table(
        "notification_routes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("source_filter", sa.JSON(), nullable=False),
        sa.Column("severity_filter", sa.JSON(), nullable=False),
        sa.Column("label_matchers", sa.JSON(), nullable=False),
        sa.Column("channel_ids", sa.JSON(), nullable=False),
        sa.Column("continue_matching", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_notification_routes"),
    )
    op.create_index(
        "ix_notification_routes_priority", "notification_routes", ["priority"], unique=False
    )

    op.create_table(
        "push_subscriptions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=False),
        sa.Column("endpoint", sa.LargeBinary(), nullable=False),
        sa.Column("p256dh", sa.LargeBinary(), nullable=False),
        sa.Column("auth", sa.LargeBinary(), nullable=False),
        sa.Column("user_agent", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_push_subscriptions_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_push_subscriptions"),
    )
    op.create_index(
        "ix_push_subscriptions_user_id", "push_subscriptions", ["user_id"], unique=False
    )

    op.create_table(
        "deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("channel_id", sa.String(length=36), nullable=False),
        sa.Column("subscription_id", sa.String(length=36), nullable=True),
        sa.Column("owner_node_id", sa.String(length=128), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("provider_status", sa.String(length=255), nullable=True),
        sa.Column("error_code", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["channel_id"],
            ["notification_channels.id"],
            name="fk_deliveries_channel_id_notification_channels",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["incident_events.id"],
            name="fk_deliveries_event_id_incident_events",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["subscription_id"],
            ["push_subscriptions.id"],
            name="fk_deliveries_subscription_id_push_subscriptions",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_deliveries"),
    )
    op.create_index("ix_deliveries_channel_id", "deliveries", ["channel_id"], unique=False)
    op.create_index("ix_deliveries_event_id", "deliveries", ["event_id"], unique=False)
    op.create_index("ix_deliveries_owner_node_id", "deliveries", ["owner_node_id"], unique=False)
    op.create_index("ix_deliveries_status", "deliveries", ["status"], unique=False)

    op.create_table(
        "outbox",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("topic", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("available_at", sa.DateTime(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("locked_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_outbox"),
    )
    op.create_index("ix_outbox_available_at", "outbox", ["available_at"], unique=False)
    op.create_index("ix_outbox_completed_at", "outbox", ["completed_at"], unique=False)
    op.create_index("ix_outbox_topic", "outbox", ["topic"], unique=False)

    op.create_table(
        "sync_cursors",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("peer_node_id", sa.String(length=128), nullable=False),
        sa.Column("origin_node_id", sa.String(length=128), nullable=False),
        sa.Column("origin_seq", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_sync_cursors"),
        sa.UniqueConstraint("peer_node_id", "origin_node_id", name="uq_sync_cursors_peer_node_id"),
    )
    op.create_index(
        "ix_sync_cursors_origin_node_id", "sync_cursors", ["origin_node_id"], unique=False
    )
    op.create_index("ix_sync_cursors_peer_node_id", "sync_cursors", ["peer_node_id"], unique=False)

    op.create_table(
        "cluster_events",
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("origin_node_id", sa.String(length=128), nullable=False),
        sa.Column("origin_seq", sa.Integer(), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("event_id", name="pk_cluster_events"),
        sa.UniqueConstraint("origin_node_id", "origin_seq", name="uq_cluster_events_origin_seq"),
    )
    op.create_index("ix_cluster_events_entity_id", "cluster_events", ["entity_id"], unique=False)
    op.create_index(
        "ix_cluster_events_entity_type", "cluster_events", ["entity_type"], unique=False
    )
    op.create_index(
        "ix_cluster_events_occurred_at", "cluster_events", ["occurred_at"], unique=False
    )
    op.create_index(
        "ix_cluster_events_origin_cursor",
        "cluster_events",
        ["origin_node_id", "origin_seq"],
        unique=False,
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("node_id", sa.String(length=128), nullable=False),
        sa.Column("actor_user_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=True),
        sa.Column("entity_id", sa.String(length=128), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_audit_log_actor_user_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"], unique=False)
    op.create_index("ix_audit_log_node_id", "audit_log", ["node_id"], unique=False)
    op.create_index("ix_audit_log_occurred_at", "audit_log", ["occurred_at"], unique=False)

    op.create_table(
        "prometheus_datasources",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("node_id", sa.String(length=128), nullable=True),
        sa.Column("region", sa.String(length=128), nullable=True),
        sa.Column("encrypted_credentials", sa.LargeBinary(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_prometheus_datasources"),
    )
    op.create_index(
        "ix_prometheus_datasources_node_id",
        "prometheus_datasources",
        ["node_id"],
        unique=False,
    )
    op.create_index(
        "ix_prometheus_datasources_region",
        "prometheus_datasources",
        ["region"],
        unique=False,
    )

    op.create_table(
        "heartbeat_state",
        sa.Column("source_id", sa.String(length=36), nullable=False),
        sa.Column("last_received_at", sa.DateTime(), nullable=False),
        sa.Column("missed", sa.Boolean(), nullable=False),
        sa.Column("last_event_key", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name="fk_heartbeat_state_source_id_sources",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("source_id", name="pk_heartbeat_state"),
    )


def downgrade() -> None:
    op.drop_table("heartbeat_state")
    op.drop_table("prometheus_datasources")
    op.drop_table("audit_log")
    op.drop_table("cluster_events")
    op.drop_table("sync_cursors")
    op.drop_table("outbox")
    op.drop_table("deliveries")
    op.drop_table("push_subscriptions")
    op.drop_table("notification_routes")
    op.drop_table("notification_channels")
    op.drop_table("incident_events")
    op.drop_table("incidents")
    op.drop_table("sources")
    op.drop_table("sessions")
    op.drop_table("users")
    op.drop_table("nodes")
