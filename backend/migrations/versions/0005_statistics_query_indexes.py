"""Add bounded-window statistics query indexes.

Revision ID: 0005_statistics_indexes
Revises: 0004_monitoring_settings
Create Date: 2026-09-05
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_statistics_indexes"
down_revision: str | None = "0004_monitoring_settings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_incidents_status_severity",
        "incidents",
        ["status", "severity"],
        unique=False,
    )
    op.create_index(
        "ix_incident_events_incident_time_key",
        "incident_events",
        ["incident_id", "occurred_at", "event_key"],
        unique=False,
    )
    # The new index preserves the released index's complete prefix, so N-1 code
    # retains its incident/time lookup before the redundant write cost is removed.
    op.drop_index("ix_incident_events_incident_time", table_name="incident_events")
    op.create_index(
        "ix_incident_events_type_time_incident",
        "incident_events",
        ["event_type", "occurred_at", "incident_id"],
        unique=False,
    )
    op.create_index(
        "ix_cluster_events_type_operation_time",
        "cluster_events",
        ["entity_type", "operation", "occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_cluster_events_type_operation_time",
        table_name="cluster_events",
    )
    op.drop_index(
        "ix_incident_events_type_time_incident",
        table_name="incident_events",
    )
    op.create_index(
        "ix_incident_events_incident_time",
        "incident_events",
        ["incident_id", "occurred_at"],
        unique=False,
    )
    op.drop_index(
        "ix_incident_events_incident_time_key",
        table_name="incident_events",
    )
    op.drop_index(
        "ix_incidents_status_severity",
        table_name="incidents",
    )
