"""Index the cluster event order used by the browser event stream.

Revision ID: 0008_cluster_event_stream_index
Revises: 0007_service_tokens
Create Date: 2026-11-10
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008_cluster_event_stream_index"
down_revision: str | None = "0007_service_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_cluster_events_received_at_event_id",
        "cluster_events",
        ["received_at", "event_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_cluster_events_received_at_event_id", table_name="cluster_events")
