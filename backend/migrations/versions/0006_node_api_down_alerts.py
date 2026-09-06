"""Add per-node API-down alert settings and verified peer identities.

Revision ID: 0006_node_api_down_alerts
Revises: 0005_statistics_indexes
Create Date: 2026-09-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_node_api_down_alerts"
down_revision: str | None = "0005_statistics_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("nodes") as batch_op:
        batch_op.add_column(
            sa.Column(
                "api_down_alert_enabled",
                sa.Boolean(),
                server_default=sa.false(),
                nullable=False,
            )
        )
    op.create_table(
        "peer_endpoint_identities",
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("node_id", sa.String(length=128), nullable=False),
        sa.Column("verified_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name="fk_peer_endpoint_identities_node_id_nodes",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("base_url", name="pk_peer_endpoint_identities"),
    )
    op.create_index(
        "ix_peer_endpoint_identities_node_id",
        "peer_endpoint_identities",
        ["node_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_peer_endpoint_identities_node_id",
        table_name="peer_endpoint_identities",
    )
    op.drop_table("peer_endpoint_identities")
    with op.batch_alter_table("nodes") as batch_op:
        batch_op.drop_column("api_down_alert_enabled")
