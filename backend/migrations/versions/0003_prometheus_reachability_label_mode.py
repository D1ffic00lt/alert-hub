"""Add explicit Prometheus reachability label selection.

Revision ID: 0003_reachability_labels
Revises: 0002_push_session
Create Date: 2026-09-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_reachability_labels"
down_revision: str | None = "0002_push_session"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("prometheus_datasources") as batch_op:
        batch_op.add_column(
            sa.Column(
                "reachability_label_mode",
                sa.String(length=32),
                server_default="canonical",
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("prometheus_datasources") as batch_op:
        batch_op.drop_column("reachability_label_mode")
