"""Add replicated application monitoring settings.

Revision ID: 0004_monitoring_settings
Revises: 0003_reachability_labels
Create Date: 2026-09-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_monitoring_settings"
down_revision: str | None = "0003_reachability_labels"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "application_settings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("grafana_url", sa.String(length=2048), nullable=True),
        sa.Column("key_job_globs", sa.JSON(), nullable=False),
        sa.Column("alert_hub_job_globs", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_application_settings"),
    )


def downgrade() -> None:
    op.drop_table("application_settings")
