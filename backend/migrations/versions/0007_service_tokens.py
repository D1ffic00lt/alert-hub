"""Add replicated read-only service tokens.

Revision ID: 0007_service_tokens
Revises: 0006_node_api_down_alerts
Create Date: 2026-09-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_service_tokens"
down_revision: str | None = "0006_node_api_down_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("scopes_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_service_tokens_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_service_tokens"),
    )
    op.create_index(
        "ix_service_tokens_expires_at",
        "service_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_service_tokens_revoked_at",
        "service_tokens",
        ["revoked_at"],
        unique=False,
    )
    op.create_index(
        "ix_service_tokens_token_hash",
        "service_tokens",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_service_tokens_user_id",
        "service_tokens",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_service_tokens_user_id", table_name="service_tokens")
    op.drop_index("ix_service_tokens_token_hash", table_name="service_tokens")
    op.drop_index("ix_service_tokens_revoked_at", table_name="service_tokens")
    op.drop_index("ix_service_tokens_expires_at", table_name="service_tokens")
    op.drop_table("service_tokens")
