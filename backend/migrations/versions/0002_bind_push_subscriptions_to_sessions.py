"""Bind Web Push subscriptions to authenticated browser sessions.

Revision ID: 0002_push_session
Revises: 0001_initial
Create Date: 2026-09-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_push_session"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DELIVERY_COLUMNS = (
    "id, event_id, channel_id, subscription_id, owner_node_id, attempt, status, "
    "provider_status, error_code, created_at, finished_at"
)
_SQLITE_DELIVERY_BACKUP = "_alert_hub_0002_deliveries"


def _backup_sqlite_subscription_deliveries() -> bool:
    """Preserve child rows while SQLite recreates their referenced table."""

    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        return False
    if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 1:
        raise RuntimeError("SQLite foreign-key enforcement must be enabled during migration")
    connection.exec_driver_sql(
        f"CREATE TEMPORARY TABLE {_SQLITE_DELIVERY_BACKUP} AS "
        f"SELECT {_DELIVERY_COLUMNS} FROM deliveries WHERE subscription_id IS NOT NULL"
    )
    return True


def _restore_sqlite_subscription_deliveries() -> None:
    """Restore cascaded rows and prove that every reconstructed FK is valid."""

    connection = op.get_bind()
    expected = connection.exec_driver_sql(
        f"SELECT COUNT(*) FROM {_SQLITE_DELIVERY_BACKUP}"
    ).scalar_one()
    connection.exec_driver_sql(
        f"INSERT INTO deliveries ({_DELIVERY_COLUMNS}) "
        f"SELECT {_DELIVERY_COLUMNS} FROM {_SQLITE_DELIVERY_BACKUP}"
    )
    restored = connection.exec_driver_sql(
        "SELECT COUNT(*) FROM deliveries WHERE subscription_id IS NOT NULL"
    ).scalar_one()
    if restored != expected:
        raise RuntimeError("SQLite subscription migration did not restore every dependent delivery")
    violations = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(f"SQLite foreign-key validation failed: {violations!r}")
    if connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() != 1:
        raise RuntimeError("SQLite foreign-key enforcement was disabled during migration")
    connection.exec_driver_sql(f"DROP TABLE {_SQLITE_DELIVERY_BACKUP}")


def upgrade() -> None:
    restore_deliveries = _backup_sqlite_subscription_deliveries()
    with op.batch_alter_table("push_subscriptions") as batch_op:
        batch_op.add_column(sa.Column("session_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_push_subscriptions_session_id_sessions",
            "sessions",
            ["session_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index(
            "ix_push_subscriptions_session_id",
            ["session_id"],
            unique=False,
        )
    if restore_deliveries:
        _restore_sqlite_subscription_deliveries()
    # Existing endpoints predate browser-session ownership. They cannot be
    # safely attributed to a live login, so require the browser to register
    # them again instead of continuing delivery after an upgrade or logout.
    op.execute(
        sa.text(
            "UPDATE push_subscriptions "
            "SET disabled_at = CURRENT_TIMESTAMP "
            "WHERE session_id IS NULL AND disabled_at IS NULL"
        )
    )


def downgrade() -> None:
    restore_deliveries = _backup_sqlite_subscription_deliveries()
    with op.batch_alter_table("push_subscriptions") as batch_op:
        batch_op.drop_index("ix_push_subscriptions_session_id")
        batch_op.drop_constraint(
            "fk_push_subscriptions_session_id_sessions",
            type_="foreignkey",
        )
        batch_op.drop_column("session_id")
    if restore_deliveries:
        _restore_sqlite_subscription_deliveries()
