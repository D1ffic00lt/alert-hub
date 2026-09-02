from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from alert_hub.infrastructure.db import models  # noqa: F401
from alert_hub.infrastructure.db.base import Base


def test_initial_migration_builds_and_downgrades_schema(tmp_path: Path) -> None:
    backend_dir = Path(__file__).parents[1]
    database = tmp_path / "migration.db"
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{database}")
    tables = set(inspect(engine).get_table_names())
    assert tables == {
        "alembic_version",
        "audit_log",
        "cluster_events",
        "deliveries",
        "heartbeat_state",
        "incident_events",
        "incidents",
        "nodes",
        "notification_channels",
        "notification_routes",
        "outbox",
        "prometheus_datasources",
        "push_subscriptions",
        "sessions",
        "sources",
        "sync_cursors",
        "users",
    }

    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        assert compare_metadata(context, Base.metadata) == []

    command.downgrade(config, "base")
    assert inspect(engine).get_table_names() == ["alembic_version"]
    engine.dispose()


def test_initial_migration_is_independent_from_live_orm_metadata() -> None:
    migration = (
        Path(__file__).parents[1] / "migrations" / "versions" / "0001_initial_schema.py"
    ).read_text(encoding="utf-8")

    assert "Base.metadata" not in migration
    assert ".create_all(" not in migration
    assert ".drop_all(" not in migration
