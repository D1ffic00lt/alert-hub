from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

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

    push_columns = {
        column["name"]: column for column in inspect(engine).get_columns("push_subscriptions")
    }
    assert push_columns["session_id"]["nullable"] is True
    push_indexes = {index["name"] for index in inspect(engine).get_indexes("push_subscriptions")}
    assert "ix_push_subscriptions_session_id" in push_indexes
    push_foreign_keys = {
        foreign_key["name"]: foreign_key
        for foreign_key in inspect(engine).get_foreign_keys("push_subscriptions")
    }
    session_foreign_key = push_foreign_keys["fk_push_subscriptions_session_id_sessions"]
    assert session_foreign_key["referred_table"] == "sessions"
    assert session_foreign_key["constrained_columns"] == ["session_id"]
    assert session_foreign_key["options"].get("ondelete") == "SET NULL"

    command.downgrade(config, "0001_initial")
    downgraded_columns = {
        column["name"] for column in inspect(engine).get_columns("push_subscriptions")
    }
    assert "session_id" not in downgraded_columns
    command.upgrade(config, "head")

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


def test_session_binding_migration_disables_legacy_push_subscriptions(tmp_path: Path) -> None:
    backend_dir = Path(__file__).parents[1]
    database = tmp_path / "legacy-push.db"
    config = Config(str(backend_dir / "alembic.ini"))
    config.set_main_option("script_location", str(backend_dir / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    command.upgrade(config, "0001_initial")

    engine = create_engine(f"sqlite:///{database}")
    created_at = "2026-09-02 12:00:00"
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        connection.execute(
            text(
                "INSERT INTO users "
                "(id, username, password_hash, is_admin, created_at, disabled_at) "
                "VALUES (:id, :username, :password_hash, :is_admin, :created_at, NULL)"
            ),
            {
                "id": "legacy-user",
                "username": "legacy-user",
                "password_hash": "legacy-hash",
                "is_admin": False,
                "created_at": created_at,
            },
        )
        connection.execute(
            text(
                "INSERT INTO sources "
                "(id, name, kind, enabled, region, config_json, token_hash, created_at, "
                "updated_at, deleted_at) VALUES "
                "('legacy-source', 'Legacy source', 'generic_json', 1, NULL, '{}', "
                "'legacy-token-hash', :created_at, :created_at, NULL)"
            ),
            {"created_at": created_at},
        )
        connection.execute(
            text(
                "INSERT INTO incidents "
                "(id, source_id, fingerprint, title, description, severity, status, "
                "labels_json, annotations_json, starts_at, last_event_at, resolved_at, "
                "acknowledged_at, acknowledged_by) VALUES "
                "('legacy-incident', 'legacy-source', :fingerprint, 'Legacy incident', '', "
                "'warning', 'open', '{}', '{}', :created_at, :created_at, NULL, NULL, NULL)"
            ),
            {"fingerprint": "f" * 64, "created_at": created_at},
        )
        connection.execute(
            text(
                "INSERT INTO incident_events "
                "(id, origin_node_id, origin_seq, event_key, incident_id, event_type, "
                "occurred_at, received_at, payload_json) VALUES "
                "('legacy-event', 'legacy-node', 1, 'legacy-event-key', 'legacy-incident', "
                "'firing', :created_at, :created_at, '{}')"
            ),
            {"created_at": created_at},
        )
        connection.execute(
            text(
                "INSERT INTO notification_channels "
                "(id, name, kind, enabled, encrypted_config, eligible_nodes_or_regions, "
                "created_at, updated_at, deleted_at) VALUES "
                "('legacy-channel', 'Legacy push', 'web_push', 1, :encrypted_config, '{}', "
                ":created_at, :created_at, NULL)"
            ),
            {"encrypted_config": b"encrypted-config", "created_at": created_at},
        )
        connection.execute(
            text(
                "INSERT INTO push_subscriptions "
                "(id, user_id, device_name, endpoint, p256dh, auth, user_agent, "
                "created_at, last_success_at, disabled_at) "
                "VALUES (:id, :user_id, :device_name, :endpoint, :p256dh, :auth, NULL, "
                ":created_at, NULL, NULL)"
            ),
            {
                "id": "legacy-subscription",
                "user_id": "legacy-user",
                "device_name": "Legacy browser",
                "endpoint": b"encrypted-endpoint",
                "p256dh": b"encrypted-p256dh",
                "auth": b"encrypted-auth",
                "created_at": created_at,
            },
        )
        connection.execute(
            text(
                "INSERT INTO deliveries "
                "(id, event_id, channel_id, subscription_id, owner_node_id, attempt, status, "
                "provider_status, error_code, created_at, finished_at) VALUES "
                "('legacy-delivery', 'legacy-event', 'legacy-channel', "
                "'legacy-subscription', 'legacy-node', 1, 'succeeded', 'http_201', NULL, "
                ":created_at, :created_at)"
            ),
            {"created_at": created_at},
        )

    command.upgrade(config, "head")
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT session_id, disabled_at FROM push_subscriptions "
                "WHERE id = 'legacy-subscription'"
            )
        ).one()
        delivery = connection.execute(
            text("SELECT subscription_id, status FROM deliveries WHERE id = 'legacy-delivery'")
        ).one()
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    assert row.session_id is None
    assert row.disabled_at is not None
    assert delivery.subscription_id == "legacy-subscription"
    assert delivery.status == "succeeded"
    engine.dispose()
