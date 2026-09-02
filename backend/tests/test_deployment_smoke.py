from __future__ import annotations

from sqlalchemy import func, select

from alert_hub.deployment_smoke import (
    provision_deployment_smoke_source,
    source_id_for_node,
)
from alert_hub.infrastructure.db.base import Base
from alert_hub.infrastructure.db.models import ClusterEvent, HeartbeatState, Source
from alert_hub.infrastructure.db.session import create_db_engine, create_session_factory
from alert_hub.security import hash_token
from alert_hub.settings import Settings


def _prepare_database(settings: Settings):
    engine = create_db_engine(settings)
    Base.metadata.create_all(engine)
    return engine, create_session_factory(engine)


def test_deployment_smoke_source_identity_is_stable_per_node() -> None:
    assert source_id_for_node("ru") == source_id_for_node("ru")
    assert source_id_for_node("ru") != source_id_for_node("nl")


def test_deployment_smoke_source_is_provisioned_idempotently(settings: Settings) -> None:
    token = "a" * 64
    engine, session_factory = _prepare_database(settings)
    try:
        source_id = provision_deployment_smoke_source(settings, token)
        assert provision_deployment_smoke_source(settings, token) == source_id

        with session_factory() as db:
            source = db.get(Source, source_id)
            assert source is not None
            assert source.kind == "heartbeat"
            assert source.enabled is True
            assert source.deleted_at is None
            assert source.config_json["deployment_smoke"] is True
            assert source.config_json["interval_seconds"] == 315_360_000
            assert source.token_hash == hash_token(token, settings.signing_key, "source")
            assert db.get(HeartbeatState, source_id) is not None
            assert (
                db.scalar(
                    select(func.count(ClusterEvent.event_id)).where(
                        ClusterEvent.entity_type == "source",
                        ClusterEvent.entity_id == source_id,
                    )
                )
                == 1
            )
    finally:
        engine.dispose()


def test_deployment_smoke_source_rejects_token_mismatch(
    settings: Settings,
) -> None:
    engine, session_factory = _prepare_database(settings)
    try:
        source_id = provision_deployment_smoke_source(settings, "a" * 64)

        try:
            provision_deployment_smoke_source(settings, "b" * 64)
        except RuntimeError as exc:
            assert str(exc) == "deployment smoke source does not match its trusted state"
        else:
            raise AssertionError("a mismatched deployment smoke token was accepted")

        with session_factory() as db:
            source = db.get(Source, source_id)
            assert source is not None
            assert source.token_hash == hash_token("a" * 64, settings.signing_key, "source")
    finally:
        engine.dispose()


def test_deployment_smoke_source_rejects_malformed_token(settings: Settings) -> None:
    for token in ("short", "a" * 32 + "\n", "a" * 32 + "\r"):
        try:
            provision_deployment_smoke_source(settings, token)
        except ValueError as exc:
            assert str(exc) == "deployment smoke token is malformed"
        else:
            raise AssertionError("a malformed deployment smoke token was accepted")
