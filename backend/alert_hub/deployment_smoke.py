from __future__ import annotations

import sys
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select

from alert_hub.application.incidents import append_cluster_event
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import HeartbeatState, Source
from alert_hub.infrastructure.db.session import create_db_engine, create_session_factory
from alert_hub.security import constant_time_equal, hash_token
from alert_hub.settings import Settings

_SMOKE_INTERVAL_SECONDS = 315_360_000


def source_id_for_node(node_id: str) -> str:
    """Return the stable per-node identity used only by the deployment smoke."""

    return str(uuid5(NAMESPACE_URL, f"alert-hub:deployment-smoke:{node_id}"))


def _source_payload(source: Source) -> dict[str, object]:
    return {
        "name": source.name,
        "kind": source.kind,
        "enabled": source.enabled,
        "region": source.region,
        "config": source.config_json,
        "token_hash": source.token_hash,
        "created_at": source.created_at.isoformat(),
        "updated_at": source.updated_at.isoformat(),
        "deleted_at": None,
    }


def provision_deployment_smoke_source(settings: Settings, token: str) -> str:
    """Create or verify the persistent heartbeat source used by the host rollout gate."""

    if len(token) < 32 or "\n" in token or "\r" in token:
        raise ValueError("deployment smoke token is malformed")

    source_id = source_id_for_node(settings.node_id)
    expected_hash = hash_token(token, settings.signing_key, "source")
    engine = create_db_engine(settings)
    session_factory = create_session_factory(engine)
    try:
        with session_factory.begin() as db:
            source = db.scalar(select(Source).where(Source.id == source_id))
            if source is None:
                now = utc_now()
                source = Source(
                    id=source_id,
                    name=f"[system] Deployment smoke {settings.node_id}"[:255],
                    kind="heartbeat",
                    enabled=True,
                    region=settings.node_region,
                    config_json={
                        "allowed_cidrs": [],
                        "deployment_smoke": True,
                        "grace_seconds": 0,
                        "interval_seconds": _SMOKE_INTERVAL_SECONDS,
                        "labels": {
                            "node": settings.node_id,
                            "purpose": "deployment-smoke",
                        },
                        "severity": "info",
                    },
                    token_hash=expected_hash,
                    created_at=now,
                    updated_at=now,
                )
                db.add(source)
                db.flush()
                db.add(HeartbeatState(source_id=source.id, last_received_at=now))
                append_cluster_event(
                    db,
                    settings,
                    entity_type="source",
                    entity_id=source.id,
                    operation="upsert",
                    payload=_source_payload(source),
                )
            else:
                config = source.config_json or {}
                if (
                    source.kind != "heartbeat"
                    or not source.enabled
                    or source.deleted_at is not None
                    or config.get("deployment_smoke") is not True
                    or not constant_time_equal(source.token_hash, expected_hash)
                ):
                    raise RuntimeError("deployment smoke source does not match its trusted state")
                if db.get(HeartbeatState, source.id) is None:
                    db.add(HeartbeatState(source_id=source.id, last_received_at=utc_now()))
    finally:
        engine.dispose()
    return source_id


def main() -> int:
    token = sys.stdin.read().rstrip("\n")
    try:
        source_id = provision_deployment_smoke_source(Settings(), token)
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(source_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
