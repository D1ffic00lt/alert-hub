from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from alert_hub.infrastructure.db.base import Base, utc_now
from alert_hub.infrastructure.db.models import Node
from alert_hub.settings import Settings


def _prepare_sqlite_directory(database_url: str) -> None:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return
    Path(url.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def create_db_engine(settings: Settings) -> Engine:
    _prepare_sqlite_directory(settings.database_url)
    url = make_url(settings.database_url)
    kwargs: dict[str, object] = {"pool_pre_ping": True}
    if url.get_backend_name() == "sqlite":
        kwargs["connect_args"] = {"check_same_thread": False}
        if url.database in {None, "", ":memory:"}:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(settings.database_url, **kwargs)

    if url.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def set_sqlite_pragmas(dbapi_connection: object, connection_record: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={settings.sqlite_busy_timeout_ms:d}")
            if url.database not in {None, "", ":memory:"}:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def initialize_database(
    engine: Engine,
    session_factory: sessionmaker[Session],
    settings: Settings,
) -> None:
    if settings.auto_create_schema:
        Base.metadata.create_all(engine)
    with session_factory.begin() as db:
        node = db.scalar(select(Node).where(Node.id == settings.node_id))
        if node is None:
            db.add(
                Node(
                    id=settings.node_id,
                    name=settings.node_name,
                    region=settings.node_region,
                    public_api_url=settings.public_api_url,
                    private_peer_url=settings.private_peer_url,
                    enabled_roles=settings.enabled_roles(),
                    software_version=settings.software_version,
                    last_seen_at=utc_now(),
                )
            )
        else:
            node.name = settings.node_name
            node.region = settings.node_region
            node.public_api_url = settings.public_api_url
            node.private_peer_url = settings.private_peer_url
            node.enabled_roles = settings.enabled_roles()
            node.software_version = settings.software_version
            node.last_seen_at = utc_now()


def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as session:
        yield session
