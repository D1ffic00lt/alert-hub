from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session, sessionmaker

from alert_hub.application.sync import (
    IncomingClusterEvent,
    advance_peer_cursor,
    apply_cluster_events,
    peer_cursor,
)
from alert_hub.domain.events import as_utc
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import Node
from alert_hub.metrics import CLOCK_SKEW_SUSPECTED, PEER_UP, SYNC_EVENTS, SYNC_LAG
from alert_hub.settings import Settings

logger = logging.getLogger("alert_hub.sync")


class PeerHealthResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: str
    node_id: str = Field(min_length=1, max_length=128)
    region: str = Field(default="unknown", max_length=128)
    software_version: str = Field(default="unknown", max_length=64)
    cursor: dict[str, int]


class SyncPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[IncomingClusterEvent] = Field(max_length=1_000)
    cursor: dict[str, int]
    has_more: bool


class SyncProtocolError(RuntimeError):
    pass


def clock_skew_exceeds_threshold(
    occurred_at: datetime,
    observed_at: datetime,
    threshold_seconds: float,
) -> bool:
    return abs((as_utc(occurred_at) - as_utc(observed_at)).total_seconds()) > threshold_seconds


def record_clock_skew(
    events: Sequence[IncomingClusterEvent],
    *,
    peer_node_id: str,
    observed_at: datetime,
    threshold_seconds: float,
    already_suspected: bool = False,
) -> dict[str, bool]:
    suspected_by_origin: dict[str, bool] = {}
    for event in events:
        suspected = clock_skew_exceeds_threshold(
            event.occurred_at,
            observed_at,
            threshold_seconds,
        )
        suspected_by_origin[event.origin_node_id] = (
            suspected_by_origin.get(event.origin_node_id, False) or suspected
        )
    suspected = already_suspected or any(suspected_by_origin.values())
    CLOCK_SKEW_SUSPECTED.labels(peer_node_id=peer_node_id).set(1 if suspected else 0)
    return suspected_by_origin


@dataclass(slots=True)
class PeerState:
    base_url: str
    node_id: str | None = None
    failures: int = 0
    next_attempt_at: float = 0.0
    last_success_at: datetime | None = None
    last_error: str | None = None
    lag_seconds: float = 0.0

    @property
    def metric_id(self) -> str:
        if self.node_id:
            return self.node_id
        host = urlsplit(self.base_url).netloc
        if host:
            return host[:128]
        return "peer-" + hashlib.sha256(self.base_url.encode()).hexdigest()[:12]


class PeerSyncWorker:
    """Periodic pull synchronizer with independent peer backoff."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        random_value: Callable[[], float] = random.random,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self._client = client
        self._monotonic = monotonic
        self._random_value = random_value
        self.states = {url: PeerState(base_url=url) for url in settings.peer_urls}

    def _timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.settings.sync_connect_timeout_seconds,
            read=self.settings.sync_read_timeout_seconds,
            write=self.settings.sync_write_timeout_seconds,
            pool=self.settings.sync_pool_timeout_seconds,
        )

    def backoff_delay(self, failures: int) -> float:
        exponent = max(0, failures - 1)
        base = min(
            self.settings.sync_backoff_initial_seconds * (2.0**exponent),
            self.settings.sync_backoff_max_seconds,
        )
        jitter = self.settings.sync_backoff_jitter_ratio
        factor = 1.0 + ((self._random_value() * 2.0) - 1.0) * jitter
        return max(0.0, base * factor)

    async def run(self) -> None:
        if self._client is not None:
            await self._run_forever()
            return
        limits = httpx.Limits(
            max_connections=max(4, len(self.states) * 2),
            max_keepalive_connections=max(2, len(self.states)),
        )
        async with httpx.AsyncClient(
            timeout=self._timeout(),
            limits=limits,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            self._client = client
            try:
                await self._run_forever()
            finally:
                self._client = None

    async def _run_forever(self) -> None:
        while True:
            await self.sync_once()
            delay = self._next_wakeup_delay()
            await asyncio.sleep(delay)

    def _next_wakeup_delay(self) -> float:
        now = self._monotonic()
        waiting = [max(0.0, state.next_attempt_at - now) for state in self.states.values()]
        positive = [delay for delay in waiting if delay > 0]
        if not positive:
            return self.settings.sync_interval_seconds
        return max(0.05, min(self.settings.sync_interval_seconds, min(positive)))

    async def sync_once(self) -> None:
        if self._client is None:
            async with httpx.AsyncClient(
                timeout=self._timeout(),
                trust_env=False,
                follow_redirects=False,
            ) as client:
                self._client = client
                try:
                    await self._sync_ready_peers()
                finally:
                    self._client = None
            return
        await self._sync_ready_peers()

    async def _sync_ready_peers(self) -> None:
        now = self._monotonic()
        for state in self.states.values():
            if state.next_attempt_at > now:
                continue
            try:
                await self._sync_peer(state)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._mark_failure(state, exc)
            else:
                self._mark_success(state)

    def _headers(self, secret: str | None = None) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {secret or self.settings.cluster_secret}",
            "Accept": "application/json",
            "User-Agent": f"alert-hub/{self.settings.software_version}",
        }

    async def _request(
        self,
        method: str,
        url: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        client = self._client
        if client is None:
            raise RuntimeError("peer sync client is not initialized")
        response = await self._bounded_request(method, url, payload=payload)
        previous = self.settings.cluster_previous_secret
        if response.status_code == 401 and previous:
            response = await self._bounded_request(method, url, payload=payload, secret=previous)
        if response.is_redirect:
            raise SyncProtocolError("peer redirects are not allowed")
        response.raise_for_status()
        return response

    async def _bounded_request(
        self,
        method: str,
        url: str,
        *,
        payload: Mapping[str, Any] | None,
        secret: str | None = None,
    ) -> httpx.Response:
        client = self._client
        if client is None:
            raise RuntimeError("peer sync client is not initialized")
        limit = self.settings.sync_max_response_bytes
        async with client.stream(
            method,
            url,
            headers=self._headers(secret),
            json=payload,
            timeout=self._timeout(),
        ) as streamed:
            content_length = streamed.headers.get("content-length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = 0
                if declared_length > limit:
                    raise SyncProtocolError("peer response exceeds SYNC_MAX_RESPONSE_BYTES")
            body = bytearray()
            async for chunk in streamed.aiter_bytes():
                if len(body) + len(chunk) > limit:
                    raise SyncProtocolError("peer response exceeds SYNC_MAX_RESPONSE_BYTES")
                body.extend(chunk)
            return httpx.Response(
                status_code=streamed.status_code,
                headers=streamed.headers,
                content=bytes(body),
                request=streamed.request,
                extensions=streamed.extensions,
            )

    async def _sync_peer(self, state: PeerState) -> None:
        internal_url = f"{state.base_url.rstrip('/')}/internal/v1"
        health_response = await self._request(
            "GET",
            f"{internal_url}/nodes/health",
        )
        health = PeerHealthResponse.model_validate(health_response.json())
        if health.status != "ok":
            raise SyncProtocolError(f"peer {health.node_id} reported status {health.status!r}")
        if health.node_id == self.settings.node_id:
            raise SyncProtocolError("configured peer URL resolves to this node")
        state.node_id = health.node_id
        with self.session_factory.begin() as db:
            self._touch_peer_node(db, health)
            cursor = peer_cursor(db, health.node_id)

        oldest_observed: datetime | None = None
        clock_skew_suspected = False
        for _page_number in range(self.settings.sync_max_pages_per_cycle):
            response = await self._request(
                "POST",
                f"{internal_url}/sync/events/query",
                payload={"cursor": cursor, "limit": self.settings.sync_page_size},
            )
            page = SyncPageResponse.model_validate(response.json())
            observed_at = utc_now()
            for event in page.events:
                occurred_at = as_utc(event.occurred_at)
                oldest_observed = (
                    occurred_at if oldest_observed is None else min(oldest_observed, occurred_at)
                )
            skew_by_origin = record_clock_skew(
                page.events,
                peer_node_id=health.node_id,
                observed_at=observed_at,
                threshold_seconds=self.settings.clock_skew_threshold_seconds,
                already_suspected=clock_skew_suspected,
            )
            clock_skew_suspected = clock_skew_suspected or any(skew_by_origin.values())
            with self.session_factory.begin() as db:
                result = apply_cluster_events(db, page.events, self.settings)
                next_cursor = advance_peer_cursor(db, health.node_id, page.cursor)
                self._touch_peer_node(db, health)
            SYNC_EVENTS.labels(direction="inbound", result="applied").inc(result.applied)
            SYNC_EVENTS.labels(direction="inbound", result="duplicate").inc(result.duplicates)
            if page.has_more and next_cursor == cursor:
                raise SyncProtocolError("peer page did not advance a contiguous vector cursor")
            cursor = next_cursor
            if not page.has_more:
                break
        else:
            raise SyncProtocolError("peer exceeded the configured page limit for one cycle")

        state.lag_seconds = self._lag_seconds(health.cursor, cursor, oldest_observed)
        SYNC_LAG.labels(peer_node_id=health.node_id).set(state.lag_seconds)

    def _touch_peer_node(self, db: Session, health: PeerHealthResponse) -> None:
        node = db.get(Node, health.node_id)
        if node is None:
            node = Node(
                id=health.node_id,
                name=health.node_id,
                region=health.region,
                enabled_roles=["sync"],
                software_version=health.software_version,
            )
            db.add(node)
        node.region = health.region
        node.software_version = health.software_version
        node.last_seen_at = utc_now()

    def _lag_seconds(
        self,
        remote_cursor: Mapping[str, int],
        local_cursor: Mapping[str, int],
        oldest_observed: datetime | None,
    ) -> float:
        behind = any(
            local_cursor.get(origin, 0) < sequence for origin, sequence in remote_cursor.items()
        )
        if not behind:
            return 0.0
        if oldest_observed is None:
            return self.settings.sync_interval_seconds
        return max(0.0, (utc_now() - oldest_observed).total_seconds())

    def _mark_failure(self, state: PeerState, exc: Exception) -> None:
        state.failures += 1
        state.last_error = f"{type(exc).__name__}: {exc}"[:1_024]
        state.next_attempt_at = self._monotonic() + self.backoff_delay(state.failures)
        PEER_UP.labels(peer_node_id=state.metric_id).set(0)
        SYNC_EVENTS.labels(direction="pull", result="error").inc()
        logger.warning(
            "peer_sync_failed",
            extra={
                "event": "peer_sync_failed",
                "peer_node_id": state.node_id,
                "failure_count": state.failures,
                "exception_type": type(exc).__name__,
            },
        )

    def _mark_success(self, state: PeerState) -> None:
        state.failures = 0
        state.last_error = None
        state.last_success_at = utc_now()
        state.next_attempt_at = self._monotonic() + self.settings.sync_interval_seconds
        PEER_UP.labels(peer_node_id=state.metric_id).set(1)
        SYNC_EVENTS.labels(direction="pull", result="success").inc()

    def status_snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            state.metric_id: {
                "url": state.base_url,
                "up": state.failures == 0 and state.last_success_at is not None,
                "last_success_at": state.last_success_at,
                "last_error": state.last_error,
                "failures": state.failures,
                "lag_seconds": state.lag_seconds,
            }
            for state in self.states.values()
        }
