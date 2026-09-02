from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

EventStatus = Literal["firing", "resolved"]
Severity = Literal["info", "warning", "critical", "unknown"]
IncidentStatus = Literal["open", "acknowledged", "resolved", "silenced"]


def utc_now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: str | datetime | None, *, default: datetime | None = None) -> datetime:
    if value is None:
        return default or utc_now()
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    else:
        parsed = value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_severity(value: object) -> Severity:
    normalized = str(value or "unknown").strip().lower()
    aliases = {
        "ok": "info",
        "notice": "info",
        "minor": "warning",
        "warn": "warning",
        "error": "critical",
        "fatal": "critical",
        "page": "critical",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"info", "warning", "critical", "unknown"}:
        return "unknown"
    return normalized  # type: ignore[return-value]


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_label_key(labels: Mapping[str, Any]) -> str:
    """Build a stable dedup key without discarding adapter-specific labels."""

    normalized = {str(key): str(value) for key, value in labels.items()}
    return canonical_json(normalized)


def incident_fingerprint(source_id: str, dedup_key: str) -> str:
    raw = f"{source_id}\0{dedup_key}".encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    dedup_key: str
    status: EventStatus
    title: str
    description: str = ""
    severity: Severity = "unknown"
    starts_at: datetime = field(default_factory=utc_now)
    ends_at: datetime | None = None
    labels: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    source_url: str | None = None
    external_event_id: str | None = None
    schema_version: int = 1
    raw_payload: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.dedup_key.strip():
            raise ValueError("dedup_key is required")
        if self.status not in {"firing", "resolved"}:
            raise ValueError("status must be firing or resolved")
        if self.schema_version != 1:
            raise ValueError("unsupported normalized event schema version")
        object.__setattr__(self, "starts_at", as_utc(self.starts_at))
        if self.ends_at is not None:
            object.__setattr__(self, "ends_at", as_utc(self.ends_at))
        object.__setattr__(self, "severity", normalize_severity(self.severity))

    def event_key(self, source_id: str) -> str:
        identity = {
            "source_id": source_id,
            "external_event_id": self.external_event_id,
            "dedup_key": self.dedup_key,
            "status": self.status,
            "starts_at": self.starts_at.isoformat(),
            "ends_at": self.ends_at.isoformat() if self.ends_at else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "labels": self.labels,
            "annotations": self.annotations,
        }
        return hashlib.sha256(canonical_json(identity).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ProjectionEvent:
    event_id: str
    event_type: str
    occurred_at: datetime
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IncidentProjection:
    status: IncidentStatus
    starts_at: datetime | None
    resolved_at: datetime | None
    acknowledged_at: datetime | None
    silenced_at: datetime | None


def project_incident(events: Iterable[ProjectionEvent]) -> IncidentProjection:
    """Apply timeline events using a deterministic timestamp/event-id order."""

    status: IncidentStatus = "open"
    starts_at: datetime | None = None
    resolved_at: datetime | None = None
    acknowledged_at: datetime | None = None
    silenced_at: datetime | None = None

    ordered = sorted(events, key=lambda event: (as_utc(event.occurred_at), event.event_id))
    for event in ordered:
        occurred_at = as_utc(event.occurred_at)
        if event.event_type == "firing":
            candidate = as_utc(event.payload.get("starts_at"), default=occurred_at)
            if starts_at is None or candidate > starts_at or status == "resolved":
                starts_at = candidate
                resolved_at = None
                acknowledged_at = None
                silenced_at = None
                status = "open"
        elif event.event_type == "resolved":
            # A stale resolution must not close a newer occurrence.
            occurrence = event.payload.get("starts_at")
            if occurrence is None or starts_at is None or as_utc(occurrence) >= starts_at:
                resolved_at = occurred_at
                status = "resolved"
        elif event.event_type == "acknowledged" and status != "resolved":
            acknowledged_at = occurred_at
            status = "acknowledged"
        elif event.event_type == "unacknowledged" and status == "acknowledged":
            acknowledged_at = None
            status = "open"
        elif event.event_type == "silenced" and status != "resolved":
            silenced_at = occurred_at
            status = "silenced"
        elif event.event_type == "unsilenced" and status == "silenced":
            silenced_at = None
            status = "acknowledged" if acknowledged_at else "open"

    return IncidentProjection(status, starts_at, resolved_at, acknowledged_at, silenced_at)


def rendezvous_rank(key: str, node_ids: Sequence[str]) -> list[str]:
    """Return a stable highest-random-weight ordering of eligible nodes."""

    unique = set(node_ids)
    return sorted(
        unique,
        key=lambda node_id: hashlib.sha256(f"{key}\0{node_id}".encode()).digest(),
        reverse=True,
    )
