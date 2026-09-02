from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from alert_hub.domain.adapters import AdapterError, normalize_alertmanager, normalize_generic
from alert_hub.domain.events import (
    NormalizedEvent,
    ProjectionEvent,
    incident_fingerprint,
    project_incident,
    rendezvous_rank,
)


def test_generic_normalization_and_event_key_are_stable() -> None:
    payload = {
        "schema_version": 1,
        "dedup_key": "database-primary",
        "status": "firing",
        "title": "Database unavailable",
        "severity": "fatal",
        "starts_at": "2026-09-01T12:00:00Z",
        "labels": {"region": "ru", "service": "db"},
        "annotations": {"runbook": "https://example.test/runbook"},
    }
    first = normalize_generic(payload)
    second = normalize_generic(dict(reversed(list(payload.items()))))
    assert first.severity == "critical"
    assert first.starts_at.tzinfo is UTC
    assert first.event_key("source-1") == second.event_key("source-1")
    assert incident_fingerprint("source-1", first.dedup_key) == incident_fingerprint(
        "source-1", second.dedup_key
    )


def test_alertmanager_preserves_unknown_labels_and_uses_provided_fingerprint() -> None:
    events = normalize_alertmanager(
        {
            "version": "4",
            "externalURL": "https://am.example.test",
            "alerts": [
                {
                    "status": "firing",
                    "fingerprint": "abc123",
                    "startsAt": "2026-09-01T12:00:00Z",
                    "labels": {
                        "alertname": "EndpointDown",
                        "severity": "warning",
                        "custom_label": "preserved",
                    },
                    "annotations": {"summary": "Endpoint down", "unknown": {"nested": True}},
                }
            ],
        }
    )
    assert len(events) == 1
    assert events[0].dedup_key == "abc123"
    assert events[0].labels["custom_label"] == "preserved"
    assert events[0].annotations["unknown"] == {"nested": True}


def test_generic_requires_dedup_key() -> None:
    with pytest.raises(AdapterError):
        normalize_generic({"status": "firing", "title": "Missing key"})


def test_projection_is_deterministic_and_new_occurrence_reopens() -> None:
    start = datetime(2026, 9, 1, 12, tzinfo=UTC)
    events = [
        ProjectionEvent("b", "acknowledged", start + timedelta(minutes=1)),
        ProjectionEvent("a", "firing", start, {"starts_at": start.isoformat()}),
        ProjectionEvent(
            "c", "resolved", start + timedelta(minutes=2), {"starts_at": start.isoformat()}
        ),
        ProjectionEvent(
            "d",
            "firing",
            start + timedelta(minutes=3),
            {"starts_at": (start + timedelta(minutes=3)).isoformat()},
        ),
    ]
    forward = project_incident(events)
    reverse = project_incident(reversed(events))
    assert forward == reverse
    assert forward.status == "open"
    assert forward.starts_at == start + timedelta(minutes=3)
    assert forward.resolved_at is None


def test_rendezvous_ranking_is_stable_and_complete() -> None:
    nodes = ["ru", "nl", "de", "nl"]
    first = rendezvous_rank("event/channel", nodes)
    assert first == rendezvous_rank("event/channel", list(reversed(nodes)))
    assert set(first) == {"ru", "nl", "de"}


def test_normalized_event_rejects_unknown_status() -> None:
    with pytest.raises(ValueError):
        NormalizedEvent(dedup_key="x", status="broken", title="x")  # type: ignore[arg-type]
