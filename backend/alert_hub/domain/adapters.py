from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from alert_hub.domain.events import (
    NormalizedEvent,
    as_utc,
    normalize_severity,
    stable_label_key,
)


class AdapterError(ValueError):
    pass


def _mapping(value: object, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AdapterError(f"{field} must be an object")
    return {str(key): item for key, item in value.items()}


def normalize_generic(payload: Mapping[str, Any]) -> NormalizedEvent:
    if payload.get("schema_version", 1) != 1:
        raise AdapterError("unsupported schema_version")
    labels = _mapping(payload.get("labels"), "labels")
    annotations = _mapping(payload.get("annotations"), "annotations")
    dedup_key = str(payload.get("dedup_key") or "").strip()
    if not dedup_key:
        raise AdapterError("dedup_key is required")
    status = str(payload.get("status") or "").lower()
    if status not in {"firing", "resolved"}:
        raise AdapterError("status must be firing or resolved")
    title = str(payload.get("title") or labels.get("alertname") or dedup_key).strip()
    return NormalizedEvent(
        schema_version=1,
        external_event_id=(
            str(payload["external_event_id"]) if payload.get("external_event_id") else None
        ),
        dedup_key=dedup_key,
        status=status,  # type: ignore[arg-type]
        title=title,
        description=str(payload.get("description") or ""),
        severity=normalize_severity(payload.get("severity")),
        starts_at=as_utc(payload.get("starts_at")),
        ends_at=as_utc(payload["ends_at"]) if payload.get("ends_at") else None,
        labels=labels,
        annotations=annotations,
        source_url=str(payload["source_url"]) if payload.get("source_url") else None,
        raw_payload=dict(payload),
    )


def normalize_alertmanager(payload: Mapping[str, Any]) -> list[NormalizedEvent]:
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        raise AdapterError("alerts must be an array")
    normalized: list[NormalizedEvent] = []
    for raw in alerts:
        if not isinstance(raw, Mapping):
            raise AdapterError("each alert must be an object")
        labels = _mapping(raw.get("labels"), "labels")
        annotations = _mapping(raw.get("annotations"), "annotations")
        status = str(raw.get("status") or payload.get("status") or "firing").lower()
        if status not in {"firing", "resolved"}:
            raise AdapterError("alert status must be firing or resolved")
        provided_fingerprint = str(raw.get("fingerprint") or "").strip()
        dedup_key = provided_fingerprint or stable_label_key(labels)
        if not labels and not provided_fingerprint:
            raise AdapterError("alert needs fingerprint or labels")
        title = str(
            annotations.get("summary")
            or annotations.get("title")
            or labels.get("alertname")
            or "Alertmanager alert"
        )
        description = str(annotations.get("description") or annotations.get("message") or "")
        generator_url = raw.get("generatorURL") or payload.get("externalURL")
        normalized.append(
            NormalizedEvent(
                external_event_id=provided_fingerprint or None,
                dedup_key=dedup_key,
                status=status,  # type: ignore[arg-type]
                title=title,
                description=description,
                severity=normalize_severity(labels.get("severity")),
                starts_at=as_utc(raw.get("startsAt")),
                ends_at=as_utc(raw["endsAt"]) if raw.get("endsAt") else None,
                labels=labels,
                annotations=annotations,
                source_url=str(generator_url) if generator_url else None,
                raw_payload=dict(raw),
            )
        )
    return normalized
