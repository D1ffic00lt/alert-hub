from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_user, get_db, get_settings
from alert_hub.api.prometheus import get_prometheus_client
from alert_hub.application.monitoring_settings import monitoring_settings_snapshot
from alert_hub.application.prometheus import (
    DatasourceQueryFailure,
    prepare_enabled_datasources,
    query_datasource_targets,
)
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import (
    Delivery,
    Incident,
    NotificationChannel,
    Outbox,
    PrometheusDatasource,
    User,
)
from alert_hub.infrastructure.encryption import EnvelopeCipher
from alert_hub.infrastructure.prometheus import FixedQueryName, PrometheusClient
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics-summary"])


@router.get("/summary")
def metrics_summary(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    monitoring = monitoring_settings_snapshot(db, settings)
    since = utc_now() - timedelta(hours=24)
    open_count = int(
        db.scalar(select(func.count(Incident.id)).where(Incident.status == "open")) or 0
    )
    acknowledged = int(
        db.scalar(select(func.count(Incident.id)).where(Incident.status == "acknowledged")) or 0
    )
    critical = int(
        db.scalar(
            select(func.count(Incident.id)).where(
                Incident.severity == "critical",
                Incident.status != "resolved",
            )
        )
        or 0
    )
    delivery_total = int(
        db.scalar(select(func.count(Delivery.id)).where(Delivery.created_at >= since)) or 0
    )
    delivery_success = int(
        db.scalar(
            select(func.count(Delivery.id)).where(
                Delivery.created_at >= since,
                Delivery.status.in_(("succeeded", "success", "delivered")),
            )
        )
        or 0
    )
    delivery_rate = round((delivery_success / delivery_total) * 100, 1) if delivery_total else None
    return {
        "open": open_count,
        "acknowledged": acknowledged,
        "critical": critical,
        "incidents_open": open_count,
        "incidents_acknowledged": acknowledged,
        "incidents_critical": critical,
        "delivery_rate": delivery_rate,
        "delivery_success_rate": delivery_rate,
        "deliveries_24h": delivery_total,
        "delivery_success_24h": delivery_success,
        "grafana_url": monitoring.grafana_url,
        "key_job_globs": monitoring.key_job_globs,
        "alert_hub_job_globs": monitoring.alert_hub_job_globs,
        "channels_enabled": int(
            db.scalar(
                select(func.count(NotificationChannel.id)).where(
                    NotificationChannel.enabled.is_(True),
                    NotificationChannel.deleted_at.is_(None),
                )
            )
            or 0
        ),
        "outbox_pending": int(
            db.scalar(select(func.count(Outbox.id)).where(Outbox.completed_at.is_(None))) or 0
        ),
    }


@router.get("/reachability")
async def metrics_reachability(
    request: Request,
    db: Session = Depends(get_db),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    configured = int(
        db.scalar(
            select(func.count(PrometheusDatasource.id)).where(
                PrometheusDatasource.enabled.is_(True)
            )
        )
        or 0
    )
    if configured == 0:
        return {
            "cells": [],
            "errors": [],
            "datasources": 0,
            "status": "not_configured",
            "detail": "No Prometheus reachability datasource is configured",
        }
    cipher: EnvelopeCipher | None = request.app.state.envelope_cipher
    targets, failures, datasource_count = prepare_enabled_datasources(db, cipher)
    # Release SQLite before network I/O; query targets are immutable decrypted snapshots.
    db.close()
    results, transport_failures = await query_datasource_targets(
        targets, prometheus, "reachability"
    )
    failures.extend(transport_failures)
    selected: dict[tuple[str, str], tuple[Any, str, str, float]] = {}
    for result in results:
        missing_labels = 0
        for sample in result.samples:
            if result.reachability_label_mode == "server":
                source_region = sample.labels.get("source_server", "").strip()
                target_name = sample.labels.get("target_server", "").strip()
            else:
                source_region = sample.labels.get("source_region", "").strip()
                target_name = sample.labels.get("target_name", "").strip()
            if not source_region or not target_name:
                missing_labels += 1
                continue
            key = (source_region, target_name)
            candidate = (
                sample.timestamp,
                result.datasource_id,
                result.datasource_name,
                sample.value,
            )
            current = selected.get(key)
            if current is None or candidate[:2] > current[:2]:
                selected[key] = candidate
        if missing_labels:
            failures.append(
                DatasourceQueryFailure(
                    result.datasource_id,
                    result.datasource_name,
                    "missing_labels",
                    (
                        f"Ignored {missing_labels} samples without the configured reachability "
                        f"label pair ({result.reachability_label_mode})"
                    ),
                )
            )
    cells = [
        {
            "source": source,
            "source_region": source,
            "target": target,
            "target_name": target,
            "success": value > 0,
            "probe_success": value,
            "latency": None,
            "latency_ms": None,
            "checked_at": timestamp,
            "timestamp": timestamp,
            "datasource_id": datasource_id,
            "datasource_name": datasource_name,
        }
        for (source, target), (timestamp, datasource_id, datasource_name, value) in sorted(
            selected.items()
        )
    ]
    errors = [_failure_response(failure) for failure in failures]
    if cells and errors:
        status_value = "partial"
        detail = "Reachability data is available from only part of the configured datasources"
    elif cells:
        status_value = "ok"
        detail = "Reachability data loaded from configured Prometheus datasources"
    elif errors:
        status_value = "unavailable"
        detail = "Configured Prometheus datasources did not return usable reachability data"
    else:
        status_value = "empty"
        detail = "Prometheus returned no probe_success samples"
    return {
        "cells": cells,
        "errors": errors,
        "datasources": datasource_count,
        "status": status_value,
        "detail": detail,
    }


def _failure_response(failure: DatasourceQueryFailure) -> dict[str, str]:
    return {
        "datasource_id": failure.datasource_id,
        "datasource_name": failure.datasource_name,
        "code": failure.code,
        "detail": failure.detail,
    }


@router.get("/queries/{query_name}")
async def metrics_named_query(
    query_name: FixedQueryName,
    request: Request,
    db: Session = Depends(get_db),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    cipher: EnvelopeCipher | None = request.app.state.envelope_cipher
    targets, failures, datasource_count = prepare_enabled_datasources(db, cipher)
    monitoring = monitoring_settings_snapshot(db, settings)
    db.close()
    job_globs = None
    if query_name == "key_jobs_up":
        job_globs = monitoring.key_job_globs
    elif query_name == "alert_hub_health":
        job_globs = monitoring.alert_hub_job_globs
    results, transport_failures = await query_datasource_targets(
        targets,
        prometheus,
        query_name,
        job_globs=job_globs,
    )
    failures.extend(transport_failures)
    samples = [
        {
            "datasource_id": result.datasource_id,
            "datasource_name": result.datasource_name,
            "metric": sample.labels,
            "value": sample.value,
            "timestamp": sample.timestamp,
        }
        for result in results
        for sample in result.samples
    ]
    errors = [_failure_response(failure) for failure in failures]
    if datasource_count == 0:
        status_value = "not_configured"
    elif samples and errors:
        status_value = "partial"
    elif errors:
        status_value = "unavailable"
    else:
        status_value = "ok"
    return {
        "query": query_name,
        "status": status_value,
        "datasources": datasource_count,
        "samples": samples,
        "errors": errors,
    }
