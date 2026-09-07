from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_user, get_db, get_settings
from alert_hub.api.prometheus import get_prometheus_client
from alert_hub.application.prometheus import (
    DatasourceQueryFailure,
    DatasourceQueryResult,
    DatasourceRulesResult,
    prepare_enabled_datasources,
    query_datasource_rules_targets,
    query_datasource_targets,
)
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import Incident, User
from alert_hub.infrastructure.encryption import EnvelopeCipher
from alert_hub.infrastructure.prometheus import (
    AVAILABILITY_QUERY_NAMES,
    AlertRule,
    PrometheusClient,
    VectorSample,
)
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1", tags=["alerts"])

AlertRuleFilter = Literal["firing", "pending", "inactive", "error"]
AvailabilityWindow = Literal["24h", "7d", "30d"]

_PUBLIC_FAILURE_DETAILS = {
    "authentication_failed": "Prometheus rejected the configured datasource credentials",
    "credentials": "Prometheus datasource credentials are incomplete",
    "credentials_unavailable": "Prometheus datasource credentials are unavailable on this node",
    "http_error": "Prometheus returned an unsuccessful HTTP status",
    "invalid_json": "Prometheus returned invalid JSON",
    "invalid_response": "Prometheus returned an invalid response",
    "invalid_result_type": "Prometheus returned an unexpected result type",
    "invalid_rule": "Prometheus returned an invalid alert rule",
    "invalid_rule_group": "Prometheus returned an invalid alert rule group",
    "missing_labels": "Prometheus availability series is missing configured labels",
    "redirect_rejected": "Prometheus returned a redirect, which is not allowed",
    "response_too_large": "Prometheus response exceeded the configured byte limit",
    "rules_failed": "Prometheus could not return alert rules",
    "timeout": "Prometheus request timed out",
    "too_many_rules": "Prometheus returned more rules than the configured limit",
    "too_many_samples": "Prometheus returned more series than the configured limit",
    "transport": "Prometheus request failed",
    "unsafe_url": "Prometheus datasource address did not pass the network safety check",
}


def _stable_rule_id(datasource_id: str, rule: AlertRule) -> str:
    identity = "\0".join((datasource_id, rule.file, rule.group, rule.name)).encode()
    return f"ar_{hashlib.sha256(identity).hexdigest()}"


def _failure_response(failure: DatasourceQueryFailure) -> dict[str, str]:
    return {
        "datasource_id": failure.datasource_id,
        "datasource_name": failure.datasource_name,
        "code": failure.code if failure.code in _PUBLIC_FAILURE_DETAILS else "prometheus_error",
        "detail": _PUBLIC_FAILURE_DETAILS.get(
            failure.code, "Prometheus datasource could not be queried"
        ),
    }


def _data_state(
    datasource_count: int,
    *,
    has_data: bool,
    failures: list[DatasourceQueryFailure],
) -> Literal["ok", "partial", "unavailable", "not_configured"]:
    if datasource_count == 0:
        return "not_configured"
    if failures and has_data:
        return "partial"
    if failures:
        return "unavailable"
    return "ok"


def _incident_counts(db: Session) -> dict[tuple[str, str], int]:
    datasource = func.json_extract(Incident.labels_json, "$.prometheus_datasource_id")
    alertname = func.json_extract(Incident.labels_json, "$.alertname")
    rows = db.execute(
        select(datasource, alertname, func.count(Incident.id))
        .where(datasource.is_not(None), alertname.is_not(None))
        .group_by(datasource, alertname)
    )
    return {
        (str(row[0]), str(row[1])): int(row[2])
        for row in rows
        if isinstance(row[0], str) and isinstance(row[1], str)
    }


def _rule_response(
    result: DatasourceRulesResult,
    rule: AlertRule,
    incident_counts: dict[tuple[str, str], int],
) -> dict[str, Any]:
    related_incidents = incident_counts.get((result.datasource_id, rule.name), 0)
    return {
        "id": _stable_rule_id(result.datasource_id, rule),
        "datasource_id": result.datasource_id,
        "datasource_name": result.datasource_name,
        "group": rule.group,
        "file": rule.file,
        "name": rule.name,
        "state": rule.state,
        "health": rule.health,
        "firing_instances": rule.firing_instances,
        "pending_instances": rule.pending_instances,
        "last_evaluation": rule.last_evaluation,
        "evaluation_time_seconds": rule.evaluation_time_seconds,
        "last_error": rule.last_error,
        "labels": rule.labels,
        "annotations": rule.annotations,
        "related_incidents": related_incidents,
        "incidents_href": (
            f"/incidents?q={quote(rule.name, safe='')}" if related_incidents > 0 else None
        ),
    }


@router.get("/alert-rules")
async def alert_rules(
    request: Request,
    datasource_id: str | None = Query(default=None, max_length=36),
    state: AlertRuleFilter | None = None,
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(get_db),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    cipher: EnvelopeCipher | None = request.app.state.envelope_cipher
    targets, failures, datasource_count = prepare_enabled_datasources(db, cipher)
    incident_counts = _incident_counts(db)
    db.close()
    results, transport_failures = await query_datasource_rules_targets(targets, prometheus)
    failures.extend(transport_failures)

    all_rules = [
        _rule_response(result, rule, incident_counts) for result in results for rule in result.rules
    ]
    all_rules.sort(
        key=lambda item: (
            str(item["datasource_name"]).casefold(),
            str(item["datasource_id"]),
            str(item["file"]),
            str(item["group"]).casefold(),
            str(item["name"]).casefold(),
            str(item["id"]),
        )
    )
    totals = {
        "rules": len(all_rules),
        "firing_instances": sum(int(item["firing_instances"]) for item in all_rules),
        "pending_instances": sum(int(item["pending_instances"]) for item in all_rules),
        "unhealthy_rules": sum(item["health"] != "ok" for item in all_rules),
        "related_incidents": sum(int(item["related_incidents"]) for item in all_rules),
    }

    needle = q.strip().casefold() if q else ""
    filtered = [
        item
        for item in all_rules
        if (datasource_id is None or item["datasource_id"] == datasource_id)
        and (not needle or needle in str(item["name"]).casefold())
        and (
            state is None
            or (state == "error" and item["health"] != "ok")
            or (state != "error" and item["state"] == state)
        )
    ]
    offset = (page - 1) * page_size
    return {
        "data_state": _data_state(
            datasource_count,
            has_data=bool(results),
            failures=failures,
        ),
        "generated_at": utc_now(),
        "totals": totals,
        "rules": filtered[offset : offset + page_size],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": len(filtered),
            "total_pages": math.ceil(len(filtered) / page_size),
        },
        "errors": [_failure_response(failure) for failure in failures],
    }


def _series_key(sample: VectorSample) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(sample.labels.items()))


def _result_by_datasource(
    results: Iterable[DatasourceQueryResult],
) -> dict[str, DatasourceQueryResult]:
    return {result.datasource_id: result for result in results}


def _sample_map(result: DatasourceQueryResult | None) -> dict[tuple[tuple[str, str], ...], float]:
    if result is None:
        return {}
    return {_series_key(sample): sample.value for sample in result.samples}


@router.get("/availability")
async def availability(
    request: Request,
    window: AvailabilityWindow = Query(default="24h"),
    db: Session = Depends(get_db),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    generated_at = utc_now()
    cipher: EnvelopeCipher | None = request.app.state.envelope_cipher
    targets, failures, datasource_count = prepare_enabled_datasources(db, cipher)
    db.close()
    average_query, count_query, last_query = AVAILABILITY_QUERY_NAMES[window]
    query_results = await asyncio.gather(
        query_datasource_targets(targets, prometheus, average_query, evaluated_at=generated_at),
        query_datasource_targets(targets, prometheus, count_query, evaluated_at=generated_at),
        query_datasource_targets(targets, prometheus, last_query, evaluated_at=generated_at),
    )
    (
        (average_results, average_failures),
        (count_results, count_failures),
        (
            last_results,
            last_failures,
        ),
    ) = query_results
    failures.extend(average_failures)
    failures.extend(count_failures)
    failures.extend(last_failures)
    average_by_datasource = _result_by_datasource(average_results)
    count_by_datasource = _result_by_datasource(count_results)
    last_by_datasource = _result_by_datasource(last_results)

    rows: list[dict[str, Any]] = []
    for target in targets:
        average_values = _sample_map(average_by_datasource.get(target.datasource_id))
        count_values = _sample_map(count_by_datasource.get(target.datasource_id))
        last_values = _sample_map(last_by_datasource.get(target.datasource_id))
        series_keys = sorted(average_values.keys() | count_values.keys() | last_values.keys())
        for key in series_keys:
            labels = dict(key)
            if target.reachability_label_mode == "server":
                source = labels.get("source_server", "").strip()
                target_name = labels.get("target_server", "").strip()
            else:
                source = labels.get("source_region", "").strip()
                target_name = labels.get("target_name", "").strip()
            if not source or not target_name:
                failures.append(
                    DatasourceQueryFailure(
                        target.datasource_id,
                        target.datasource_name,
                        "missing_labels",
                        "Availability series is missing its configured source/target labels",
                    )
                )
                continue
            average_value = average_values.get(key)
            count_value = count_values.get(key)
            last_value = last_values.get(key)
            valid_average = (
                average_value is not None
                and math.isfinite(average_value)
                and 0 <= average_value <= 1
            )
            valid_count = count_value is not None and math.isfinite(count_value) and count_value > 0
            last_sample_at: datetime | None = None
            if last_value is not None and math.isfinite(last_value) and last_value > 0:
                try:
                    last_sample_at = datetime.fromtimestamp(last_value, tz=UTC)
                except (OverflowError, OSError, ValueError):
                    last_sample_at = None
            if not valid_average or not valid_count or last_sample_at is None:
                item_state = "unknown"
                percent = None
                samples_count = None
            else:
                assert count_value is not None
                item_state = (
                    "stale"
                    if generated_at - last_sample_at
                    > timedelta(seconds=settings.availability_stale_after_seconds)
                    else "ok"
                )
                assert average_value is not None
                percent = round(average_value * 100, 5)
                samples_count = int(count_value)
            rows.append(
                {
                    "datasource_id": target.datasource_id,
                    "datasource_name": target.datasource_name,
                    "source": source,
                    "region": source,
                    "target": target_name,
                    "window": window,
                    "observed_availability_percent": percent,
                    "samples_count": samples_count,
                    "last_sample_at": last_sample_at,
                    "data_state": item_state,
                }
            )

    rows.sort(
        key=lambda item: (
            str(item["target"]).casefold(),
            str(item["source"]).casefold(),
            str(item["datasource_name"]).casefold(),
            str(item["datasource_id"]),
        )
    )
    unique_failures = {(failure.datasource_id, failure.code): failure for failure in failures}
    public_failures = list(unique_failures.values())
    return {
        "data_state": _data_state(
            datasource_count,
            has_data=bool(average_results or count_results or last_results),
            failures=public_failures,
        ),
        "generated_at": generated_at,
        "window": window,
        "targets": rows,
        "errors": [_failure_response(failure) for failure in public_failures],
    }
