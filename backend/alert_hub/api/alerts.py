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


def _stable_rule_id(category: str | None, name: str) -> str:
    identity = "\0".join((category or "", name)).encode()
    return f"ar_{hashlib.sha256(identity).hexdigest()}"


def _stable_replica_id(datasource_id: str, rule: AlertRule) -> str:
    identity = "\0".join((datasource_id, rule.file, rule.group, rule.name)).encode()
    return f"arr_{hashlib.sha256(identity).hexdigest()}"


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
    has_success: bool,
    has_rules: bool,
    failures: list[DatasourceQueryFailure],
) -> Literal["ok", "partial", "empty", "unavailable", "not_configured"]:
    if datasource_count == 0:
        return "not_configured"
    if failures and has_success:
        return "partial"
    if failures:
        return "unavailable"
    if not has_rules:
        return "empty"
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


def _rule_category(rule: AlertRule) -> str | None:
    category = rule.labels.get("alert_category", "").strip()
    return category or None


def _replica_response(
    result: DatasourceRulesResult,
    rule: AlertRule,
    incident_counts: dict[tuple[str, str], int],
) -> dict[str, Any]:
    related_incidents = incident_counts.get((result.datasource_id, rule.name), 0)
    return {
        "id": _stable_replica_id(result.datasource_id, rule),
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
            "/incidents?"
            f"alertname={quote(rule.name, safe='')}&"
            f"datasource_id={quote(result.datasource_id, safe='')}"
            if rule.state in {"firing", "pending"}
            else None
        ),
    }


def _replica_has_error(replica: dict[str, Any]) -> bool:
    return replica["health"] != "ok" or bool(replica["last_error"])


def _replica_is_firing(replica: dict[str, Any]) -> bool:
    return replica["state"] == "firing" or int(replica["firing_instances"]) > 0


def _replica_is_pending(replica: dict[str, Any]) -> bool:
    return replica["state"] == "pending" or int(replica["pending_instances"]) > 0


def _rule_state(replicas: list[dict[str, Any]]) -> AlertRuleFilter:
    if any(_replica_is_firing(replica) for replica in replicas):
        return "firing"
    if any(_replica_is_pending(replica) for replica in replicas):
        return "pending"
    if any(_replica_has_error(replica) for replica in replicas):
        return "error"
    return "inactive"


def _grouped_rule_response(
    category: str | None,
    name: str,
    replicas: list[dict[str, Any]],
) -> dict[str, Any]:
    replicas.sort(
        key=lambda item: (
            str(item["datasource_name"]).casefold(),
            str(item["datasource_id"]),
            str(item["file"]),
            str(item["group"]).casefold(),
            str(item["id"]),
        )
    )
    return {
        "id": _stable_rule_id(category, name),
        "name": name,
        "category": category,
        "state": _rule_state(replicas),
        "firing_instances": sum(int(replica["firing_instances"]) for replica in replicas),
        "pending_instances": sum(int(replica["pending_instances"]) for replica in replicas),
        "has_error": any(_replica_has_error(replica) for replica in replicas),
        "datasource_count": len({str(replica["datasource_id"]) for replica in replicas}),
        "related_incidents": sum(int(replica["related_incidents"]) for replica in replicas),
        "replicas": replicas,
    }


def _group_rules(
    results: list[DatasourceRulesResult],
    incident_counts: dict[tuple[str, str], int],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
    for result in results:
        for rule in result.rules:
            category = _rule_category(rule)
            grouped.setdefault((category, rule.name), []).append(
                _replica_response(result, rule, incident_counts)
            )
    return [
        _grouped_rule_response(category, name, replicas)
        for (category, name), replicas in grouped.items()
    ]


def _rule_sort_key(item: dict[str, Any]) -> tuple[int, str, str, str]:
    rank = {"firing": 0, "pending": 1, "error": 2, "inactive": 3}
    return (
        rank[str(item["state"])],
        str(item["category"] or "").casefold(),
        str(item["name"]).casefold(),
        str(item["id"]),
    )


def _category_pages(rules: list[dict[str, Any]], page_size: int) -> list[list[dict[str, Any]]]:
    """Pack whole categories into pages without splitting a disclosure group."""
    grouped: dict[str | None, list[dict[str, Any]]] = {}
    for rule in rules:
        category = rule["category"]
        grouped.setdefault(category if isinstance(category, str) else None, []).append(rule)

    pages: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for category_rules in grouped.values():
        if current and len(current) + len(category_rules) > page_size:
            pages.append(current)
            current = []
        current.extend(category_rules)
        if len(current) >= page_size:
            pages.append(current)
            current = []
    if current:
        pages.append(current)
    return pages


@router.get("/alert-rules")
async def alert_rules(
    request: Request,
    datasource_id: str | None = Query(default=None, max_length=36),
    category: str | None = Query(default=None, max_length=2_048),
    uncategorized: bool = False,
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

    all_rules = _group_rules(results, incident_counts)
    all_rules.sort(key=_rule_sort_key)
    totals = {
        "rules": len(all_rules),
        "firing_rules": sum(item["state"] == "firing" for item in all_rules),
        "pending_rules": sum(
            any(_replica_is_pending(replica) for replica in item["replicas"]) for item in all_rules
        ),
        "error_rules": sum(bool(item["has_error"]) for item in all_rules),
        "datasources": datasource_count,
        "related_incidents": sum(int(item["related_incidents"]) for item in all_rules),
    }
    categories = sorted(
        {str(item["category"]) for item in all_rules if item["category"] is not None},
        key=str.casefold,
    )
    has_uncategorized = any(item["category"] is None for item in all_rules)

    needle = q.strip().casefold() if q else ""
    filtered: list[dict[str, Any]] = []
    for item in all_rules:
        if category is not None and item["category"] != category:
            continue
        if uncategorized and item["category"] is not None:
            continue
        if needle and needle not in str(item["name"]).casefold():
            continue
        replicas = item["replicas"]
        if datasource_id is not None:
            replicas = [
                replica for replica in replicas if replica["datasource_id"] == datasource_id
            ]
            if not replicas:
                continue
            item = _grouped_rule_response(item["category"], str(item["name"]), replicas)
        if state == "error" and not item["has_error"]:
            continue
        if state in {"firing", "pending"} and not any(
            (_replica_is_firing(replica) if state == "firing" else _replica_is_pending(replica))
            for replica in item["replicas"]
        ):
            continue
        if state == "inactive" and item["state"] != "inactive":
            continue
        filtered.append(item)
    filtered.sort(key=_rule_sort_key)
    pages = _category_pages(filtered, page_size)
    generated_at = utc_now()
    return {
        "data_state": _data_state(
            datasource_count,
            has_success=bool(results),
            has_rules=bool(all_rules),
            failures=failures,
        ),
        "generated_at": generated_at,
        "last_successful_refresh": generated_at if results else None,
        "totals": totals,
        "filtered_rules": len(filtered),
        "categories": categories,
        "has_uncategorized": has_uncategorized,
        "rules": pages[page - 1] if page <= len(pages) else [],
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": len(filtered),
            "total_pages": len(pages),
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
            has_success=bool(average_results or count_results or last_results),
            has_rules=bool(rows),
            failures=public_failures,
        ),
        "generated_at": generated_at,
        "window": window,
        "targets": rows,
        "errors": [_failure_response(failure) for failure in public_failures],
    }
