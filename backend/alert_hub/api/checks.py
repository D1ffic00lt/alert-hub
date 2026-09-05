from __future__ import annotations

import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, cast
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_user, get_db, get_settings
from alert_hub.api.prometheus import get_prometheus_client
from alert_hub.application.checks import (
    CheckFilters,
    ChecksDataError,
    ChecksSnapshot,
    ChecksSnapshotCache,
    build_check_grafana_url,
    evaluate_checks_snapshot,
    filter_checks,
    normalize_check_identifier,
    problem_checks,
    summarize_checks,
)
from alert_hub.application.prometheus import prepare_enabled_datasources
from alert_hub.domain.checks import (
    DEFAULT_CANARY,
    DEFAULT_SCENARIO,
    DEFAULT_SOURCE,
    DEFAULT_VARIANT,
    AggregatedCheck,
    CheckAssertion,
    CheckCanary,
    CheckPart,
    CheckResultView,
    CheckStatus,
)
from alert_hub.infrastructure.db.models import Incident, IncidentEvent, User
from alert_hub.infrastructure.encryption import EnvelopeCipher
from alert_hub.infrastructure.prometheus import PrometheusClient
from alert_hub.settings import Settings

logger = logging.getLogger("alert_hub.checks")

router = APIRouter(prefix="/api/v1/checks", tags=["checks"])

ChecksDataState = Literal["ready", "empty", "stale", "unavailable", "disabled"]
_PUBLIC_ERROR_CODES = frozenset({"checks_limit_exceeded", "prometheus_unavailable"})
_MAX_RELATED_ITEMS = 200
_MAX_API_RESPONSE_BYTES = 2_097_152


class ErrorResponse(BaseModel):
    detail: str


class ValidationErrorResponse(BaseModel):
    detail: str | list[dict[str, Any]]


class ChecksMetadataResponse(BaseModel):
    enabled: bool
    data_state: ChecksDataState
    snapshot_id: str | None = None
    fetched_at: datetime | None = None
    evaluated_at: datetime | None = None
    cache_expires_at: datetime | None = None
    error_code: str | None = None
    warning_codes: list[str] = Field(default_factory=list)


class CheckListItemResponse(BaseModel):
    check_id: str
    name: str
    group: str | None
    target: str | None
    status: CheckStatus
    status_reason: str
    last_checked_at: datetime | None
    oldest_checked_at: datetime | None
    sources_total: int
    sources_up: int
    stale_results: int
    data_incomplete: bool
    latency_seconds: float | None
    scenarios: list[str]
    sources: list[str]
    active_alerts: int | None
    diagnostic_codes: list[str]


class CheckCanaryResponse(BaseModel):
    canary: str | None
    success: bool | None
    status_reason: str | None


class CheckAssertionResponse(BaseModel):
    key: str
    success: bool | None
    status_reason: str | None


class CheckResultResponse(BaseModel):
    source: str | None
    scenario: str | None
    variant: str | None
    target: str | None
    status: CheckStatus
    status_reason: str
    success: bool | None
    last_run_at: datetime | None
    duration_seconds: float | None
    ttfb_seconds: float | None
    canaries: list[CheckCanaryResponse]
    assertions: list[CheckAssertionResponse]
    stale: bool
    data_incomplete: bool
    diagnostic_codes: list[str]


class CheckPartResponse(BaseModel):
    scenario: str | None
    variant: str | None
    status: CheckStatus
    status_reason: str
    sources_total: int
    sources_up: int
    stale_results: int
    data_incomplete: bool


class RelatedAlertResponse(BaseModel):
    id: str
    name: str
    severity: str
    status: str
    starts_at: datetime
    last_event_at: datetime
    resolved_at: datetime | None
    incident_id: str
    href: str


class RelatedIncidentResponse(BaseModel):
    id: str
    title: str
    status: str
    href: str


class CheckDetailItemResponse(CheckListItemResponse):
    results: list[CheckResultResponse]
    parts: list[CheckPartResponse]
    related_alerts: list[RelatedAlertResponse]
    incidents: list[RelatedIncidentResponse]
    alerts_available: bool
    related_alerts_total: int | None
    incidents_total: int | None
    relations_incomplete: bool
    relation_warning_codes: list[str]
    grafana_url: str | None


class LastKnownMetadataResponse(BaseModel):
    snapshot_id: str
    fetched_at: datetime
    evaluated_at: datetime
    cache_expires_at: datetime
    warning_codes: list[str] = Field(default_factory=list)


class ChecksListLastKnownResponse(LastKnownMetadataResponse):
    items: list[CheckListItemResponse]
    total: int


class ChecksSummaryValuesResponse(BaseModel):
    total: int
    up: int
    degraded: int
    down: int
    stale: int
    unknown: int
    problem_checks: list[CheckListItemResponse]


class ChecksSummaryLastKnownResponse(LastKnownMetadataResponse, ChecksSummaryValuesResponse):
    pass


class CheckDetailLastKnownResponse(LastKnownMetadataResponse):
    check: CheckDetailItemResponse


class ChecksListResponse(ChecksMetadataResponse):
    items: list[CheckListItemResponse]
    total: int | None
    limit: int
    offset: int
    last_known: ChecksListLastKnownResponse | None


class ChecksSummaryResponse(ChecksMetadataResponse):
    total: int | None
    up: int | None
    degraded: int | None
    down: int | None
    stale: int | None
    unknown: int | None
    problem_checks: list[CheckListItemResponse]
    last_known: ChecksSummaryLastKnownResponse | None


class CheckDetailResponse(ChecksMetadataResponse):
    check: CheckDetailItemResponse | None
    last_known: CheckDetailLastKnownResponse | None


@dataclass(frozen=True, slots=True)
class _SnapshotResult:
    snapshot: ChecksSnapshot | None
    last_known: ChecksSnapshot | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class _IncidentRelations:
    active_counts: dict[str, int]
    incident_counts: dict[str, int]
    active: dict[str, tuple[Incident, ...]]
    all: dict[str, tuple[Incident, ...]]
    warning_codes: tuple[str, ...] = ()


def _snapshot_metadata(snapshot: ChecksSnapshot) -> dict[str, Any]:
    return {
        "snapshot_id": snapshot.snapshot_id,
        "fetched_at": snapshot.fetched_at,
        "evaluated_at": snapshot.evaluated_at,
        "cache_expires_at": snapshot.cache_expires_at,
        "warning_codes": list(snapshot.warning_codes),
    }


def _response_metadata(
    *,
    enabled: bool,
    data_state: ChecksDataState,
    snapshot: ChecksSnapshot | None = None,
    error_code: str | None = None,
) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "data_state": data_state,
        "snapshot_id": snapshot.snapshot_id if snapshot is not None else None,
        "fetched_at": snapshot.fetched_at if snapshot is not None else None,
        "evaluated_at": snapshot.evaluated_at if snapshot is not None else None,
        "cache_expires_at": snapshot.cache_expires_at if snapshot is not None else None,
        "error_code": error_code,
        "warning_codes": list(snapshot.warning_codes) if snapshot is not None else [],
    }


def _bounded_response[ResponseModel: BaseModel](
    payload: ResponseModel,
    fallback: ResponseModel,
    response: Response,
) -> ResponseModel:
    if len(payload.model_dump_json().encode("utf-8")) <= _MAX_API_RESPONSE_BYTES:
        return payload
    response.status_code = 503
    return fallback


def _limited_list_response(limit: int, offset: int) -> ChecksListResponse:
    return ChecksListResponse(
        **_response_metadata(
            enabled=True,
            data_state="unavailable",
            error_code="checks_limit_exceeded",
        ),
        items=[],
        total=None,
        limit=limit,
        offset=offset,
        last_known=None,
    )


def _limited_summary_response() -> ChecksSummaryResponse:
    return ChecksSummaryResponse(
        **_response_metadata(
            enabled=True,
            data_state="unavailable",
            error_code="checks_limit_exceeded",
        ),
        total=None,
        up=None,
        degraded=None,
        down=None,
        stale=None,
        unknown=None,
        problem_checks=[],
        last_known=None,
    )


def _limited_detail_response() -> CheckDetailResponse:
    return CheckDetailResponse(
        **_response_metadata(
            enabled=True,
            data_state="unavailable",
            error_code="checks_limit_exceeded",
        ),
        check=None,
        last_known=None,
    )


def _cache(request: Request) -> ChecksSnapshotCache:
    return cast(ChecksSnapshotCache, request.app.state.checks_snapshot_cache)


def _public_error_code(value: str) -> str:
    return value if value in _PUBLIC_ERROR_CODES else "prometheus_unavailable"


async def _get_snapshot(
    request: Request,
    db: Session,
    prometheus: PrometheusClient,
    settings: Settings,
) -> _SnapshotResult:
    cache = _cache(request)
    try:
        cipher = cast(EnvelopeCipher | None, request.app.state.envelope_cipher)
        targets, failures, _ = prepare_enabled_datasources(db, cipher)
    except Exception:
        logger.error(
            "checks_datasource_preparation_failed",
            extra={"event": "checks_datasource_preparation_failed"},
        )
        return _SnapshotResult(None, cache.peek(), "prometheus_unavailable")

    # Keep SQLite transactions away from Prometheus network I/O. SQLAlchemy sessions can be
    # reused for the small related-incident query after close() resets their transaction state.
    db.close()
    try:
        snapshot = await cache.get_or_refresh(
            targets,
            prometheus,
            settings,
            preparation_failures=failures,
        )
    except ChecksDataError as exc:
        return _SnapshotResult(None, cache.peek(), _public_error_code(exc.code))
    except Exception:
        logger.error(
            "checks_snapshot_refresh_failed",
            extra={"event": "checks_snapshot_refresh_failed"},
        )
        return _SnapshotResult(None, cache.peek(), "prometheus_unavailable")
    return _SnapshotResult(snapshot, None, None)


def _unavailable_result(result: CheckResultView) -> CheckResultView:
    return CheckResultView(
        key=result.key,
        target=result.target,
        status="unknown",
        status_reason="prometheus_unavailable",
        success=None,
        last_run_at=None,
        duration_seconds=None,
        ttfb_seconds=None,
        canaries=tuple(
            CheckCanary(
                canary=canary.canary,
                success=None,
                status_reason="prometheus_unavailable",
            )
            for canary in result.canaries
        ),
        assertions=tuple(
            CheckAssertion(
                key=assertion.key,
                success=None,
                status_reason="prometheus_unavailable",
            )
            for assertion in result.assertions
        ),
        stale=False,
        data_incomplete=True,
        diagnostics=(),
    )


def _unavailable_check(check: AggregatedCheck) -> AggregatedCheck:
    return AggregatedCheck(
        check_id=check.check_id,
        name=check.name,
        group=check.group,
        target=check.target,
        targets=check.targets,
        status="unknown",
        status_reason="prometheus_unavailable",
        last_checked_at=None,
        oldest_checked_at=None,
        sources_total=check.sources_total,
        sources_up=0,
        stale_results=0,
        data_incomplete=True,
        latency_seconds=None,
        scenarios=check.scenarios,
        parts=tuple(
            CheckPart(
                scenario=part.scenario,
                variant=part.variant,
                status="unknown",
                status_reason="prometheus_unavailable",
                sources_total=part.sources_total,
                sources_up=0,
                stale_results=0,
                data_incomplete=True,
            )
            for part in check.parts
        ),
        results=tuple(_unavailable_result(result) for result in check.results),
        diagnostics=(),
    )


def _load_incident_relations(
    db: Session,
    check_ids: set[str],
    *,
    include_items: bool = False,
) -> _IncidentRelations | None:
    if not check_ids:
        return _IncidentRelations({}, {}, {}, {})
    try:
        current_check_id = Incident.labels_json["check_id"].as_string()
        active_count_rows = db.execute(
            select(current_check_id, func.count(Incident.id))
            .where(
                current_check_id.in_(sorted(check_ids)),
                Incident.status != "resolved",
            )
            .group_by(current_check_id)
        ).all()
        active_counts = {str(check_id): int(count) for check_id, count in active_count_rows}
        active: dict[str, tuple[Incident, ...]] = {}
        all_relations: dict[str, tuple[Incident, ...]] = {}
        incident_counts: dict[str, int] = {}
        warning_codes: set[str] = set()

        if include_items:
            historical_check_id = IncidentEvent.payload_json["labels"]["check_id"].as_string()
            for check_id in sorted(check_ids):
                relation_predicate = or_(
                    current_check_id == check_id,
                    historical_check_id == check_id,
                )
                related_count = int(
                    db.scalar(
                        select(func.count(func.distinct(Incident.id)))
                        .select_from(Incident)
                        .outerjoin(IncidentEvent)
                        .where(relation_predicate)
                    )
                    or 0
                )
                incident_counts[check_id] = related_count
                related = tuple(
                    db.scalars(
                        select(Incident)
                        .outerjoin(IncidentEvent)
                        .where(relation_predicate)
                        .group_by(Incident.id)
                        .order_by(Incident.last_event_at.desc(), Incident.id)
                        .limit(_MAX_RELATED_ITEMS)
                    ).all()
                )
                current_active = tuple(
                    db.scalars(
                        select(Incident)
                        .where(
                            current_check_id == check_id,
                            Incident.status != "resolved",
                        )
                        .order_by(Incident.last_event_at.desc(), Incident.id)
                        .limit(_MAX_RELATED_ITEMS)
                    ).all()
                )
                all_relations[check_id] = related
                active[check_id] = current_active
                if related_count > len(related):
                    warning_codes.add("related_incidents_truncated")
                if active_counts.get(check_id, 0) > len(current_active):
                    warning_codes.add("related_alerts_truncated")
    except Exception:
        with suppress(Exception):
            db.rollback()
        logger.error(
            "checks_incident_lookup_failed",
            extra={"event": "checks_incident_lookup_failed"},
        )
        return None
    return _IncidentRelations(
        active_counts=active_counts,
        incident_counts=incident_counts,
        active=active,
        all=all_relations,
        warning_codes=tuple(sorted(warning_codes)),
    )


def _public_dimension(value: str, default: str) -> str | None:
    return None if value == default else value


def _active_count(
    relations: _IncidentRelations | None,
    check_id: str,
) -> int | None:
    if relations is None:
        return None
    return relations.active_counts.get(check_id, 0)


def _list_item(
    check: AggregatedCheck,
    relations: _IncidentRelations | None,
) -> CheckListItemResponse:
    sources = sorted(
        {result.key.source for result in check.results if result.key.source != DEFAULT_SOURCE}
    )
    return CheckListItemResponse(
        check_id=check.check_id,
        name=check.name,
        group=check.group,
        target=check.target,
        status=check.status,
        status_reason=check.status_reason,
        last_checked_at=check.last_checked_at,
        oldest_checked_at=check.oldest_checked_at,
        sources_total=check.sources_total,
        sources_up=check.sources_up,
        stale_results=check.stale_results,
        data_incomplete=check.data_incomplete,
        latency_seconds=check.latency_seconds,
        scenarios=list(check.scenarios),
        sources=sources,
        active_alerts=_active_count(relations, check.check_id),
        diagnostic_codes=list(check.diagnostics),
    )


def _canary_response(canary: CheckCanary) -> CheckCanaryResponse:
    return CheckCanaryResponse(
        canary=_public_dimension(canary.canary, DEFAULT_CANARY),
        success=canary.success,
        status_reason=canary.status_reason,
    )


def _assertion_response(assertion: CheckAssertion) -> CheckAssertionResponse:
    return CheckAssertionResponse(
        key=assertion.key,
        success=assertion.success,
        status_reason=assertion.status_reason,
    )


def _result_response(result: CheckResultView) -> CheckResultResponse:
    return CheckResultResponse(
        source=_public_dimension(result.key.source, DEFAULT_SOURCE),
        scenario=_public_dimension(result.key.scenario, DEFAULT_SCENARIO),
        variant=_public_dimension(result.key.variant, DEFAULT_VARIANT),
        target=result.target,
        status=result.status,
        status_reason=result.status_reason,
        success=result.success,
        last_run_at=result.last_run_at,
        duration_seconds=result.duration_seconds,
        ttfb_seconds=result.ttfb_seconds,
        canaries=[_canary_response(canary) for canary in result.canaries],
        assertions=[_assertion_response(assertion) for assertion in result.assertions],
        stale=result.stale,
        data_incomplete=result.data_incomplete,
        diagnostic_codes=list(result.diagnostics),
    )


def _part_response(part: CheckPart) -> CheckPartResponse:
    return CheckPartResponse(
        scenario=_public_dimension(part.scenario, DEFAULT_SCENARIO),
        variant=_public_dimension(part.variant, DEFAULT_VARIANT),
        status=part.status,
        status_reason=part.status_reason,
        sources_total=part.sources_total,
        sources_up=part.sources_up,
        stale_results=part.stale_results,
        data_incomplete=part.data_incomplete,
    )


def _related_alert(incident: Incident) -> RelatedAlertResponse:
    return RelatedAlertResponse(
        id=incident.id,
        name=incident.title,
        severity=incident.severity,
        status=incident.status,
        starts_at=incident.starts_at,
        last_event_at=incident.last_event_at,
        resolved_at=incident.resolved_at,
        incident_id=incident.id,
        href=f"/incidents/{quote(incident.id, safe='')}",
    )


def _related_incident(incident: Incident) -> RelatedIncidentResponse:
    return RelatedIncidentResponse(
        id=incident.id,
        title=incident.title,
        status=incident.status,
        href=f"/incidents/{quote(incident.id, safe='')}",
    )


def _detail_item(
    check: AggregatedCheck,
    relations: _IncidentRelations | None,
    settings: Settings,
) -> CheckDetailItemResponse:
    base = _list_item(check, relations)
    active = relations.active.get(check.check_id, ()) if relations is not None else ()
    incidents = relations.all.get(check.check_id, ()) if relations is not None else ()
    relation_warning_codes = (
        list(relations.warning_codes)
        if relations is not None
        else ["incident_relations_unavailable"]
    )
    return CheckDetailItemResponse(
        **base.model_dump(),
        results=[_result_response(result) for result in check.results],
        parts=[_part_response(part) for part in check.parts],
        related_alerts=(
            [_related_alert(incident) for incident in active] if relations is not None else []
        ),
        incidents=(
            [_related_incident(incident) for incident in incidents] if relations is not None else []
        ),
        alerts_available=relations is not None,
        related_alerts_total=(
            relations.active_counts.get(check.check_id, 0) if relations is not None else None
        ),
        incidents_total=(
            relations.incident_counts.get(check.check_id, 0) if relations is not None else None
        ),
        relations_incomplete=relations is None or bool(relation_warning_codes),
        relation_warning_codes=relation_warning_codes,
        grafana_url=build_check_grafana_url(
            settings.checks_grafana_base_url,
            check.check_id,
        ),
    )


def _filters(
    status_filter: CheckStatus | None,
    group: str | None,
    source: str | None,
    target: str | None,
    scenario: str | None,
    search: str | None,
) -> CheckFilters:
    return CheckFilters(
        status=status_filter,
        group=group,
        source=source,
        target=target,
        scenario=scenario,
        search=search,
    )


def _last_known_list(
    snapshot: ChecksSnapshot,
    checks: tuple[AggregatedCheck, ...],
    total: int,
    relations: _IncidentRelations | None,
) -> ChecksListLastKnownResponse:
    return ChecksListLastKnownResponse(
        **_snapshot_metadata(snapshot),
        items=[_list_item(check, relations) for check in checks],
        total=total,
    )


def _summary_values(
    checks: tuple[AggregatedCheck, ...],
    relations: _IncidentRelations | None,
) -> ChecksSummaryValuesResponse:
    summary = summarize_checks(checks)
    return ChecksSummaryValuesResponse(
        total=summary.total,
        up=summary.up,
        degraded=summary.degraded,
        down=summary.down,
        stale=summary.stale,
        unknown=summary.unknown,
        problem_checks=[_list_item(check, relations) for check in problem_checks(checks)],
    )


def _last_known_summary(
    snapshot: ChecksSnapshot,
    checks: tuple[AggregatedCheck, ...],
    relations: _IncidentRelations | None,
) -> ChecksSummaryLastKnownResponse:
    values = _summary_values(checks, relations)
    return ChecksSummaryLastKnownResponse(
        **_snapshot_metadata(snapshot),
        **values.model_dump(),
    )


def _disabled_list(limit: int, offset: int) -> ChecksListResponse:
    return ChecksListResponse(
        **_response_metadata(enabled=False, data_state="disabled"),
        items=[],
        total=None,
        limit=limit,
        offset=offset,
        last_known=None,
    )


_LIST_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse, "description": "Authentication required"},
    422: {"model": ValidationErrorResponse, "description": "Invalid query parameters"},
    503: {"model": ChecksListResponse, "description": "Checks data unavailable"},
}
_SUMMARY_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse, "description": "Authentication required"},
    422: {"model": ValidationErrorResponse, "description": "Invalid query parameters"},
    503: {"model": ChecksSummaryResponse, "description": "Checks data unavailable"},
}
_DETAIL_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse, "description": "Authentication required"},
    404: {"model": CheckDetailResponse, "description": "Check absent from current inventory"},
    422: {"model": ValidationErrorResponse, "description": "Invalid check identifier"},
    503: {"model": CheckDetailResponse, "description": "Checks data unavailable"},
}


@router.get("", response_model=ChecksListResponse, responses=_LIST_ERROR_RESPONSES)
async def list_checks(
    request: Request,
    response: Response,
    status_filter: CheckStatus | None = Query(default=None, alias="status"),
    group: str | None = Query(default=None, max_length=128),
    source: str | None = Query(default=None, max_length=128),
    target: str | None = Query(default=None, max_length=255),
    scenario: str | None = Query(default=None, max_length=128),
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
) -> ChecksListResponse:
    del user
    if not settings.checks_enabled:
        return _disabled_list(limit, offset)

    selected_filters = _filters(status_filter, group, source, target, scenario, search)
    result = await _get_snapshot(request, db, prometheus, settings)
    if result.snapshot is not None:
        checks = filter_checks(
            evaluate_checks_snapshot(result.snapshot, settings), selected_filters
        )
        page = checks[offset : offset + limit]
        relations = _load_incident_relations(db, {check.check_id for check in page})
        payload = ChecksListResponse(
            **_response_metadata(
                enabled=True,
                data_state="ready" if result.snapshot.checks else "empty",
                snapshot=result.snapshot,
            ),
            items=[_list_item(check, relations) for check in page],
            total=len(checks),
            limit=limit,
            offset=offset,
            last_known=None,
        )
        return _bounded_response(
            payload,
            _limited_list_response(limit, offset),
            response,
        )

    response.status_code = 503
    if result.last_known is None:
        return ChecksListResponse(
            **_response_metadata(
                enabled=True,
                data_state="unavailable",
                error_code=result.error_code,
            ),
            items=[],
            total=None,
            limit=limit,
            offset=offset,
            last_known=None,
        )
    known = evaluate_checks_snapshot(result.last_known, settings)
    current = filter_checks(tuple(_unavailable_check(check) for check in known), selected_filters)
    previous = filter_checks(known, selected_filters)
    current_page = current[offset : offset + limit]
    previous_page = previous[offset : offset + limit]
    relations = _load_incident_relations(
        db,
        {check.check_id for check in (*current_page, *previous_page)},
    )
    payload = ChecksListResponse(
        **_response_metadata(
            enabled=True,
            data_state="unavailable",
            error_code=result.error_code,
        ),
        items=[_list_item(check, relations) for check in current_page],
        total=len(current),
        limit=limit,
        offset=offset,
        last_known=_last_known_list(result.last_known, previous_page, len(previous), relations),
    )
    return _bounded_response(
        payload,
        _limited_list_response(limit, offset),
        response,
    )


# Keep this static route above /{check_id}; otherwise "summary" is parsed as an identifier.
@router.get(
    "/summary",
    response_model=ChecksSummaryResponse,
    responses=_SUMMARY_ERROR_RESPONSES,
)
async def checks_summary(
    request: Request,
    response: Response,
    status_filter: CheckStatus | None = Query(default=None, alias="status"),
    group: str | None = Query(default=None, max_length=128),
    source: str | None = Query(default=None, max_length=128),
    target: str | None = Query(default=None, max_length=255),
    scenario: str | None = Query(default=None, max_length=128),
    search: str | None = Query(default=None, max_length=200),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
) -> ChecksSummaryResponse:
    del user
    if not settings.checks_enabled:
        return ChecksSummaryResponse(
            **_response_metadata(enabled=False, data_state="disabled"),
            total=None,
            up=None,
            degraded=None,
            down=None,
            stale=None,
            unknown=None,
            problem_checks=[],
            last_known=None,
        )

    selected_filters = _filters(status_filter, group, source, target, scenario, search)
    result = await _get_snapshot(request, db, prometheus, settings)
    if result.snapshot is not None:
        checks = filter_checks(
            evaluate_checks_snapshot(result.snapshot, settings), selected_filters
        )
        problem = problem_checks(checks)
        relations = _load_incident_relations(db, {check.check_id for check in problem})
        values = _summary_values(checks, relations)
        payload = ChecksSummaryResponse(
            **_response_metadata(
                enabled=True,
                data_state="ready" if result.snapshot.checks else "empty",
                snapshot=result.snapshot,
            ),
            **values.model_dump(),
            last_known=None,
        )
        return _bounded_response(
            payload,
            _limited_summary_response(),
            response,
        )

    response.status_code = 503
    if result.last_known is None:
        return ChecksSummaryResponse(
            **_response_metadata(
                enabled=True,
                data_state="unavailable",
                error_code=result.error_code,
            ),
            total=None,
            up=None,
            degraded=None,
            down=None,
            stale=None,
            unknown=None,
            problem_checks=[],
            last_known=None,
        )
    known = evaluate_checks_snapshot(result.last_known, settings)
    current = filter_checks(tuple(_unavailable_check(check) for check in known), selected_filters)
    previous = filter_checks(known, selected_filters)
    relation_ids = {
        check.check_id for check in (*problem_checks(current), *problem_checks(previous))
    }
    relations = _load_incident_relations(db, relation_ids)
    current_values = _summary_values(current, relations)
    payload = ChecksSummaryResponse(
        **_response_metadata(
            enabled=True,
            data_state="unavailable",
            error_code=result.error_code,
        ),
        **current_values.model_dump(),
        last_known=_last_known_summary(result.last_known, previous, relations),
    )
    return _bounded_response(
        payload,
        _limited_summary_response(),
        response,
    )


@router.get(
    "/{check_id}",
    response_model=CheckDetailResponse,
    responses=_DETAIL_ERROR_RESPONSES,
)
async def check_detail(
    request: Request,
    response: Response,
    check_id: str = Path(min_length=1, max_length=128),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
) -> CheckDetailResponse:
    del user
    if not settings.checks_enabled:
        return CheckDetailResponse(
            **_response_metadata(enabled=False, data_state="disabled"),
            check=None,
            last_known=None,
        )
    normalized_check_id = normalize_check_identifier(check_id)
    if normalized_check_id is None:
        raise HTTPException(status_code=422, detail="Invalid check identifier")
    check_id = normalized_check_id

    result = await _get_snapshot(request, db, prometheus, settings)
    if result.snapshot is not None:
        checks = evaluate_checks_snapshot(result.snapshot, settings)
        check = next((item for item in checks if item.check_id == check_id), None)
        data_state: ChecksDataState = "ready" if result.snapshot.checks else "empty"
        if check is None:
            response.status_code = 404
            return CheckDetailResponse(
                **_response_metadata(
                    enabled=True,
                    data_state=data_state,
                    snapshot=result.snapshot,
                ),
                check=None,
                last_known=None,
            )
        relations = _load_incident_relations(db, {check_id}, include_items=True)
        payload = CheckDetailResponse(
            **_response_metadata(enabled=True, data_state=data_state, snapshot=result.snapshot),
            check=_detail_item(check, relations, settings),
            last_known=None,
        )
        return _bounded_response(
            payload,
            _limited_detail_response(),
            response,
        )

    response.status_code = 503
    if result.last_known is None:
        return CheckDetailResponse(
            **_response_metadata(
                enabled=True,
                data_state="unavailable",
                error_code=result.error_code,
            ),
            check=None,
            last_known=None,
        )
    known = evaluate_checks_snapshot(result.last_known, settings)
    previous = next((item for item in known if item.check_id == check_id), None)
    if previous is None:
        return CheckDetailResponse(
            **_response_metadata(
                enabled=True,
                data_state="unavailable",
                error_code=result.error_code,
            ),
            check=None,
            last_known=None,
        )
    relations = _load_incident_relations(db, {check_id}, include_items=True)
    payload = CheckDetailResponse(
        **_response_metadata(
            enabled=True,
            data_state="unavailable",
            error_code=result.error_code,
        ),
        check=_detail_item(_unavailable_check(previous), relations, settings),
        last_known=CheckDetailLastKnownResponse(
            **_snapshot_metadata(result.last_known),
            check=_detail_item(previous, relations, settings),
        ),
    )
    return _bounded_response(
        payload,
        _limited_detail_response(),
        response,
    )
