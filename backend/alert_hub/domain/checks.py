from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

CheckStatus = Literal["up", "degraded", "down", "stale", "unknown"]

# These values are deliberately private to the domain model. API serializers turn them into
# ``null`` so a minimal check does not expose implementation-only dimensions to operators.
DEFAULT_SOURCE = "__alert_hub_default_source__"
DEFAULT_SCENARIO = "__alert_hub_default_scenario__"
DEFAULT_VARIANT = "__alert_hub_default_variant__"
DEFAULT_CANARY = "__alert_hub_default_canary__"


@dataclass(frozen=True, slots=True, order=True)
class CheckResultKey:
    check_id: str
    source: str = DEFAULT_SOURCE
    scenario: str = DEFAULT_SCENARIO
    variant: str = DEFAULT_VARIANT


@dataclass(frozen=True, slots=True)
class CheckCanary:
    canary: str
    success: bool | None
    status_reason: str | None = None


@dataclass(frozen=True, slots=True)
class CheckAssertion:
    key: str
    success: bool | None
    status_reason: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedCheckResult:
    key: CheckResultKey
    target: str | None
    success: bool | None
    last_run_at: datetime | None
    duration_seconds: float | None = None
    ttfb_seconds: float | None = None
    canaries: tuple[CheckCanary, ...] = ()
    assertions: tuple[CheckAssertion, ...] = ()
    diagnostics: tuple[str, ...] = ()
    known_via_info: bool = False


@dataclass(frozen=True, slots=True)
class CheckResultView:
    key: CheckResultKey
    target: str | None
    status: CheckStatus
    status_reason: str
    success: bool | None
    last_run_at: datetime | None
    duration_seconds: float | None
    ttfb_seconds: float | None
    canaries: tuple[CheckCanary, ...]
    assertions: tuple[CheckAssertion, ...]
    stale: bool
    data_incomplete: bool
    diagnostics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CheckPart:
    scenario: str
    variant: str
    status: CheckStatus
    status_reason: str
    sources_total: int
    sources_up: int
    stale_results: int
    data_incomplete: bool


@dataclass(frozen=True, slots=True)
class AggregatedCheck:
    check_id: str
    name: str
    group: str | None
    target: str | None
    targets: tuple[str, ...]
    status: CheckStatus
    status_reason: str
    last_checked_at: datetime | None
    oldest_checked_at: datetime | None
    sources_total: int
    sources_up: int
    stale_results: int
    data_incomplete: bool
    latency_seconds: float | None
    scenarios: tuple[str, ...]
    parts: tuple[CheckPart, ...]
    results: tuple[CheckResultView, ...]
    diagnostics: tuple[str, ...]


def _result_view(
    result: NormalizedCheckResult,
    *,
    now: datetime,
    stale_after_seconds: float,
) -> CheckResultView:
    invalid_timestamp = any(
        diagnostic in {"invalid_timestamp", "conflicting_timestamp"}
        for diagnostic in result.diagnostics
    )
    invalid_status = any(
        diagnostic in {"invalid_status", "conflicting_status"} for diagnostic in result.diagnostics
    )
    invalid_inventory = "invalid_info" in result.diagnostics
    incomplete_primary = any(
        diagnostic
        in {
            "missing_status",
            "invalid_status",
            "conflicting_status",
            "missing_timestamp",
            "invalid_timestamp",
            "conflicting_timestamp",
            "invalid_info",
            "missing_current_result",
        }
        for diagnostic in result.diagnostics
    )
    if result.last_run_at is None:
        status: CheckStatus = "unknown"
        reason = "invalid_data" if invalid_timestamp or invalid_inventory else "incomplete_data"
    else:
        age = (now - result.last_run_at).total_seconds()
        if age > stale_after_seconds:
            status = "stale"
            reason = "expired_measurements"
        elif result.success is None:
            status = "unknown"
            reason = "invalid_data" if invalid_status or invalid_inventory else "incomplete_data"
        elif result.success:
            status = "up"
            reason = "result_up"
        else:
            status = "down"
            reason = "result_failed"
    return CheckResultView(
        key=result.key,
        target=result.target,
        status=status,
        status_reason=reason,
        success=result.success,
        last_run_at=result.last_run_at,
        duration_seconds=result.duration_seconds,
        ttfb_seconds=result.ttfb_seconds,
        canaries=result.canaries,
        assertions=result.assertions,
        stale=status == "stale",
        data_incomplete=status == "unknown" or incomplete_primary,
        diagnostics=result.diagnostics,
    )


def _part_status(
    results: Sequence[CheckResultView],
    *,
    min_failure_sources: int,
) -> tuple[CheckStatus, str, bool]:
    fresh_successes = {result.key.source for result in results if result.status == "up"}
    fresh_failures = {result.key.source for result in results if result.status == "down"}
    stale_count = sum(result.status == "stale" for result in results)
    unknown_count = sum(result.status == "unknown" for result in results)

    if fresh_successes and fresh_failures:
        status: CheckStatus = "degraded"
        reason = "mixed_results"
    elif not fresh_successes and len(fresh_failures) >= min_failure_sources:
        status = "down"
        reason = "confirmed_failures"
    elif results and all(result.status == "up" for result in results):
        status = "up"
        reason = "all_sources_up"
    elif results and all(result.status == "stale" for result in results):
        status = "stale"
        reason = "expired_measurements"
    else:
        status = "unknown"
        if any(result.status_reason == "invalid_data" for result in results):
            reason = "invalid_data"
        elif fresh_failures and len(fresh_failures) < min_failure_sources:
            reason = "insufficient_sources"
        else:
            reason = "incomplete_data"

    # An entirely stale part is complete-but-expired. In every mixed state, an expired or
    # unknown member means the currently evaluated set is incomplete, even if fresh votes are
    # sufficient to retain degraded/down according to the ordered rules above.
    incomplete = (
        status == "unknown"
        or unknown_count > 0
        or any(result.data_incomplete for result in results)
        or (stale_count > 0 and stale_count != len(results))
    )
    return status, reason, incomplete


def aggregate_check(
    check_id: str,
    name: str,
    group: str | None,
    results: Sequence[NormalizedCheckResult],
    *,
    now: datetime,
    stale_after_seconds: float,
    min_failure_sources: int,
    diagnostics: Sequence[str] = (),
) -> AggregatedCheck:
    """Aggregate one universal Check without relying on protocol-specific dimensions."""

    if stale_after_seconds <= 0:
        raise ValueError("stale_after_seconds must be positive")
    if min_failure_sources < 1:
        raise ValueError("min_failure_sources must be at least one")

    views = tuple(
        sorted(
            (
                _result_view(
                    result,
                    now=now,
                    stale_after_seconds=stale_after_seconds,
                )
                for result in results
            ),
            key=lambda item: item.key,
        )
    )
    by_part: dict[tuple[str, str], list[CheckResultView]] = defaultdict(list)
    for result in views:
        by_part[(result.key.scenario, result.key.variant)].append(result)

    parts: list[CheckPart] = []
    for (scenario, variant), part_results in sorted(by_part.items()):
        part_status, reason, incomplete = _part_status(
            part_results,
            min_failure_sources=min_failure_sources,
        )
        parts.append(
            CheckPart(
                scenario=scenario,
                variant=variant,
                status=part_status,
                status_reason=reason,
                sources_total=len({result.key.source for result in part_results}),
                sources_up=len(
                    {result.key.source for result in part_results if result.status == "up"}
                ),
                stale_results=sum(result.status == "stale" for result in part_results),
                data_incomplete=incomplete,
            )
        )

    if any(part.status == "down" for part in parts):
        status: CheckStatus = "down"
        reason = "confirmed_failures"
    elif any(part.status == "degraded" for part in parts):
        status = "degraded"
        reason = "mixed_results"
    elif parts and all(part.status == "up" for part in parts):
        status = "up"
        reason = "all_results_up"
    elif parts and all(part.status == "stale" for part in parts):
        status = "stale"
        reason = "expired_measurements"
    else:
        status = "unknown"
        part_reasons = {part.status_reason for part in parts}
        if "invalid_data" in part_reasons:
            reason = "invalid_data"
        elif "insufficient_sources" in part_reasons:
            reason = "insufficient_sources"
        else:
            reason = "incomplete_data"

    # A malformed Source/Scenario/Variant on a primary or inventory sample proves that the
    # visible result set is incomplete. It must never be discarded in a way that improves an
    # otherwise all-up/all-stale Check. Confirmed down and mixed-result degraded retain their
    # ordered priority, but an already unknown Check should expose the stronger invalid-data
    # reason.
    if "invalid_identifier" in diagnostics and status not in {"down", "degraded"}:
        status = "unknown"
        reason = "invalid_data"

    sources = {result.key.source for result in views}
    source_results: dict[str, list[CheckResultView]] = defaultdict(list)
    for result in views:
        source_results[result.key.source].append(result)
    sources_up = sum(
        bool(source_views) and all(result.status == "up" for result in source_views)
        for source_views in source_results.values()
    )
    timestamps = [result.last_run_at for result in views if result.last_run_at is not None]
    latencies = [
        result.duration_seconds
        for result in views
        if result.status == "up" and result.duration_seconds is not None
    ]
    targets = tuple(sorted({result.target for result in views if result.target is not None}))
    scenarios = tuple(
        sorted({result.key.scenario for result in views if result.key.scenario != DEFAULT_SCENARIO})
    )
    diagnostic_values = {
        *diagnostics,
        *(diagnostic for result in views for diagnostic in result.diagnostics),
    }
    if len(targets) > 1:
        diagnostic_values.add("conflicting_target")
    combined_diagnostics = tuple(sorted(diagnostic_values))
    overall_incomplete = (
        status == "unknown"
        or any(part.data_incomplete for part in parts)
        or (status != "stale" and any(part.status == "stale" for part in parts))
        or "invalid_identifier" in diagnostics
    )
    return AggregatedCheck(
        check_id=check_id,
        name=name,
        group=group,
        target=targets[0] if len(targets) == 1 else None,
        targets=targets,
        status=status,
        status_reason=reason,
        last_checked_at=max(timestamps) if timestamps else None,
        oldest_checked_at=min(timestamps) if timestamps else None,
        sources_total=len(sources),
        sources_up=sources_up,
        stale_results=sum(result.status == "stale" for result in views),
        data_incomplete=overall_incomplete,
        latency_seconds=max(latencies) if latencies else None,
        scenarios=scenarios,
        parts=tuple(parts),
        results=views,
        diagnostics=combined_diagnostics,
    )
