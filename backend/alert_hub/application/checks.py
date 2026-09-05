from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import time
import unicodedata
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID, uuid4

from alert_hub.application.prometheus import (
    DatasourceQueryFailure,
    DatasourceQueryTarget,
    query_datasource_targets,
)
from alert_hub.domain.checks import (
    DEFAULT_CANARY,
    DEFAULT_SCENARIO,
    DEFAULT_SOURCE,
    DEFAULT_VARIANT,
    AggregatedCheck,
    CheckAssertion,
    CheckCanary,
    CheckResultKey,
    CheckStatus,
    NormalizedCheckResult,
    aggregate_check,
)
from alert_hub.infrastructure.prometheus import CheckQueryName, PrometheusClient, VectorSample
from alert_hub.settings import Settings

CHECK_QUERY_NAMES: tuple[CheckQueryName, ...] = (
    "check_info",
    "check_status",
    "check_last_run",
    "check_canary_success",
    "check_duration",
    "check_ttfb",
    "check_egress_match",
)
MANDATORY_CHECK_QUERIES: frozenset[CheckQueryName] = frozenset({"check_status", "check_last_run"})
MAX_RESULTS_PER_CHECK = 1_000
MAX_CANARIES_PER_RESULT = 100

_PRIMARY_CHECK_QUERIES: frozenset[CheckQueryName] = frozenset(
    {"check_info", "check_status", "check_last_run"}
)
_LIMIT_FAILURE_CODES = frozenset({"too_many_samples", "response_too_large"})
_OPTIONAL_WARNING_CODES: dict[CheckQueryName, str] = {
    "check_info": "check_info_unavailable",
    "check_canary_success": "check_canary_unavailable",
    "check_duration": "check_duration_unavailable",
    "check_ttfb": "check_ttfb_unavailable",
    "check_egress_match": "check_assertions_unavailable",
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}")
_SENSITIVE_DISPLAY = re.compile(
    r"(?i)(?:[a-z][a-z0-9+.-]*://|bearer\s+\S|"
    r"(?:token|password|secret|api[_-]?key)\s*[:=])"
)
_RESERVED_IDENTIFIER_PREFIX = "__alert_hub_"
_RESERVED_IDENTIFIERS = frozenset({"summary"})
_UUID_CANDIDATE = re.compile(
    r"(?i)(?<![A-Za-z0-9])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}(?![A-Za-z0-9])"
)
_IPV4_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9])")
_IPV6_CANDIDATE = re.compile(
    r"(?i)\[[0-9a-f:.%]+\](?::[0-9]{1,5})?|"
    r"(?<![A-Za-z0-9])[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:]+(?![A-Za-z0-9])"
)


class ChecksDataError(RuntimeError):
    """A safe, client-facing reason why a current Checks snapshot is unavailable."""

    def __init__(self, code: str = "prometheus_unavailable") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class NormalizedCheck:
    check_id: str
    name: str
    group: str | None
    results: tuple[NormalizedCheckResult, ...]
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ChecksSnapshot:
    snapshot_id: str
    fetched_at: datetime
    evaluated_at: datetime
    cache_expires_at: datetime
    checks: tuple[NormalizedCheck, ...]
    warning_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CheckFilters:
    status: CheckStatus | None = None
    group: str | None = None
    source: str | None = None
    target: str | None = None
    scenario: str | None = None
    search: str | None = None


@dataclass(frozen=True, slots=True)
class ChecksSummary:
    total: int
    up: int
    degraded: int
    down: int
    stale: int
    unknown: int


@dataclass(frozen=True, slots=True)
class _AcceptedSample:
    sample: VectorSample
    key: CheckResultKey
    name: str | None
    group: str | None
    target: str | None
    canary: str | None


def normalize_check_identifier(
    value: object,
    *,
    allow_reserved_routes: bool = False,
) -> str | None:
    """Return a bounded path-safe public identifier, never an internal sentinel."""

    if not isinstance(value, str):
        return None
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        return None
    candidate = value.strip()
    if (
        not candidate
        or candidate != value
        or candidate.startswith(_RESERVED_IDENTIFIER_PREFIX)
        or (not allow_reserved_routes and candidate.casefold() in _RESERVED_IDENTIFIERS)
        or _IDENTIFIER.fullmatch(candidate) is None
        or _safe_display(candidate, max_length=128) != candidate
        or _UUID_CANDIDATE.search(candidate) is not None
    ):
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return None
    try:
        UUID(candidate)
    except ValueError:
        pass
    else:
        return None
    return candidate


def _safe_display(value: object, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        return None
    candidate = " ".join(value.strip().split())
    if not candidate or len(candidate) > max_length or _SENSITIVE_DISPLAY.search(candidate):
        return None
    address_candidates = [
        candidate,
        *(_IPV4_CANDIDATE.findall(candidate)),
        *(_IPV6_CANDIDATE.findall(candidate)),
    ]
    for address_candidate in address_candidates:
        if address_candidate.startswith("[") and "]" in address_candidate:
            address_candidate = address_candidate[1 : address_candidate.index("]")]
        address_candidate = address_candidate.split("%", 1)[0]
        try:
            ipaddress.ip_address(address_candidate.strip("[]"))
        except ValueError:
            continue
        return None
    return candidate


def _optional_identifier(
    labels: Mapping[str, str],
    label: str,
    default: str,
) -> tuple[str | None, bool]:
    raw = labels.get(label)
    if raw is None or raw == "":
        return default, True
    return normalize_check_identifier(raw, allow_reserved_routes=True), False


def _accept_sample(
    query_name: CheckQueryName,
    sample: VectorSample,
    diagnostics: dict[str, set[str]],
) -> _AcceptedSample | None:
    raw_check_id = sample.labels.get("check_id")
    check_id = normalize_check_identifier(raw_check_id)
    if check_id is None:
        return None

    source, _ = _optional_identifier(sample.labels, "source", DEFAULT_SOURCE)
    scenario, _ = _optional_identifier(sample.labels, "scenario", DEFAULT_SCENARIO)
    variant, _ = _optional_identifier(sample.labels, "variant", DEFAULT_VARIANT)
    if source is None or scenario is None or variant is None:
        diagnostics[check_id].add(
            "invalid_identifier"
            if query_name in _PRIMARY_CHECK_QUERIES
            else "invalid_optional_identifier"
        )
        return None

    name = _safe_display(sample.labels.get("check_name"), max_length=255)
    if sample.labels.get("check_name", "").strip() and name is None:
        diagnostics[check_id].add("invalid_name")
    group = _safe_display(sample.labels.get("group"), max_length=128)
    if sample.labels.get("group", "").strip() and group is None:
        diagnostics[check_id].add("invalid_group")
    target = _safe_display(sample.labels.get("target"), max_length=255)
    if sample.labels.get("target", "").strip() and target is None:
        diagnostics[check_id].add("invalid_target")

    canary: str | None = None
    if query_name == "check_canary_success":
        parsed_canary, _ = _optional_identifier(sample.labels, "canary", DEFAULT_CANARY)
        if parsed_canary is None:
            diagnostics[check_id].add("invalid_canary")
            return None
        canary = parsed_canary

    return _AcceptedSample(
        sample=sample,
        key=CheckResultKey(check_id, source, scenario, variant),
        name=name,
        group=group,
        target=target,
        canary=canary,
    )


def _binary_value(
    samples: Sequence[_AcceptedSample],
    *,
    missing_code: str | None,
    invalid_code: str,
    conflict_code: str,
) -> tuple[bool | None, set[str]]:
    if not samples:
        return None, {missing_code} if missing_code is not None else set()
    invalid = any(
        not math.isfinite(item.sample.value) or item.sample.value not in {0.0, 1.0}
        for item in samples
    )
    values = {
        bool(item.sample.value)
        for item in samples
        if math.isfinite(item.sample.value) and item.sample.value in {0.0, 1.0}
    }
    if invalid:
        return None, {invalid_code}
    if len(values) != 1:
        return None, {conflict_code}
    return next(iter(values)), set()


def _last_run_value(
    samples: Sequence[_AcceptedSample],
    *,
    evaluated_at: datetime,
    future_tolerance_seconds: float,
) -> tuple[datetime | None, set[str]]:
    if not samples:
        return None, {"missing_timestamp"}
    upper_bound = evaluated_at.timestamp() + future_tolerance_seconds
    values: set[float] = set()
    invalid = False
    for item in samples:
        value = item.sample.value
        if not math.isfinite(value) or value < 0 or value > upper_bound:
            invalid = True
            continue
        try:
            datetime.fromtimestamp(value, tz=UTC)
        except (OSError, OverflowError, ValueError):
            invalid = True
            continue
        values.add(value)
    if invalid:
        return None, {"invalid_timestamp"}
    if len(values) != 1:
        return None, {"conflicting_timestamp"}
    return datetime.fromtimestamp(next(iter(values)), tz=UTC), set()


def _non_negative_value(
    samples: Sequence[_AcceptedSample],
    *,
    label: str,
) -> tuple[float | None, set[str]]:
    if not samples:
        return None, set()
    invalid = any(not math.isfinite(item.sample.value) or item.sample.value < 0 for item in samples)
    values = {
        item.sample.value
        for item in samples
        if math.isfinite(item.sample.value) and item.sample.value >= 0
    }
    if invalid:
        return None, {f"invalid_{label}"}
    if len(values) != 1:
        return None, {f"conflicting_{label}"}
    return next(iter(values)), set()


def _metadata_value(
    values: set[str],
    *,
    conflict_code: str,
) -> tuple[str | None, set[str]]:
    if len(values) > 1:
        return None, {conflict_code}
    return (next(iter(values)) if values else None), set()


def normalize_check_metrics(
    samples_by_query: Mapping[CheckQueryName, Sequence[VectorSample]],
    *,
    evaluated_at: datetime,
    future_tolerance_seconds: float,
    max_series: int,
    previous: ChecksSnapshot | None = None,
) -> tuple[NormalizedCheck, ...]:
    """Normalize allowlisted metric fields and merge replicas by logical result key."""

    if max_series < 1:
        raise ValueError("max_series must be positive")
    sample_count = sum(len(samples_by_query.get(name, ())) for name in CHECK_QUERY_NAMES)
    if sample_count > max_series:
        raise ChecksDataError("checks_limit_exceeded")

    evaluated_at = evaluated_at.astimezone(UTC)
    accepted: dict[CheckQueryName, list[_AcceptedSample]] = {
        query_name: [] for query_name in CHECK_QUERY_NAMES
    }
    check_diagnostics: dict[str, set[str]] = defaultdict(set)
    for query_name in CHECK_QUERY_NAMES:
        for sample in samples_by_query.get(query_name, ()):
            item = _accept_sample(query_name, sample, check_diagnostics)
            if item is not None:
                accepted[query_name].append(item)

    primary_keys = {
        item.key for query_name in _PRIMARY_CHECK_QUERIES for item in accepted[query_name]
    }
    current_check_ids = {key.check_id for key in primary_keys}
    raw_info_samples = samples_by_query.get("check_info", ())
    info_is_authoritative = bool(raw_info_samples) and len(accepted["check_info"]) == len(
        raw_info_samples
    )
    info_is_authoritative = info_is_authoritative and all(
        math.isfinite(item.sample.value) and item.sample.value == 1.0
        for item in accepted["check_info"]
    )
    valid_info_keys = (
        {item.key for item in accepted["check_info"]} if info_is_authoritative else set()
    )
    # Only a wholly valid info response can be treated as an authoritative inventory. Invalid
    # or rejected samples are still normalized where possible so operators see `invalid_data`,
    # but they must not make previous results disappear and accidentally improve a Check.
    info_is_present = info_is_authoritative
    previous_by_id = {check.check_id: check for check in previous.checks} if previous else {}
    previous_results_by_key = (
        {result.key: result for check in previous.checks for result in check.results}
        if previous
        else {}
    )

    by_query_key: dict[CheckQueryName, dict[CheckResultKey, list[_AcceptedSample]]] = {
        query_name: defaultdict(list) for query_name in CHECK_QUERY_NAMES
    }
    names: dict[str, set[str]] = defaultdict(set)
    groups: dict[str, set[str]] = defaultdict(set)
    targets: dict[CheckResultKey, set[str]] = defaultdict(set)
    for query_name, items in accepted.items():
        for item in items:
            by_query_key[query_name][item.key].append(item)
            if item.name is not None:
                names[item.key.check_id].add(item.name)
            if item.group is not None:
                groups[item.key.check_id].add(item.group)
            if item.target is not None:
                targets[item.key].add(item.target)

    normalized_results: dict[CheckResultKey, NormalizedCheckResult] = {}
    for key in sorted(primary_keys):
        result_diagnostics: set[str] = set()
        success, status_diagnostics = _binary_value(
            by_query_key["check_status"].get(key, ()),
            missing_code="missing_status",
            invalid_code="invalid_status",
            conflict_code="conflicting_status",
        )
        result_diagnostics.update(status_diagnostics)
        last_run_at, timestamp_diagnostics = _last_run_value(
            by_query_key["check_last_run"].get(key, ()),
            evaluated_at=evaluated_at,
            future_tolerance_seconds=future_tolerance_seconds,
        )
        result_diagnostics.update(timestamp_diagnostics)
        duration, duration_diagnostics = _non_negative_value(
            by_query_key["check_duration"].get(key, ()), label="duration"
        )
        result_diagnostics.update(duration_diagnostics)
        ttfb, ttfb_diagnostics = _non_negative_value(
            by_query_key["check_ttfb"].get(key, ()), label="ttfb"
        )
        result_diagnostics.update(ttfb_diagnostics)
        target, target_diagnostics = _metadata_value(
            targets[key], conflict_code="conflicting_target"
        )
        result_diagnostics.update(target_diagnostics)

        info_samples = by_query_key["check_info"].get(key, ())
        if info_samples and any(
            not math.isfinite(item.sample.value) or item.sample.value != 1.0
            for item in info_samples
        ):
            result_diagnostics.add("invalid_info")

        canary_groups: dict[str, list[_AcceptedSample]] = defaultdict(list)
        for item in by_query_key["check_canary_success"].get(key, ()):
            assert item.canary is not None
            canary_groups[item.canary].append(item)
        if len(canary_groups) > MAX_CANARIES_PER_RESULT:
            raise ChecksDataError("checks_limit_exceeded")
        canaries: list[CheckCanary] = []
        for canary, canary_samples in sorted(canary_groups.items()):
            canary_success, canary_diagnostics = _binary_value(
                canary_samples,
                missing_code=None,
                invalid_code="invalid_canary",
                conflict_code="conflicting_canary",
            )
            result_diagnostics.update(canary_diagnostics)
            canaries.append(
                CheckCanary(
                    canary=canary,
                    success=canary_success,
                    status_reason="invalid_data" if canary_success is None else None,
                )
            )

        assertions: list[CheckAssertion] = []
        assertion_samples = by_query_key["check_egress_match"].get(key, ())
        if assertion_samples:
            assertion_success, assertion_diagnostics = _binary_value(
                assertion_samples,
                missing_code=None,
                invalid_code="invalid_assertion",
                conflict_code="conflicting_assertion",
            )
            result_diagnostics.update(assertion_diagnostics)
            assertions.append(
                CheckAssertion(
                    key="egress_match",
                    success=assertion_success,
                    status_reason="invalid_data" if assertion_success is None else None,
                )
            )

        previously_declared = previous_results_by_key.get(key)
        normalized_results[key] = NormalizedCheckResult(
            key=key,
            target=target,
            success=success,
            last_run_at=last_run_at,
            duration_seconds=duration,
            ttfb_seconds=ttfb,
            canaries=tuple(canaries),
            assertions=tuple(assertions),
            diagnostics=tuple(sorted(result_diagnostics)),
            known_via_info=(
                key in valid_info_keys
                or (
                    not info_is_present
                    and previously_declared is not None
                    and previously_declared.known_via_info
                )
            ),
        )

    if previous is not None:
        retained_missing_count = 0
        for previous_check in previous.checks:
            for previous_result in previous_check.results:
                if previous_result.key in normalized_results:
                    continue
                # A complete current info family may remove only tuples that were themselves
                # declared by info. Status-only executors can coexist with info publishers; an
                # unrelated info series must not silently erase their remembered inventory.
                if info_is_present and previous_result.known_via_info:
                    continue
                retained_missing_count += 1
                if sample_count + retained_missing_count > max_series:
                    raise ChecksDataError("checks_limit_exceeded")
                normalized_results[previous_result.key] = NormalizedCheckResult(
                    key=previous_result.key,
                    target=previous_result.target,
                    success=None,
                    last_run_at=previous_result.last_run_at,
                    diagnostics=tuple(
                        sorted({*previous_result.diagnostics, "missing_current_result"})
                    ),
                    known_via_info=previous_result.known_via_info,
                )
        if len(normalized_results) > max_series:
            raise ChecksDataError("checks_limit_exceeded")

    results_by_check: dict[str, list[NormalizedCheckResult]] = defaultdict(list)
    for key, result in normalized_results.items():
        results_by_check[key.check_id].append(result)

    normalized_checks: list[NormalizedCheck] = []
    for check_id, results in sorted(results_by_check.items()):
        if len(results) > MAX_RESULTS_PER_CHECK:
            raise ChecksDataError("checks_limit_exceeded")
        diagnostics = check_diagnostics[check_id]
        name_values = names[check_id]
        if len(name_values) > 1:
            name = check_id
            diagnostics.add("conflicting_name")
        elif name_values:
            name = next(iter(name_values))
        elif check_id not in current_check_ids and check_id in previous_by_id:
            name = previous_by_id[check_id].name
        else:
            name = check_id

        group_values = groups[check_id]
        if len(group_values) > 1:
            group = None
            diagnostics.add("conflicting_group")
        elif group_values:
            group = next(iter(group_values))
        elif check_id not in current_check_ids and check_id in previous_by_id:
            group = previous_by_id[check_id].group
        else:
            group = None
        normalized_checks.append(
            NormalizedCheck(
                check_id=check_id,
                name=name,
                group=group,
                results=tuple(sorted(results, key=lambda item: item.key)),
                diagnostics=tuple(sorted(diagnostics)),
            )
        )
    return tuple(normalized_checks)


async def refresh_checks_snapshot(
    targets: list[DatasourceQueryTarget],
    client: PrometheusClient,
    settings: Settings,
    *,
    preparation_failures: Sequence[DatasourceQueryFailure] = (),
    previous: ChecksSnapshot | None = None,
    evaluated_at: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ChecksSnapshot:
    """Fetch every fixed Checks metric at one evaluation time and build a raw snapshot."""

    utc_clock = clock or (lambda: datetime.now(UTC))
    query_time = (evaluated_at or utc_clock()).astimezone(UTC)
    if preparation_failures:
        raise ChecksDataError("prometheus_unavailable")

    samples_by_query: dict[CheckQueryName, list[VectorSample]] = {
        query_name: [] for query_name in CHECK_QUERY_NAMES
    }
    failures_by_query: dict[CheckQueryName, list[DatasourceQueryFailure]] = {
        query_name: [] for query_name in CHECK_QUERY_NAMES
    }
    if targets:
        try:
            query_results = await asyncio.gather(
                *(
                    query_datasource_targets(
                        targets,
                        client,
                        query_name,
                        evaluated_at=query_time,
                        allow_non_finite_values=True,
                    )
                    for query_name in CHECK_QUERY_NAMES
                )
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise ChecksDataError("prometheus_unavailable") from exc
        for query_name, (successes, failures) in zip(CHECK_QUERY_NAMES, query_results, strict=True):
            samples_by_query[query_name].extend(
                sample for result in successes for sample in result.samples
            )
            failures_by_query[query_name].extend(failures)

    all_failures = [failure for failures in failures_by_query.values() for failure in failures]
    if any(failure.code in _LIMIT_FAILURE_CODES for failure in all_failures):
        raise ChecksDataError("checks_limit_exceeded")
    if any(failures_by_query[name] for name in MANDATORY_CHECK_QUERIES):
        raise ChecksDataError("prometheus_unavailable")
    if sum(len(samples) for samples in samples_by_query.values()) > settings.checks_max_series:
        raise ChecksDataError("checks_limit_exceeded")

    warning_codes = tuple(
        sorted(
            {
                warning
                for query_name, warning in _OPTIONAL_WARNING_CODES.items()
                if failures_by_query[query_name]
            }
        )
    )
    for query_name in _OPTIONAL_WARNING_CODES:
        if failures_by_query[query_name]:
            # A capability is either based on one complete query set or unavailable. Returning
            # values from only the datasources that happened to answer would make missing
            # optional results look authoritative.
            samples_by_query[query_name] = []
    checks = normalize_check_metrics(
        samples_by_query,
        evaluated_at=query_time,
        future_tolerance_seconds=settings.checks_future_tolerance_seconds,
        max_series=settings.checks_max_series,
        previous=previous,
    )
    fetched_at = utc_clock().astimezone(UTC)
    return ChecksSnapshot(
        snapshot_id=str(uuid4()),
        fetched_at=fetched_at,
        evaluated_at=query_time,
        cache_expires_at=fetched_at + timedelta(seconds=settings.checks_cache_ttl_seconds),
        checks=checks,
        warning_codes=warning_codes,
    )


class ChecksSnapshotCache:
    """Short process-local cache with a shared in-flight refresh task."""

    def __init__(
        self,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
        utc_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._monotonic_clock = monotonic_clock
        self._utc_clock = utc_clock or (lambda: datetime.now(UTC))
        self._lock = asyncio.Lock()
        self._snapshot: ChecksSnapshot | None = None
        self._expires_monotonic = 0.0
        self._refresh_task: asyncio.Task[ChecksSnapshot] | None = None

    def peek(self) -> ChecksSnapshot | None:
        return self._snapshot

    async def get_or_refresh(
        self,
        targets: list[DatasourceQueryTarget],
        client: PrometheusClient,
        settings: Settings,
        *,
        preparation_failures: Sequence[DatasourceQueryFailure] = (),
    ) -> ChecksSnapshot:
        if self._snapshot is not None and self._monotonic_clock() < self._expires_monotonic:
            return self._snapshot

        async with self._lock:
            if self._snapshot is not None and self._monotonic_clock() < self._expires_monotonic:
                return self._snapshot
            task = self._refresh_task
            if task is None or (task.done() and task.cancelled()):
                task = asyncio.create_task(
                    refresh_checks_snapshot(
                        targets,
                        client,
                        settings,
                        preparation_failures=preparation_failures,
                        previous=self._snapshot,
                        clock=self._utc_clock,
                    ),
                    name="checks-snapshot-refresh",
                )
                self._refresh_task = task

        try:
            snapshot = await asyncio.shield(task)
            self._snapshot = snapshot
            self._expires_monotonic = self._monotonic_clock() + settings.checks_cache_ttl_seconds
            return snapshot
        finally:
            if task.done():
                async with self._lock:
                    if self._refresh_task is task:
                        self._refresh_task = None


def evaluate_checks_snapshot(
    snapshot: ChecksSnapshot,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> tuple[AggregatedCheck, ...]:
    """Recompute freshness on every response, including cache hits."""

    evaluated_now = (now or datetime.now(UTC)).astimezone(UTC)
    return tuple(
        aggregate_check(
            check.check_id,
            check.name,
            check.group,
            check.results,
            now=evaluated_now,
            stale_after_seconds=settings.checks_stale_after_seconds,
            min_failure_sources=settings.checks_min_failure_sources,
            diagnostics=check.diagnostics,
        )
        for check in snapshot.checks
    )


def filter_checks(
    checks: Sequence[AggregatedCheck],
    filters: CheckFilters,
) -> tuple[AggregatedCheck, ...]:
    search = filters.search.strip().casefold() if filters.search else None

    def included(check: AggregatedCheck) -> bool:
        if filters.status is not None and check.status != filters.status:
            return False
        if filters.group is not None and check.group != filters.group:
            return False
        if filters.source is not None and not any(
            result.key.source == filters.source for result in check.results
        ):
            return False
        if filters.target is not None and not any(
            result.target == filters.target for result in check.results
        ):
            return False
        if filters.scenario is not None and not any(
            result.key.scenario == filters.scenario for result in check.results
        ):
            return False
        return search is None or any(
            search in value.casefold()
            for value in (
                check.check_id,
                check.name,
                *(result.target for result in check.results if result.target is not None),
            )
        )

    return tuple(
        sorted(
            (check for check in checks if included(check)),
            key=lambda check: (
                check.group is None,
                (check.group or "").casefold(),
                check.name.casefold(),
                check.check_id,
            ),
        )
    )


def summarize_checks(checks: Sequence[AggregatedCheck]) -> ChecksSummary:
    counts = {status: 0 for status in ("up", "degraded", "down", "stale", "unknown")}
    for check in checks:
        counts[check.status] += 1
    return ChecksSummary(
        total=len(checks),
        up=counts["up"],
        degraded=counts["degraded"],
        down=counts["down"],
        stale=counts["stale"],
        unknown=counts["unknown"],
    )


def problem_checks(
    checks: Sequence[AggregatedCheck],
    *,
    limit: int = 5,
) -> tuple[AggregatedCheck, ...]:
    if limit < 0:
        raise ValueError("limit cannot be negative")
    priority = {"down": 0, "degraded": 1, "unknown": 2, "stale": 3}
    return tuple(
        sorted(
            (check for check in checks if check.status != "up"),
            key=lambda check: (
                priority[check.status],
                check.group is None,
                (check.group or "").casefold(),
                check.name.casefold(),
                check.check_id,
            ),
        )[:limit]
    )


def build_check_grafana_url(base_url: str | None, check_id: str) -> str | None:
    """Add one encoded, server-owned dashboard variable without changing URL authority/path."""

    safe_check_id = normalize_check_identifier(check_id)
    if base_url is None or safe_check_id is None:
        return None
    try:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        query = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key != "var-check_id"
        ]
        query.append(("var-check_id", safe_check_id))
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
        )
    except ValueError:
        return None
