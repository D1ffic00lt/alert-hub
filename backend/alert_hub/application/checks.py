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
from typing import cast
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
    CheckAssertionState,
    CheckCanary,
    CheckErrorReason,
    CheckResultKey,
    CheckResultState,
    CheckStatus,
    CheckTarget,
    NormalizedCheckResult,
    aggregate_check,
)
from alert_hub.domain.monitoring import is_grafana_dashboard_url
from alert_hub.infrastructure.prometheus import CheckQueryName, PrometheusClient, VectorSample
from alert_hub.settings import Settings

CHECK_QUERY_NAMES: tuple[CheckQueryName, ...] = (
    "check_info",
    "check_state",
    "check_status",
    "check_last_run",
    "check_canary_success",
    "check_target_success",
    "check_target_state",
    "check_duration",
    "check_ttfb",
    "check_egress_state",
    "check_egress_match",
    "check_errors_total",
)
MANDATORY_CHECK_QUERIES: frozenset[CheckQueryName] = frozenset({"check_status", "check_last_run"})
MAX_RESULTS_PER_CHECK = 1_000
MAX_CANARIES_PER_RESULT = 100
MAX_TARGETS_PER_RESULT = 100
MAX_ASSERTIONS_PER_RESULT = 100
MAX_CONCURRENT_CHECK_REQUESTS = 16

_PRIMARY_CHECK_QUERIES: frozenset[CheckQueryName] = frozenset(
    {"check_info", "check_state", "check_status", "check_last_run"}
)
_LIMIT_FAILURE_CODES = frozenset({"too_many_samples", "response_too_large"})
_OPTIONAL_WARNING_CODES: dict[CheckQueryName, str] = {
    "check_info": "check_info_unavailable",
    "check_state": "check_state_unavailable",
    "check_canary_success": "check_canary_unavailable",
    "check_target_success": "check_targets_unavailable",
    "check_target_state": "check_target_states_unavailable",
    "check_duration": "check_duration_unavailable",
    "check_ttfb": "check_ttfb_unavailable",
    "check_egress_state": "check_assertion_states_unavailable",
    "check_egress_match": "check_assertions_unavailable",
    "check_errors_total": "check_error_reasons_unavailable",
}
_CHECK_STATES = frozenset({"unknown", "success", "failure", "error", "stale", "disabled"})
_EGRESS_STATES = frozenset({"match", "mismatch", "unknown", "error", "stale", "disabled"})
_SAFE_ERROR_REASONS = frozenset(
    {
        "connect",
        "proxy",
        "dns",
        "timeout",
        "tls",
        "http_status",
        "body_mismatch",
        "egress_mismatch",
        "response_invalid",
        "config_invalid",
        "unsupported",
        "runtime_start",
        "runtime_exit",
        "scheduler",
        "source_fetch",
        "source_parse",
        "identity_conflict",
        "internal",
    }
)
_DEFAULT_ASSERTION = "__alert_hub_default_assertion__"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}")
_RESERVED_IDENTIFIER_PREFIX = "__alert_hub_"
_RESERVED_IDENTIFIERS = frozenset({"summary"})
_UUID_CANDIDATE = re.compile(
    r"(?i)(?<![A-Za-z0-9])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}(?![A-Za-z0-9])"
)
_DISPLAY_LENGTH_LIMIT = 255
_ASCII_DIGITS = frozenset("0123456789")
_IPV6_RUN_CHARACTERS = frozenset("0123456789abcdefABCDEF:")
_SENSITIVE_ASSIGNMENT_NAMES = ("token", "password", "secret", "apikey", "api_key", "api-key")
_IGNORE_CASE_TRANSLATION = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZİıſK",
    "abcdefghijklmnopqrstuvwxyziisk",
)


def _contains_sensitive_display(value: str) -> bool:
    """Detect credential-shaped display text with bounded linear scans."""

    folded = value.translate(_IGNORE_CASE_TRANSLATION)
    if "://" in folded:
        return True

    marker_at = folded.find("bearer")
    while marker_at >= 0:
        cursor = marker_at + len("bearer")
        if cursor < len(value) and value[cursor].isspace():
            while cursor < len(value) and value[cursor].isspace():
                cursor += 1
            if cursor < len(value):
                return True
        marker_at = folded.find("bearer", marker_at + 1)

    for name in _SENSITIVE_ASSIGNMENT_NAMES:
        marker_at = folded.find(name)
        while marker_at >= 0:
            cursor = marker_at + len(name)
            while cursor < len(value) and value[cursor].isspace():
                cursor += 1
            if cursor < len(value) and value[cursor] in {":", "="}:
                return True
            marker_at = folded.find(name, marker_at + 1)
    return False


def _is_ascii_alphanumeric(character: str) -> bool:
    return character.isascii() and character.isalnum()


def _contains_ipv4_address(value: str) -> bool:
    for start, character in enumerate(value):
        if character not in _ASCII_DIGITS:
            continue
        if start > 0 and _is_ascii_alphanumeric(value[start - 1]):
            continue

        cursor = start
        octets: list[str] = []
        for octet_index in range(4):
            octet_start = cursor
            while cursor < len(value) and value[cursor] in _ASCII_DIGITS:
                cursor += 1
            octet = value[octet_start:cursor]
            if not 1 <= len(octet) <= 3:
                break
            octets.append(octet)
            if octet_index < 3:
                if cursor >= len(value) or value[cursor] != ".":
                    break
                cursor += 1
        if len(octets) != 4:
            continue
        if cursor < len(value) and _is_ascii_alphanumeric(value[cursor]):
            continue
        try:
            ipaddress.IPv4Address(".".join(octets))
        except ipaddress.AddressValueError:
            continue
        return True
    return False


def _contains_ipv6_address(value: str) -> bool:
    for bracket_start, character in enumerate(value):
        if character != "[":
            continue
        bracket_end = value.find("]", bracket_start + 1)
        if bracket_end < 0:
            continue
        candidate = value[bracket_start + 1 : bracket_end].split("%", 1)[0]
        try:
            ipaddress.IPv6Address(candidate)
        except ipaddress.AddressValueError:
            continue
        return True

    cursor = 0
    while cursor < len(value):
        if value[cursor] not in _IPV6_RUN_CHARACTERS:
            cursor += 1
            continue
        run_start = cursor
        while cursor < len(value) and value[cursor] in _IPV6_RUN_CHARACTERS:
            cursor += 1
        run_end = cursor
        if cursor < len(value) and _is_ascii_alphanumeric(value[cursor]):
            continue

        for candidate_start in range(run_start, run_end):
            if candidate_start > 0 and _is_ascii_alphanumeric(value[candidate_start - 1]):
                continue
            candidate = value[candidate_start:run_end]
            if candidate.count(":") < 2:
                break
            try:
                ipaddress.IPv6Address(candidate)
            except ipaddress.AddressValueError:
                pass
            else:
                return True
            # This is the first maximal candidate the former regex would consume;
            # do not reinterpret one of its internal fields as a separate address.
            break
    return False


def _contains_ip_address(value: str) -> bool:
    return _contains_ipv4_address(value) or _contains_ipv6_address(value)


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
    logical_source: str
    name: str | None
    name_priority: int | None
    derived_name: str | None
    group: str | None
    target: str | None
    canary: str | None
    target_id: str | None
    assertion_id: str | None
    state: str | None
    reason: str | None
    info_conflict: bool = False
    scenario_info_hint_applied: bool = False
    variant_info_hint_applied: bool = False
    key_dimensions_defaulted: bool = False


@dataclass(frozen=True, slots=True)
class _InfoHint:
    scenario: str | None
    variant: str | None
    target: str | None
    logical_source: str | None
    scenario_conflict: bool = False
    variant_conflict: bool = False
    target_conflict: bool = False
    logical_source_conflict: bool = False


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
    if max_length < 1 or len(value) > min(max_length, _DISPLAY_LENGTH_LIMIT):
        return None
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        return None
    candidate = " ".join(value.strip().split())
    if not candidate or _contains_sensitive_display(candidate) or _contains_ip_address(candidate):
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


def _priority_identifier(
    labels: Mapping[str, str],
    names: Sequence[str],
    default: str,
) -> tuple[str | None, bool]:
    """Choose the first declared safe identifier without silently skipping an invalid label."""

    for name in names:
        raw = labels.get(name)
        if raw is None or raw == "":
            continue
        return normalize_check_identifier(raw, allow_reserved_routes=True), False
    return default, True


def _humanize_identifier(value: str) -> str:
    """Turn a validated opaque identifier into display text without inventing metadata."""

    words = " ".join(part for part in re.split(r"[_.:\-]+", value) if part)
    return words[:1].upper() + words[1:] if words else value


def _derived_info_name(labels: Mapping[str, str]) -> str | None:
    parts: list[str] = []
    for label in ("mode", "source_id", "target_set_id"):
        identifier, missing = _optional_identifier(labels, label, DEFAULT_VARIANT)
        if not missing and identifier is not None:
            parts.append(_humanize_identifier(identifier))
    candidate = " · ".join(parts)
    return _safe_display(candidate, max_length=255) if candidate else None


def _build_info_hints(samples: Sequence[VectorSample]) -> dict[tuple[str, str], _InfoHint]:
    values: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(
        lambda: {"scenario": set(), "variant": set(), "target": set(), "logical_source": set()}
    )
    for sample in samples:
        check_id = normalize_check_identifier(sample.labels.get("check_id"))
        instance, _ = _priority_identifier(
            sample.labels,
            ("instance_id", "source", "source_id"),
            DEFAULT_SOURCE,
        )
        if check_id is None or instance is None:
            continue
        logical_source, _ = _priority_identifier(
            sample.labels,
            ("source", "source_id"),
            instance,
        )
        if logical_source is not None:
            values[(check_id, instance)]["logical_source"].add(logical_source)
        scenario, scenario_missing = _priority_identifier(
            sample.labels,
            ("scenario", "mode"),
            DEFAULT_SCENARIO,
        )
        variant, variant_missing = _priority_identifier(
            sample.labels,
            ("variant", "target_set_id"),
            DEFAULT_VARIANT,
        )
        if not scenario_missing and scenario is not None:
            values[(check_id, instance)]["scenario"].add(scenario)
        if not variant_missing and variant is not None:
            values[(check_id, instance)]["variant"].add(variant)

        raw_target = sample.labels.get("target")
        explicit_target = _safe_display(raw_target, max_length=255)
        if raw_target and explicit_target is not None:
            values[(check_id, instance)]["target"].add(explicit_target)

    hints: dict[tuple[str, str], _InfoHint] = {}
    for key, fields in values.items():
        hints[key] = _InfoHint(
            scenario=next(iter(fields["scenario"])) if len(fields["scenario"]) == 1 else None,
            variant=next(iter(fields["variant"])) if len(fields["variant"]) == 1 else None,
            target=next(iter(fields["target"])) if len(fields["target"]) == 1 else None,
            logical_source=(
                next(iter(fields["logical_source"])) if len(fields["logical_source"]) == 1 else None
            ),
            scenario_conflict=len(fields["scenario"]) > 1,
            variant_conflict=len(fields["variant"]) > 1,
            target_conflict=len(fields["target"]) > 1,
            logical_source_conflict=len(fields["logical_source"]) > 1,
        )
    return hints


def _build_previous_info_hints(previous: ChecksSnapshot) -> dict[tuple[str, str], _InfoHint]:
    """Recover only unambiguous dimensions that a prior authoritative info row established."""

    values: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(
        lambda: {"scenario": set(), "variant": set(), "target": set(), "logical_source": set()}
    )
    for check in previous.checks:
        for result in check.results:
            if not result.known_via_info:
                continue
            base_key = (result.key.check_id, result.key.source)
            values[base_key]["scenario"].add(result.key.scenario)
            values[base_key]["variant"].add(result.key.variant)
            values[base_key]["logical_source"].add(result.logical_source or result.key.source)
            if result.target is not None:
                values[base_key]["target"].add(result.target)

    hints: dict[tuple[str, str], _InfoHint] = {}
    for key, fields in values.items():
        hints[key] = _InfoHint(
            scenario=next(iter(fields["scenario"])) if len(fields["scenario"]) == 1 else None,
            variant=next(iter(fields["variant"])) if len(fields["variant"]) == 1 else None,
            target=next(iter(fields["target"])) if len(fields["target"]) == 1 else None,
            logical_source=(
                next(iter(fields["logical_source"])) if len(fields["logical_source"]) == 1 else None
            ),
            scenario_conflict=len(fields["scenario"]) > 1,
            variant_conflict=len(fields["variant"]) > 1,
            target_conflict=len(fields["target"]) > 1,
            logical_source_conflict=len(fields["logical_source"]) > 1,
        )
    return hints


def _matches_proven_info_rekey(
    previous_result: NormalizedCheckResult,
    declared_keys: set[CheckResultKey],
    hinted_dimensions_by_key: Mapping[CheckResultKey, set[str]],
) -> bool:
    """Identify a proven missing-info key superseded by one authoritative declaration."""

    previous_key = previous_result.key
    if (
        not previous_result.provisional_info_dimensions
        or len(declared_keys) != 1
        or (previous_key.scenario != DEFAULT_SCENARIO and previous_key.variant != DEFAULT_VARIANT)
    ):
        return False
    declared = next(iter(declared_keys))
    hinted_dimensions = hinted_dimensions_by_key.get(declared, set())
    required_hints = {
        dimension
        for dimension, previous_value, declared_value in (
            ("scenario", previous_key.scenario, declared.scenario),
            ("variant", previous_key.variant, declared.variant),
        )
        if previous_value != declared_value
    }
    return (
        bool(required_hints)
        and required_hints <= hinted_dimensions
        and previous_key.scenario
        in {
            DEFAULT_SCENARIO,
            declared.scenario,
        }
        and previous_key.variant in {DEFAULT_VARIANT, declared.variant}
    )


def _accept_sample(
    query_name: CheckQueryName,
    sample: VectorSample,
    diagnostics: dict[str, set[str]],
    info_hints: Mapping[tuple[str, str], _InfoHint],
) -> _AcceptedSample | None:
    raw_check_id = sample.labels.get("check_id")
    check_id = normalize_check_identifier(raw_check_id)
    if check_id is None:
        return None

    source, _ = _priority_identifier(
        sample.labels,
        ("instance_id", "source", "source_id"),
        DEFAULT_SOURCE,
    )
    if source is None:
        diagnostics[check_id].add(
            "invalid_identifier"
            if query_name in _PRIMARY_CHECK_QUERIES
            else "invalid_optional_identifier"
        )
        return None

    hint = info_hints.get((check_id, source))
    logical_source, logical_source_missing = _priority_identifier(
        sample.labels,
        ("source", "source_id"),
        source,
    )
    if logical_source_missing and hint is not None and hint.logical_source is not None:
        logical_source = hint.logical_source
    if logical_source is None:
        diagnostics[check_id].add(
            "invalid_identifier"
            if query_name in _PRIMARY_CHECK_QUERIES
            else "invalid_optional_identifier"
        )
        return None
    scenario, scenario_missing = _priority_identifier(
        sample.labels,
        ("scenario", "mode"),
        DEFAULT_SCENARIO,
    )
    variant, variant_missing = _priority_identifier(
        sample.labels,
        ("variant", "target_set_id"),
        DEFAULT_VARIANT,
    )
    info_conflict = False
    if hint is not None:
        info_conflict = hint.logical_source_conflict
    scenario_info_hint_applied = False
    variant_info_hint_applied = False
    key_dimensions_defaulted = False
    if scenario_missing and hint is not None:
        if hint.scenario is not None:
            scenario = hint.scenario
            scenario_info_hint_applied = True
        info_conflict = info_conflict or hint.scenario_conflict
    if scenario_missing and (hint is None or hint.scenario is None):
        key_dimensions_defaulted = True
    if variant_missing and hint is not None:
        if hint.variant is not None:
            variant = hint.variant
            variant_info_hint_applied = True
        info_conflict = info_conflict or hint.variant_conflict
    if variant_missing and (hint is None or hint.variant is None):
        key_dimensions_defaulted = True
    if source is None or scenario is None or variant is None:
        diagnostics[check_id].add(
            "invalid_identifier"
            if query_name in _PRIMARY_CHECK_QUERIES
            else "invalid_optional_identifier"
        )
        return None

    raw_check_name = sample.labels.get("check_name")
    raw_entry_name = sample.labels.get("entry_name") if query_name == "check_info" else None
    check_name = _safe_display(raw_check_name, max_length=255)
    entry_name = _safe_display(raw_entry_name, max_length=255)
    if raw_check_name and raw_check_name.strip() and check_name is None:
        diagnostics[check_id].add("invalid_name")
    if raw_entry_name and raw_entry_name.strip() and entry_name is None:
        diagnostics[check_id].add("invalid_name")
    if check_name is not None:
        name = check_name
        name_priority = 0
    elif entry_name is not None:
        name = entry_name
        name_priority = 1
    else:
        name = None
        name_priority = None
    group = _safe_display(sample.labels.get("group"), max_length=128)
    if sample.labels.get("group", "").strip() and group is None:
        diagnostics[check_id].add("invalid_group")
    raw_target = sample.labels.get("target")
    target = _safe_display(raw_target, max_length=255)
    if raw_target and raw_target.strip() and target is None:
        diagnostics[check_id].add("invalid_target")
    if not raw_target and target is None and hint is not None:
        target = hint.target
        info_conflict = info_conflict or hint.target_conflict

    canary: str | None = None
    if query_name == "check_canary_success":
        parsed_canary, _ = _optional_identifier(sample.labels, "canary", DEFAULT_CANARY)
        if parsed_canary is None:
            diagnostics[check_id].add("invalid_canary")
            return None
        canary = parsed_canary

    target_id: str | None = None
    if query_name in {
        "check_target_success",
        "check_target_state",
        "check_duration",
        "check_ttfb",
    }:
        raw_target_id = sample.labels.get("target_id")
        if raw_target_id:
            target_id = normalize_check_identifier(raw_target_id, allow_reserved_routes=True)
            if target_id is None:
                diagnostics[check_id].add("invalid_target_id")
                return None
        elif query_name in {"check_target_success", "check_target_state"}:
            diagnostics[check_id].add("invalid_target_id")
            return None

    assertion_id: str | None = None
    if query_name in {"check_egress_state", "check_egress_match"}:
        parsed_assertion_id, assertion_missing = _optional_identifier(
            sample.labels, "assertion_id", _DEFAULT_ASSERTION
        )
        if parsed_assertion_id is None:
            diagnostics[check_id].add("invalid_assertion_id")
            return None
        assertion_id = None if assertion_missing else parsed_assertion_id

    state = (
        sample.labels.get("state")
        if query_name in {"check_state", "check_target_state", "check_egress_state"}
        else None
    )
    reason = sample.labels.get("reason") if query_name == "check_errors_total" else None

    return _AcceptedSample(
        sample=sample,
        key=CheckResultKey(check_id, source, scenario, variant),
        logical_source=logical_source,
        name=name,
        name_priority=name_priority,
        derived_name=_derived_info_name(sample.labels) if query_name == "check_info" else None,
        group=group,
        target=target,
        canary=canary,
        target_id=target_id,
        assertion_id=assertion_id,
        state=state,
        reason=reason,
        info_conflict=info_conflict,
        scenario_info_hint_applied=scenario_info_hint_applied,
        variant_info_hint_applied=variant_info_hint_applied,
        key_dimensions_defaulted=key_dimensions_defaulted,
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


def _one_hot_state(
    samples: Sequence[_AcceptedSample],
    *,
    allowed: frozenset[str],
    invalid_code: str,
    conflict_code: str,
) -> tuple[str | None, set[str]]:
    if not samples:
        return None, set()
    values_by_state: dict[str, set[bool]] = defaultdict(set)
    invalid = False
    for item in samples:
        if item.state not in allowed:
            invalid = True
            continue
        value = item.sample.value
        if not math.isfinite(value) or value not in {0.0, 1.0}:
            invalid = True
            continue
        values_by_state[item.state].add(bool(value))
    if invalid:
        return None, {invalid_code}
    if any(len(values) != 1 for values in values_by_state.values()):
        return None, {conflict_code}
    active = sorted(state for state, values in values_by_state.items() if True in values)
    if len(active) != 1:
        return None, {invalid_code if not active else conflict_code}
    return active[0], set()


def _reconcile_success(
    binary_samples: Sequence[_AcceptedSample],
    state_samples: Sequence[_AcceptedSample],
    *,
    allowed_states: frozenset[str],
    success_state: str,
    failure_state: str,
    missing_code: str | None,
    invalid_binary_code: str,
    conflicting_binary_code: str,
    invalid_state_code: str,
    conflicting_state_code: str,
    conflicting_pair_code: str,
    require_binary_for_result_states: bool = False,
) -> tuple[bool | None, str | None, set[str]]:
    binary, diagnostics = _binary_value(
        binary_samples,
        missing_code=None,
        invalid_code=invalid_binary_code,
        conflict_code=conflicting_binary_code,
    )
    state, state_diagnostics = _one_hot_state(
        state_samples,
        allowed=allowed_states,
        invalid_code=invalid_state_code,
        conflict_code=conflicting_state_code,
    )
    diagnostics.update(state_diagnostics)
    if state_diagnostics:
        return None, None, diagnostics

    state_success: bool | None = None
    if state == success_state:
        state_success = True
    elif state == failure_state:
        state_success = False

    if state is not None:
        if binary is not None and (state_success is None or binary != state_success):
            diagnostics.add(conflicting_pair_code)
            return None, state, diagnostics
        if (
            binary is None
            and not diagnostics
            and require_binary_for_result_states
            and state_success is not None
        ):
            if missing_code is not None:
                diagnostics.add(missing_code)
        elif binary is None and not diagnostics:
            binary = state_success
    elif binary is None and not diagnostics and missing_code is not None:
        diagnostics.add(missing_code)
    elif state is None and binary is not None:
        state = success_state if binary else failure_state
    return binary, state, diagnostics


def _nested_status_reason(
    state: str | None,
    success: bool | None,
    diagnostics: set[str],
) -> str | None:
    if diagnostics:
        return "invalid_data"
    if state in {"error", "stale", "disabled", "unknown"}:
        return f"executor_{state}"
    if success is None:
        return "incomplete_data"
    return None


def _counter_value(
    samples: Sequence[_AcceptedSample],
) -> tuple[int | None, set[str]]:
    if not samples:
        return None, set()
    if any(
        not math.isfinite(item.sample.value)
        or item.sample.value < 0
        or not item.sample.value.is_integer()
        or item.sample.value > 9_007_199_254_740_991
        for item in samples
    ):
        return None, {"invalid_error_count"}
    valid_values = {item.sample.value for item in samples}
    if len(valid_values) != 1:
        return None, {"conflicting_error_count"}
    return int(next(iter(valid_values))), set()


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
    reuse_previous_info_dimensions: bool = False,
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
    raw_info_samples = samples_by_query.get("check_info", ())
    info_hints = _build_info_hints(raw_info_samples)
    reuse_previous_info_metadata = (
        reuse_previous_info_dimensions and previous is not None and not raw_info_samples
    )
    if reuse_previous_info_metadata:
        assert previous is not None
        info_hints = _build_previous_info_hints(previous)
    for query_name in CHECK_QUERY_NAMES:
        for sample in samples_by_query.get(query_name, ()):
            item = _accept_sample(query_name, sample, check_diagnostics, info_hints)
            if item is not None:
                accepted[query_name].append(item)

    primary_keys = {
        item.key for query_name in _PRIMARY_CHECK_QUERIES for item in accepted[query_name]
    }
    current_check_ids = {key.check_id for key in primary_keys}
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
    valid_info_keys_by_base: dict[tuple[str, str], set[CheckResultKey]] = defaultdict(set)
    for key in valid_info_keys:
        valid_info_keys_by_base[(key.check_id, key.source)].add(key)
    info_hinted_operational_dimensions: dict[CheckResultKey, set[str]] = defaultdict(set)
    for query_name in ("check_state", "check_status", "check_last_run"):
        for item in accepted[query_name]:
            if item.scenario_info_hint_applied:
                info_hinted_operational_dimensions[item.key].add("scenario")
            if item.variant_info_hint_applied:
                info_hinted_operational_dimensions[item.key].add("variant")
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
    names: dict[str, dict[int, set[str]]] = defaultdict(lambda: defaultdict(set))
    derived_names: dict[str, set[str]] = defaultdict(set)
    groups: dict[str, set[str]] = defaultdict(set)
    targets: dict[CheckResultKey, set[str]] = defaultdict(set)
    for query_name, items in accepted.items():
        for item in items:
            by_query_key[query_name][item.key].append(item)
            if item.name is not None and item.name_priority is not None:
                names[item.key.check_id][item.name_priority].add(item.name)
            if item.derived_name is not None:
                derived_names[item.key.check_id].add(item.derived_name)
            if item.group is not None:
                groups[item.key.check_id].add(item.group)
            if item.target is not None:
                targets[item.key].add(item.target)

    normalized_results: dict[CheckResultKey, NormalizedCheckResult] = {}
    for key in sorted(primary_keys):
        result_diagnostics: set[str] = set()
        previously_declared = previous_results_by_key.get(key)
        logical_sources = {
            item.logical_source
            for query_name in CHECK_QUERY_NAMES
            for item in by_query_key[query_name].get(key, ())
        }
        if len(logical_sources) > 1:
            logical_source = key.source
            result_diagnostics.update({"conflicting_info_metadata", "invalid_info"})
        elif logical_sources:
            logical_source = next(iter(logical_sources))
        else:
            logical_source = (
                previously_declared.logical_source
                if previously_declared is not None and previously_declared.logical_source
                else key.source
            )
        success, state, status_diagnostics = _reconcile_success(
            by_query_key["check_status"].get(key, ()),
            by_query_key["check_state"].get(key, ()),
            allowed_states=_CHECK_STATES,
            success_state="success",
            failure_state="failure",
            missing_code="missing_status",
            invalid_binary_code="invalid_status",
            conflicting_binary_code="conflicting_status",
            invalid_state_code="invalid_state",
            conflicting_state_code="conflicting_state",
            conflicting_pair_code="conflicting_state_status",
            require_binary_for_result_states=True,
        )
        result_diagnostics.update(status_diagnostics)
        last_run_samples = by_query_key["check_last_run"].get(key, ())
        last_run_at, timestamp_diagnostics = _last_run_value(
            last_run_samples,
            evaluated_at=evaluated_at,
            future_tolerance_seconds=future_tolerance_seconds,
        )
        if (state in {"unknown", "error", "stale", "disabled"} and not last_run_samples) or (
            success is None
            and bool(last_run_samples)
            and all(item.sample.value == 0.0 for item in last_run_samples)
        ):
            # The prober deliberately exports zero before the first completed run. Epoch is not
            # evidence of a stale run when there is no confirmed binary result; a non-result
            # one-hot state already explains why the binary status is absent.
            last_run_at = None
            timestamp_diagnostics = set()
        result_diagnostics.update(timestamp_diagnostics)
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
        if any(
            item.info_conflict
            for query_name in CHECK_QUERY_NAMES
            for item in by_query_key[query_name].get(key, ())
        ):
            result_diagnostics.update({"conflicting_info_metadata", "invalid_info"})

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

        target_ids = sorted(
            {
                item.target_id
                for query_name in (
                    "check_target_success",
                    "check_target_state",
                    "check_duration",
                    "check_ttfb",
                )
                for item in by_query_key[query_name].get(key, ())
                if item.target_id is not None
            }
        )
        if len(target_ids) > MAX_TARGETS_PER_RESULT:
            raise ChecksDataError("checks_limit_exceeded")
        normalized_targets: list[CheckTarget] = []
        for target_id in target_ids:
            target_success, target_state, target_status_diagnostics = _reconcile_success(
                tuple(
                    item
                    for item in by_query_key["check_target_success"].get(key, ())
                    if item.target_id == target_id
                ),
                tuple(
                    item
                    for item in by_query_key["check_target_state"].get(key, ())
                    if item.target_id == target_id
                ),
                allowed_states=_CHECK_STATES,
                success_state="success",
                failure_state="failure",
                missing_code=None,
                invalid_binary_code="invalid_target_status",
                conflicting_binary_code="conflicting_target_status",
                invalid_state_code="invalid_target_state",
                conflicting_state_code="conflicting_target_state",
                conflicting_pair_code="conflicting_target_state_status",
            )
            target_duration, target_duration_diagnostics = _non_negative_value(
                tuple(
                    item
                    for item in by_query_key["check_duration"].get(key, ())
                    if item.target_id == target_id
                ),
                label="target_duration",
            )
            target_ttfb, target_ttfb_diagnostics = _non_negative_value(
                tuple(
                    item
                    for item in by_query_key["check_ttfb"].get(key, ())
                    if item.target_id == target_id
                ),
                label="target_ttfb",
            )
            nested_diagnostics = {
                *target_status_diagnostics,
                *target_duration_diagnostics,
                *target_ttfb_diagnostics,
            }
            result_diagnostics.update(nested_diagnostics)
            normalized_targets.append(
                CheckTarget(
                    target_id=target_id,
                    name=_humanize_identifier(target_id),
                    state=cast(CheckResultState | None, target_state),
                    success=target_success,
                    duration_seconds=target_duration,
                    ttfb_seconds=target_ttfb,
                    status_reason=_nested_status_reason(
                        target_state,
                        target_success,
                        nested_diagnostics,
                    ),
                )
            )

        legacy_duration, duration_diagnostics = _non_negative_value(
            tuple(
                item
                for item in by_query_key["check_duration"].get(key, ())
                if item.target_id is None
            ),
            label="duration",
        )
        result_diagnostics.update(duration_diagnostics)
        legacy_ttfb, ttfb_diagnostics = _non_negative_value(
            tuple(
                item for item in by_query_key["check_ttfb"].get(key, ()) if item.target_id is None
            ),
            label="ttfb",
        )
        result_diagnostics.update(ttfb_diagnostics)
        duration_values = [
            value
            for value in (
                legacy_duration,
                *(item.duration_seconds for item in normalized_targets),
            )
            if value is not None
        ]
        ttfb_values = [
            value
            for value in (
                legacy_ttfb,
                *(item.ttfb_seconds for item in normalized_targets),
            )
            if value is not None
        ]
        duration = max(duration_values) if duration_values else None
        ttfb = max(ttfb_values) if ttfb_values else None

        assertions: list[CheckAssertion] = []
        assertion_ids = sorted(
            {
                item.assertion_id or _DEFAULT_ASSERTION
                for query_name in ("check_egress_state", "check_egress_match")
                for item in by_query_key[query_name].get(key, ())
            }
        )
        if len(assertion_ids) > MAX_ASSERTIONS_PER_RESULT:
            raise ChecksDataError("checks_limit_exceeded")
        for assertion_id in assertion_ids:
            assertion_success, assertion_state, assertion_diagnostics = _reconcile_success(
                tuple(
                    item
                    for item in by_query_key["check_egress_match"].get(key, ())
                    if (item.assertion_id or _DEFAULT_ASSERTION) == assertion_id
                ),
                tuple(
                    item
                    for item in by_query_key["check_egress_state"].get(key, ())
                    if (item.assertion_id or _DEFAULT_ASSERTION) == assertion_id
                ),
                allowed_states=_EGRESS_STATES,
                success_state="match",
                failure_state="mismatch",
                missing_code=None,
                invalid_binary_code="invalid_assertion",
                conflicting_binary_code="conflicting_assertion",
                invalid_state_code="invalid_assertion_state",
                conflicting_state_code="conflicting_assertion_state",
                conflicting_pair_code="conflicting_assertion_state_match",
            )
            result_diagnostics.update(assertion_diagnostics)
            public_key = "egress_match" if assertion_id == _DEFAULT_ASSERTION else assertion_id
            assertions.append(
                CheckAssertion(
                    key=public_key,
                    success=assertion_success,
                    status_reason=_nested_status_reason(
                        assertion_state,
                        assertion_success,
                        assertion_diagnostics,
                    ),
                    name=_humanize_identifier(public_key),
                    state=cast(CheckAssertionState | None, assertion_state),
                )
            )

        errors_by_reason: dict[str, list[_AcceptedSample]] = defaultdict(list)
        for item in by_query_key["check_errors_total"].get(key, ()):
            if item.reason not in _SAFE_ERROR_REASONS:
                result_diagnostics.add("invalid_error_reason")
                continue
            errors_by_reason[item.reason].append(item)
        error_reasons: list[CheckErrorReason] = []
        for reason, reason_samples in sorted(errors_by_reason.items()):
            count, count_diagnostics = _counter_value(reason_samples)
            result_diagnostics.update(count_diagnostics)
            if count is not None:
                error_reasons.append(CheckErrorReason(reason=reason, count=count))

        provisional_info_dimensions = reuse_previous_info_dimensions and any(
            item.key_dimensions_defaulted
            for query_name in ("check_state", "check_status", "check_last_run")
            for item in by_query_key[query_name].get(key, ())
        )
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
            provisional_info_dimensions=(
                provisional_info_dimensions
                or (
                    not info_is_present
                    and previously_declared is not None
                    and previously_declared.provisional_info_dimensions
                )
            ),
            state=cast(CheckResultState | None, state),
            targets=tuple(normalized_targets),
            error_reasons=tuple(error_reasons),
            logical_source=logical_source,
        )

    if previous is not None:
        retained_missing_count = 0
        for previous_check in previous.checks:
            for previous_result in previous_check.results:
                if previous_result.key in normalized_results:
                    continue
                # Preserve every previously observed executor when it disappears from the
                # current scrape. Prometheus cannot distinguish a stopped instance from a
                # deliberate configuration removal, and hiding the tuple would make coverage
                # look healthier precisely when a region stopped reporting.
                if (
                    info_is_present
                    and previous_result.known_via_info
                    and valid_info_keys_by_base[
                        (previous_result.key.check_id, previous_result.key.source)
                    ]
                ):
                    # The same executor is still declared under a different Scenario/Variant;
                    # retire only its superseded tuple, never a wholly missing executor.
                    continue
                if info_is_present and _matches_proven_info_rekey(
                    previous_result,
                    valid_info_keys_by_base[
                        (previous_result.key.check_id, previous_result.key.source)
                    ],
                    info_hinted_operational_dimensions,
                ):
                    # A result first observed while info was unavailable used one or more private
                    # default dimensions. Once a single authoritative info row declares that same
                    # check/source, its enriched current key replaces the provisional tuple.
                    continue
                retained_missing_count += 1
                if sample_count + retained_missing_count > max_series:
                    raise ChecksDataError("checks_limit_exceeded")
                normalized_results[previous_result.key] = NormalizedCheckResult(
                    key=previous_result.key,
                    target=previous_result.target,
                    success=None,
                    last_run_at=previous_result.last_run_at,
                    assertions=tuple(
                        CheckAssertion(
                            key=assertion.key,
                            success=None,
                            status_reason="incomplete_data",
                            name=assertion.name,
                            state=None,
                        )
                        for assertion in previous_result.assertions
                    ),
                    diagnostics=tuple(
                        sorted({*previous_result.diagnostics, "missing_current_result"})
                    ),
                    known_via_info=previous_result.known_via_info,
                    provisional_info_dimensions=previous_result.provisional_info_dimensions,
                    targets=tuple(
                        CheckTarget(
                            target_id=item.target_id,
                            name=item.name,
                            state=None,
                            success=None,
                            status_reason="incomplete_data",
                        )
                        for item in previous_result.targets
                    ),
                    logical_source=previous_result.logical_source,
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
        name_values = next(
            (names[check_id][priority] for priority in (0, 1) if names[check_id][priority]),
            set(),
        )
        if len(name_values) > 1:
            name = check_id
            diagnostics.add("conflicting_name")
        elif name_values:
            name = next(iter(name_values))
        elif len(derived_names[check_id]) > 1:
            name = _humanize_identifier(check_id)
            diagnostics.add("conflicting_name")
        elif derived_names[check_id]:
            name = next(iter(derived_names[check_id]))
        elif check_id in previous_by_id and (
            check_id not in current_check_ids
            or (reuse_previous_info_metadata and "invalid_name" not in diagnostics)
        ):
            name = previous_by_id[check_id].name
        else:
            name = _humanize_identifier(check_id)

        group_values = groups[check_id]
        if len(group_values) > 1:
            group = None
            diagnostics.add("conflicting_group")
        elif group_values:
            group = next(iter(group_values))
        elif check_id in previous_by_id and (
            check_id not in current_check_ids
            or (reuse_previous_info_metadata and "invalid_group" not in diagnostics)
        ):
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
        concurrency_limiter = asyncio.Semaphore(MAX_CONCURRENT_CHECK_REQUESTS)
        try:
            query_results = await asyncio.gather(
                *(
                    query_datasource_targets(
                        targets,
                        client,
                        query_name,
                        evaluated_at=query_time,
                        allow_non_finite_values=True,
                        concurrency_limiter=concurrency_limiter,
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
        reuse_previous_info_dimensions=bool(failures_by_query["check_info"]),
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
            (result.logical_source or result.key.source) == filters.source
            for result in check.results
        ):
            return False
        if filters.target is not None and not any(
            result.target == filters.target
            or any(
                target.target_id == filters.target or target.name == filters.target
                for target in result.targets
            )
            for result in check.results
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
                *(target.name for result in check.results for target in result.targets),
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
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or not is_grafana_dashboard_url(base_url)
        ):
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
