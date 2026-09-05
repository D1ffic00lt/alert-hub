from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from alert_hub.domain.checks import (
    DEFAULT_SCENARIO,
    DEFAULT_SOURCE,
    DEFAULT_VARIANT,
    CheckResultKey,
    NormalizedCheckResult,
    aggregate_check,
)

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _result(
    *,
    source: str = DEFAULT_SOURCE,
    scenario: str = DEFAULT_SCENARIO,
    variant: str = DEFAULT_VARIANT,
    success: bool | None = True,
    age: float | None = 0,
    duration: float | None = None,
    target: str | None = None,
    diagnostics: tuple[str, ...] = (),
) -> NormalizedCheckResult:
    return NormalizedCheckResult(
        key=CheckResultKey("check-a", source, scenario, variant),
        target=target,
        success=success,
        last_run_at=None if age is None else NOW - timedelta(seconds=age),
        duration_seconds=duration,
        diagnostics=diagnostics,
    )


def _aggregate(
    *results: NormalizedCheckResult,
    minimum: int = 1,
    now: datetime = NOW,
):
    return aggregate_check(
        "check-a",
        "Check A",
        None,
        results,
        now=now,
        stale_after_seconds=180,
        min_failure_sources=minimum,
    )


@pytest.mark.parametrize(
    ("results", "minimum", "status", "reason"),
    [
        ((_result(success=True),), 1, "up", "all_results_up"),
        ((_result(success=False),), 1, "down", "confirmed_failures"),
        (
            (_result(source="source-a", success=True), _result(source="source-b", success=False)),
            1,
            "degraded",
            "mixed_results",
        ),
        ((_result(age=181),), 1, "stale", "expired_measurements"),
        ((_result(success=None, diagnostics=("invalid_status",)),), 1, "unknown", "invalid_data"),
    ],
)
def test_all_five_statuses_follow_the_ordered_rules(
    results: tuple[NormalizedCheckResult, ...],
    minimum: int,
    status: str,
    reason: str,
) -> None:
    check = _aggregate(*results, minimum=minimum)
    assert check.status == status
    assert check.status_reason == reason


def test_stale_boundary_is_inclusive_and_uses_run_timestamp() -> None:
    at_boundary = _aggregate(_result(age=180))
    just_past = _aggregate(_result(age=180), now=NOW + timedelta(microseconds=1))

    assert at_boundary.status == "up"
    assert just_past.status == "stale"
    assert just_past.stale_results == 1


def test_failure_quorum_counts_distinct_sources_only() -> None:
    insufficient = _aggregate(_result(source="source-a", success=False), minimum=2)
    confirmed = _aggregate(
        _result(source="source-a", success=False),
        _result(source="source-b", success=False),
        minimum=2,
    )

    assert insufficient.status == "unknown"
    assert insufficient.status_reason == "insufficient_sources"
    assert insufficient.data_incomplete is True
    assert confirmed.status == "down"
    assert confirmed.sources_total == 2

    repeated_source = _aggregate(
        _result(source="source-a", success=False),
        _result(source="source-a", success=False),
        minimum=2,
    )
    assert (repeated_source.status, repeated_source.status_reason) == (
        "unknown",
        "insufficient_sources",
    )


def test_three_sources_can_confirm_failure_while_expired_evidence_stays_incomplete() -> None:
    check = _aggregate(
        _result(source="source-a", success=False),
        _result(source="source-b", success=False),
        _result(source="source-c", success=True, age=181),
        minimum=2,
    )

    assert check.status == "down"
    assert check.sources_total == 3
    assert check.sources_up == 0
    assert check.stale_results == 1
    assert check.data_incomplete is True


def test_failures_in_different_scenarios_never_combine_into_one_quorum() -> None:
    check = _aggregate(
        _result(source="source-a", scenario="login", success=False),
        _result(source="source-b", scenario="checkout", success=False),
        minimum=2,
    )

    assert check.status == "unknown"
    assert check.status_reason == "insufficient_sources"
    assert [part.status for part in check.parts] == ["unknown", "unknown"]


def test_variants_are_independent_parts_and_follow_overall_priority() -> None:
    check = _aggregate(
        _result(source="a", scenario="purchase", variant="card", success=True),
        _result(source="b", scenario="purchase", variant="card", success=False),
        _result(source="a", scenario="purchase", variant="cash", success=True),
    )

    assert [(part.variant, part.status) for part in check.parts] == [
        ("card", "degraded"),
        ("cash", "up"),
    ]
    assert check.status == "degraded"


def test_overall_part_priority_and_per_source_success_are_conservative() -> None:
    check = _aggregate(
        _result(
            source="source-a",
            scenario="availability",
            success=True,
            duration=0.2,
            target="Primary",
        ),
        _result(
            source="source-b",
            scenario="availability",
            success=True,
            duration=0.4,
            target="Secondary",
        ),
        _result(source="source-a", scenario="transaction", success=False),
    )

    assert check.status == "down"
    assert check.sources_total == 2
    assert check.sources_up == 1
    assert check.latency_seconds == 0.4
    assert check.scenarios == ("availability", "transaction")
    assert check.target is None
    assert "conflicting_target" in check.diagnostics


def test_missing_and_mixed_expired_results_are_incomplete_but_all_stale_is_not() -> None:
    mixed = _aggregate(_result(source="fresh"), _result(source="old", age=181))
    all_stale = _aggregate(
        _result(source="old-a", age=181),
        _result(source="old-b", age=500),
    )
    missing = _aggregate(_result(age=None, diagnostics=("invalid_timestamp",)))

    assert (mixed.status, mixed.data_incomplete) == ("unknown", True)
    assert (all_stale.status, all_stale.data_incomplete) == ("stale", False)
    assert (missing.status, missing.status_reason, missing.data_incomplete) == (
        "unknown",
        "invalid_data",
        True,
    )

    mixed_parts = _aggregate(
        _result(scenario="fresh", age=0),
        _result(scenario="expired", age=181),
    )
    assert (mixed_parts.status, mixed_parts.data_incomplete) == ("unknown", True)

    disappeared = _aggregate(_result(age=181, diagnostics=("missing_current_result",)))
    assert (disappeared.status, disappeared.data_incomplete) == ("stale", True)


@pytest.mark.parametrize(
    "diagnostic",
    ["missing_status", "invalid_status", "conflicting_status", "invalid_info"],
)
def test_expired_timestamp_does_not_hide_incomplete_primary_data(diagnostic: str) -> None:
    check = _aggregate(_result(success=None, age=181, diagnostics=(diagnostic,)))

    assert check.status == "stale"
    assert check.status_reason == "expired_measurements"
    assert check.data_incomplete is True


@pytest.mark.parametrize("diagnostic", ["conflicting_status", "conflicting_timestamp"])
def test_conflicting_primary_values_are_invalid_not_merely_missing(diagnostic: str) -> None:
    result = _result(
        success=None,
        age=None if diagnostic == "conflicting_timestamp" else 0,
        diagnostics=(diagnostic,),
    )
    check = _aggregate(result)
    assert check.status == "unknown"
    assert check.status_reason == "invalid_data"


def test_empty_collection_is_never_up_and_invalid_configuration_is_rejected() -> None:
    empty = _aggregate()
    assert empty.status == "unknown"
    assert empty.sources_total == 0
    assert empty.data_incomplete is True

    with pytest.raises(ValueError, match="positive"):
        aggregate_check(
            "check-a",
            "Check A",
            None,
            [],
            now=NOW,
            stale_after_seconds=0,
            min_failure_sources=1,
        )
