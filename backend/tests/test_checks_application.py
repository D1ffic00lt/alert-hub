from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from alert_hub.application.checks import (
    CHECK_QUERY_NAMES,
    MAX_CANARIES_PER_RESULT,
    MAX_RESULTS_PER_CHECK,
    CheckFilters,
    ChecksDataError,
    ChecksSnapshot,
    ChecksSnapshotCache,
    build_check_grafana_url,
    evaluate_checks_snapshot,
    filter_checks,
    normalize_check_metrics,
    problem_checks,
    refresh_checks_snapshot,
    summarize_checks,
)
from alert_hub.application.prometheus import DatasourceQueryFailure, DatasourceQueryTarget
from alert_hub.domain.checks import DEFAULT_SCENARIO, DEFAULT_SOURCE, DEFAULT_VARIANT
from alert_hub.infrastructure.prometheus import (
    CheckQueryName,
    FixedQueryName,
    PrometheusQueryError,
    VectorSample,
)
from alert_hub.settings import Settings

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _sample(value: float, **labels: str) -> VectorSample:
    # This instant-vector timestamp is deliberately unrelated to the run timestamp value.
    return VectorSample(labels=labels, value=value, timestamp=NOW - timedelta(days=1))


def _metrics(
    **overrides: Sequence[VectorSample],
) -> dict[CheckQueryName, Sequence[VectorSample]]:
    values: dict[CheckQueryName, Sequence[VectorSample]] = {
        query_name: () for query_name in CHECK_QUERY_NAMES
    }
    for query_name, samples in overrides.items():
        assert query_name in CHECK_QUERY_NAMES
        values[query_name] = samples  # type: ignore[literal-required]
    return values


def _settings(**overrides: Any) -> Settings:
    return Settings(
        environment="test",
        signing_key="checks-test-signing-key",
        cluster_secret="checks-test-cluster-key",
        cookie_secure=False,
        heartbeat_scan_seconds=0,
        checks_enabled=True,
        **overrides,
    )


def _snapshot(checks, *, fetched_at: datetime = NOW) -> ChecksSnapshot:
    return ChecksSnapshot(
        snapshot_id="snapshot-1",
        fetched_at=fetched_at,
        evaluated_at=NOW,
        cache_expires_at=fetched_at + timedelta(seconds=5),
        checks=checks,
    )


class _FakePrometheus:
    def __init__(
        self,
        responses: Mapping[CheckQueryName, Sequence[VectorSample]],
        *,
        failures: Mapping[CheckQueryName, str] | None = None,
        gate: asyncio.Event | None = None,
    ) -> None:
        self.responses = responses
        self.failures = failures or {}
        self.gate = gate
        self.calls: list[tuple[str, FixedQueryName, datetime | None, bool]] = []

    def validate_url(self, value: str) -> str:
        return value

    async def query(
        self,
        url: str,
        credentials: Mapping[str, Any],
        query_name: FixedQueryName,
        *,
        job_globs: Sequence[str] | None = None,
        evaluated_at: datetime | None = None,
        allow_non_finite_values: bool = False,
    ) -> list[VectorSample]:
        del credentials, job_globs
        self.calls.append((url, query_name, evaluated_at, allow_non_finite_values))
        if self.gate is not None:
            await self.gate.wait()
        if query_name in self.failures:
            raise PrometheusQueryError(self.failures[query_name], "internal address is secret")
        assert query_name in CHECK_QUERY_NAMES
        return list(self.responses[query_name])


def _target(identifier: str = "prom-1") -> DatasourceQueryTarget:
    return DatasourceQueryTarget(
        datasource_id=identifier,
        datasource_name=identifier,
        url=f"https://{identifier}.example",
        reachability_label_mode="canonical",
        credentials={"auth_type": "none"},
    )


def test_minimal_check_uses_contract_defaults_and_drops_unknown_labels() -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(
                    1,
                    check_id="public-api",
                    instance="10.0.0.1:9090",
                    bearer_token="must-not-leak",
                )
            ],
            check_last_run=[_sample(NOW.timestamp(), check_id="public-api", job="prober")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    assert len(checks) == 1
    check = checks[0]
    assert (check.check_id, check.name, check.group) == ("public-api", "public-api", None)
    assert len(check.results) == 1
    result = check.results[0]
    assert (result.key.source, result.key.scenario, result.key.variant) == (
        DEFAULT_SOURCE,
        DEFAULT_SCENARIO,
        DEFAULT_VARIANT,
    )
    assert result.success is True
    assert result.last_run_at == NOW
    assert result.duration_seconds is None
    assert result.ttfb_seconds is None
    assert result.canaries == ()
    assert result.assertions == ()
    assert "10.0.0.1" not in repr(check)
    assert "must-not-leak" not in repr(check)


def test_static_api_route_name_is_reserved_only_for_check_id() -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="valid-check", source="summary")],
            check_last_run=[_sample(NOW.timestamp(), check_id="valid-check", source="summary")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=10,
    )

    assert checks[0].results[0].key.source == "summary"


def test_identical_duplicates_merge_but_conflicts_are_never_chosen() -> None:
    common = {
        "check_id": "checkout",
        "source": "ams",
        "check_name": "Checkout",
        "group": "payments",
        "target": "Primary API",
    }
    checks = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, **common), _sample(1, **common), _sample(0, **common)],
            check_last_run=[
                _sample(NOW.timestamp(), **common),
                _sample((NOW - timedelta(seconds=1)).timestamp(), **common),
            ],
            check_duration=[_sample(0.4, **common), _sample(0.5, **common)],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    result = checks[0].results[0]
    assert result.success is None
    assert result.last_run_at is None
    assert result.duration_seconds is None
    assert {"conflicting_status", "conflicting_timestamp", "conflicting_duration"} <= set(
        result.diagnostics
    )
    evaluated = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)
    assert (evaluated[0].status, evaluated[0].status_reason) == ("unknown", "invalid_data")


def test_conflicting_safe_metadata_falls_back_without_exposing_a_value_set() -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(
                    1,
                    check_id="api",
                    check_name="API east",
                    group="edge",
                    target="Primary",
                )
            ],
            check_last_run=[
                _sample(
                    NOW.timestamp(),
                    check_id="api",
                    check_name="API west",
                    group="core",
                    target="Secondary",
                )
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    assert checks[0].name == "api"
    assert checks[0].group is None
    assert checks[0].results[0].target is None
    assert {"conflicting_name", "conflicting_group"} <= set(checks[0].diagnostics)
    assert "conflicting_target" in checks[0].results[0].diagnostics


def test_invalid_identifiers_values_and_display_secrets_are_bounded() -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(1, check_id=""),
                _sample(1, check_id="bad/id"),
                _sample(1, check_id=" safe-id "),
                _sample(1, check_id="safe\nid"),
                _sample(1, check_id="10.0.0.1"),
                _sample(1, check_id="123e4567-e89b-12d3-a456-426614174000"),
                _sample(1, check_id="agent-123e4567-e89b-12d3-a456-426614174000"),
                _sample(1, check_id="agent-01951e38-4d5a-7cc4-b682-adf7c25f37c8"),
                _sample(1, check_id="edge-10.0.0.1"),
                _sample(1, check_id="edge:2001:db8::1"),
                _sample(1, check_id="token:supersecret"),
                _sample(1, check_id="summary"),
                _sample(1, check_id="__alert_hub_default_source__"),
                _sample(
                    float("nan"),
                    check_id="safe-id",
                    source="bad/source",
                ),
                _sample(
                    float("inf"),
                    check_id="safe-id",
                    check_name="token=super-secret",
                ),
                _sample(
                    1,
                    check_id="display-safe",
                    check_name="Node [fd00::1]:443",
                    group="edge\nproduction",
                    target="edge 2001:db8::1",
                ),
            ],
            check_last_run=[
                _sample(
                    NOW.timestamp() + 31,
                    check_id="safe-id",
                    check_name="https://internal.example/path",
                ),
                _sample(NOW.timestamp(), check_id="display-safe"),
            ],
            check_duration=[_sample(-0.1, check_id="safe-id", target="10.0.0.1")],
            check_ttfb=[_sample(float("inf"), check_id="safe-id")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    assert [check.check_id for check in checks] == ["display-safe", "safe-id"]
    display_check, check = checks
    assert (display_check.name, display_check.group, display_check.results[0].target) == (
        "display-safe",
        None,
        None,
    )
    assert {"invalid_name", "invalid_group", "invalid_target"} <= set(display_check.diagnostics)
    assert check.name == "safe-id"
    assert "invalid_name" in check.diagnostics
    assert "invalid_target" in check.diagnostics
    result = check.results[0]
    assert result.success is None
    assert result.last_run_at is None
    assert result.duration_seconds is None
    assert result.ttfb_seconds is None
    assert {"invalid_status", "invalid_timestamp", "invalid_duration", "invalid_ttfb"} <= set(
        result.diagnostics
    )


def test_future_clock_tolerance_is_inclusive() -> None:
    accepted = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="clock")],
            check_last_run=[_sample(NOW.timestamp() + 30, check_id="clock")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    rejected = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="clock")],
            check_last_run=[_sample(NOW.timestamp() + 30.001, check_id="clock")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    assert accepted[0].results[0].last_run_at == NOW + timedelta(seconds=30)
    assert rejected[0].results[0].last_run_at is None
    assert "invalid_timestamp" in rejected[0].results[0].diagnostics


def test_optional_metrics_normalize_without_changing_primary_success() -> None:
    labels = {
        "check_id": "transaction",
        "source": "paris",
        "scenario": "purchase",
        "variant": "card",
        "target": "Storefront",
    }
    checks = normalize_check_metrics(
        _metrics(
            check_info=[_sample(1, **labels)],
            check_status=[_sample(1, **labels)],
            check_last_run=[_sample(NOW.timestamp(), **labels)],
            check_canary_success=[
                _sample(1, **labels, canary="dns"),
                _sample(0, **labels, canary="tls"),
            ],
            check_duration=[_sample(0.42, **labels)],
            check_ttfb=[_sample(0.11, **labels)],
            check_egress_match=[_sample(0, **labels)],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    result = checks[0].results[0]
    assert result.success is True
    assert (result.duration_seconds, result.ttfb_seconds) == (0.42, 0.11)
    assert [(item.canary, item.success) for item in result.canaries] == [
        ("dns", True),
        ("tls", False),
    ]
    assert [(item.key, item.success) for item in result.assertions] == [("egress_match", False)]


def test_info_without_results_is_unknown_and_no_info_retains_disappeared_keys() -> None:
    initial = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(1, check_id="replicated", source="a"),
                _sample(1, check_id="replicated", source="b"),
            ],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="replicated", source="a"),
                _sample(NOW.timestamp(), check_id="replicated", source="b"),
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    previous = _snapshot(initial)
    retained = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="replicated", source="a")],
            check_last_run=[_sample(NOW.timestamp(), check_id="replicated", source="a")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
        previous=previous,
    )
    authoritative = normalize_check_metrics(
        _metrics(check_info=[_sample(1, check_id="known-before-first-run")]),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
        previous=previous,
    )

    assert [item.key.source for item in retained[0].results] == ["a", "b"]
    disappeared = retained[0].results[1]
    assert disappeared.success is None
    assert "missing_current_result" in disappeared.diagnostics
    stale_retained = evaluate_checks_snapshot(
        _snapshot(retained),
        _settings(),
        now=NOW + timedelta(seconds=181),
    )[0]
    assert stale_retained.status == "stale"
    assert stale_retained.data_incomplete is True
    assert [check.check_id for check in authoritative] == [
        "known-before-first-run",
        "replicated",
    ]
    known = authoritative[0].results[0]
    assert known.success is None and known.last_run_at is None
    assert all(
        "missing_current_result" in result.diagnostics for result in authoritative[1].results
    )


@pytest.mark.parametrize("info_values", [(0.0,), (1.0, 0.0), (1.0, float("nan"))])
def test_invalid_info_cannot_drop_a_previously_known_source_or_improve_status(
    info_values: tuple[float, ...],
) -> None:
    initial = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(1, check_id="replicated", source="a"),
                _sample(0, check_id="replicated", source="b"),
            ],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="replicated", source="a"),
                _sample(NOW.timestamp(), check_id="replicated", source="b"),
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    current = normalize_check_metrics(
        _metrics(
            check_info=[_sample(value, check_id="replicated", source="a") for value in info_values],
            check_status=[_sample(1, check_id="replicated", source="a")],
            check_last_run=[_sample(NOW.timestamp(), check_id="replicated", source="a")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
        previous=_snapshot(initial),
    )

    assert [item.key.source for item in current[0].results] == ["a", "b"]
    assert "invalid_info" in current[0].results[0].diagnostics
    assert "missing_current_result" in current[0].results[1].diagnostics
    evaluated = evaluate_checks_snapshot(_snapshot(current), _settings(), now=NOW)[0]
    assert (evaluated.status, evaluated.data_incomplete) == ("unknown", True)


def test_partial_info_does_not_erase_a_status_only_executor_inventory() -> None:
    initial = normalize_check_metrics(
        _metrics(
            check_info=[_sample(1, check_id="mixed-inventory", source="declared")],
            check_status=[
                _sample(1, check_id="mixed-inventory", source="declared"),
                _sample(0, check_id="mixed-inventory", source="status-only"),
            ],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="mixed-inventory", source="declared"),
                _sample(NOW.timestamp(), check_id="mixed-inventory", source="status-only"),
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    assert [result.known_via_info for result in initial[0].results] == [True, False]

    current = normalize_check_metrics(
        _metrics(
            check_info=[_sample(1, check_id="mixed-inventory", source="declared")],
            check_status=[_sample(1, check_id="mixed-inventory", source="declared")],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="mixed-inventory", source="declared")
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
        previous=_snapshot(initial),
    )

    assert [result.key.source for result in current[0].results] == ["declared", "status-only"]
    retained = current[0].results[1]
    assert retained.success is None
    assert retained.known_via_info is False
    assert "missing_current_result" in retained.diagnostics
    evaluated = evaluate_checks_snapshot(_snapshot(current), _settings(), now=NOW)[0]
    assert (evaluated.status, evaluated.status_reason, evaluated.data_incomplete) == (
        "unknown",
        "incomplete_data",
        True,
    )


def test_authoritative_info_can_remove_only_a_previously_declared_tuple() -> None:
    initial = normalize_check_metrics(
        _metrics(
            check_info=[
                _sample(1, check_id="declared", source="a"),
                _sample(1, check_id="declared", source="b"),
            ]
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    current = normalize_check_metrics(
        _metrics(check_info=[_sample(1, check_id="declared", source="a")]),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
        previous=_snapshot(initial),
    )

    assert [result.key.source for result in current[0].results] == ["a"]


def test_invalid_primary_dimension_cannot_improve_check_to_up() -> None:
    metrics = _metrics(
        check_status=[
            _sample(1, check_id="dimension-safe", source="good"),
            _sample(0, check_id="dimension-safe", source="bad/source"),
        ],
        check_last_run=[
            _sample(NOW.timestamp(), check_id="dimension-safe", source="good"),
            _sample(NOW.timestamp(), check_id="dimension-safe", source="bad/source"),
        ],
        check_duration=[_sample(0.2, check_id="dimension-safe", source="also/bad")],
    )
    checks = normalize_check_metrics(
        metrics,
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    assert {"invalid_identifier", "invalid_optional_identifier"} <= set(checks[0].diagnostics)
    evaluated = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)[0]
    assert (evaluated.status, evaluated.status_reason, evaluated.data_incomplete) == (
        "unknown",
        "invalid_data",
        True,
    )
    assert evaluated.latency_seconds is None


def test_current_series_do_not_inherit_removed_optional_display_metadata() -> None:
    initial = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="renamed", check_name="Old name", group="legacy")],
            check_last_run=[
                _sample(
                    NOW.timestamp(),
                    check_id="renamed",
                    check_name="Old name",
                    group="legacy",
                )
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    current = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="renamed")],
            check_last_run=[_sample(NOW.timestamp(), check_id="renamed")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
        previous=_snapshot(initial),
    )

    assert (current[0].name, current[0].group) == ("renamed", None)


def test_global_series_limit_counts_invalid_input_and_retained_registry() -> None:
    with pytest.raises(ChecksDataError) as raw_limit:
        normalize_check_metrics(
            _metrics(
                check_status=[
                    _sample(1, check_id="valid"),
                    _sample(1, check_id="invalid/id"),
                ]
            ),
            evaluated_at=NOW,
            future_tolerance_seconds=30,
            max_series=1,
        )
    assert raw_limit.value.code == "checks_limit_exceeded"

    previous_checks = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(1, check_id="a"),
                _sample(1, check_id="b"),
            ]
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=2,
    )
    with pytest.raises(ChecksDataError) as retained_limit:
        normalize_check_metrics(
            _metrics(check_status=[_sample(1, check_id="c")]),
            evaluated_at=NOW,
            future_tolerance_seconds=30,
            max_series=2,
            previous=_snapshot(previous_checks),
        )
    assert retained_limit.value.code == "checks_limit_exceeded"

    with pytest.raises(ChecksDataError) as combined_limit:
        normalize_check_metrics(
            _metrics(
                check_status=[_sample(1, check_id="c")],
                check_last_run=[_sample(NOW.timestamp(), check_id="c")],
                check_duration=[_sample(0.1, check_id="c")],
            ),
            evaluated_at=NOW,
            future_tolerance_seconds=30,
            max_series=4,
            previous=_snapshot(previous_checks),
        )
    assert combined_limit.value.code == "checks_limit_exceeded"


def test_per_check_result_and_canary_collections_are_bounded() -> None:
    with pytest.raises(ChecksDataError) as result_limit:
        normalize_check_metrics(
            _metrics(
                check_info=[
                    _sample(1, check_id="wide", source=f"source-{index}")
                    for index in range(MAX_RESULTS_PER_CHECK + 1)
                ]
            ),
            evaluated_at=NOW,
            future_tolerance_seconds=30,
            max_series=MAX_RESULTS_PER_CHECK + 1,
        )
    assert result_limit.value.code == "checks_limit_exceeded"

    labels = {"check_id": "nested", "source": "source"}
    with pytest.raises(ChecksDataError) as canary_limit:
        normalize_check_metrics(
            _metrics(
                check_info=[_sample(1, **labels)],
                check_canary_success=[
                    _sample(1, **labels, canary=f"canary-{index}")
                    for index in range(MAX_CANARIES_PER_RESULT + 1)
                ],
            ),
            evaluated_at=NOW,
            future_tolerance_seconds=30,
            max_series=MAX_CANARIES_PER_RESULT + 2,
        )
    assert canary_limit.value.code == "checks_limit_exceeded"


def test_refresh_uses_one_evaluation_time_and_degrades_only_optional_queries() -> None:
    responses = _metrics(
        check_status=[_sample(1, check_id="api")],
        check_last_run=[_sample(NOW.timestamp(), check_id="api")],
    )
    optional_failure = _FakePrometheus(responses, failures={"check_ttfb": "timeout"})
    snapshot = asyncio.run(
        refresh_checks_snapshot(
            [_target()],
            optional_failure,
            _settings(),
            evaluated_at=NOW,
            clock=lambda: NOW,
        )
    )

    assert snapshot.warning_codes == ("check_ttfb_unavailable",)
    assert len(optional_failure.calls) == len(CHECK_QUERY_NAMES)
    assert {call[2] for call in optional_failure.calls} == {NOW}
    assert all(call[3] is True for call in optional_failure.calls)

    mandatory_failure = _FakePrometheus(responses, failures={"check_status": "timeout"})
    with pytest.raises(ChecksDataError) as unavailable:
        asyncio.run(
            refresh_checks_snapshot(
                [_target()],
                mandatory_failure,
                _settings(),
                evaluated_at=NOW,
            )
        )
    assert unavailable.value.code == "prometheus_unavailable"

    bounded_failure = _FakePrometheus(
        responses, failures={"check_canary_success": "response_too_large"}
    )
    with pytest.raises(ChecksDataError) as limited:
        asyncio.run(
            refresh_checks_snapshot(
                [_target()],
                bounded_failure,
                _settings(),
                evaluated_at=NOW,
            )
        )
    assert limited.value.code == "checks_limit_exceeded"


def test_partial_optional_query_is_entirely_unavailable_and_setup_failure_is_safe() -> None:
    responses = _metrics(
        check_status=[_sample(1, check_id="api")],
        check_last_run=[_sample(NOW.timestamp(), check_id="api")],
        check_ttfb=[_sample(0.1, check_id="api")],
    )

    class PartialFailure(_FakePrometheus):
        async def query(
            self,
            url: str,
            credentials: Mapping[str, Any],
            query_name: FixedQueryName,
            *,
            job_globs: Sequence[str] | None = None,
            evaluated_at: datetime | None = None,
            allow_non_finite_values: bool = False,
        ) -> list[VectorSample]:
            if url == "https://prom-2.example" and query_name == "check_ttfb":
                self.calls.append((url, query_name, evaluated_at, allow_non_finite_values))
                raise PrometheusQueryError("timeout", "private upstream detail")
            return await super().query(
                url,
                credentials,
                query_name,
                job_globs=job_globs,
                evaluated_at=evaluated_at,
                allow_non_finite_values=allow_non_finite_values,
            )

    fake = PartialFailure(responses)
    snapshot = asyncio.run(
        refresh_checks_snapshot(
            [_target("prom-1"), _target("prom-2")],
            fake,
            _settings(),
            evaluated_at=NOW,
            clock=lambda: NOW,
        )
    )
    assert snapshot.warning_codes == ("check_ttfb_unavailable",)
    assert snapshot.checks[0].results[0].ttfb_seconds is None

    with pytest.raises(ChecksDataError) as aggregate_limit:
        asyncio.run(
            refresh_checks_snapshot(
                [_target("prom-1"), _target("prom-2")],
                PartialFailure(responses),
                _settings(checks_max_series=4),
                evaluated_at=NOW,
                clock=lambda: NOW,
            )
        )
    assert aggregate_limit.value.code == "checks_limit_exceeded"

    setup_failure = DatasourceQueryFailure(
        datasource_id="private-id",
        datasource_name="private-name",
        code="credentials_unavailable",
        detail="secret internal detail",
    )
    unused = _FakePrometheus(responses)
    with pytest.raises(ChecksDataError) as unavailable:
        asyncio.run(
            refresh_checks_snapshot(
                [_target()],
                unused,
                _settings(),
                preparation_failures=[setup_failure],
            )
        )
    assert unavailable.value.code == "prometheus_unavailable"
    assert "secret" not in str(unavailable.value)
    assert unused.calls == []


def test_empty_target_set_is_an_authoritative_empty_snapshot_without_queries() -> None:
    fake = _FakePrometheus(_metrics())
    snapshot = asyncio.run(
        refresh_checks_snapshot([], fake, _settings(), evaluated_at=NOW, clock=lambda: NOW)
    )

    assert snapshot.checks == ()
    assert fake.calls == []


def test_single_flight_cache_does_not_serve_old_success_after_refresh_error() -> None:
    async def exercise() -> None:
        monotonic = [10.0]
        gate = asyncio.Event()
        responses = _metrics(
            check_status=[_sample(1, check_id="api")],
            check_last_run=[_sample(NOW.timestamp(), check_id="api")],
        )
        fake = _FakePrometheus(responses, gate=gate)
        cache = ChecksSnapshotCache(
            monotonic_clock=lambda: monotonic[0],
            utc_clock=lambda: NOW,
        )
        settings = _settings(checks_cache_ttl_seconds=1)
        requests = [
            asyncio.create_task(cache.get_or_refresh([_target()], fake, settings)) for _ in range(3)
        ]
        for _ in range(20):
            if len(fake.calls) == len(CHECK_QUERY_NAMES):
                break
            await asyncio.sleep(0)
        assert len(fake.calls) == len(CHECK_QUERY_NAMES)
        gate.set()
        snapshots = await asyncio.gather(*requests)
        assert len({snapshot.snapshot_id for snapshot in snapshots}) == 1
        assert len(fake.calls) == len(CHECK_QUERY_NAMES)

        # An unexpired hit makes no network call.
        assert await cache.get_or_refresh([_target()], fake, settings) is snapshots[0]
        assert len(fake.calls) == len(CHECK_QUERY_NAMES)
        fresh = evaluate_checks_snapshot(snapshots[0], settings, now=NOW)[0]
        expired_measurement = evaluate_checks_snapshot(
            snapshots[0], settings, now=NOW + timedelta(seconds=181)
        )[0]
        assert (fresh.status, expired_measurement.status) == ("up", "stale")
        assert len(fake.calls) == len(CHECK_QUERY_NAMES)

        # Once expired, a mandatory failure is surfaced. The peekable prior snapshot remains
        # last-known state only; get_or_refresh never returns it as current data.
        monotonic[0] += 2
        fake.failures = {"check_last_run": "timeout"}
        with pytest.raises(ChecksDataError) as error:
            await cache.get_or_refresh([_target()], fake, settings)
        assert error.value.code == "prometheus_unavailable"
        assert cache.peek() is snapshots[0]

    asyncio.run(exercise())


def test_filters_preserve_whole_check_status_and_summary_is_consistent() -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(
                    1,
                    check_id="mixed",
                    source="a",
                    group="edge",
                    target="Public API",
                ),
                _sample(
                    0,
                    check_id="mixed",
                    source="b",
                    group="edge",
                    target="Public API",
                ),
                _sample(1, check_id="healthy", source="a", group="core"),
            ],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="mixed", source="a", group="edge"),
                _sample(NOW.timestamp(), check_id="mixed", source="b", group="edge"),
                _sample(NOW.timestamp(), check_id="healthy", source="a", group="core"),
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    evaluated = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)
    selected = filter_checks(
        evaluated,
        CheckFilters(status="degraded", group="edge", source="a", search="public"),
    )

    assert len(selected) == 1
    assert selected[0].check_id == "mixed"
    assert selected[0].status == "degraded"
    assert selected[0].sources_total == 2
    summary = summarize_checks(selected)
    assert summary.total == 1
    assert summary.degraded == 1
    assert (
        sum((summary.up, summary.degraded, summary.down, summary.stale, summary.unknown))
        == summary.total
    )


def test_problem_order_and_grafana_deep_link_are_stable_and_encoded() -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_status=[
                _sample(0, check_id="down"),
                _sample(1, check_id="stale"),
                _sample(float("nan"), check_id="unknown"),
            ],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="down"),
                _sample((NOW - timedelta(seconds=181)).timestamp(), check_id="stale"),
                _sample(NOW.timestamp(), check_id="unknown"),
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )
    evaluated = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)
    assert [check.status for check in problem_checks(evaluated)] == [
        "down",
        "unknown",
        "stale",
    ]

    link = build_check_grafana_url(
        "https://grafana.example/d/checks?orgId=1&var-check_id=old#panel",
        "api:edge-blue",
    )
    assert link == ("https://grafana.example/d/checks?orgId=1&var-check_id=api%3Aedge-blue#panel")
    assert build_check_grafana_url("javascript:alert(1)", "api") is None
    assert build_check_grafana_url("https://user:pass@grafana.example/d/checks", "api") is None
