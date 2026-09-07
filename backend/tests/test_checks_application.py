from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from alert_hub.application import checks as checks_application
from alert_hub.application.checks import (
    CHECK_QUERY_NAMES,
    MAX_ASSERTIONS_PER_RESULT,
    MAX_CANARIES_PER_RESULT,
    MAX_CONCURRENT_CHECK_REQUESTS,
    MAX_RESULTS_PER_CHECK,
    MAX_TARGETS_PER_RESULT,
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
    assert (check.check_id, check.name, check.group) == ("public-api", "Public api", None)
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
        "Display safe",
        None,
        None,
    )
    assert {"invalid_name", "invalid_group", "invalid_target"} <= set(display_check.diagnostics)
    assert check.name == "Safe id"
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


@pytest.mark.parametrize(
    "value",
    [
        "https://internal.example/path",
        "HtTpS://internal.example/path",
        "Bearer private-value",
        "password : private-value",
        "API-Key = private-value",
        "ſecret=private-value",
        "apiKey=private-value",
        "apİkey=private-value",
        "apıkey=private-value",
        "Node [fd00::1]:443",
        "Node [fe80::1%eth0]:443",
        "edge 2001:db8::1",
        "target 10.0.0.1:443",
        "Node 10.0.0.1.",
        "ip:10.0.0.1:443",
        "Node:10.0.0.1",
        "ip:[fd00::1]:443",
        "Node:[fd00::1]:443",
        "Node:2001:db8::1",
        "fd00::1.example",
        "fd00::1.a",
        "node.fd00::1",
        "node%fd00::1",
        "node]fd00::1",
        "fd00::1[abc]",
    ],
)
def test_safe_display_rejects_sensitive_and_address_shaped_values(value: str) -> None:
    assert checks_application._safe_display(value, max_length=255) is None


@pytest.mark.parametrize(
    "value",
    [
        "a" * 255,
        ":" * 255,
        "0" * 255,
        "release dead:beef",
        "ratio 12:34:56",
        "release v1.2.3.4",
    ],
)
def test_safe_display_handles_adversarial_repetition_with_bounded_scans(value: str) -> None:
    assert checks_application._safe_display(value, max_length=255) == value


def test_safe_display_rejects_input_above_the_fixed_display_limit() -> None:
    assert checks_application._safe_display("a" * 256, max_length=1_000) is None


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
            check_egress_match=[_sample(0, **labels, route="ignored-unknown-label")],
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


def test_xray_prober_contract_joins_instances_and_preserves_nested_identities() -> None:
    info_labels = {
        "check_id": "primary-xray",
        "source_id": "subscription-main",
        "entry_name": "RU Primary XTLS",
        "mode": "connection",
        "target_set_id": "public-web",
    }
    checks = normalize_check_metrics(
        _metrics(
            check_info=[
                _sample(1, **info_labels, instance_id="edge-a"),
                _sample(1, **info_labels, instance_id="edge-b"),
            ],
            check_state=[
                _sample(1, check_id="primary-xray", instance_id="edge-a", state="success"),
                _sample(1, check_id="primary-xray", instance_id="edge-b", state="error"),
            ],
            check_status=[_sample(1, check_id="primary-xray", instance_id="edge-a")],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="primary-xray", instance_id="edge-a"),
                _sample(NOW.timestamp(), check_id="primary-xray", instance_id="edge-b"),
            ],
            check_target_success=[
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="landing-page",
                ),
                _sample(
                    0,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="status-api",
                ),
            ],
            check_target_state=[
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="dns-probe",
                    state="error",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="landing-page",
                    state="success",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="pending-api",
                    state="unknown",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="status-api",
                    state="failure",
                ),
            ],
            check_duration=[
                _sample(
                    0.2,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="landing-page",
                ),
                _sample(
                    0.8,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="status-api",
                ),
            ],
            check_ttfb=[
                _sample(
                    0.1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="landing-page",
                ),
                _sample(
                    0.3,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    target_id="status-api",
                ),
            ],
            check_egress_state=[
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    assertion_id="backup-route",
                    state="mismatch",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    assertion_id="exit-check",
                    state="error",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    assertion_id="office-cidr",
                    state="match",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    assertion_id="pending-route",
                    state="unknown",
                ),
            ],
            check_egress_match=[
                _sample(
                    0,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    assertion_id="backup-route",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    assertion_id="office-cidr",
                ),
            ],
            check_errors_total=[
                _sample(
                    2,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    reason="timeout",
                ),
                _sample(
                    1,
                    check_id="primary-xray",
                    instance_id="edge-a",
                    reason="token=must-not-leak",
                ),
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=100,
    )

    assert len(checks) == 1
    check = checks[0]
    assert check.name == "RU Primary XTLS"
    assert [item.key.source for item in check.results] == ["edge-a", "edge-b"]
    assert [item.logical_source for item in check.results] == [
        "subscription-main",
        "subscription-main",
    ]
    assert {(item.key.scenario, item.key.variant) for item in check.results} == {
        ("connection", "public-web")
    }

    edge_a, edge_b = check.results
    assert (edge_a.state, edge_a.success, edge_a.duration_seconds, edge_a.ttfb_seconds) == (
        "success",
        True,
        0.8,
        0.3,
    )
    assert "conflicting_duration" not in edge_a.diagnostics
    assert [
        (item.target_id, item.state, item.success, item.duration_seconds, item.ttfb_seconds)
        for item in edge_a.targets
    ] == [
        ("dns-probe", "error", None, None, None),
        ("landing-page", "success", True, 0.2, 0.1),
        ("pending-api", "unknown", None, None, None),
        ("status-api", "failure", False, 0.8, 0.3),
    ]
    assert [(item.key, item.state, item.success) for item in edge_a.assertions] == [
        ("backup-route", "mismatch", False),
        ("exit-check", "error", None),
        ("office-cidr", "match", True),
        ("pending-route", "unknown", None),
    ]
    target_reasons = {item.target_id: item.status_reason for item in edge_a.targets}
    assert target_reasons["dns-probe"] == "executor_error"
    assert target_reasons["pending-api"] == "executor_unknown"
    assertion_reasons = {item.key: item.status_reason for item in edge_a.assertions}
    assert assertion_reasons["exit-check"] == "executor_error"
    assert assertion_reasons["pending-route"] == "executor_unknown"
    assert [(item.reason, item.count) for item in edge_a.error_reasons] == [("timeout", 2)]
    assert "invalid_error_reason" in edge_a.diagnostics
    assert "must-not-leak" not in repr(check)

    assert (edge_b.state, edge_b.success) == ("error", None)
    assert "missing_status" not in edge_b.diagnostics
    evaluated = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)[0]
    assert (evaluated.sources_up, evaluated.sources_total) == (0, 1)
    assert evaluated.target is None
    assert evaluated.targets == ("Dns probe", "Landing page", "Pending api", "Status api")
    assert filter_checks((evaluated,), CheckFilters(target="dns-probe")) == (evaluated,)
    views = {item.key.source: item for item in evaluated.results}
    assert (views["edge-a"].status, views["edge-a"].status_reason) == ("up", "result_up")
    assert (views["edge-b"].status, views["edge-b"].status_reason) == (
        "unknown",
        "executor_error",
    )


@pytest.mark.parametrize("state", ["unknown", "error"])
def test_prober_non_result_zero_timestamp_is_not_epoch_and_source_priority_is_stable(
    state: str,
) -> None:
    common = {
        "check_id": "never-run",
        "source": "logical-source",
        "instance_id": "edge-a",
        "source_id": "subscription-main",
        "scenario": "explicit-scenario",
        "mode": "profile",
        "variant": "explicit-variant",
        "target_set_id": "public-web",
    }
    checks = normalize_check_metrics(
        _metrics(
            check_state=[_sample(1, **common, state=state)],
            check_last_run=[_sample(0, **common)],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
    )

    result = checks[0].results[0]
    assert result.key.source == "edge-a"
    assert result.logical_source == "logical-source"
    assert (result.key.scenario, result.key.variant) == (
        "explicit-scenario",
        "explicit-variant",
    )
    assert result.last_run_at is None
    assert "missing_status" not in result.diagnostics
    assert "missing_timestamp" not in result.diagnostics
    view = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)[0].results[0]
    assert (view.status, view.status_reason) == ("unknown", f"executor_{state}")

    source_id_only = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="source-fallback", source_id="config-source")],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="source-fallback", source_id="config-source")
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=10,
    )
    assert source_id_only[0].results[0].key.source == "config-source"


def test_prober_name_uses_safe_exported_metadata_when_entry_name_is_unusable() -> None:
    info = {
        "check_id": "opaque-check",
        "instance_id": "edge-a",
        "source_id": "subscription-main",
        "entry_name": "token=must-not-leak",
        "mode": "profile",
        "target_set_id": "public-web",
    }
    checks = normalize_check_metrics(
        _metrics(
            check_info=[_sample(1, **info)],
            check_status=[_sample(1, check_id="opaque-check", instance_id="edge-a")],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="opaque-check", instance_id="edge-a")
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
    )

    assert checks[0].name == "Profile · Subscription main · Public web"
    assert "invalid_name" in checks[0].diagnostics
    assert "must-not-leak" not in repr(checks[0])


def test_explicit_check_name_has_priority_over_exporter_entry_names() -> None:
    info = {
        "check_id": "named-check",
        "instance_id": "edge-a",
        "mode": "profile",
        "target_set_id": "public-web",
    }
    checks = normalize_check_metrics(
        _metrics(
            check_info=[
                _sample(1, **info, entry_name="Lower priority A"),
                _sample(1, **info, entry_name="Lower priority B"),
            ],
            check_status=[
                _sample(1, check_id="named-check", instance_id="edge-a", check_name="Preferred")
            ],
            check_last_run=[_sample(NOW.timestamp(), check_id="named-check", instance_id="edge-a")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
    )

    assert checks[0].name == "Preferred"
    assert "conflicting_name" not in checks[0].diagnostics


def test_one_hot_state_conflicts_fail_closed_instead_of_overriding_binary_status() -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_state=[_sample(1, check_id="conflict", state="error")],
            check_status=[_sample(1, check_id="conflict")],
            check_last_run=[_sample(NOW.timestamp(), check_id="conflict")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=10,
    )

    result = checks[0].results[0]
    assert result.success is None
    assert "conflicting_state_status" in result.diagnostics
    view = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)[0].results[0]
    assert (view.status, view.status_reason) == ("unknown", "invalid_data")


@pytest.mark.parametrize("state", ["success", "failure"])
def test_primary_result_state_cannot_replace_missing_mandatory_status(state: str) -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_state=[_sample(1, check_id="state-only", state=state)],
            check_last_run=[_sample(NOW.timestamp(), check_id="state-only")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=10,
    )

    result = checks[0].results[0]
    assert (result.state, result.success) == (state, None)
    assert "missing_status" in result.diagnostics
    view = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)[0].results[0]
    assert (view.status, view.status_reason) == ("unknown", "incomplete_data")


@pytest.mark.parametrize(
    ("state", "expected_status", "expected_reason"),
    [
        ("unknown", "unknown", "executor_unknown"),
        ("error", "unknown", "executor_error"),
        ("disabled", "unknown", "executor_disabled"),
        ("stale", "stale", "executor_stale"),
    ],
)
def test_non_result_state_explains_missing_status_without_a_binary_result(
    state: str,
    expected_status: str,
    expected_reason: str,
) -> None:
    checks = normalize_check_metrics(
        _metrics(
            check_state=[_sample(1, check_id="non-result", state=state)],
            check_last_run=[_sample(NOW.timestamp(), check_id="non-result")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=10,
    )

    result = checks[0].results[0]
    assert result.success is None
    assert "missing_status" not in result.diagnostics
    view = evaluate_checks_snapshot(_snapshot(checks), _settings(), now=NOW)[0].results[0]
    assert (view.status, view.status_reason) == (expected_status, expected_reason)


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


def test_authoritative_info_retains_a_missing_previously_declared_instance() -> None:
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

    assert [result.key.source for result in current[0].results] == ["a", "b"]
    assert current[0].results[1].success is None
    assert "missing_current_result" in current[0].results[1].diagnostics


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

    assert (current[0].name, current[0].group) == ("Renamed", None)


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


def test_per_check_nested_collections_are_bounded() -> None:
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

    with pytest.raises(ChecksDataError) as target_limit:
        normalize_check_metrics(
            _metrics(
                check_info=[_sample(1, **labels)],
                check_target_state=[
                    _sample(
                        1,
                        **labels,
                        target_id=f"target-{index}",
                        state="unknown",
                    )
                    for index in range(MAX_TARGETS_PER_RESULT + 1)
                ],
            ),
            evaluated_at=NOW,
            future_tolerance_seconds=30,
            max_series=MAX_TARGETS_PER_RESULT + 2,
        )
    assert target_limit.value.code == "checks_limit_exceeded"

    with pytest.raises(ChecksDataError) as assertion_limit:
        normalize_check_metrics(
            _metrics(
                check_info=[_sample(1, **labels)],
                check_egress_state=[
                    _sample(
                        1,
                        **labels,
                        assertion_id=f"assertion-{index}",
                        state="unknown",
                    )
                    for index in range(MAX_ASSERTIONS_PER_RESULT + 1)
                ],
            ),
            evaluated_at=NOW,
            future_tolerance_seconds=30,
            max_series=MAX_ASSERTIONS_PER_RESULT + 2,
        )
    assert assertion_limit.value.code == "checks_limit_exceeded"


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


def test_refresh_bounds_concurrency_across_all_queries_and_datasources() -> None:
    async def exercise() -> None:
        gate = asyncio.Event()

        class ConcurrencyTrackingPrometheus(_FakePrometheus):
            def __init__(self) -> None:
                super().__init__(_metrics(), gate=gate)
                self.active = 0
                self.peak = 0
                self.saturated = asyncio.Event()

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
                self.active += 1
                self.peak = max(self.peak, self.active)
                if self.active == MAX_CONCURRENT_CHECK_REQUESTS:
                    self.saturated.set()
                try:
                    return await super().query(
                        url,
                        credentials,
                        query_name,
                        job_globs=job_globs,
                        evaluated_at=evaluated_at,
                        allow_non_finite_values=allow_non_finite_values,
                    )
                finally:
                    self.active -= 1

        fake = ConcurrencyTrackingPrometheus()
        target_count = MAX_CONCURRENT_CHECK_REQUESTS // len(CHECK_QUERY_NAMES) + 1
        refresh = asyncio.create_task(
            refresh_checks_snapshot(
                [_target(f"prom-{index}") for index in range(target_count)],
                fake,
                _settings(),
                evaluated_at=NOW,
                clock=lambda: NOW,
            )
        )
        await asyncio.wait_for(fake.saturated.wait(), timeout=5)
        await asyncio.sleep(0)

        assert fake.active == MAX_CONCURRENT_CHECK_REQUESTS
        assert fake.peak == MAX_CONCURRENT_CHECK_REQUESTS
        assert len(fake.calls) == MAX_CONCURRENT_CHECK_REQUESTS

        gate.set()
        snapshot = await asyncio.wait_for(refresh, timeout=5)
        assert snapshot.checks == ()
        assert fake.active == 0
        assert fake.peak == MAX_CONCURRENT_CHECK_REQUESTS
        assert len(fake.calls) == target_count * len(CHECK_QUERY_NAMES)

    asyncio.run(exercise())


def test_optional_info_failure_reuses_unique_previous_result_dimensions() -> None:
    info_labels = {
        "check_id": "primary-xray",
        "instance_id": "edge-a",
        "source_id": "subscription-main",
        "entry_name": "Primary XTLS",
        "group": "network",
        "mode": "connection",
        "target_set_id": "public-web",
    }
    responses = _metrics(
        check_info=[_sample(1, **info_labels)],
        check_status=[_sample(1, check_id="primary-xray", instance_id="edge-a")],
        check_last_run=[_sample(NOW.timestamp(), check_id="primary-xray", instance_id="edge-a")],
    )
    initial = asyncio.run(
        refresh_checks_snapshot(
            [_target()],
            _FakePrometheus(responses),
            _settings(),
            evaluated_at=NOW,
            clock=lambda: NOW,
        )
    )

    refreshed = asyncio.run(
        refresh_checks_snapshot(
            [_target()],
            _FakePrometheus(responses, failures={"check_info": "timeout"}),
            _settings(),
            previous=initial,
            evaluated_at=NOW,
            clock=lambda: NOW,
        )
    )

    assert refreshed.warning_codes == ("check_info_unavailable",)
    assert (refreshed.checks[0].name, refreshed.checks[0].group) == (
        "Primary XTLS",
        "network",
    )
    assert len(refreshed.checks[0].results) == 1
    result = refreshed.checks[0].results[0]
    assert (result.key.source, result.key.scenario, result.key.variant) == (
        "edge-a",
        "connection",
        "public-web",
    )
    assert result.success is True
    assert result.known_via_info is True
    assert "missing_current_result" not in result.diagnostics
    evaluated = evaluate_checks_snapshot(refreshed, _settings(), now=NOW)
    assert (evaluated[0].status, len(evaluated[0].parts)) == ("up", 1)


def test_info_restore_retires_cold_refresh_provisional_dimensions() -> None:
    status_only = _metrics(
        check_status=[_sample(1, check_id="primary-xray", instance_id="edge-a")],
        check_last_run=[_sample(NOW.timestamp(), check_id="primary-xray", instance_id="edge-a")],
    )
    cold = asyncio.run(
        refresh_checks_snapshot(
            [_target()],
            _FakePrometheus(status_only, failures={"check_info": "timeout"}),
            _settings(),
            evaluated_at=NOW,
            clock=lambda: NOW,
        )
    )
    assert cold.checks[0].results[0].key.scenario == DEFAULT_SCENARIO
    assert cold.checks[0].results[0].known_via_info is False
    assert cold.checks[0].results[0].provisional_info_dimensions is True

    retained = asyncio.run(
        refresh_checks_snapshot(
            [_target()],
            _FakePrometheus(_metrics()),
            _settings(),
            previous=cold,
            evaluated_at=NOW,
            clock=lambda: NOW,
        )
    )
    assert retained.checks[0].results[0].provisional_info_dimensions is True
    assert "missing_current_result" in retained.checks[0].results[0].diagnostics

    restored_responses = _metrics(
        check_info=[
            _sample(
                1,
                check_id="primary-xray",
                instance_id="edge-a",
                source_id="subscription-main",
                entry_name="Primary XTLS",
                mode="connection",
                target_set_id="public-web",
            )
        ],
        check_status=status_only["check_status"],
        check_last_run=status_only["check_last_run"],
    )
    restored = asyncio.run(
        refresh_checks_snapshot(
            [_target()],
            _FakePrometheus(restored_responses),
            _settings(),
            previous=retained,
            evaluated_at=NOW,
            clock=lambda: NOW,
        )
    )

    assert len(restored.checks[0].results) == 1
    assert restored.checks[0].name == "Primary XTLS"
    result = restored.checks[0].results[0]
    assert (result.key.scenario, result.key.variant) == ("connection", "public-web")
    assert result.known_via_info is True
    assert result.provisional_info_dimensions is False
    assert "missing_current_result" not in result.diagnostics


def test_info_restore_does_not_rekey_a_status_only_default_without_failure_provenance() -> None:
    initial = normalize_check_metrics(
        _metrics(
            check_status=[_sample(0, check_id="coexisting", source="edge-a")],
            check_last_run=[_sample(NOW.timestamp(), check_id="coexisting", source="edge-a")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
    )
    assert initial[0].results[0].provisional_info_dimensions is False

    current = normalize_check_metrics(
        _metrics(
            check_info=[
                _sample(
                    1,
                    check_id="coexisting",
                    source="edge-a",
                    scenario="purchase",
                    variant="standard",
                )
            ],
            # These rows prove that the current result used the info hint, but the old default
            # result predates an info-query failure and therefore remains a separate inventory row.
            check_status=[_sample(1, check_id="coexisting", source="edge-a")],
            check_last_run=[_sample(NOW.timestamp(), check_id="coexisting", source="edge-a")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
        previous=_snapshot(initial),
    )

    by_scenario = {result.key.scenario: result for result in current[0].results}
    assert set(by_scenario) == {DEFAULT_SCENARIO, "purchase"}
    retained = by_scenario[DEFAULT_SCENARIO]
    assert retained.success is None
    assert "missing_current_result" in retained.diagnostics
    evaluated = evaluate_checks_snapshot(_snapshot(current), _settings(), now=NOW)[0]
    assert (evaluated.status, evaluated.data_incomplete) == ("unknown", True)


def test_info_restore_requires_hints_for_every_rekeyed_dimension() -> None:
    cold = normalize_check_metrics(
        _metrics(
            check_status=[_sample(0, check_id="explicit-current", source="edge-a")],
            check_last_run=[_sample(NOW.timestamp(), check_id="explicit-current", source="edge-a")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
        reuse_previous_info_dimensions=True,
    )
    assert cold[0].results[0].provisional_info_dimensions is True

    explicit_labels = {
        "check_id": "explicit-current",
        "source": "edge-a",
        "scenario": "purchase",
        "variant": "standard",
    }
    current = normalize_check_metrics(
        _metrics(
            check_info=[_sample(1, **explicit_labels)],
            # Variant is supplied by the info hint, but Scenario is explicit. That partial hint
            # cannot prove that the old default/default tuple is the same current result.
            check_status=[
                _sample(
                    1,
                    check_id="explicit-current",
                    source="edge-a",
                    scenario="purchase",
                )
            ],
            check_last_run=[
                _sample(
                    NOW.timestamp(),
                    check_id="explicit-current",
                    source="edge-a",
                    scenario="purchase",
                )
            ],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
        previous=_snapshot(cold),
    )

    by_scenario = {result.key.scenario: result for result in current[0].results}
    assert set(by_scenario) == {DEFAULT_SCENARIO, "purchase"}
    retained = by_scenario[DEFAULT_SCENARIO]
    assert retained.provisional_info_dimensions is True
    assert "missing_current_result" in retained.diagnostics
    evaluated = evaluate_checks_snapshot(_snapshot(current), _settings(), now=NOW)[0]
    assert (evaluated.status, evaluated.data_incomplete) == ("unknown", True)


def test_previous_info_dimension_conflicts_are_not_resolved_arbitrarily() -> None:
    previous_checks = normalize_check_metrics(
        _metrics(
            check_info=[
                _sample(
                    1,
                    check_id="multi-mode",
                    instance_id="edge-a",
                    mode=mode,
                    target_set_id="public-web",
                )
                for mode in ("connection", "profile")
            ]
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
    )
    current = normalize_check_metrics(
        _metrics(
            check_status=[_sample(1, check_id="multi-mode", instance_id="edge-a")],
            check_last_run=[_sample(NOW.timestamp(), check_id="multi-mode", instance_id="edge-a")],
        ),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
        previous=_snapshot(previous_checks),
        reuse_previous_info_dimensions=True,
    )

    by_scenario = {result.key.scenario: result for result in current[0].results}
    assert set(by_scenario) == {DEFAULT_SCENARIO, "connection", "profile"}
    assert {"conflicting_info_metadata", "invalid_info"} <= set(
        by_scenario[DEFAULT_SCENARIO].diagnostics
    )


def test_current_authoritative_info_never_uses_stale_dimension_hints() -> None:
    def metrics(mode: str, entry_name: str) -> dict[CheckQueryName, Sequence[VectorSample]]:
        return _metrics(
            check_info=[
                _sample(
                    1,
                    check_id="changed-mode",
                    instance_id="edge-a",
                    entry_name=entry_name,
                    mode=mode,
                    target_set_id="public-web",
                )
            ],
            check_status=[_sample(1, check_id="changed-mode", instance_id="edge-a")],
            check_last_run=[
                _sample(NOW.timestamp(), check_id="changed-mode", instance_id="edge-a")
            ],
        )

    previous_checks = normalize_check_metrics(
        metrics("connection", "Old name"),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
    )
    current = normalize_check_metrics(
        metrics("profile", "Current name"),
        evaluated_at=NOW,
        future_tolerance_seconds=30,
        max_series=20,
        previous=_snapshot(previous_checks),
        reuse_previous_info_dimensions=True,
    )

    assert current[0].name == "Current name"
    assert [result.key.scenario for result in current[0].results] == ["profile"]


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
    assert build_check_grafana_url("https://grafana.example/", "api") is None
    assert build_check_grafana_url("https://grafana.example/d/../", "api") is None
    assert build_check_grafana_url("https://grafana.example/d/checks/../../", "api") is None
    assert build_check_grafana_url("https://grafana.example/d/checks/%2e%2e/", "api") is None
    assert build_check_grafana_url("https://grafana.example/d/checks/..\\..", "api") is None
    assert build_check_grafana_url("https://grafana.example/d/checks/%5c..", "api") is None
    assert build_check_grafana_url("javascript:alert(1)", "api") is None
    assert build_check_grafana_url("https://user:pass@grafana.example/d/checks", "api") is None
