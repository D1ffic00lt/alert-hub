from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alert_hub.application.checks import ChecksDataError, ChecksSnapshot
from alert_hub.domain.checks import (
    DEFAULT_CANARY,
    CheckAssertion,
    CheckCanary,
    CheckResultKey,
    NormalizedCheckResult,
)
from alert_hub.infrastructure.db.models import Incident
from alert_hub.infrastructure.prometheus import FixedQueryName, VectorSample
from alert_hub.main import create_app
from alert_hub.settings import Settings


class _UnusedPrometheus:
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
        raise AssertionError("the stub cache must prevent Prometheus queries")


class _StubCache:
    def __init__(
        self,
        result: ChecksSnapshot | ChecksDataError,
        *,
        previous: ChecksSnapshot | None = None,
    ) -> None:
        self.result = result
        self.previous = previous
        self.calls = 0

    def peek(self) -> ChecksSnapshot | None:
        return self.previous

    async def get_or_refresh(self, *args: object, **kwargs: object) -> ChecksSnapshot:
        del args, kwargs
        self.calls += 1
        if isinstance(self.result, ChecksDataError):
            raise self.result
        return self.result


def _settings(tmp_path: Path, *, enabled: bool, **overrides: Any) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / ('checks-on.db' if enabled else 'checks-off.db')}",
        auto_create_schema=True,
        node_id="checks-api-node",
        node_name="Checks API node",
        node_region="test",
        signing_key="checks-api-signing-key-with-enough-entropy",
        cluster_secret="checks-api-cluster-key-with-enough-entropy",
        bootstrap_token="checks-api-bootstrap-token",
        cookie_secure=False,
        trusted_origins=["http://testserver"],
        peer_allowed_cidrs=[],
        heartbeat_scan_seconds=0,
        notify_enabled=False,
        sync_enabled=False,
        checks_enabled=enabled,
        **overrides,
    )


def _client(
    tmp_path: Path,
    cache: _StubCache,
    *,
    enabled: bool = True,
    **settings_overrides: Any,
) -> tuple[TestClient, dict[str, str]]:
    app = create_app(_settings(tmp_path, enabled=enabled, **settings_overrides))
    app.state.checks_snapshot_cache = cache
    app.state.prometheus_client = _UnusedPrometheus()
    client = TestClient(app, base_url="http://testserver")
    client.__enter__()
    bootstrap = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_token": "checks-api-bootstrap-token",
            "username": "admin",
            "password": "a-strong-test-password",
        },
    )
    assert bootstrap.status_code == 201, bootstrap.text
    return client, {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}


def _snapshot(
    *checks: tuple[str, str, str | None, tuple[NormalizedCheckResult, ...]],
) -> ChecksSnapshot:
    from alert_hub.application.checks import NormalizedCheck

    now = datetime.now(UTC)
    return ChecksSnapshot(
        snapshot_id="checks-snapshot",
        fetched_at=now,
        evaluated_at=now,
        cache_expires_at=now + timedelta(seconds=5),
        checks=tuple(
            NormalizedCheck(check_id, name, group, results)
            for check_id, name, group, results in checks
        ),
    )


def _result(
    check_id: str,
    *,
    success: bool,
    source: str | None = None,
    scenario: str | None = None,
    target: str | None = None,
    duration: float | None = None,
    canaries: tuple[CheckCanary, ...] = (),
    assertions: tuple[CheckAssertion, ...] = (),
    diagnostics: tuple[str, ...] = (),
) -> NormalizedCheckResult:
    key_values: dict[str, str] = {"check_id": check_id}
    if source is not None:
        key_values["source"] = source
    if scenario is not None:
        key_values["scenario"] = scenario
    return NormalizedCheckResult(
        key=CheckResultKey(**key_values),
        target=target,
        success=success,
        last_run_at=datetime.now(UTC),
        duration_seconds=duration,
        canaries=canaries,
        assertions=assertions,
        diagnostics=diagnostics,
    )


def test_disabled_checks_authenticate_before_returning_no_data(tmp_path: Path) -> None:
    cache = _StubCache(ChecksDataError("must_not_be_called"))
    client, auth = _client(tmp_path, cache, enabled=False)
    try:
        for path in ("/api/v1/checks", "/api/v1/checks/summary", "/api/v1/checks/anything"):
            assert client.get(path).status_code == 401
            response = client.get(path, headers=auth)
            assert response.status_code == 200
            assert response.json()["enabled"] is False
            assert response.json()["data_state"] == "disabled"
        assert cache.calls == 0
    finally:
        client.__exit__(None, None, None)


def test_list_and_summary_share_and_filters_without_reaggregating(tmp_path: Path) -> None:
    mixed = (
        _result("mixed", success=True, source="eu", scenario="purchase", target="Checkout"),
        _result("mixed", success=False, source="us", scenario="purchase", target="Checkout"),
    )
    snapshot = _snapshot(
        ("alpha", "Same", "core", (_result("alpha", success=True),)),
        ("beta", "Same", "core", (_result("beta", success=False, source="eu"),)),
        ("mixed", "Checkout", "edge", mixed),
    )
    client, auth = _client(tmp_path, _StubCache(snapshot))
    try:
        response = client.get(
            "/api/v1/checks?group=edge&source=eu&scenario=purchase&search=checkout",
            headers=auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["data_state"] == "ready"
        assert body["limit"] == 50
        assert body["total"] == 1
        assert body["items"][0]["check_id"] == "mixed"
        assert body["items"][0]["status"] == "degraded"

        summary = client.get(
            "/api/v1/checks/summary?group=edge&source=eu&scenario=purchase&search=checkout",
            headers=auth,
        )
        assert summary.status_code == 200, summary.text
        assert summary.json()["total"] == 1
        assert summary.json()["degraded"] == 1
        assert summary.json()["problem_checks"][0]["check_id"] == "mixed"

        ordered = client.get("/api/v1/checks?limit=2", headers=auth).json()
        assert [item["check_id"] for item in ordered["items"]] == ["alpha", "beta"]
        assert client.get("/api/v1/checks?limit=201", headers=auth).status_code == 422
    finally:
        client.__exit__(None, None, None)


def test_detail_serializes_defaults_relations_and_safe_grafana_link(tmp_path: Path) -> None:
    snapshot = _snapshot(
        (
            "minimal",
            "Minimal",
            None,
            (
                _result(
                    "minimal",
                    success=True,
                    duration=0,
                    canaries=(CheckCanary(DEFAULT_CANARY, True),),
                    assertions=(CheckAssertion("egress_match", True),),
                    diagnostics=("conflicting_ttfb",),
                ),
            ),
        )
    )
    client, auth = _client(
        tmp_path,
        _StubCache(snapshot),
        checks_grafana_base_url="https://grafana.example/d/checks?orgId=1",
    )
    try:
        source = client.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "Checks alerts", "kind": "generic_json", "region": "test"},
        ).json()
        ingest_headers = {"Authorization": f"Bearer {source['token']}"}
        incident_ids: list[str] = []
        for index in range(2):
            ingested = client.post(
                f"/ingest/v1/events/{source['id']}",
                headers=ingest_headers,
                json={
                    "schema_version": 1,
                    "external_event_id": f"check-api-alert-{index}",
                    "dedup_key": f"check-api-incident-{index}",
                    "status": "firing",
                    "title": f"Minimal failed {index}",
                    "severity": "critical",
                    "starts_at": "2026-09-05T12:00:00Z",
                    "labels": {"check_id": "minimal"},
                },
            )
            assert ingested.status_code == 200, ingested.text
            incident_ids.extend(ingested.json()["incident_ids"])
        relabeled = client.post(
            f"/ingest/v1/events/{source['id']}",
            headers=ingest_headers,
            json={
                "schema_version": 1,
                "external_event_id": "check-api-alert-relabeled",
                "dedup_key": "check-api-incident-1",
                "status": "firing",
                "title": "Now related to another Check",
                "severity": "warning",
                "starts_at": "2026-09-05T12:01:00Z",
                "labels": {"check_id": "another-check"},
            },
        )
        assert relabeled.status_code == 200, relabeled.text
        resolved = client.post(
            f"/api/v1/incidents/{incident_ids[-1]}/resolve",
            headers=auth,
            json={"reason": "test"},
        )
        assert resolved.status_code == 200

        response = client.get("/api/v1/checks/minimal", headers=auth)
        assert response.status_code == 200, response.text
        check = response.json()["check"]
        result = check["results"][0]
        assert (result["source"], result["scenario"], result["variant"]) == (
            None,
            None,
            None,
        )
        assert result["canaries"][0]["canary"] is None
        assert result["duration_seconds"] == 0
        assert result["diagnostic_codes"] == ["conflicting_ttfb"]
        assert check["diagnostic_codes"] == ["conflicting_ttfb"]
        assert check["active_alerts"] == 1
        assert len(check["related_alerts"]) == 1
        assert len(check["incidents"]) == 2
        assert check["grafana_url"].endswith("orgId=1&var-check_id=minimal")
        assert "labels" not in check["related_alerts"][0]
        assert check["relations_incomplete"] is False
    finally:
        client.__exit__(None, None, None)


def test_detail_bounds_related_items_and_reports_exact_totals(tmp_path: Path) -> None:
    snapshot = _snapshot(("bounded", "Bounded", None, (_result("bounded", success=False),)))
    client, auth = _client(tmp_path, _StubCache(snapshot))
    try:
        source = client.post(
            "/api/v1/sources",
            headers=auth,
            json={"name": "Bounded alerts", "kind": "generic_json", "region": "test"},
        ).json()
        now = datetime.now(UTC)
        with client.app.state.session_factory.begin() as db:
            db.add_all(
                Incident(
                    source_id=source["id"],
                    fingerprint=f"{index:064x}",
                    title=f"Bounded incident {index}",
                    description="",
                    severity="warning",
                    status="open",
                    labels_json={"check_id": "bounded"},
                    annotations_json={},
                    starts_at=now,
                    last_event_at=now + timedelta(microseconds=index),
                )
                for index in range(205)
            )

        response = client.get("/api/v1/checks/bounded", headers=auth)
        assert response.status_code == 200, response.text
        check = response.json()["check"]
        assert check["active_alerts"] == 205
        assert check["related_alerts_total"] == 205
        assert check["incidents_total"] == 205
        assert len(check["related_alerts"]) == 200
        assert len(check["incidents"]) == 200
        assert check["relations_incomplete"] is True
        assert check["relation_warning_codes"] == [
            "related_alerts_truncated",
            "related_incidents_truncated",
        ]
    finally:
        client.__exit__(None, None, None)


def test_authoritative_empty_is_200_but_missing_detail_is_404(tmp_path: Path) -> None:
    snapshot = _snapshot()
    client, auth = _client(tmp_path, _StubCache(snapshot))
    try:
        listing = client.get("/api/v1/checks", headers=auth)
        assert listing.status_code == 200
        assert listing.json()["data_state"] == "empty"
        assert listing.json()["total"] == 0

        summary = client.get("/api/v1/checks/summary", headers=auth)
        assert summary.status_code == 200
        assert {
            key: summary.json()[key]
            for key in ("total", "up", "degraded", "down", "stale", "unknown")
        } == {"total": 0, "up": 0, "degraded": 0, "down": 0, "stale": 0, "unknown": 0}

        detail = client.get("/api/v1/checks/missing", headers=auth)
        assert detail.status_code == 404
        assert detail.json()["data_state"] == "empty"
        assert detail.json()["check"] is None
    finally:
        client.__exit__(None, None, None)


def test_unavailable_without_inventory_is_never_empty_or_not_found(tmp_path: Path) -> None:
    cache = _StubCache(ChecksDataError("checks_limit_exceeded"))
    client, auth = _client(tmp_path, cache)
    try:
        listing = client.get("/api/v1/checks", headers=auth)
        assert listing.status_code == 503
        assert listing.json()["data_state"] == "unavailable"
        assert listing.json()["total"] is None
        assert listing.json()["error_code"] == "checks_limit_exceeded"

        summary = client.get("/api/v1/checks/summary", headers=auth)
        assert summary.status_code == 503
        assert summary.json()["total"] is None
        assert summary.json()["unknown"] is None

        detail = client.get("/api/v1/checks/not-known", headers=auth)
        assert detail.status_code == 503
        assert detail.json()["check"] is None
        assert "internal" not in detail.text
    finally:
        client.__exit__(None, None, None)


def test_unavailable_inventory_is_unknown_and_old_values_are_only_last_known(
    tmp_path: Path,
) -> None:
    previous = _snapshot(
        (
            "remembered",
            "Remembered",
            "core",
            (_result("remembered", success=True, duration=0.25),),
        )
    )
    cache = _StubCache(ChecksDataError("prometheus_unavailable"), previous=previous)
    client, auth = _client(tmp_path, cache)
    try:
        listing = client.get("/api/v1/checks", headers=auth)
        assert listing.status_code == 503
        current = listing.json()["items"][0]
        assert current["status"] == "unknown"
        assert current["last_checked_at"] is None
        assert current["latency_seconds"] is None
        prior = listing.json()["last_known"]["items"][0]
        assert prior["status"] == "up"
        assert prior["last_checked_at"] is not None
        assert prior["latency_seconds"] == 0.25

        summary = client.get("/api/v1/checks/summary", headers=auth)
        assert summary.status_code == 503
        assert (summary.json()["total"], summary.json()["unknown"], summary.json()["up"]) == (
            1,
            1,
            0,
        )
        assert summary.json()["last_known"]["up"] == 1

        detail = client.get("/api/v1/checks/remembered", headers=auth)
        assert detail.status_code == 503
        current_result = detail.json()["check"]["results"][0]
        assert current_result["success"] is None
        assert current_result["last_run_at"] is None
        assert current_result["duration_seconds"] is None
        previous_result = detail.json()["last_known"]["check"]["results"][0]
        assert previous_result["success"] is True
        assert previous_result["last_run_at"] is not None
        assert previous_result["duration_seconds"] == 0.25

        missing = client.get("/api/v1/checks/absent", headers=auth)
        assert missing.status_code == 503
    finally:
        client.__exit__(None, None, None)


def test_incident_lookup_failure_does_not_change_check_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot(("healthy", "Healthy", None, (_result("healthy", success=True),)))
    client, auth = _client(tmp_path, _StubCache(snapshot))
    monkeypatch.setattr(
        "alert_hub.api.checks._load_incident_relations",
        lambda db, ids, **kwargs: None,
    )
    try:
        listing = client.get("/api/v1/checks", headers=auth)
        assert listing.status_code == 200
        assert listing.json()["items"][0]["status"] == "up"
        assert listing.json()["items"][0]["active_alerts"] is None

        detail = client.get("/api/v1/checks/healthy", headers=auth)
        assert detail.status_code == 200
        assert detail.json()["check"]["status"] == "up"
        assert detail.json()["check"]["alerts_available"] is False
        assert detail.json()["check"]["relations_incomplete"] is True
    finally:
        client.__exit__(None, None, None)


@pytest.mark.parametrize(
    ("path", "empty_field"),
    [
        ("/api/v1/checks", "items"),
        ("/api/v1/checks/summary", "problem_checks"),
        ("/api/v1/checks/bounded-response", "check"),
    ],
)
def test_checks_api_response_size_limit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    empty_field: str,
) -> None:
    snapshot = _snapshot(
        (
            "bounded-response",
            "Bounded response",
            None,
            (_result("bounded-response", success=True),),
        )
    )
    monkeypatch.setattr("alert_hub.api.checks._MAX_API_RESPONSE_BYTES", 1)
    client, auth = _client(tmp_path, _StubCache(snapshot))
    try:
        response = client.get(path, headers=auth)
        assert response.status_code == 503
        assert response.json()["data_state"] == "unavailable"
        assert response.json()["error_code"] == "checks_limit_exceeded"
        assert response.json()[empty_field] in ([], None)
    finally:
        client.__exit__(None, None, None)


def test_checks_openapi_declares_models_and_error_statuses(tmp_path: Path) -> None:
    schema = create_app(_settings(tmp_path, enabled=True)).openapi()
    paths = schema["paths"]
    assert set(paths["/api/v1/checks"]["get"]["responses"]) >= {"200", "401", "422", "503"}
    assert set(paths["/api/v1/checks/summary"]["get"]["responses"]) >= {
        "200",
        "401",
        "422",
        "503",
    }
    assert set(paths["/api/v1/checks/{check_id}"]["get"]["responses"]) >= {
        "200",
        "401",
        "404",
        "422",
        "503",
    }
    schemas = schema["components"]["schemas"]
    for model in ("ChecksListResponse", "ChecksSummaryResponse", "CheckDetailResponse"):
        assert model in schemas
    assert paths["/api/v1/checks/summary"]["get"]["operationId"].startswith("checks_summary")


def test_last_known_pagination_retains_the_filtered_total(tmp_path: Path) -> None:
    previous = _snapshot(
        *(
            (f"check-{index}", "Same", None, (_result(f"check-{index}", success=True),))
            for index in range(3)
        )
    )
    client, auth = _client(
        tmp_path,
        _StubCache(ChecksDataError("prometheus_unavailable"), previous=previous),
    )
    try:
        response = client.get("/api/v1/checks?limit=1", headers=auth)
        assert response.status_code == 503
        assert len(response.json()["last_known"]["items"]) == 1
        assert response.json()["last_known"]["total"] == 3
    finally:
        client.__exit__(None, None, None)


@pytest.mark.parametrize(
    "invalid_id",
    ["10.0.0.1", "123e4567-e89b-12d3-a456-426614174000", "__alert_hub_reserved"],
)
def test_detail_uses_the_metric_identifier_validator(tmp_path: Path, invalid_id: str) -> None:
    client, auth = _client(tmp_path, _StubCache(_snapshot()))
    try:
        response = client.get(f"/api/v1/checks/{invalid_id}", headers=auth)
        assert response.status_code == 422
        assert response.json() == {"detail": "Invalid check identifier"}
    finally:
        client.__exit__(None, None, None)
