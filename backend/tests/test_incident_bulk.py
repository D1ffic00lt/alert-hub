from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import select

from alert_hub.infrastructure.db.models import IncidentEvent


def _create_source(client: TestClient, auth: dict[str, str]) -> dict[str, Any]:
    response = client.post(
        "/api/v1/sources",
        headers=auth,
        json={"name": "Bulk source", "kind": "generic_json", "region": "test"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_incident(
    client: TestClient,
    source: dict[str, Any],
    *,
    key: str,
    severity: str = "critical",
    title: str | None = None,
) -> str:
    response = client.post(
        f"/ingest/v1/events/{source['id']}",
        headers={"Authorization": f"Bearer {source['token']}"},
        json={
            "schema_version": 1,
            "external_event_id": key,
            "dedup_key": key,
            "status": "firing",
            "title": title or f"Bulk incident {key}",
            "description": f"Description for {key}",
            "severity": severity,
            "starts_at": "2026-09-01T12:00:00Z",
            "labels": {"target_name": f"target-{key}", "source_region": "test"},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == 1
    return str(response.json()["incident_ids"][0])


def test_incident_list_filters_on_server_and_compact_view_is_bounded(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
) -> None:
    source = _create_source(client, auth)
    first_id = _create_incident(client, source, key="alpha", title="API percent % incident")
    _create_incident(client, source, key="beta", severity="warning")
    resolved_id = _create_incident(client, source, key="gamma")
    resolved = client.post(
        f"/api/v1/incidents/{resolved_id}/resolve",
        headers=auth,
        json={},
    )
    assert resolved.status_code == 200, resolved.text

    selects: list[str] = []

    def capture_selects(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        if statement.lstrip().lower().startswith("select"):
            selects.append(statement)

    sqlalchemy_event.listen(app.state.engine, "before_cursor_execute", capture_selects)
    try:
        response = client.get(
            "/api/v1/incidents",
            headers=auth,
            params={
                "status": "active",
                "severity": "critical",
                "q": "%",
                "view": "compact",
            },
        )
    finally:
        sqlalchemy_event.remove(app.state.engine, "before_cursor_execute", capture_selects)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 1
    assert payload["counts"] == {
        "active": 1,
        "open": 1,
        "acknowledged": 0,
        "resolved": 0,
        "silenced": 0,
        "all": 1,
    }
    assert payload["bulk_limit"] == 500
    assert payload["items"] == [
        {
            **payload["items"][0],
            "id": first_id,
            "title": "API percent % incident",
            "region": "test",
            "target": "target-alpha",
            "summary_only": True,
        }
    ]
    assert "description" not in payload["items"][0]
    assert "labels" not in payload["items"][0]
    assert "annotations" not in payload["items"][0]
    incident_selects = [
        statement
        for statement in selects
        if " incidents " in f" {' '.join(statement.lower().split())} "
        or " sources " in f" {' '.join(statement.lower().split())} "
    ]
    # Status counts, the incident page and its batched source load stay constant-size;
    # the two bearer-session queries are deliberately outside this endpoint budget.
    assert len(incident_selects) == 3
    page_statement = next(
        statement
        for statement in incident_selects
        if "order by incidents.last_event_at desc" in " ".join(statement.lower().split())
    )
    normalized_page_statement = " ".join(page_statement.lower().split())
    selected_columns = normalized_page_statement.split(" from incidents", maxsplit=1)[0]
    assert "incidents.labels_json" in selected_columns
    assert "incidents.description" not in selected_columns
    assert "incidents.fingerprint" not in selected_columns
    assert "incidents.annotations_json" not in selected_columns
    assert "incidents.status in" in normalized_page_statement


def test_bulk_incident_action_reports_partial_and_idempotent_results(
    client: TestClient,
    auth: dict[str, str],
    app: Any,
) -> None:
    source = _create_source(client, auth)
    first_id = _create_incident(client, source, key="first")
    second_id = _create_incident(client, source, key="second")
    resolved_id = _create_incident(client, source, key="resolved")
    assert (
        client.post(
            f"/api/v1/incidents/{resolved_id}/resolve",
            headers=auth,
            json={},
        ).status_code
        == 200
    )
    missing_id = "00000000-0000-0000-0000-000000000000"

    partial = client.post(
        "/api/v1/incidents/bulk-action",
        headers=auth,
        json={
            "action": "acknowledge",
            "selection_mode": "ids",
            "incident_ids": [first_id, resolved_id, missing_id],
            "reason": "operator accepted the bulk selection",
        },
    )
    assert partial.status_code == 207, partial.text
    payload = partial.json()
    assert (payload["matched"], payload["updated"], payload["unchanged"], payload["failed"]) == (
        3,
        1,
        0,
        2,
    )
    assert [result["outcome"] for result in payload["results"]] == [
        "updated",
        "conflict",
        "not_found",
    ]

    repeated = client.post(
        "/api/v1/incidents/bulk-action",
        headers=auth,
        json={
            "action": "acknowledge",
            "selection_mode": "ids",
            "incident_ids": [first_id],
        },
    )
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["updated"] == 0
    assert repeated.json()["unchanged"] == 1

    filtered = client.post(
        "/api/v1/incidents/bulk-action",
        headers=auth,
        json={
            "action": "silence",
            "selection_mode": "filter",
            "excluded_incident_ids": [first_id],
            "filters": {"status": "active", "severity": "critical", "q": "Bulk incident"},
        },
    )
    assert filtered.status_code == 200, filtered.text
    assert filtered.json()["matched"] == 1
    assert filtered.json()["results"][0] == {
        "incident_id": second_id,
        "outcome": "updated",
        "status": "silenced",
        "detail": None,
    }

    with app.state.session_factory() as db:
        acknowledged = db.scalars(
            select(IncidentEvent).where(
                IncidentEvent.incident_id == first_id,
                IncidentEvent.event_type == "acknowledged",
            )
        ).all()
        assert len(acknowledged) == 1


def test_bulk_incident_action_requires_bearer_auth_without_cookie_csrf(
    client: TestClient,
    auth: dict[str, str],
) -> None:
    body = {
        "action": "resolve",
        "selection_mode": "ids",
        "incident_ids": ["00000000-0000-0000-0000-000000000000"],
    }
    assert client.post("/api/v1/incidents/bulk-action", json=body).status_code == 401
    bearer_only = client.post("/api/v1/incidents/bulk-action", headers=auth, json=body)
    assert bearer_only.status_code == 207
    assert bearer_only.json()["results"][0]["outcome"] == "not_found"
    # Access tokens are bearer-authenticated, not cookie-authenticated. An Origin
    # header cannot weaken or strengthen that boundary; cookie mutations are the
    # only ones that require the separate Origin/CSRF check.
    without_csrf = {key: value for key, value in auth.items() if key.lower() != "x-csrf-token"}
    assert (
        client.post(
            "/api/v1/incidents/bulk-action",
            headers={**without_csrf, "Origin": "https://attacker.example"},
            json=body,
        ).status_code
        == 207
    )


def test_bulk_incident_action_rejects_ambiguous_selection(
    client: TestClient,
    auth: dict[str, str],
) -> None:
    response = client.post(
        "/api/v1/incidents/bulk-action",
        headers=auth,
        json={
            "action": "resolve",
            "selection_mode": "ids",
            "incident_ids": ["00000000-0000-0000-0000-000000000000"],
            "filters": {"status": "active"},
        },
    )
    assert response.status_code == 422


def test_bulk_incident_action_openapi_documents_partial_response(app: Any) -> None:
    schema = app.openapi()
    operation = schema["paths"]["/api/v1/incidents/bulk-action"]["post"]
    responses = operation["responses"]
    assert {"200", "207", "401", "422"} <= set(responses)
    for status in ("200", "207"):
        assert responses[status]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/IncidentBulkActionResponse"
        }
