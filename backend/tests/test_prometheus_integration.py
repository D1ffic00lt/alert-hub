from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from alert_hub.application.sync import IncomingClusterEvent, apply_cluster_events
from alert_hub.infrastructure.db.models import (
    AuditLog,
    ClusterEvent,
    PrometheusDatasource,
)
from alert_hub.infrastructure.prometheus import (
    FIXED_PROMQL,
    PrometheusHTTPClient,
    PrometheusQueryError,
    basic_authorization_value,
    parse_vector_response,
)
from alert_hub.infrastructure.url_safety import UnsafeURL, validate_monitoring_url
from alert_hub.main import create_app
from alert_hub.settings import Settings


def _vector(*samples: tuple[dict[str, str], float, float]) -> dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {"metric": labels, "value": [timestamp, str(value)]}
                for labels, value, timestamp in samples
            ],
        },
    }


def test_vector_parser_preserves_labels_and_rejects_invalid_values() -> None:
    payload = _vector(
        (
            {"__name__": "probe_success", "source_region": "ru", "target_name": "nl-1"},
            1,
            1_788_256_800,
        )
    )
    samples = parse_vector_response(payload, max_samples=10)
    assert len(samples) == 1
    assert samples[0].labels["source_region"] == "ru"
    assert samples[0].labels["target_name"] == "nl-1"
    assert samples[0].value == 1
    assert samples[0].timestamp == datetime.fromtimestamp(1_788_256_800, tz=UTC)

    invalid = _vector(({"source_region": "ru", "target_name": "nl"}, float("nan"), 1))
    with pytest.raises(PrometheusQueryError, match="non-finite"):
        parse_vector_response(invalid, max_samples=10)
    with pytest.raises(PrometheusQueryError, match="sample limit"):
        parse_vector_response(payload, max_samples=0)


def test_monitoring_url_requires_explicit_http_private_opt_in() -> None:
    with pytest.raises(UnsafeURL, match="HTTPS"):
        validate_monitoring_url("http://10.0.0.2:9090")
    with pytest.raises(UnsafeURL, match="private"):
        validate_monitoring_url("http://10.0.0.2:9090", allow_http=True)
    assert (
        validate_monitoring_url(
            "http://10.0.0.2:9090/",
            allow_http=True,
            allow_private=True,
        )
        == "http://10.0.0.2:9090"
    )
    with pytest.raises(UnsafeURL, match="link-local"):
        validate_monitoring_url(
            "http://169.254.169.254/latest/meta-data",
            allow_http=True,
            allow_private=True,
        )
    with pytest.raises(UnsafeURL, match="embedded credentials"):
        validate_monitoring_url("https://user:password@1.1.1.1")


def test_send_time_dns_revalidation_blocks_rebinding_and_redirects(settings: Settings) -> None:
    resolver_answers = ["1.1.1.1", "169.254.169.254"]
    requests = [0]

    def resolver(
        host: str, port: int, *, type: socket.SocketKind
    ) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
        del host, port, type
        address = resolver_answers.pop(0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 9090))]

    def should_not_send(request: httpx.Request) -> httpx.Response:
        requests[0] += 1
        return httpx.Response(200, request=request, json=_vector())

    client = PrometheusHTTPClient(
        settings,
        resolver=resolver,
        transport=httpx.MockTransport(should_not_send),
    )
    assert client.validate_url("https://prometheus.example") == "https://prometheus.example"
    with pytest.raises(PrometheusQueryError) as rebound:
        asyncio.run(
            client.query("https://prometheus.example", {"auth_type": "none"}, "reachability")
        )
    assert rebound.value.code == "unsafe_url"
    assert requests[0] == 0

    redirect_client = PrometheusHTTPClient(
        settings,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                302,
                request=request,
                headers={"Location": "http://127.0.0.1:9090"},
            )
        ),
    )
    with pytest.raises(PrometheusQueryError) as redirected:
        asyncio.run(redirect_client.query("https://1.1.1.1", {"auth_type": "none"}, "reachability"))
    assert redirected.value.code == "redirect_rejected"


def test_datasource_crud_encrypts_redacts_auth_and_tests_connection(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    seen_authorization: list[str] = []

    def prometheus(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers.get("authorization", ""))
        assert request.url.params["query"] == FIXED_PROMQL["connection_test"]
        return httpx.Response(200, request=request, json=_vector(({}, 1, 1_788_256_800)))

    app.state.prometheus_http_transport = httpx.MockTransport(prometheus)
    bearer = "prometheus-bearer-secret"
    created = client.post(
        "/api/v1/prometheus-datasources",
        headers=auth,
        json={
            "name": "Regional Prometheus",
            "url": "https://1.1.1.1:9090/monitoring/",
            "node_id": "ru-node",
            "region": "ru",
            "credentials": {"auth_type": "bearer", "bearer_token": bearer},
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert bearer not in created.text
    assert body["auth_type"] == "bearer"
    assert body["configured_fields"] == ["bearer_token"]
    assert body["url"] == "https://1.1.1.1:9090/monitoring"

    tested = client.post(
        f"/api/v1/prometheus-datasources/{body['id']}/test",
        headers=auth,
    )
    assert tested.status_code == 200, tested.text
    assert seen_authorization[-1] == f"Bearer {bearer}"

    username = "prom-reader"
    password = "basic-password-secret"
    updated = client.patch(
        f"/api/v1/prometheus-datasources/{body['id']}",
        headers=auth,
        json={
            "auth": {
                "auth_type": "basic",
                "username": username,
                "password": password,
            }
        },
    )
    assert updated.status_code == 200, updated.text
    assert username not in updated.text
    assert password not in updated.text
    assert updated.json()["configured_fields"] == ["username", "password"]
    second_test = client.post(
        f"/api/v1/prometheus-datasources/{body['id']}/test",
        headers=auth,
    )
    assert second_test.status_code == 200, second_test.text
    assert seen_authorization[-1] == basic_authorization_value(username, password)

    listing = client.get("/api/v1/prometheus-datasources", headers=auth)
    assert listing.status_code == 200
    assert (
        bearer not in listing.text and username not in listing.text and password not in listing.text
    )

    with app.state.session_factory() as db:
        datasource = db.get(PrometheusDatasource, body["id"])
        assert datasource is not None and datasource.encrypted_credentials is not None
        assert bearer.encode() not in datasource.encrypted_credentials
        assert password.encode() not in datasource.encrypted_credentials
        credentials = app.state.envelope_cipher.decrypt_json(
            datasource.encrypted_credentials,
            context=f"prometheus_datasource:{datasource.id}:credentials",
        )
        assert credentials == {
            "auth_type": "basic",
            "username": username,
            "password": password,
        }
        history = "\n".join(
            str(event.payload_json)
            for event in db.scalars(
                select(ClusterEvent).where(ClusterEvent.entity_type == "prometheus_datasource")
            ).all()
        )
        assert bearer not in history and password not in history

    deleted = client.delete(
        f"/api/v1/prometheus-datasources/{body['id']}",
        headers=auth,
    )
    assert deleted.status_code == 204
    assert client.get("/api/v1/prometheus-datasources", headers=auth).json() == []
    with app.state.session_factory() as db:
        assert db.get(PrometheusDatasource, body["id"]) is None
        actions = {
            entry.action
            for entry in db.scalars(
                select(AuditLog).where(AuditLog.entity_type == "prometheus_datasource")
            ).all()
        }
        assert {
            "prometheus_datasource_created",
            "prometheus_datasource_updated",
            "prometheus_datasource_test_succeeded",
            "prometheus_datasource_deleted",
        } <= actions
        latest = db.scalars(
            select(ClusterEvent)
            .where(ClusterEvent.entity_type == "prometheus_datasource")
            .order_by(ClusterEvent.origin_seq.desc())
        ).first()
        assert latest is not None and latest.operation == "tombstone"


def test_reachability_merges_actual_labels_and_reports_partial_failures(
    client: TestClient,
    auth: dict[str, str],
    app,
) -> None:
    query_values: list[str] = []

    def prometheus(request: httpx.Request) -> httpx.Response:
        query = request.url.params["query"]
        query_values.append(query)
        if request.url.host == "9.9.9.9":
            return httpx.Response(503, request=request)
        if query == FIXED_PROMQL["reachability"]:
            timestamp = 100 if request.url.host == "1.1.1.1" else 200
            value = 1 if request.url.host == "1.1.1.1" else 0
            return httpx.Response(
                200,
                request=request,
                json=_vector(
                    (
                        {
                            "source_region": "ru",
                            "target_name": "nl-edge-1",
                            "target_region": "nl",
                        },
                        value,
                        timestamp,
                    )
                ),
            )
        return httpx.Response(
            200,
            request=request,
            json=_vector(({"alertname": "DatabaseDown", "alertstate": "firing"}, 1, 300)),
        )

    app.state.prometheus_http_transport = httpx.MockTransport(prometheus)
    for index, host in enumerate(("1.1.1.1", "8.8.8.8", "9.9.9.9"), start=1):
        response = client.post(
            "/api/v1/prometheus-datasources",
            headers=auth,
            json={"name": f"Prometheus {index}", "url": f"https://{host}:9090"},
        )
        assert response.status_code == 201, response.text

    reachability = client.get("/api/v1/metrics/reachability", headers=auth)
    assert reachability.status_code == 200, reachability.text
    payload = reachability.json()
    assert payload["status"] == "partial"
    assert payload["datasources"] == 3
    assert payload["cells"] == [
        {
            "source": "ru",
            "source_region": "ru",
            "target": "nl-edge-1",
            "target_name": "nl-edge-1",
            "success": False,
            "probe_success": 0.0,
            "latency": None,
            "latency_ms": None,
            "checked_at": "1970-01-01T00:03:20Z",
            "timestamp": "1970-01-01T00:03:20Z",
            "datasource_id": payload["cells"][0]["datasource_id"],
            "datasource_name": "Prometheus 2",
        }
    ]
    assert payload["errors"][0]["datasource_name"] == "Prometheus 3"
    assert payload["errors"][0]["code"] == "http_error"
    assert query_values.count(FIXED_PROMQL["reachability"]) == 3

    alerts = client.get("/api/v1/metrics/queries/firing_alerts", headers=auth)
    assert alerts.status_code == 200
    assert alerts.json()["status"] == "partial"
    assert alerts.json()["samples"][0]["metric"]["alertname"] == "DatabaseDown"
    assert FIXED_PROMQL["firing_alerts"] in query_values
    assert client.get("/api/v1/metrics/queries/arbitrary", headers=auth).status_code == 422


def test_prometheus_datasource_cluster_projection_and_tombstone(tmp_path: Path) -> None:
    shared = {
        "environment": "test",
        "auto_create_schema": True,
        "signing_key": "shared-prometheus-signing-key",
        "cluster_secret": "shared-prometheus-cluster-key",
        "cookie_secure": False,
        "heartbeat_scan_seconds": 0,
    }
    settings_a = Settings(
        **shared,
        node_id="prom-a",
        database_url=f"sqlite:///{tmp_path / 'prom-a.db'}",
        bootstrap_token="bootstrap-a",
    )
    settings_b = Settings(
        **shared,
        node_id="prom-b",
        database_url=f"sqlite:///{tmp_path / 'prom-b.db'}",
        bootstrap_token="bootstrap-b",
    )
    app_a = create_app(settings_a)
    app_b = create_app(settings_b)
    with (
        TestClient(app_a) as client_a,
        TestClient(app_b),
    ):
        bootstrap = client_a.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_token": "bootstrap-a",
                "username": "admin",
                "password": "a-strong-test-password",
            },
        )
        auth = {"Authorization": f"Bearer {bootstrap.json()['access_token']}"}
        secret = "replicated-prometheus-secret"
        created = client_a.post(
            "/api/v1/prometheus-datasources",
            headers=auth,
            json={
                "name": "Replicated Prometheus",
                "url": "https://1.1.1.1:9090",
                "credentials": {"auth_type": "bearer", "bearer_token": secret},
            },
        )
        datasource_id = created.json()["id"]

        with app_a.state.session_factory() as db:
            upsert = db.scalars(
                select(ClusterEvent).where(
                    ClusterEvent.entity_type == "prometheus_datasource",
                    ClusterEvent.entity_id == datasource_id,
                )
            ).one()
            upsert_occurred_at = upsert.occurred_at
            upsert_payload = dict(upsert.payload_json)
            incoming = IncomingClusterEvent(
                event_id=upsert.event_id,
                origin_node_id=upsert.origin_node_id,
                origin_seq=upsert.origin_seq,
                entity_type=upsert.entity_type,
                entity_id=upsert.entity_id,
                operation=upsert.operation,
                occurred_at=upsert.occurred_at,
                payload=upsert.payload_json,
            )
        with app_b.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [incoming], settings_b).applied == 1
        with app_b.state.session_factory() as db:
            replicated = db.get(PrometheusDatasource, datasource_id)
            assert replicated is not None and replicated.encrypted_credentials is not None
            credentials = app_b.state.envelope_cipher.decrypt_json(
                replicated.encrypted_credentials,
                context=f"prometheus_datasource:{datasource_id}:credentials",
            )
            assert credentials["bearer_token"] == secret

        assert (
            client_a.delete(
                f"/api/v1/prometheus-datasources/{datasource_id}", headers=auth
            ).status_code
            == 204
        )
        with app_a.state.session_factory() as db:
            tombstone = db.scalars(
                select(ClusterEvent)
                .where(
                    ClusterEvent.entity_type == "prometheus_datasource",
                    ClusterEvent.entity_id == datasource_id,
                    ClusterEvent.operation == "tombstone",
                )
                .order_by(ClusterEvent.origin_seq.desc())
            ).first()
            assert tombstone is not None
            incoming_tombstone = IncomingClusterEvent(
                event_id=tombstone.event_id,
                origin_node_id=tombstone.origin_node_id,
                origin_seq=tombstone.origin_seq,
                entity_type=tombstone.entity_type,
                entity_id=tombstone.entity_id,
                operation=tombstone.operation,
                occurred_at=tombstone.occurred_at,
                payload=tombstone.payload_json,
            )
        with app_b.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [incoming_tombstone], settings_b).applied == 1
        with app_b.state.session_factory() as db:
            assert db.get(PrometheusDatasource, datasource_id) is None

        stale_upsert = IncomingClusterEvent(
            event_id="00000000-0000-0000-0000-000000009999",
            origin_node_id="stale-prometheus-node",
            origin_seq=1,
            entity_type="prometheus_datasource",
            entity_id=datasource_id,
            operation="upsert",
            occurred_at=upsert_occurred_at - timedelta(seconds=1),
            payload=upsert_payload,
        )
        with app_b.state.session_factory.begin() as db:
            assert apply_cluster_events(db, [stale_upsert], settings_b).applied == 1
        with app_b.state.session_factory() as db:
            assert db.get(PrometheusDatasource, datasource_id) is None
