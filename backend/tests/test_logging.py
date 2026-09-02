from __future__ import annotations

import io
import json
import logging
import re
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient

from alert_hub.infrastructure.logging import (
    JsonLogFormatter,
    TextLogFormatter,
    configure_logging,
)
from alert_hub.main import create_app
from alert_hub.settings import Settings


def test_json_formatter_has_utc_context_and_redacted_bounded_fields() -> None:
    try:
        raise ValueError("authorization=Bearer exception-secret password='hunter2'")
    except ValueError:
        exception_info = sys.exc_info()

    record = logging.LogRecord(
        name="alert_hub.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="delivery failed access_token=message-secret",
        args=(),
        exc_info=exception_info,
    )
    record.event = "delivery_failed"
    record.request_id = "request-123"
    record.incident_id = "incident-123"
    record.authorization = "Bearer structured-secret"
    record.cookie = "session=cookie-secret"
    record.body = {"password": "body-secret"}
    record.peer_url = "https://10.0.0.5/private"

    rendered = JsonLogFormatter().format(record)
    payload = json.loads(rendered)

    assert payload["timestamp"].endswith("Z")
    assert payload["level"] == "ERROR"
    assert payload["logger"] == "alert_hub.test"
    assert payload["event"] == "delivery_failed"
    assert payload["request_id"] == "request-123"
    assert payload["incident_id"] == "incident-123"
    assert payload["exception"]["type"] == "ValueError"
    assert "Traceback" in payload["exception"]["trace"]
    assert "authorization" not in payload
    assert "cookie" not in payload
    assert "body" not in payload
    assert "peer_url" not in payload
    for secret in (
        "message-secret",
        "exception-secret",
        "hunter2",
        "structured-secret",
        "cookie-secret",
        "body-secret",
        "10.0.0.5",
    ):
        assert secret not in rendered


def test_text_formatter_and_runtime_configuration_disable_uvicorn_access() -> None:
    record = logging.LogRecord(
        name="alert_hub.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="http_request_completed",
        args=(),
        exc_info=None,
    )
    record.request_id = "request-456"
    rendered = TextLogFormatter().format(record)
    assert rendered.endswith('http_request_completed request_id="request-456"')

    configure_logging("ERROR", "text")
    assert logging.getLogger("alert_hub").level == logging.ERROR
    assert logging.getLogger("uvicorn.error").level == logging.ERROR
    assert logging.getLogger("uvicorn.access").disabled is True


def _capture_app_logs(app: FastAPI) -> tuple[io.StringIO, logging.Handler]:
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(JsonLogFormatter())
    application_logger = logging.getLogger("alert_hub")
    application_logger.handlers = [handler]
    application_logger.setLevel(logging.INFO)
    return output, handler


def test_request_logs_and_request_id_cover_early_and_exception_responses(
    settings: Settings,
) -> None:
    runtime_settings = settings.model_copy(
        update={
            "ingest_enabled": False,
            "bootstrap_rate_limit_attempts": 1,
            "max_payload_bytes": 1_024,
        }
    )
    app = create_app(runtime_settings)

    @app.get("/test/unhandled")
    async def unhandled() -> None:
        raise RuntimeError("authorization=Bearer exception-path-secret")

    output, handler = _capture_app_logs(app)
    try:
        with TestClient(app, base_url="http://testserver", raise_server_exceptions=False) as client:
            invalid_length = client.get(
                "/health/ready",
                headers={"Content-Length": "invalid", "X-Request-ID": "bad length id"},
            )
            assert invalid_length.status_code == 400
            assert invalid_length.headers["X-Request-ID"] != "bad length id"
            assert re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                invalid_length.headers["X-Request-ID"],
            )

            too_large = client.post(
                "/api/v1/auth/login",
                content=b"{}",
                headers={"Content-Length": "1025", "X-Request-ID": "too-large"},
            )
            assert too_large.status_code == 413
            assert too_large.headers["X-Request-ID"] == "too-large"

            disabled = client.post(
                "/ingest/v1/generic/missing",
                content=b"{}",
                headers={"X-Request-ID": "role-disabled"},
            )
            assert disabled.status_code == 503
            assert disabled.headers["X-Request-ID"] == "role-disabled"

            query = client.get(
                "/health/ready?access_token=query-secret",
                headers={"X-Request-ID": "query-redacted"},
            )
            assert query.status_code == 200
            assert query.headers["X-Request-ID"] == "query-redacted"

            first_bootstrap = client.post(
                "/api/v1/auth/bootstrap",
                json={},
                headers={"X-Request-ID": "bootstrap-first"},
            )
            assert first_bootstrap.status_code == 422
            rate_limited = client.post(
                "/api/v1/auth/bootstrap",
                json={},
                headers={"X-Request-ID": "bootstrap-limited"},
            )
            assert rate_limited.status_code == 429
            assert rate_limited.headers["X-Request-ID"] == "bootstrap-limited"
            assert rate_limited.headers["Retry-After"]

            failed = client.get(
                "/test/unhandled",
                headers={
                    "Authorization": "Bearer request-header-secret",
                    "Cookie": "session=request-cookie-secret",
                    "X-Request-ID": "exception-request",
                },
            )
            assert failed.status_code == 500
            assert failed.json() == {"detail": "Internal server error"}
            assert failed.headers["X-Request-ID"] == "exception-request"
    finally:
        logging.getLogger("alert_hub").removeHandler(handler)
        configure_logging(runtime_settings.log_level, runtime_settings.log_format)

    records = [json.loads(line) for line in output.getvalue().splitlines()]
    by_request_id = {record["request_id"]: record for record in records if "request_id" in record}
    assert by_request_id[invalid_length.headers["X-Request-ID"]]["status"] == 400
    assert by_request_id["too-large"]["status"] == 413
    assert by_request_id["role-disabled"]["status"] == 503
    assert by_request_id["query-redacted"]["path"] == "/health/ready"
    assert by_request_id["bootstrap-limited"]["status"] == 429
    assert by_request_id["exception-request"]["status"] == 500
    assert by_request_id["exception-request"]["event"] == "http_request_failed"
    assert by_request_id["exception-request"]["exception"]["type"] == "RuntimeError"
    rendered = output.getvalue()
    assert "exception-path-secret" not in rendered
    assert "request-header-secret" not in rendered
    assert "request-cookie-secret" not in rendered
    assert "query-secret" not in rendered
