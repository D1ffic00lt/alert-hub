from __future__ import annotations

import json
import logging
import math
import re
import sys
from datetime import UTC, datetime
from typing import Final

_SAFE_EXTRA_FIELDS: Final[tuple[str, ...]] = (
    "request_id",
    "node_id",
    "method",
    "path",
    "status",
    "duration_ms",
    "scope",
    "retry_after",
    "source_id",
    "incident_id",
    "channel_id",
    "route_id",
    "item_id",
    "event_id",
    "origin_node_id",
    "origin_seq",
    "peer_node_id",
    "failure_count",
    "attempt",
    "error_code",
    "exception_type",
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:authorization|set-cookie|cookie|password|passwd|token|secret|"
    r"credential|api[_-]?key|private[_-]?key)[a-z0-9_-]*)\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_MAX_FIELD_LENGTH: Final = 2_048
_MAX_TRACE_LENGTH: Final = 16_384


def _redact(value: str, *, limit: int = _MAX_FIELD_LENGTH) -> str:
    redacted = _BEARER_VALUE.sub("Bearer [REDACTED]", value)
    redacted = _SENSITIVE_VALUE.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)
    if len(redacted) > limit:
        return f"{redacted[:limit]}...[truncated]"
    return redacted


def _safe_extra(value: object) -> str | int | float | bool | None:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _redact(value)
    return None


def _timestamp(record: logging.LogRecord) -> str:
    return (
        datetime.fromtimestamp(record.created, tz=UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _exception_fields(
    formatter: logging.Formatter,
    record: logging.LogRecord,
) -> tuple[str, str] | None:
    if record.exc_info is None:
        return None
    exception_type = record.exc_info[0].__name__ if record.exc_info[0] is not None else "Exception"
    trace = _redact(formatter.formatException(record.exc_info), limit=_MAX_TRACE_LENGTH)
    return exception_type, trace


class JsonLogFormatter(logging.Formatter):
    """Emit one bounded JSON object containing only explicitly safe context fields."""

    def format(self, record: logging.LogRecord) -> str:
        message = _redact(record.getMessage())
        event = _safe_extra(getattr(record, "event", None))
        payload: dict[str, object] = {
            "timestamp": _timestamp(record),
            "level": record.levelname,
            "logger": record.name,
            "event": event if isinstance(event, str) and event else message,
            "message": message,
        }
        for field in _SAFE_EXTRA_FIELDS:
            value = _safe_extra(getattr(record, field, None))
            if value is not None:
                payload[field] = value
        exception = _exception_fields(self, record)
        if exception is not None:
            payload["exception"] = {"type": exception[0], "trace": exception[1]}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


class TextLogFormatter(logging.Formatter):
    """Human-readable local format with the same field allowlist and redaction boundary."""

    def format(self, record: logging.LogRecord) -> str:
        message = _redact(record.getMessage())
        parts = [_timestamp(record), record.levelname, record.name, message]
        for field in _SAFE_EXTRA_FIELDS:
            value = _safe_extra(getattr(record, field, None))
            if value is not None:
                parts.append(f"{field}={json.dumps(value, ensure_ascii=False)}")
        exception = _exception_fields(self, record)
        if exception is not None:
            parts.append(f"exception_type={exception[0]}")
            parts.append(exception[1])
        return " ".join(parts)


def configure_logging(level: str, log_format: str) -> None:
    """Configure Alert Hub and Uvicorn once per app factory invocation."""

    formatter: logging.Formatter = (
        JsonLogFormatter() if log_format == "json" else TextLogFormatter()
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(formatter)

    application_logger = logging.getLogger("alert_hub")
    application_logger.handlers = [handler]
    application_logger.setLevel(level)
    application_logger.propagate = False

    uvicorn_logger = logging.getLogger("uvicorn")
    uvicorn_logger.handlers = [handler]
    uvicorn_logger.setLevel(level)
    uvicorn_logger.propagate = False
    for logger_name in ("uvicorn.error", "uvicorn.asgi"):
        child_logger = logging.getLogger(logger_name)
        child_logger.handlers = []
        child_logger.setLevel(level)
        child_logger.propagate = True

    access_logger = logging.getLogger("uvicorn.access")
    access_logger.handlers = []
    access_logger.propagate = False
    access_logger.disabled = True
