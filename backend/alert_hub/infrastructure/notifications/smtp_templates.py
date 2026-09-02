from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC
from typing import Any

from alert_hub.application.notifications import NotificationMessage

DEFAULT_SMTP_SUBJECT_TEMPLATE = "[{{app_name}}] [{{state}}] [{{severity_upper}}] {{title}}"
DEFAULT_SMTP_BODY_TEMPLATE = "{{body}}{{incident_link}}"

_SUBJECT_TEMPLATE_MAX_LENGTH = 1_000
_BODY_TEMPLATE_MAX_LENGTH = 32_000
_PLACEHOLDER = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)\s*\}\}")
_ALLOWED_PLACEHOLDERS = frozenset(
    {
        "annotations",
        "app_name",
        "body",
        "description",
        "event_id",
        "event_type",
        "incident_id",
        "incident_link",
        "incident_url",
        "labels",
        "occurred_at",
        "severity",
        "severity_upper",
        "source_id",
        "state",
        "status",
        "title",
    }
)


class SMTPTemplateError(ValueError):
    """An SMTP template is unsafe or cannot be rendered deterministically."""


def _validate_template(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise SMTPTemplateError(f"SMTP {field} must be a string")
    if not value.strip():
        raise SMTPTemplateError(f"SMTP {field} must not be empty")
    maximum = (
        _SUBJECT_TEMPLATE_MAX_LENGTH if field == "subject_template" else _BODY_TEMPLATE_MAX_LENGTH
    )
    if len(value) > maximum:
        raise SMTPTemplateError(f"SMTP {field} exceeds {maximum} characters")
    if "\x00" in value:
        raise SMTPTemplateError(f"SMTP {field} contains a null byte")
    if field == "subject_template" and any(ord(character) < 32 for character in value):
        raise SMTPTemplateError("SMTP subject_template contains control characters")

    names = {match.group(1) for match in _PLACEHOLDER.finditer(value)}
    remainder = _PLACEHOLDER.sub("", value)
    if "{{" in remainder or "}}" in remainder:
        raise SMTPTemplateError(f"SMTP {field} contains malformed placeholder syntax")
    unknown = sorted(names - _ALLOWED_PLACEHOLDERS)
    if unknown:
        raise SMTPTemplateError(f"Unknown SMTP template placeholder: {', '.join(unknown)}")
    return value


def normalize_smtp_template_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate configured templates; JSON null resets a template to its default."""

    normalized = dict(config)
    for field in ("subject_template", "body_template"):
        if field not in normalized:
            continue
        if normalized[field] is None:
            normalized.pop(field)
            continue
        normalized[field] = _validate_template(normalized[field], field=field)
    return normalized


def _json_mapping(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise SMTPTemplateError("SMTP template data is not JSON serializable") from exc


def _template_values(message: NotificationMessage) -> dict[str, str]:
    incident_url = message.incident_url or ""
    return {
        "annotations": _json_mapping(message.annotations),
        "app_name": message.app_name,
        "body": message.body or message.title,
        "description": message.body or message.title,
        "event_id": message.event_id,
        "event_type": message.event_type,
        "incident_id": message.incident_id,
        "incident_link": f"\n\nOpen incident: {incident_url}" if incident_url else "",
        "incident_url": incident_url,
        "labels": _json_mapping(message.labels),
        "occurred_at": message.occurred_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "severity": message.severity,
        "severity_upper": message.severity.upper(),
        "source_id": message.source_id,
        "state": "RESOLVED" if message.event_type == "resolved" else "FIRING",
        "status": message.status,
        "title": message.title,
    }


def _render(template: str, values: Mapping[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda match: values[match.group(1)], template)


def _header_safe(value: str) -> str:
    # Template values are data, not RFC 5322 structure. Flatten all control
    # characters before handing the rendered value to the email library.
    return "".join(
        " " if ord(character) < 32 or ord(character) == 127 else character for character in value
    )


def render_smtp_templates(
    config: Mapping[str, Any],
    message: NotificationMessage,
) -> tuple[str, str]:
    normalized = normalize_smtp_template_config(config)
    subject_template = _validate_template(
        normalized.get("subject_template", DEFAULT_SMTP_SUBJECT_TEMPLATE),
        field="subject_template",
    )
    body_template = _validate_template(
        normalized.get("body_template", DEFAULT_SMTP_BODY_TEMPLATE),
        field="body_template",
    )
    values = _template_values(message)
    header_values = {name: _header_safe(value) for name, value in values.items()}
    subject = _render(subject_template, header_values).strip()
    if not subject:
        raise SMTPTemplateError("SMTP subject_template rendered an empty subject")
    return subject, _render(body_template, values)
