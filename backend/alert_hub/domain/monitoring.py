from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from urllib.parse import urlsplit, urlunsplit

DEFAULT_KEY_JOB_GLOBS = ("prometheus", "alertmanager", "blackbox*")
DEFAULT_ALERT_HUB_JOB_GLOBS = ("alert-hub*", "alert_hub*", "alerthub*")
MAX_JOB_GLOBS = 32
MAX_JOB_GLOB_LENGTH = 128

_JOB_GLOB = re.compile(r"[A-Za-z0-9_.:/-]*(?:\*[A-Za-z0-9_.:/-]*)*")


def normalize_grafana_url(value: object, *, https_only: bool = False) -> str | None:
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    if len(candidate) > 2_048:
        raise ValueError("Grafana URL must not exceed 2048 characters")
    if (
        "*" in candidate
        or "\\" in candidate
        or any(
            character.isspace() or unicodedata.category(character) == "Cc"
            for character in candidate
        )
    ):
        raise ValueError("Grafana URL must not contain wildcards, backslashes, or whitespace")
    try:
        parsed = urlsplit(candidate)
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("Grafana URL is invalid") from exc
    allowed_schemes = {"https"} if https_only else {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes or not parsed.hostname:
        protocol = "https" if https_only else "http or https"
        raise ValueError(f"Grafana URL must use {protocol} and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Grafana URL must not contain credentials")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    netloc = host if parsed_port is None else f"{host}:{parsed_port}"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc.lower(),
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def normalize_job_globs(value: object, *, field_name: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{field_name} must be a list")
    if not 1 <= len(value) <= MAX_JOB_GLOBS:
        raise ValueError(f"{field_name} must contain between 1 and {MAX_JOB_GLOBS} patterns")
    normalized: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise ValueError(f"{field_name} patterns must be strings")
        candidate = raw.strip()
        if (
            not candidate
            or len(candidate) > MAX_JOB_GLOB_LENGTH
            or not _JOB_GLOB.fullmatch(candidate)
        ):
            raise ValueError(
                f"{field_name} patterns may contain letters, digits, '.', '_', ':', '/', '-', "
                "and '*' only"
            )
        if candidate not in normalized:
            normalized.append(candidate)
    if not normalized:
        raise ValueError(f"{field_name} must contain at least one pattern")
    return normalized


def job_globs_to_re2(globs: Sequence[str]) -> str:
    """Convert validated shell-style job globs into one Prometheus-safe RE2 alternation."""

    normalized = normalize_job_globs(globs, field_name="job_globs")
    alternatives: list[str] = []
    for pattern in normalized:
        escaped = "".join(
            ".*" if character == "*" else r"\." if character == "." else character
            for character in pattern
        )
        alternatives.append(escaped)
    return "|".join(alternatives)
