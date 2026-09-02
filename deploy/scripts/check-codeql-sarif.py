#!/usr/bin/env python3
"""Fail closed on CodeQL results except one fully pinned reviewed finding."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[2]
APPROVED_FINDINGS = {
    (
        "py/insecure-cookie",
        "backend/alert_hub/api/auth.py",
        50,
        5,
        59,
        6,
        "unspecified",
        "Cookie is added without the HttpOnly attribute properly set.",
    ),
}
REVIEWED_SOURCE_DIGESTS = {
    "backend/alert_hub/api/auth.py": (
        "4f1a3de109386c007c70d744ec0b2a31af2839b993ae6cffeca12f72b36ccd8e"
    ),
    "backend/alert_hub/api/dependencies.py": (
        "3c6f31d61bcef3950ce5fc2564b0f683e24f85004f32eda34d3193d9e7d91556"
    ),
    "backend/alert_hub/application/auth.py": (
        "80d393b5300b561ae9eab121ba0f0a8137777becfe54b4d6dca24c130fa2b8b4"
    ),
    "backend/alert_hub/security.py": (
        "912f34432dbc46a2c801096d61fc5065bd2bf2c48c28c8acbd0b93707163cb58"
    ),
}
APPROVED_SOURCE = (
    "    # This random double-submit value must remain readable by the same-origin",
    "    # client. It cannot authenticate a request: the API also requires the",
    "    # HttpOnly refresh cookie, one exact trusted Origin, and an equal header.",
    "    # codeql[py/insecure-cookie]",
    "    response.set_cookie(",
    "        settings.csrf_cookie_name,",
    "        issued.csrf_token,",
    "        httponly=False,",
    "        max_age=settings.refresh_absolute_days * 86_400,",
    '        path="/",',
    "        secure=settings.cookie_secure,",
    '        samesite="strict",',
    "        domain=settings.cookie_domain,",
    "    )",
)


def _primary_location(result: Mapping[str, Any]) -> tuple[str, int, int, int, int] | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or len(locations) != 1:
        return None
    location = locations[0]
    if not isinstance(location, Mapping):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not isinstance(artifact, Mapping) or not isinstance(region, Mapping):
        return None
    uri = artifact.get("uri")
    if (
        artifact.get("uriBaseId") != "%SRCROOT%"
        or type(artifact.get("index")) is not int
        or artifact["index"] != 0
    ):
        return None
    coordinates = (
        region.get("startLine"),
        region.get("startColumn"),
        region.get("endLine"),
        region.get("endColumn"),
    )
    if not isinstance(uri, str) or any(type(value) is not int for value in coordinates):
        return None
    return (
        uri,
        int(coordinates[0]),
        int(coordinates[1]),
        int(coordinates[2]),
        int(coordinates[3]),
    )


def _source_matches_reviewed_finding(repository: Path, uri: str, line: int) -> bool:
    try:
        lines = (repository / uri).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False
    source_index = line - 5
    if source_index < 0:
        return False
    actual = tuple(lines[source_index : source_index + len(APPROVED_SOURCE)])
    return actual == APPROVED_SOURCE


def _reviewed_sources_match(repository: Path) -> bool:
    for uri, approved_digest in REVIEWED_SOURCE_DIGESTS.items():
        path = repository / uri
        if path.is_symlink():
            return False
        try:
            actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return False
        if actual_digest != approved_digest:
            return False
    return True


def _is_approved_finding(
    result: Mapping[str, Any],
    repository: Path = REPOSITORY,
) -> bool:
    """Accept only the reviewed browser-readable double-submit CSRF cookie."""

    location = _primary_location(result)
    if location is None:
        return False
    message = result.get("message")
    if not isinstance(message, Mapping) or not isinstance(message.get("text"), str):
        return False
    if result.get("level") is not None:
        return False
    signature = (
        result.get("ruleId"),
        *location,
        str(result.get("level") or "unspecified"),
        message["text"],
    )
    if result.get("suppressions") is not None or signature not in APPROVED_FINDINGS:
        return False
    return _source_matches_reviewed_finding(
        repository, location[0], location[1]
    ) and _reviewed_sources_match(repository)


def _document_results(path: Path) -> Iterable[Mapping[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot read SARIF: {exc}") from exc
    if not isinstance(document, Mapping):
        raise TypeError(f"{path}: SARIF root must be an object")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise TypeError(f"{path}: SARIF must contain at least one run")
    for run_index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            raise TypeError(f"{path}: run {run_index} must be an object")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise TypeError(f"{path}: run {run_index} results must be an array")
        for result_index, result in enumerate(results):
            if not isinstance(result, Mapping):
                raise TypeError(f"{path}: run {run_index} result {result_index} must be an object")
            yield result


def _display(result: Mapping[str, Any]) -> str:
    rule_id = str(result.get("ruleId", "unknown-rule"))
    level = str(result.get("level") or "unspecified")
    location = _primary_location(result)
    where = f"{location[0]}:{location[1]}" if location is not None else "unknown-location"
    message = result.get("message")
    text = message.get("text", "") if isinstance(message, Mapping) else ""
    normalized = " ".join(str(text).split())
    return f"{rule_id}\t{level}\t{where}\t{normalized}"


def main(arguments: Sequence[str] | None = None) -> int:
    paths = list(arguments if arguments is not None else sys.argv[1:])
    if not paths:
        print("No CodeQL SARIF files were provided.", file=sys.stderr)
        return 2

    findings: list[Mapping[str, Any]] = []
    try:
        for raw_path in paths:
            findings.extend(
                result
                for result in _document_results(Path(raw_path))
                if not _is_approved_finding(result)
            )
    except (TypeError, ValueError) as exc:
        print(f"Invalid CodeQL SARIF: {exc}", file=sys.stderr)
        return 2

    if not findings:
        return 0
    print(f"CodeQL reported {len(findings)} non-approved finding(s):", file=sys.stderr)
    for finding in findings:
        print(_display(finding), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
