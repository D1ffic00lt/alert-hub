#!/usr/bin/env python3
"""Fail closed on CodeQL results except explicitly reviewed suppressions."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

APPROVED_SUPPRESSIONS = {
    (
        "py/insecure-cookie",
        "backend/alert_hub/api/auth.py",
        50,
    ),
}


def _primary_location(result: Mapping[str, Any]) -> tuple[str, int] | None:
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
    line = region.get("startLine")
    if not isinstance(uri, str) or not isinstance(line, int):
        return None
    return uri, line


def _is_approved_suppression(result: Mapping[str, Any]) -> bool:
    suppressions = result.get("suppressions")
    if not isinstance(suppressions, list) or len(suppressions) != 1:
        return False
    suppression = suppressions[0]
    if not isinstance(suppression, Mapping):
        return False
    if suppression.get("kind") != "inSource":
        return False
    # CodeQL omits status for an accepted source annotation. An explicit
    # underReview/rejected/null status must remain an actionable finding.
    if suppression.get("status", "accepted") != "accepted":
        return False

    location = _primary_location(result)
    if location is None:
        return False
    rule_id = result.get("ruleId")
    return (rule_id, *location) in APPROVED_SUPPRESSIONS


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
                if not _is_approved_suppression(result)
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
