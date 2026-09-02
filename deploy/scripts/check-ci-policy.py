#!/usr/bin/env python3
"""Fail closed when GitHub workflow trust or pull-request policy drifts."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_ACTION = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
WRITE_PERMISSION = re.compile(r"(^|-)write$")
REQUIRED_CODEOWNER_PATTERNS = {
    "*",
    "/.github/deploy/",
    "/.github/workflows/",
    "/backend/migrations/",
    "/backend/Dockerfile",
    "/deploy/",
    "/docker-compose*.yml",
    "/frontend/Dockerfile",
    "/AGENTS.md",
}
REQUIRED_AGENT_MARKERS = {
    "# Alert Hub agent guide",
    "## Product invariants",
    "## Security rules",
    "## Tests and definition of done",
}
PRODUCTION_WORKFLOWS = {"deploy.yml", "rollback.yml"}
ROOT_WRAPPER = re.compile(
    r"\bsudo(?:\s+--?[A-Za-z0-9_=,.-]+)*\s+"
    r"/usr/local/sbin/docker-(?:deploy|rollback|status)-node\.sh(?:\s|$)"
)


def _load_workflow(path: Path) -> Mapping[str, Any]:
    try:
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"{path}: cannot parse workflow: {exc}") from exc
    if not isinstance(document, Mapping):
        raise TypeError(f"{path}: workflow root must be a mapping")
    return document


def _steps(workflow: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, Mapping):
        return
    for job in jobs.values():
        if not isinstance(job, Mapping):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, Mapping):
                yield step


def _pull_request_jobs(
    workflow: Mapping[str, Any],
) -> Iterable[tuple[str, Mapping[str, Any]]]:
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, Mapping):
        return
    for name, job in jobs.items():
        if not isinstance(job, Mapping):
            continue
        condition = str(job.get("if", "")).replace('"', "'").lower()
        excludes_pull_requests = (
            "github.event_name == 'push'" in condition
            or "github.event_name != 'pull_request'" in condition
            or "github.event_name == 'schedule'" in condition
            or "github.event_name == 'workflow_dispatch'" in condition
        )
        if not excludes_pull_requests:
            yield str(name), job


def _permission_errors(
    path: Path,
    workflow: Mapping[str, Any],
    top_permissions: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    for job_name, job in _pull_request_jobs(workflow):
        job_permissions = job.get("permissions", top_permissions)
        if not isinstance(job_permissions, Mapping):
            failures.append(
                f"{path}: PR job {job_name!r} must use an explicit read-only permission mapping"
            )
            continue
        writes = [
            str(scope)
            for scope, access in job_permissions.items()
            if WRITE_PERMISSION.search(str(access).lower())
        ]
        if writes:
            failures.append(
                f"{path}: PR job {job_name!r} requests write permissions: {', '.join(writes)}"
            )
    return failures


def _trigger_errors(path: Path, workflow: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    triggers = workflow.get("on", {})
    if not isinstance(triggers, Mapping):
        return failures
    if "pull_request_target" in triggers:
        failures.append(f"{path}: pull_request_target is forbidden")
    if "pull_request" not in triggers:
        return failures
    pull_request = triggers.get("pull_request")
    if not isinstance(pull_request, Mapping):
        failures.append(f"{path}: pull_request branches must be exactly [main]")
        return failures
    branches = pull_request.get("branches")
    normalized = [str(branch) for branch in branches] if isinstance(branches, list) else []
    if normalized != ["main"]:
        failures.append(
            f"{path}: pull_request branches must be exactly [main], got {normalized or branches!r}"
        )
    permissions = workflow.get("permissions")
    if not isinstance(permissions, Mapping) or permissions.get("contents") != "read":
        failures.append(f"{path}: PR workflow must declare top-level contents: read")
        permissions = {}
    failures.extend(_permission_errors(path, workflow, permissions))
    return failures


def _action_errors(path: Path, workflow: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for step in _steps(workflow):
        action = step.get("uses")
        if action is None:
            continue
        action = str(action)
        if action.startswith("./"):
            continue
        if action.startswith("docker://"):
            if not DIGEST_ACTION.fullmatch(action):
                failures.append(f"{path}: Docker action is not pinned by digest: {action}")
            continue
        _, separator, ref = action.rpartition("@")
        if not separator or not FULL_SHA.fullmatch(ref):
            failures.append(f"{path}: action is not pinned to a full commit SHA: {action}")
            continue
        if action.startswith("actions/checkout@"):
            options = step.get("with", {})
            persist = options.get("persist-credentials") if isinstance(options, Mapping) else None
            if str(persist).lower() != "false":
                failures.append(f"{path}: actions/checkout must set persist-credentials: false")
    return failures


def _production_workflow_errors(path: Path, workflow: Mapping[str, Any]) -> list[str]:
    if path.name not in PRODUCTION_WORKFLOWS:
        return []

    failures: list[str] = []
    triggers = workflow.get("on", {})
    if not isinstance(triggers, Mapping) or set(triggers) != {"workflow_dispatch"}:
        failures.append(f"{path}: production workflow must be workflow_dispatch-only")

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, Mapping):
        return [*failures, f"{path}: jobs must be a mapping"]
    for job_name, job in jobs.items():
        if not isinstance(job, Mapping):
            continue
        runs_on = job.get("runs-on", [])
        labels = runs_on if isinstance(runs_on, list) else [runs_on]
        if "self-hosted" not in {str(label) for label in labels}:
            continue
        wrapper_seen = False
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            failures.append(f"{path}: self-hosted job {job_name!r} steps must be a list")
            continue
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            action = str(step.get("uses", ""))
            if action.startswith("actions/checkout@"):
                failures.append(
                    f"{path}: self-hosted job {job_name!r} must not check out repository code"
                )
            run = str(step.get("run", ""))
            lowered = run.lower()
            if "sudo install" in lowered or ".github/deploy" in lowered:
                failures.append(
                    f"{path}: self-hosted job {job_name!r} must not install or "
                    "execute repository deployment files"
                )
            for line in run.splitlines():
                for suffix in re.split(r"\bsudo\b", line)[1:]:
                    sudo_command = f"sudo{suffix}"
                    if not ROOT_WRAPPER.match(sudo_command):
                        failures.append(
                            f"{path}: self-hosted job {job_name!r} may sudo only a "
                            "pre-provisioned docker-*-node.sh wrapper"
                        )
                    else:
                        wrapper_seen = True
        if not wrapper_seen:
            failures.append(
                f"{path}: self-hosted job {job_name!r} must invoke a "
                "pre-provisioned docker-*-node.sh wrapper"
            )
    return failures


def _repository_file_errors(repository: Path) -> list[str]:
    failures: list[str] = []
    codeowners_path = repository / ".github" / "CODEOWNERS"
    try:
        codeowners_text = codeowners_path.read_text(encoding="utf-8")
    except OSError as exc:
        failures.append(f"{codeowners_path}: CODEOWNERS is required: {exc}")
    else:
        entries: dict[str, list[str]] = {}
        for raw_line in codeowners_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            entries[fields[0]] = fields[1:]
        for pattern in sorted(REQUIRED_CODEOWNER_PATTERNS):
            owners = entries.get(pattern, [])
            if not owners or any(not owner.startswith("@") for owner in owners):
                failures.append(f"{codeowners_path}: {pattern!r} must name at least one @owner")

    agents_path = repository / "AGENTS.md"
    try:
        agents_text = agents_path.read_text(encoding="utf-8")
    except OSError as exc:
        failures.append(f"{agents_path}: root agent guide is required: {exc}")
    else:
        for marker in sorted(REQUIRED_AGENT_MARKERS):
            if marker not in agents_text:
                failures.append(f"{agents_path}: required section is missing: {marker}")
    return failures


def check_repository(repository: Path) -> list[str]:
    workflow_directory = repository / ".github" / "workflows"
    paths = sorted([*workflow_directory.glob("*.yml"), *workflow_directory.glob("*.yaml")])
    if not paths:
        return [f"{workflow_directory}: no GitHub workflows found"]

    failures = _repository_file_errors(repository)
    ci_seen = False
    for path in paths:
        try:
            workflow = _load_workflow(path)
        except (TypeError, ValueError) as exc:
            failures.append(str(exc))
            continue
        failures.extend(_trigger_errors(path, workflow))
        failures.extend(_action_errors(path, workflow))
        failures.extend(_production_workflow_errors(path, workflow))
        if path.name == "ci.yml":
            ci_seen = True
            triggers = workflow.get("on", {})
            if not isinstance(triggers, Mapping) or "pull_request" not in triggers:
                failures.append(f"{path}: CI must run for pull requests targeting main")
    if not ci_seen:
        failures.append(f"{workflow_directory}: ci.yml is required")
    return failures


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    failures = check_repository(repository)
    if failures:
        print("GitHub workflow policy violations:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    workflow_count = len(list((repository / ".github" / "workflows").glob("*.y*ml")))
    print(f"GitHub workflow policy verified ({workflow_count} workflows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
