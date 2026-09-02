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
PULL_REQUEST_EXCLUDING_EVENT_PREDICATES = {
    "github.event_name == 'push'",
    "github.event_name == 'schedule'",
    "github.event_name == 'workflow_dispatch'",
    "github.event_name != 'pull_request'",
}
ALLOWED_PULL_REQUEST_EXCLUSION_CONJUNCTS = {
    *PULL_REQUEST_EXCLUDING_EVENT_PREDICATES,
    "github.ref == 'refs/heads/main'",
}
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
GITHUB_HOSTED_RUNNERS = {"ubuntu-24.04"}
PRODUCTION_RUNNER_LABELS = {
    ("self-hosted", "alert-hub-ru"),
    ("self-hosted", "alert-hub-nl"),
    ("self-hosted", "alert-hub-de"),
}
ROOT_WRAPPERS = {
    "/usr/local/sbin/docker-deploy-node.sh",
    "/usr/local/sbin/docker-rollback-node.sh",
    "/usr/local/sbin/docker-status-node.sh",
}
PRESERVABLE_ROOT_ENVIRONMENT = {
    "ALERT_HUB_API_IMAGE",
    "ALERT_HUB_COMPONENT",
    "ALERT_HUB_CONFIRMATION",
    "ALERT_HUB_RELEASE_COMPATIBILITY",
    "ALERT_HUB_ROLLBACK_VERSION",
    "ALERT_HUB_VERSION",
    "ALERT_HUB_WEB_IMAGE",
    "APP_NAME",
    "CLUSTER_MASTER_KEY",
    "GHCR_TOKEN",
    "GITHUB_ACTOR",
    "GITHUB_REPOSITORY",
    "NODE_IP",
    "NODE_NAME",
    "PEER_ALLOWED_CIDRS",
    "PEER_PUBLIC_URL",
    "PEER_URLS",
    "PUBLIC_DOMAIN",
    "SESSION_SIGNING_KEY",
    "VAPID_PRIVATE_KEY",
    "VAPID_PUBLIC_KEY",
}
SELF_HOSTED_SHELL_OPTIONS = "set -Eeuo pipefail"
TRUSTED_SELF_HOSTED_SHELL = "bash --noprofile --norc -e -o pipefail {0}"
REQUIRED_VALUE_CHECK = (
    r"[[ -n ${!required} ]] || { printf 'Required protected value %s is missing\n' "
    r'"${required}" >&2; exit 2; }'
)


def _is_allowed_root_wrapper(command: str) -> bool:
    """Accept only the exact no-argument sudo boundary used by production jobs."""

    parts = command.split()
    if not parts or parts[0] != "sudo":
        return False

    index = 1
    preserve_prefix = "--preserve-env="
    if index < len(parts) and parts[index].startswith(preserve_prefix):
        names = parts[index][len(preserve_prefix) :].split(",")
        if (
            not names
            or any(name not in PRESERVABLE_ROOT_ENVIRONMENT for name in names)
            or len(names) != len(set(names))
        ):
            return False
        index += 1

    return len(parts) == index + 1 and parts[index] in ROOT_WRAPPERS


def _required_environment_names(
    loop_line: str,
    step_environment: Mapping[str, Any],
) -> list[str] | None:
    prefix = "for required in "
    suffix = "; do"
    if not loop_line.startswith(prefix) or not loop_line.endswith(suffix):
        return None
    raw_names = loop_line[len(prefix) : -len(suffix)]
    names = raw_names.split()
    if not names or raw_names != " ".join(names) or len(names) != len(set(names)):
        return None
    available = {str(name) for name in step_environment}
    if any(name not in available or name not in PRESERVABLE_ROOT_ENVIRONMENT for name in names):
        return None
    return names


def _is_allowed_self_hosted_run(
    run: str,
    step_environment: Mapping[str, Any],
) -> bool:
    """Allow only the fixed validation prologue followed by root-owned wrappers."""

    lines = [line.strip() for line in run.splitlines() if line.strip()]
    if not lines:
        return False

    wrapper_lines = lines
    if lines[0] == SELF_HOSTED_SHELL_OPTIONS:
        if len(lines) < 5:
            return False
        if _required_environment_names(lines[1], step_environment) is None:
            return False
        if lines[2] != REQUIRED_VALUE_CHECK or lines[3] != "done":
            return False
        wrapper_lines = lines[4:]

    return bool(wrapper_lines) and all(_is_allowed_root_wrapper(line) for line in wrapper_lines)


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
        if not _condition_excludes_pull_requests(str(job.get("if", ""))):
            yield str(name), job


def _condition_excludes_pull_requests(condition: str) -> bool:
    """Prove a small allowlisted conjunction cannot run for a pull request."""

    normalized = condition.replace('"', "'").strip().lower()
    if normalized.startswith("${{") and normalized.endswith("}}"):
        normalized = normalized[3:-2].strip()
    if not normalized or "||" in normalized:
        return False
    conjuncts = [part.strip() for part in normalized.split("&&")]
    if not conjuncts or any(
        not conjunct or conjunct not in ALLOWED_PULL_REQUEST_EXCLUSION_CONJUNCTS
        for conjunct in conjuncts
    ):
        return False
    return any(conjunct in PULL_REQUEST_EXCLUDING_EVENT_PREDICATES for conjunct in conjuncts)


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


def _is_production_self_hosted_job(path: Path, job: Mapping[str, Any]) -> bool:
    runs_on = job.get("runs-on")
    if path.name not in PRODUCTION_WORKFLOWS or not isinstance(runs_on, list):
        return False
    return tuple(str(label) for label in runs_on) in PRODUCTION_RUNNER_LABELS


def _runner_errors(path: Path, workflow: Mapping[str, Any]) -> list[str]:
    """Allow dynamic or self-hosted scheduling only at the audited boundary."""

    failures: list[str] = []
    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, Mapping):
        return [f"{path}: jobs must be a mapping"]

    for job_name, job in jobs.items():
        if not isinstance(job, Mapping):
            failures.append(f"{path}: job {job_name!r} must be a mapping")
            continue
        runs_on = job.get("runs-on")
        if isinstance(runs_on, str) and runs_on in GITHUB_HOSTED_RUNNERS:
            continue
        if _is_production_self_hosted_job(path, job):
            continue
        failures.append(
            f"{path}: job {job_name!r} must use an approved static GitHub-hosted "
            "runner; exact production self-hosted labels are allowed only in "
            "deploy.yml and rollback.yml"
        )
    return failures


def _default_run_shell(owner: Mapping[str, Any]) -> Any | None:
    defaults = owner.get("defaults", {})
    if not isinstance(defaults, Mapping):
        return None
    run_defaults = defaults.get("run", {})
    if not isinstance(run_defaults, Mapping):
        return None
    return run_defaults.get("shell")


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
    has_self_hosted_job = any(
        isinstance(job, Mapping) and _is_production_self_hosted_job(path, job)
        for job in jobs.values()
    )
    if has_self_hosted_job and _default_run_shell(workflow) is not None:
        failures.append(
            f"{path}: workflow-level defaults.run.shell is forbidden for "
            "production self-hosted jobs"
        )
    if has_self_hosted_job and "env" in workflow:
        failures.append(f"{path}: workflow-level env is forbidden for production self-hosted jobs")
    for job_name, job in jobs.items():
        if not isinstance(job, Mapping):
            continue
        if not _is_production_self_hosted_job(path, job):
            continue
        if _default_run_shell(job) is not None:
            failures.append(
                f"{path}: self-hosted job {job_name!r} must not override defaults.run.shell"
            )
        if "env" in job:
            failures.append(
                f"{path}: self-hosted job {job_name!r} must define env only on "
                "the audited wrapper step"
            )
        if "container" in job or "services" in job:
            failures.append(
                f"{path}: self-hosted job {job_name!r} must not use job containers "
                "or service containers"
            )
        wrapper_seen = False
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            failures.append(f"{path}: self-hosted job {job_name!r} steps must be a list")
            continue
        for step in steps:
            if not isinstance(step, Mapping):
                failures.append(f"{path}: self-hosted job {job_name!r} step must be a mapping")
                continue
            shell = step.get("shell")
            if shell is not None and str(shell) != TRUSTED_SELF_HOSTED_SHELL:
                failures.append(
                    f"{path}: self-hosted job {job_name!r} uses an untrusted step shell"
                )
            action = str(step.get("uses", ""))
            if action:
                if action.startswith("actions/checkout@"):
                    failures.append(
                        f"{path}: self-hosted job {job_name!r} must not check out repository code"
                    )
                else:
                    failures.append(
                        f"{path}: self-hosted job {job_name!r} must not execute an action"
                    )
            run = str(step.get("run", ""))
            step_environment = step.get("env", {})
            if not isinstance(step_environment, Mapping):
                failures.append(f"{path}: self-hosted job {job_name!r} step env must be a mapping")
                step_environment = {}
            unsupported_environment = sorted(
                str(name)
                for name in step_environment
                if str(name) not in PRESERVABLE_ROOT_ENVIRONMENT
            )
            if unsupported_environment:
                failures.append(
                    f"{path}: self-hosted job {job_name!r} defines unsupported step "
                    f"environment: {', '.join(unsupported_environment)}"
                )
            lowered = run.lower()
            if "sudo install" in lowered or ".github/deploy" in lowered:
                failures.append(
                    f"{path}: self-hosted job {job_name!r} must not install or "
                    "execute repository deployment files"
                )
            if run.strip():
                if not _is_allowed_self_hosted_run(run, step_environment):
                    failures.append(
                        f"{path}: self-hosted job {job_name!r} may sudo only a "
                        "pre-provisioned docker-*-node.sh wrapper after the fixed "
                        "environment validation prologue"
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
        failures.extend(_runner_errors(path, workflow))
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
