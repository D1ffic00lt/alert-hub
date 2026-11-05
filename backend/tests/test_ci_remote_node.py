from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy/scripts/ci-remote-node.py"
spec = importlib.util.spec_from_file_location("ci_remote_node", SCRIPT)
assert spec and spec.loader
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


def configuration() -> dict[str, Any]:
    return {"repository": "example/monitor", "node": "nl", "node_ip": "192.0.2.10"}


def request() -> dict[str, Any]:
    return {
        "schema": 1,
        "repository": "example/monitor",
        "node": "nl",
        "operation": "status",
        "environment": {"NODE_NAME": "nl"},
    }


def test_remote_environment_keeps_only_explicit_values() -> None:
    body = request()
    body["environment"].update(
        {"GHCR_TOKEN": "job-credential", "VAPID_PRIVATE_KEY": "line1\nline2"}
    )
    environment = remote.validate_request(body, configuration())
    assert environment["GHCR_TOKEN"] == "job-credential"
    assert environment["VAPID_PRIVATE_KEY"] == "line1\nline2"
    assert environment["GITHUB_REPOSITORY"] == "example/monitor"
    assert "PYTHONPATH" not in environment


@pytest.mark.parametrize(
    "field,value",
    [("node", "de"), ("repository", "other/repo"), ("operation", "/bin/sh"), ("schema", 2)],
)
def test_remote_rejects_different_identity_and_arbitrary_commands(field: str, value: Any) -> None:
    body = request()
    body[field] = value
    with pytest.raises(ValueError):
        remote.validate_request(body, configuration())


@pytest.mark.parametrize(
    "environment",
    [
        {"BASH_ENV": "/tmp/code"},
        {"NODE_IP": "192.0.2.11"},
        {"GITHUB_REPOSITORY": "other/repo"},
        {"GHCR_TOKEN": "a\0b"},
        {"GHCR_TOKEN": "x" * 16385},
    ],
)
def test_remote_rejects_environment_injection(environment: dict[str, str]) -> None:
    body = request()
    body["environment"].update(environment)
    with pytest.raises(ValueError):
        remote.validate_request(body, configuration())


def test_remote_does_not_enable_preview_or_extra_fields_implicitly() -> None:
    body = request()
    body["operation"] = "preview"
    with pytest.raises(ValueError):
        remote.validate_request(body, configuration())
    body = request()
    body["command"] = "arbitrary"
    with pytest.raises(ValueError):
        remote.validate_request(body, configuration())
