#!/usr/bin/python3 -I
"""Root-installed transport to an existing node's fixed deployment boundary.

The operator installs copies under the four existing docker-*-node.sh names on
the CD host and as alert-hub-remote-receiver on production nodes. Configuration,
SSH identities and host keys are root-owned. No workspace code is executed.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import selectors
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

OPERATIONS = {
    "docker-deploy-node.sh": "deploy",
    "docker-deploy-preview-node.sh": "preview",
    "docker-rollback-node.sh": "rollback",
    "docker-status-node.sh": "status",
}
WRAPPERS = {value: "/usr/local/sbin/" + key for key, value in OPERATIONS.items()}
ENVIRONMENT = frozenset(
    [
        "NODE_NAME",
        "NODE_IP",
        "PUBLIC_DOMAIN",
        "PREVIEW_PUBLIC_DOMAIN",
        "PEER_PUBLIC_URL",
        "ALERT_HUB_VERSION",
        "ALERT_HUB_COMPONENT",
        "ALERT_HUB_API_IMAGE",
        "ALERT_HUB_WEB_IMAGE",
        "ALERT_HUB_RELEASE_COMPATIBILITY",
        "ALERT_HUB_PREVIEW_IMAGE",
        "ALERT_HUB_PREVIEW_REVISION",
        "ALERT_HUB_PREVIEW_COMPATIBILITY",
        "CLUSTER_MASTER_KEY",
        "SESSION_SIGNING_KEY",
        "VAPID_PRIVATE_KEY",
        "GHCR_TOKEN",
        "GITHUB_ACTOR",
        "GITHUB_REPOSITORY",
        "APP_NAME",
        "API_HA_MODE",
        "PUBLIC_UI_URL",
        "NODE_PUBLIC_API_URL",
        "PUBLIC_INGEST_URL",
        "PUBLIC_API_CANDIDATES",
        "COOKIE_DOMAIN",
        "PEER_URLS",
        "PEER_ALLOWED_CIDRS",
        "VAPID_PUBLIC_KEY",
        "CHECKS_ENABLED",
        "CHECKS_STALE_AFTER_SECONDS",
        "CHECKS_MIN_FAILURE_SOURCES",
        "CHECKS_GRAFANA_BASE_URL",
        "CHECKS_CACHE_TTL_SECONDS",
        "CHECKS_FUTURE_TOLERANCE_SECONDS",
        "CHECKS_MAX_SERIES",
        "ALERT_HUB_ROLLBACK_VERSION",
        "ALERT_HUB_CONFIRMATION",
    ]
)
LIMIT = 131072
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


def root_config(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Untrusted operator configuration")
    config: dict[str, Any] = json.loads(path.read_text())
    return config


def validate_request(request: Any, config: dict[str, Any]) -> dict[str, str]:
    if not isinstance(request, dict) or set(request) != {
        "schema",
        "repository",
        "node",
        "operation",
        "environment",
    }:
        raise ValueError("Invalid request schema")
    if (
        type(request["schema"]) is not int
        or request["schema"] != 1
        or not all(isinstance(request[key], str) for key in ["repository", "node", "operation"])
        or request["repository"] != config["repository"]
    ):
        raise ValueError("Repository does not match operator policy")
    if request["node"] != config["node"] or request["operation"] not in WRAPPERS:
        raise ValueError("Invalid node or operation")
    if request["operation"] == "preview" and not config.get("preview", False):
        raise ValueError("Preview is not enabled on this node")
    environment = request["environment"]
    if not isinstance(environment, dict) or set(environment) - ENVIRONMENT:
        raise ValueError("Unsupported environment")
    if any(not isinstance(v, str) or len(v) > 16384 or "\0" in v for v in environment.values()):
        raise ValueError("Invalid environment value")
    if environment.get("NODE_NAME") != config["node"]:
        raise ValueError("Node environment differs from operator policy")
    if environment.get("GITHUB_REPOSITORY", config["repository"]) != config["repository"]:
        raise ValueError("Repository environment differs from operator policy")
    if "NODE_IP" in environment and environment["NODE_IP"] != config["node_ip"]:
        raise ValueError("Node address differs from operator policy")
    return {**CLEAN_ENV, **environment, "GITHUB_REPOSITORY": config["repository"]}


def relay(command: str, config: dict[str, Any]) -> None:
    # A forced SSH command can relay only to the operator's fixed SSH endpoints.
    host = config.get("relays", {}).get(command)
    if not isinstance(host, str):
        raise ValueError("Unsupported SSH relay")
    ipaddress.ip_address(host)
    with socket.create_connection((host, 22), timeout=15) as connection:
        connection.settimeout(None)
        with selectors.DefaultSelector() as selector:
            selector.register(sys.stdin.buffer, selectors.EVENT_READ, "input")
            selector.register(connection, selectors.EVENT_READ, "socket")
            deadline = time.monotonic() + 3600
            while time.monotonic() < deadline:
                for key, _ in selector.select(timeout=30):
                    if key.data == "input":
                        chunk = os.read(sys.stdin.fileno(), 65536)
                        if chunk:
                            connection.sendall(chunk)
                        else:
                            connection.shutdown(socket.SHUT_WR)
                            selector.unregister(sys.stdin.buffer)
                    else:
                        chunk = connection.recv(65536)
                        if not chunk:
                            return
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
            raise TimeoutError("SSH relay lifetime exceeded")


def receive() -> int:
    config = root_config(Path("/etc/alert-hub/remote-control.json"))
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if command:
        relay(command, config)
        return 0
    payload = sys.stdin.buffer.read(LIMIT + 1)
    if len(payload) > LIMIT:
        raise ValueError("Request exceeds limit")
    request = json.loads(payload)
    environment = validate_request(request, config)
    result = subprocess.run(
        [WRAPPERS[request["operation"]]], env=environment, timeout=1500, check=False
    )
    return result.returncode


def send(operation: str) -> int:
    config = root_config(Path("/etc/ru3-cd/alert-hub/transport.json"))
    node = os.environ.get("NODE_NAME")
    if node not in {"ru", "nl", "de"}:
        raise ValueError("Explicit node is required")
    request = {
        "schema": 1,
        "repository": config["repository"],
        "node": node,
        "operation": operation,
        "environment": {name: os.environ[name] for name in ENVIRONMENT if name in os.environ},
    }
    payload = json.dumps(request).encode()
    if len(payload) > LIMIT:
        raise ValueError("Request exceeds limit")
    # sudo children stay in the existing aggregate CD slice; serialize with all
    # other Hyperion project deployments through the common root-owned lock.
    with open("/run/lock/ru3-cd-global.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = subprocess.run(
            ["/usr/bin/ssh", "-F", "/etc/ru3-cd/alert-hub/ssh_config", "ah-" + node],
            input=payload,
            env=CLEAN_ENV,
            timeout=1700,
            check=False,
        )
    return result.returncode


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        return 2
    os.umask(0o077)
    try:
        name = Path(sys.argv[0]).name
        if name == "alert-hub-remote-receiver":
            return receive()
        return send(OPERATIONS[name])
    except (KeyError, ValueError, OSError, TimeoutError, subprocess.TimeoutExpired):
        # Requests may contain production material; never echo input or errors.
        print(
            "Remote node operation failed; inspect operator-owned configuration and node health.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
