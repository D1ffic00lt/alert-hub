from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

_NODE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


class ConfigurationError(ValueError):
    """Raised when the operator-supplied MCP configuration is unsafe or incomplete."""


@dataclass(frozen=True, slots=True)
class NodeConfig:
    name: str
    base_url: str


@dataclass(frozen=True, slots=True)
class MCPSettings:
    nodes: tuple[NodeConfig, ...]
    token: str
    timeout_seconds: float = 10.0
    max_response_bytes: int = 2 * 1024 * 1024
    ca_bundle: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> MCPSettings:
        values = os.environ if env is None else env
        allow_http = _boolean(values.get("ALERT_HUB_ALLOW_HTTP"), default=False)
        nodes = _parse_nodes(values, allow_http=allow_http)
        token = _read_token(values)
        timeout_seconds = _bounded_float(
            values.get("ALERT_HUB_TIMEOUT_SECONDS"),
            default=10.0,
            minimum=0.25,
            maximum=60.0,
            name="ALERT_HUB_TIMEOUT_SECONDS",
        )
        max_response_bytes = _bounded_int(
            values.get("ALERT_HUB_MAX_RESPONSE_BYTES"),
            default=2 * 1024 * 1024,
            minimum=64 * 1024,
            maximum=10 * 1024 * 1024,
            name="ALERT_HUB_MAX_RESPONSE_BYTES",
        )
        ca_bundle = values.get("ALERT_HUB_CA_BUNDLE", "").strip() or None
        if ca_bundle is not None:
            path = Path(ca_bundle).expanduser()
            if not path.is_file():
                raise ConfigurationError("ALERT_HUB_CA_BUNDLE must reference a readable file")
            ca_bundle = str(path.resolve())
        return cls(
            nodes=nodes,
            token=token,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            ca_bundle=ca_bundle,
        )


def _boolean(raw: str | None, *, default: bool) -> bool:
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError("ALERT_HUB_ALLOW_HTTP must be true or false")


def _parse_nodes(values: Mapping[str, str], *, allow_http: bool) -> tuple[NodeConfig, ...]:
    encoded_nodes = values.get("ALERT_HUB_NODES", "").strip()
    single_url = values.get("ALERT_HUB_URL", "").strip()
    if encoded_nodes and single_url:
        raise ConfigurationError("Set ALERT_HUB_NODES or ALERT_HUB_URL, not both")
    if not encoded_nodes and not single_url:
        raise ConfigurationError("ALERT_HUB_NODES or ALERT_HUB_URL is required")
    raw_nodes = [f"default={single_url}"] if single_url else encoded_nodes.split(",")
    if len(raw_nodes) > 8:
        raise ConfigurationError("At most eight Alert Hub nodes may be configured")
    nodes: list[NodeConfig] = []
    names: set[str] = set()
    urls: set[str] = set()
    for raw_node in raw_nodes:
        name, separator, raw_url = raw_node.strip().partition("=")
        if not separator or not _NODE_NAME.fullmatch(name):
            raise ConfigurationError(
                "ALERT_HUB_NODES entries must use name=https://host with safe unique names"
            )
        normalized_url = _normalize_url(raw_url.strip(), allow_http=allow_http)
        if name in names or normalized_url in urls:
            raise ConfigurationError("Alert Hub node names and URLs must be unique")
        names.add(name)
        urls.add(normalized_url)
        nodes.append(NodeConfig(name=name, base_url=normalized_url))
    return tuple(nodes)


def _normalize_url(value: str, *, allow_http: bool) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("Alert Hub URLs must be absolute HTTP(S) origins")
    if parsed.scheme == "http" and not allow_http:
        raise ConfigurationError(
            "Alert Hub URLs must use HTTPS unless ALERT_HUB_ALLOW_HTTP=true is explicit"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError("Alert Hub URLs cannot contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ConfigurationError("Alert Hub URLs must be origins without a path")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("Alert Hub URL has an invalid port") from exc
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = f"{host}:{port}" if port is not None and port != default_port else host
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def _read_token(values: Mapping[str, str]) -> str:
    direct = values.get("ALERT_HUB_TOKEN", "").strip()
    file_value = values.get("ALERT_HUB_TOKEN_FILE", "").strip()
    if bool(direct) == bool(file_value):
        raise ConfigurationError("Set exactly one of ALERT_HUB_TOKEN or ALERT_HUB_TOKEN_FILE")
    if file_value:
        path = Path(file_value).expanduser()
        if path.is_symlink():
            raise ConfigurationError("ALERT_HUB_TOKEN_FILE must not be a symlink")
        try:
            metadata = path.stat()
        except FileNotFoundError as exc:
            raise ConfigurationError("ALERT_HUB_TOKEN_FILE does not exist") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigurationError("ALERT_HUB_TOKEN_FILE must be a regular file")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ConfigurationError("ALERT_HUB_TOKEN_FILE permissions must be 0600 or stricter")
        try:
            direct = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise ConfigurationError("ALERT_HUB_TOKEN_FILE must be readable UTF-8") from exc
    encoded_id, separator, secret = direct.removeprefix("ahs_").partition(".")
    try:
        token_id = UUID(encoded_id)
    except ValueError as exc:
        raise ConfigurationError("Alert Hub service token is malformed") from exc
    if (
        not direct.startswith("ahs_")
        or not separator
        or str(token_id) != encoded_id
        or not 20 <= len(secret) <= 256
        or re.fullmatch(r"[A-Za-z0-9_-]+", secret) is None
        or len(direct) > 512
    ):
        raise ConfigurationError("Alert Hub service token is malformed")
    return direct


def _bounded_float(
    raw: str | None,
    *,
    default: float,
    minimum: float,
    maximum: float,
    name: str,
) -> float:
    try:
        value = default if raw is None or not raw.strip() else float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_int(
    raw: str | None,
    *,
    default: int,
    minimum: int,
    maximum: int,
    name: str,
) -> int:
    try:
        value = default if raw is None or not raw.strip() else int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value
