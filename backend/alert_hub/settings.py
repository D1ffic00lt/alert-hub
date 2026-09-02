from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from alert_hub.infrastructure.request_security import parse_cidr_setting


def _normalize_peer_hostname(host: str, *, label: str) -> str:
    if "%" in host:
        raise ValueError(f"{label} must not use an IPv6 zone identifier")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    if (
        not host.isascii()
        or len(host) > 253
        or host.endswith(".")
        or re.fullmatch(r"[0-9.]+", host)
        or any(
            len(part) > 63
            or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", part) is None
            for part in host.split(".")
        )
    ):
        raise ValueError(f"{label} must use an unambiguous ASCII DNS name or IP literal")
    return host.lower()


def _normalize_peer_origin(raw: object, *, label: str) -> str:
    candidate = str(raw).strip()
    if (
        "*" in candidate
        or "\\" in candidate
        or any(
            character.isspace() or unicodedata.category(character) == "Cc"
            for character in candidate
        )
    ):
        raise ValueError(f"{label} must not contain wildcards, backslashes, or whitespace")
    try:
        parsed = urlsplit(candidate)
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {candidate}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{label} must use http or https")
    if not parsed.hostname:
        raise ValueError(f"{label} must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{label} must not contain credentials")
    if "?" in candidate or "#" in candidate:
        raise ValueError(f"{label} must not contain a query or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError(f"{label} must be an exact origin without a path")
    if parsed.netloc.endswith(":") or parsed_port == 0:
        raise ValueError(f"{label} must use a port between 1 and 65535")
    normalized_host = _normalize_peer_hostname(parsed.hostname, label=label)
    host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    netloc = host if parsed_port is None else f"{host}:{parsed_port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


class Settings(BaseSettings):
    """Runtime configuration. Secrets are supplied by the environment in production."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    app_name: str = "Alert Hub"
    environment: Literal["development", "test", "production"] = Field(
        default="development",
        validation_alias=AliasChoices("ENVIRONMENT", "APP_ENV"),
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "text"] = "json"
    software_version: str = "0.1.3"
    backend_host: str = Field(default="127.0.0.1", min_length=1, max_length=253)
    backend_port: int = Field(default=8080, ge=1, le=65_535)
    database_url: str = "sqlite:///./data/alert-hub.db"
    sqlite_busy_timeout_ms: int = Field(default=5_000, ge=1, le=120_000)
    auto_create_schema: bool = False

    node_id: str = "local-node"
    node_name: str = "Local node"
    node_region: str = "local"
    public_api_url: str | None = None
    private_peer_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("PEER_PUBLIC_URL", "PRIVATE_PEER_URL"),
    )
    grafana_url: str | None = None
    ingest_enabled: bool = True
    notify_enabled: bool = True
    sync_enabled: bool = True
    ui_enabled: bool = True

    signing_key: str = "development-only-change-me"
    signing_key_file: Path | None = Field(
        default=None,
        validation_alias=AliasChoices("SIGNING_KEY_FILE", "TOKEN_SIGNING_KEY_FILE"),
    )
    cluster_secret: str = "development-cluster-secret-change-me"
    cluster_secret_file: Path | None = Field(
        default=None,
        validation_alias=AliasChoices("CLUSTER_SECRET_FILE", "CLUSTER_BEARER_SECRET_FILE"),
    )
    cluster_previous_secret: str | None = None
    cluster_previous_secret_file: Path | None = None
    master_encryption_key_file: Path | None = None
    vapid_public_key: str | None = None
    vapid_public_key_file: Path | None = None
    vapid_private_key_file: Path | None = None
    allow_http_webhooks: bool = False
    allow_private_webhooks: bool = False
    allow_http_monitoring_urls: bool = False
    allow_private_monitoring_urls: bool = False
    bootstrap_token: str | None = None
    bootstrap_token_file: Path = Path("./data/bootstrap-token")

    access_token_ttl_seconds: int = Field(default=900, ge=60, le=86_400)
    refresh_sliding_days: int = Field(default=30, ge=1, le=365)
    refresh_absolute_days: int = Field(default=180, ge=1, le=730)
    refresh_cookie_name: str = "alert_hub_refresh"
    csrf_cookie_name: str = "alert_hub_csrf"
    stream_cookie_name: str = "alert_hub_stream"
    cookie_secure: bool = True
    cookie_domain: str | None = None
    trusted_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        validation_alias=AliasChoices("TRUSTED_ORIGINS", "CORS_ALLOWED_ORIGINS"),
    )
    trusted_proxy_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128"],
        validation_alias="TRUSTED_PROXY_CIDRS",
    )
    peer_allowed_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["127.0.0.0/8", "::1/128"],
        validation_alias="PEER_ALLOWED_CIDRS",
    )

    rate_limit_max_keys: int = Field(default=10_000, ge=1, le=1_000_000)
    rate_limit_cleanup_interval_seconds: float = Field(default=60.0, ge=1.0, le=3_600.0)
    login_rate_limit_attempts: int = Field(default=10, ge=1, le=10_000)
    login_rate_limit_window_seconds: float = Field(default=60.0, ge=1.0, le=86_400.0)
    bootstrap_rate_limit_attempts: int = Field(default=5, ge=1, le=1_000)
    bootstrap_rate_limit_window_seconds: float = Field(default=300.0, ge=1.0, le=86_400.0)
    ingest_rate_limit_attempts: int = Field(default=120, ge=1, le=1_000_000)
    ingest_rate_limit_window_seconds: float = Field(default=60.0, ge=1.0, le=86_400.0)
    peer_rate_limit_attempts: int = Field(default=600, ge=1, le=1_000_000)
    peer_rate_limit_window_seconds: float = Field(default=60.0, ge=1.0, le=86_400.0)

    max_payload_bytes: int = Field(default=1_048_576, ge=1_024, le=10_485_760)
    peer_urls: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        validation_alias="PEER_URLS",
    )
    sync_page_size: int = Field(default=200, ge=1, le=1_000)
    sync_interval_seconds: float = Field(default=5.0, ge=0.1, le=300.0)
    sync_connect_timeout_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    sync_read_timeout_seconds: float = Field(default=10.0, ge=0.1, le=120.0)
    sync_write_timeout_seconds: float = Field(default=10.0, ge=0.1, le=120.0)
    sync_pool_timeout_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    sync_backoff_initial_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    sync_backoff_max_seconds: float = Field(default=60.0, ge=0.1, le=3_600.0)
    sync_backoff_jitter_ratio: float = Field(default=0.2, ge=0.0, le=1.0)
    sync_max_pages_per_cycle: int = Field(default=100, ge=1, le=10_000)
    sync_max_response_bytes: int = Field(default=4_194_304, ge=1_024, le=67_108_864)
    clock_skew_threshold_seconds: float = Field(default=300.0, ge=1.0, le=86_400.0)
    prometheus_connect_timeout_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    prometheus_read_timeout_seconds: float = Field(default=10.0, ge=0.1, le=120.0)
    prometheus_write_timeout_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    prometheus_pool_timeout_seconds: float = Field(default=2.0, ge=0.1, le=30.0)
    prometheus_query_timeout_seconds: float = Field(default=8.0, ge=0.1, le=120.0)
    prometheus_max_response_bytes: int = Field(default=2_097_152, ge=1_024, le=20_971_520)
    prometheus_max_samples: int = Field(default=10_000, ge=1, le=100_000)
    heartbeat_scan_seconds: float = Field(default=10.0, ge=0.0, le=300.0)
    notification_poll_seconds: float = Field(default=1.0, ge=0.1, le=60.0)
    notification_lock_seconds: float = Field(default=60.0, ge=5.0, le=3_600.0)
    notification_batch_size: int = Field(default=20, ge=1, le=500)
    notification_max_attempts: int = Field(default=8, ge=1, le=100)
    notification_retry_base_seconds: float = Field(default=5.0, ge=0.1, le=3_600.0)
    notification_retry_max_seconds: float = Field(default=900.0, ge=1.0, le=86_400.0)
    notification_failover_base_seconds: float = Field(default=15.0, ge=0.0, le=3_600.0)
    notification_provider_timeout_seconds: float = Field(default=10.0, ge=0.1, le=120.0)
    web_push_ttl_seconds: int = Field(default=300, ge=0, le=86_400)
    vapid_subject: str = "mailto:admin@example.invalid"
    sse_poll_seconds: float = Field(default=2.0, ge=0.25, le=30.0)
    sse_keepalive_seconds: float = Field(default=15.0, ge=1.0, le=60.0)

    @field_validator("app_name", mode="before")
    @classmethod
    def normalize_app_name(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        safe_characters = (
            " "
            if character.isspace() or unicodedata.category(character).startswith("C")
            else character
            for character in value
        )
        normalized = " ".join("".join(safe_characters).split())
        if not normalized:
            raise ValueError("APP_NAME must not be empty")
        if len(normalized) > 80:
            raise ValueError("APP_NAME must not exceed 80 characters")
        return normalized

    @field_validator("log_level", mode="before")
    @classmethod
    def normalize_log_level(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("log_format", mode="before")
    @classmethod
    def normalize_log_format(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("trusted_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            if value.lstrip().startswith("["):
                value = json.loads(value)
            else:
                value = [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            normalized: list[str] = []
            for item in value:
                candidate = str(item).strip()
                if not candidate:
                    continue
                if candidate == "*" or "*" in candidate:
                    raise ValueError("trusted origins must not contain wildcards")
                try:
                    parsed = urlsplit(candidate)
                    parsed_port = parsed.port
                except ValueError as exc:
                    raise ValueError(f"invalid trusted origin: {candidate}") from exc
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise ValueError("trusted origins must use http or https and include a host")
                if parsed.username or parsed.password:
                    raise ValueError("trusted origins must not contain credentials")
                if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                    raise ValueError("trusted origins must not contain a path, query, or fragment")
                host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
                netloc = host if parsed_port is None else f"{host}:{parsed_port}"
                canonical = urlunsplit((parsed.scheme.lower(), netloc.lower(), "", "", ""))
                if canonical not in normalized:
                    normalized.append(canonical)
            return normalized
        return value

    @field_validator("trusted_proxy_cidrs", "peer_allowed_cidrs", mode="before")
    @classmethod
    def parse_security_cidrs(cls, value: object) -> object:
        return parse_cidr_setting(value)

    @field_validator("cookie_domain")
    @classmethod
    def validate_cookie_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip().lstrip(".").lower()
        if (
            not candidate
            or "*" in candidate
            or ":" in candidate
            or "/" in candidate
            or "@" in candidate
            or candidate == "localhost"
            or "." not in candidate
            or len(candidate) > 253
            or any(
                len(label) > 63 or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
                for label in candidate.split(".")
            )
        ):
            raise ValueError("COOKIE_DOMAIN must be a host name without scheme, port, or path")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            raise ValueError("COOKIE_DOMAIN must not be an IP address")
        return candidate

    @field_validator("public_api_url")
    @classmethod
    def validate_node_urls(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if "*" in candidate or any(character.isspace() for character in candidate):
            raise ValueError("node URLs must not contain wildcards or whitespace")
        try:
            parsed = urlsplit(candidate)
            parsed_port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid node URL: {candidate}") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("node URLs must use http or https and include a host")
        if parsed.username or parsed.password:
            raise ValueError("node URLs must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("node URLs must not contain a query or fragment")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        netloc = host if parsed_port is None else f"{host}:{parsed_port}"
        path = parsed.path.rstrip("/")
        return urlunsplit((parsed.scheme.lower(), netloc.lower(), path, "", ""))

    @field_validator("private_peer_url")
    @classmethod
    def validate_peer_public_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalize_peer_origin(value, label="PEER_PUBLIC_URL")

    @field_validator("grafana_url")
    @classmethod
    def validate_grafana_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if "*" in candidate or any(character.isspace() for character in candidate):
            raise ValueError("GRAFANA_URL must not contain wildcards or whitespace")
        try:
            parsed = urlsplit(candidate)
            parsed_port = parsed.port
        except ValueError as exc:
            raise ValueError("GRAFANA_URL is invalid") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("GRAFANA_URL must use http or https and include a host")
        if parsed.username or parsed.password:
            raise ValueError("GRAFANA_URL must not contain credentials")
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

    @field_validator("peer_urls", mode="before")
    @classmethod
    def parse_peer_urls(cls, value: object) -> object:
        if isinstance(value, str):
            if value.lstrip().startswith("["):
                value = json.loads(value)
            else:
                value = [item.strip() for item in value.split(",") if item.strip()]
        if not isinstance(value, list):
            return value
        normalized: list[str] = []
        for raw in value:
            candidate = str(raw).strip()
            if not candidate:
                continue
            canonical = _normalize_peer_origin(candidate, label="peer URLs")
            if canonical not in normalized:
                normalized.append(canonical)
        return normalized

    @model_validator(mode="after")
    def validate_sync_backoff(self) -> Settings:
        if self.sync_backoff_max_seconds < self.sync_backoff_initial_seconds:
            raise ValueError(
                "SYNC_BACKOFF_MAX_SECONDS must be greater than or equal to "
                "SYNC_BACKOFF_INITIAL_SECONDS"
            )
        return self

    @field_validator("signing_key", "cluster_secret")
    @classmethod
    def reject_empty_secrets(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("secret must not be empty")
        return value

    @model_validator(mode="after")
    def load_file_backed_secrets(self) -> Settings:
        file_fields = (
            ("signing_key", self.signing_key_file),
            ("cluster_secret", self.cluster_secret_file),
            ("cluster_previous_secret", self.cluster_previous_secret_file),
        )
        for target, path in file_fields:
            if path is None:
                continue
            try:
                value = path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ValueError(f"unable to read {target} file: {path}") from exc
            if not value:
                raise ValueError(f"{target} file must not be empty")
            setattr(self, target, value)
        return self

    def enabled_roles(self) -> list[str]:
        pairs = {
            "ingest": self.ingest_enabled,
            "notify": self.notify_enabled,
            "sync": self.sync_enabled,
            "ui": self.ui_enabled,
        }
        return [name for name, enabled in pairs.items() if enabled]


@lru_cache
def get_settings() -> Settings:
    return Settings()
