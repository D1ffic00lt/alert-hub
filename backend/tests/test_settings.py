from __future__ import annotations

from pathlib import Path

import pytest

from alert_hub.settings import Settings


def test_log_settings_are_normalized_and_invalid_values_fail() -> None:
    settings = Settings(log_level="debug", log_format="TEXT")
    assert settings.log_level == "DEBUG"
    assert settings.log_format == "text"

    with pytest.raises(ValueError, match="log_level"):
        Settings(log_level="verbose")
    with pytest.raises(ValueError, match="log_format"):
        Settings(log_format="xml")


def test_app_name_is_safe_for_headers_and_provider_titles() -> None:
    settings = Settings(app_name="  Ops\r\n\x00  Hub\tEU  ")
    assert settings.app_name == "Ops Hub EU"

    with pytest.raises(ValueError, match="APP_NAME must not be empty"):
        Settings(app_name="\r\n\x00")
    with pytest.raises(ValueError, match="APP_NAME must not exceed 80"):
        Settings(app_name="x" * 81)


def test_ops_environment_aliases_and_secret_files(tmp_path: Path, monkeypatch) -> None:
    signing = tmp_path / "signing"
    cluster = tmp_path / "cluster"
    signing.write_text("file-signing-secret\n", encoding="utf-8")
    cluster.write_text("file-cluster-secret\n", encoding="utf-8")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("TOKEN_SIGNING_KEY_FILE", str(signing))
    monkeypatch.setenv("CLUSTER_BEARER_SECRET_FILE", str(cluster))
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://hub.example,https://node.example/")

    settings = Settings()

    assert settings.environment == "production"
    assert settings.signing_key == "file-signing-secret"
    assert settings.cluster_secret == "file-cluster-secret"
    assert settings.trusted_origins == ["https://hub.example", "https://node.example"]


def test_peer_urls_are_normalized_and_reject_unsafe_shapes(monkeypatch) -> None:
    monkeypatch.setenv(
        "PEER_URLS",
        "HTTPS://Peer.Example:443/,http://10.0.0.2:8080/,https://peer.example:443",
    )
    settings = Settings()
    assert settings.peer_urls == [
        "https://peer.example:443",
        "http://10.0.0.2:8080",
    ]

    monkeypatch.setenv("PEER_URLS", "https://user:password@peer.internal")
    with pytest.raises(ValueError, match="must not contain credentials"):
        Settings()


@pytest.mark.parametrize(
    ("peer_url", "message"),
    [
        ("https://@peer.example", "credentials"),
        ("https://peer.example/internal", "exact origin"),
        ("https://peer.example?region=ru", "query or fragment"),
        ("https://peer.example#health", "query or fragment"),
        ("https://peer.example:", "port between"),
        ("https://peer.example:0", "port between"),
        ("https://peer.example:65536", "invalid peer URL"),
        ("https://peer.example.", "unambiguous ASCII DNS name"),
        ("https://peer_name.example", "unambiguous ASCII DNS name"),
        ("https://péér.example", "unambiguous ASCII DNS name"),
    ],
)
def test_peer_urls_reject_malformed_origins(peer_url: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Settings(peer_urls=[peer_url])


def test_peer_public_url_alias_is_exact_and_backward_compatible(monkeypatch) -> None:
    monkeypatch.setenv("PRIVATE_PEER_URL", "http://10.0.0.2:8080/")
    assert Settings().private_peer_url == "http://10.0.0.2:8080"

    monkeypatch.setenv("PEER_PUBLIC_URL", "HTTPS://Peer-RU.Alerts.Example:443/")
    assert Settings().private_peer_url == "https://peer-ru.alerts.example:443"

    monkeypatch.setenv("PEER_PUBLIC_URL", "https://peer.example/internal")
    with pytest.raises(ValueError, match="exact origin"):
        Settings()


def test_sync_backoff_max_cannot_be_smaller_than_initial() -> None:
    with pytest.raises(ValueError, match="SYNC_BACKOFF_MAX_SECONDS"):
        Settings(sync_backoff_initial_seconds=10, sync_backoff_max_seconds=5)


def test_grafana_url_is_normalized_and_never_accepts_credentials() -> None:
    settings = Settings(grafana_url="HTTPS://Grafana.Example:443/d/ops?orgId=1#alerts")
    assert settings.grafana_url == "https://grafana.example:443/d/ops?orgId=1#alerts"

    with pytest.raises(ValueError, match="must not contain credentials"):
        Settings(grafana_url="https://operator:secret@grafana.example/d/ops")
    with pytest.raises(ValueError, match="must use http or https"):
        Settings(grafana_url="javascript:alert(1)")


def test_checks_settings_have_safe_bounded_defaults() -> None:
    settings = Settings()

    assert settings.checks_enabled is False
    assert settings.checks_stale_after_seconds == 180
    assert settings.checks_min_failure_sources == 1
    assert settings.checks_cache_ttl_seconds == 5
    assert settings.checks_future_tolerance_seconds == 30
    assert settings.checks_max_series == 5_000


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("checks_stale_after_seconds", 0),
        ("checks_stale_after_seconds", 86_401),
        ("checks_min_failure_sources", 0),
        ("checks_min_failure_sources", 1_001),
        ("checks_cache_ttl_seconds", 0),
        ("checks_cache_ttl_seconds", 5.01),
        ("checks_future_tolerance_seconds", -1),
        ("checks_future_tolerance_seconds", 301),
        ("checks_max_series", 0),
        ("checks_max_series", 100_001),
    ],
)
def test_checks_settings_reject_values_outside_documented_bounds(
    field: str,
    value: int | float,
) -> None:
    with pytest.raises(ValueError, match=field):
        Settings(**{field: value})


def test_checks_grafana_url_fails_soft_without_logging_the_value(monkeypatch) -> None:
    secret_url = "https://operator:do-not-log@grafana.example/d/checks"
    log_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        "alert_hub.settings.logger.warning",
        lambda *args, **kwargs: log_calls.append((args, kwargs)),
    )

    settings = Settings(checks_grafana_base_url=secret_url)

    assert settings.checks_grafana_base_url is None
    assert log_calls
    logged = repr(log_calls)
    assert "checks_grafana_url_disabled" in logged
    assert secret_url not in logged
    assert "do-not-log" not in logged


def test_checks_grafana_url_requires_explicit_http_and_preserves_admin_path() -> None:
    https_settings = Settings(
        checks_grafana_base_url="HTTPS://Grafana.Example:443/d/checks?orgId=1#panel"
    )
    rejected_http = Settings(checks_grafana_base_url="http://grafana.example/d/checks")
    allowed_http = Settings(
        checks_grafana_base_url="http://grafana.example/d/checks",
        allow_http_monitoring_urls=True,
    )

    assert (
        https_settings.checks_grafana_base_url
        == "https://grafana.example:443/d/checks?orgId=1#panel"
    )
    assert rejected_http.checks_grafana_base_url is None
    assert allowed_http.checks_grafana_base_url == "http://grafana.example/d/checks"
