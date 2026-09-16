from __future__ import annotations

import os

import pytest

from alert_hub_mcp.config import ConfigurationError, MCPSettings

TOKEN = "ahs_11111111-1111-1111-1111-111111111111.abcdefghijklmnopqrstuvwxyz"


def test_loads_bounded_multi_node_configuration(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text(f"{TOKEN}\n", encoding="utf-8")
    token_file.chmod(0o600)

    settings = MCPSettings.from_env(
        {
            "ALERT_HUB_NODES": ("ru=https://ru-api.example.com/,nl=https://nl-api.example.com:443"),
            "ALERT_HUB_TOKEN_FILE": str(token_file),
            "ALERT_HUB_TIMEOUT_SECONDS": "3.5",
            "ALERT_HUB_MAX_RESPONSE_BYTES": "65536",
        }
    )

    assert [(node.name, node.base_url) for node in settings.nodes] == [
        ("ru", "https://ru-api.example.com"),
        ("nl", "https://nl-api.example.com"),
    ]
    assert settings.timeout_seconds == 3.5
    assert settings.max_response_bytes == 65_536


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"ALERT_HUB_URL": "http://alerts.example", "ALERT_HUB_TOKEN": "ahs_x"}, "HTTPS"),
        (
            {
                "ALERT_HUB_URL": "https://user:secret@alerts.example",
                "ALERT_HUB_TOKEN": "ahs_x",
            },
            "credentials",
        ),
        (
            {
                "ALERT_HUB_URL": "https://alerts.example/path",
                "ALERT_HUB_TOKEN": "ahs_x",
            },
            "without a path",
        ),
        (
            {
                "ALERT_HUB_URL": "https://alerts.example",
                "ALERT_HUB_TOKEN": "ahs_x",
                "ALERT_HUB_TOKEN_FILE": "/tmp/token",
            },
            "exactly one",
        ),
    ],
)
def test_rejects_unsafe_configuration(environment, message) -> None:
    with pytest.raises(ConfigurationError, match=message):
        MCPSettings.from_env(environment)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_rejects_group_readable_token_file(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("ahs_token", encoding="utf-8")
    token_file.chmod(0o640)

    with pytest.raises(ConfigurationError, match="0600"):
        MCPSettings.from_env(
            {
                "ALERT_HUB_URL": "https://alerts.example",
                "ALERT_HUB_TOKEN_FILE": str(token_file),
            }
        )


def test_explicit_local_http_and_direct_token_are_supported() -> None:
    settings = MCPSettings.from_env(
        {
            "ALERT_HUB_URL": "http://localhost:8080",
            "ALERT_HUB_ALLOW_HTTP": "true",
            "ALERT_HUB_TOKEN": TOKEN,
        }
    )

    assert settings.nodes[0].base_url == "http://localhost:8080"
    assert settings.token == TOKEN


@pytest.mark.parametrize(
    "environment",
    [
        {
            "ALERT_HUB_URL": "https://alerts.example",
            "ALERT_HUB_TOKEN": TOKEN,
            "ALERT_HUB_ALLOW_HTTP": "sometimes",
        },
        {
            "ALERT_HUB_URL": "https://alerts.example",
            "ALERT_HUB_TOKEN": TOKEN,
            "ALERT_HUB_TIMEOUT_SECONDS": "forever",
        },
        {
            "ALERT_HUB_URL": "https://alerts.example",
            "ALERT_HUB_TOKEN": TOKEN,
            "ALERT_HUB_MAX_RESPONSE_BYTES": "1",
        },
        {
            "ALERT_HUB_URL": "https://alerts.example:invalid",
            "ALERT_HUB_TOKEN": TOKEN,
        },
    ],
)
def test_rejects_invalid_bounded_values(environment) -> None:
    with pytest.raises(ConfigurationError):
        MCPSettings.from_env(environment)
