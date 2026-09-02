from __future__ import annotations

import base64
import socket
from pathlib import Path

import pytest

from alert_hub.infrastructure.encryption import (
    EncryptionError,
    EnvelopeCipher,
    build_envelope_cipher,
    load_master_key,
)
from alert_hub.infrastructure.url_safety import UnsafeURL, validate_headers, validate_webhook_url
from alert_hub.settings import Settings


def test_aes_gcm_envelopes_are_random_and_context_bound() -> None:
    cipher = EnvelopeCipher(b"k" * 32)
    first = cipher.encrypt_json({"token": "very-secret"}, context="channel:one:config")
    second = cipher.encrypt_json({"token": "very-secret"}, context="channel:one:config")

    assert first != second
    assert b"very-secret" not in first
    assert cipher.decrypt_json(first, context="channel:one:config") == {"token": "very-secret"}
    with pytest.raises(EncryptionError):
        cipher.decrypt_json(first, context="channel:two:config")


def test_master_key_file_accepts_base64url(tmp_path: Path) -> None:
    key = bytes(range(32))
    path = tmp_path / "master-key"
    path.write_text(base64.urlsafe_b64encode(key).decode().rstrip("="), encoding="utf-8")
    assert load_master_key(path) == key


def test_production_never_derives_an_encryption_key() -> None:
    settings = Settings(
        environment="production",
        signing_key="production-signing-key",
        cluster_secret="production-cluster-key",
    )
    assert build_envelope_cipher(settings) is None


def test_webhook_url_rejects_unsafe_destinations() -> None:
    with pytest.raises(UnsafeURL, match="HTTPS"):
        validate_webhook_url("http://example.com/hook")
    with pytest.raises(UnsafeURL, match="credentials"):
        validate_webhook_url("https://user:password@example.com/hook")
    with pytest.raises(UnsafeURL, match="private"):
        validate_webhook_url("https://127.0.0.1/hook")

    def private_resolver(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", 443))]

    with pytest.raises(UnsafeURL, match="private"):
        validate_webhook_url("https://webhook.example/hook", resolver=private_resolver)

    def public_resolver(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]

    assert (
        validate_webhook_url("https://webhook.example/hook#fragment", resolver=public_resolver)
        == "https://webhook.example/hook"
    )


def test_webhook_header_validation_blocks_injection() -> None:
    assert validate_headers({"X-Signature": "safe"}) == {"X-Signature": "safe"}
    with pytest.raises(UnsafeURL):
        validate_headers({"X-Test": "safe\r\nInjected: true"})
