from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from contextlib import suppress
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from alert_hub.settings import Settings

_ENVELOPE_MAGIC = b"AH1"
_NONCE_SIZE = 12


class EncryptionError(ValueError):
    """Raised when encrypted application data cannot be authenticated or decoded."""


def _decode_master_key(raw: bytes) -> bytes:
    stripped = raw.strip()
    if len(stripped) == 32 and any(byte > 0x7F or byte == 0 for byte in stripped):
        return stripped
    try:
        text = stripped.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EncryptionError("master encryption key has an unsupported encoding") from exc

    candidates: list[bytes] = []
    if len(text) == 64:
        with suppress(ValueError):
            candidates.append(bytes.fromhex(text))
    try:
        padding = "=" * (-len(text) % 4)
        candidates.append(base64.urlsafe_b64decode(text + padding))
    except (ValueError, binascii.Error):
        pass
    if len(stripped) == 32:
        candidates.append(stripped)
    for candidate in candidates:
        if len(candidate) == 32:
            return candidate
    raise EncryptionError("master encryption key must decode to exactly 32 bytes")


def load_master_key(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EncryptionError(f"unable to read master encryption key file: {path}") from exc
    return _decode_master_key(raw)


class EnvelopeCipher:
    """Versioned AES-256-GCM envelope with context-bound associated data."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise EncryptionError("AES-256-GCM requires a 32-byte key")
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: bytes, *, context: str) -> bytes:
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = self._aes.encrypt(nonce, plaintext, _associated_data(context))
        return _ENVELOPE_MAGIC + nonce + ciphertext

    def decrypt(self, envelope: bytes, *, context: str) -> bytes:
        minimum_size = len(_ENVELOPE_MAGIC) + _NONCE_SIZE + 16
        if len(envelope) < minimum_size or not envelope.startswith(_ENVELOPE_MAGIC):
            raise EncryptionError("unsupported or truncated encrypted envelope")
        offset = len(_ENVELOPE_MAGIC)
        nonce = envelope[offset : offset + _NONCE_SIZE]
        ciphertext = envelope[offset + _NONCE_SIZE :]
        try:
            return self._aes.decrypt(nonce, ciphertext, _associated_data(context))
        except InvalidTag as exc:
            raise EncryptionError("encrypted envelope authentication failed") from exc

    def encrypt_json(self, value: Any, *, context: str) -> bytes:
        plaintext = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return self.encrypt(plaintext, context=context)

    def decrypt_json(self, envelope: bytes, *, context: str) -> Any:
        try:
            return json.loads(self.decrypt(envelope, context=context))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EncryptionError("encrypted JSON payload is invalid") from exc


def _associated_data(context: str) -> bytes:
    if not context:
        raise EncryptionError("encryption context must not be empty")
    return f"alert_hub:v1:{context}".encode()


def build_envelope_cipher(settings: Settings) -> EnvelopeCipher | None:
    if settings.master_encryption_key_file is not None:
        return EnvelopeCipher(load_master_key(settings.master_encryption_key_file))
    if settings.environment == "production":
        return None
    # Development/test remain usable without checking a key into source control. This fallback
    # is intentionally forbidden in production and stable only while SIGNING_KEY is unchanged.
    key = hashlib.sha256(
        f"alert_hub-development-envelope\0{settings.signing_key}".encode()
    ).digest()
    return EnvelopeCipher(key)
