from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from alert_hub.settings import Settings


class VapidConfigurationError(ValueError):
    pass


_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _validated_public_key(value: str) -> tuple[str, bytes]:
    candidate = value.strip()
    if not candidate or _BASE64URL_PATTERN.fullmatch(candidate) is None:
        raise VapidConfigurationError("VAPID public key must be canonical unpadded base64url")
    try:
        padding = "=" * (-len(candidate) % 4)
        decoded = base64.b64decode(candidate + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VapidConfigurationError("VAPID public key must be base64url encoded") from exc
    if _b64url(decoded) != candidate:
        raise VapidConfigurationError("VAPID public key must be canonical unpadded base64url")
    if len(decoded) != 65 or decoded[0] != 4:
        raise VapidConfigurationError("VAPID public key must be an uncompressed P-256 point")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), decoded)
    except ValueError as exc:
        raise VapidConfigurationError(
            "VAPID public key must be an uncompressed P-256 point"
        ) from exc
    return candidate, decoded


def _load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    try:
        private_data = path.read_bytes()
        private_key = serialization.load_pem_private_key(private_data, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise VapidConfigurationError("unable to load VAPID private key") from exc
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise VapidConfigurationError("VAPID private key must use the P-256 curve")
    return private_key


def _private_public_bytes(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def vapid_public_key(settings: Settings) -> str:
    explicit_public_key: str | None = None
    if settings.vapid_public_key and settings.vapid_public_key.strip():
        explicit_public_key = settings.vapid_public_key.strip()
    elif settings.vapid_public_key_file is not None:
        try:
            value = settings.vapid_public_key_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise VapidConfigurationError("unable to read VAPID public key file") from exc
        if not value:
            raise VapidConfigurationError("VAPID public key file is empty")
        explicit_public_key = value

    if explicit_public_key is not None:
        canonical, public_bytes = _validated_public_key(explicit_public_key)
        if settings.vapid_private_key_file is not None:
            private_key = _load_private_key(settings.vapid_private_key_file)
            if public_bytes != _private_public_bytes(private_key):
                raise VapidConfigurationError("VAPID public and private keys do not match")
        return canonical

    if settings.vapid_private_key_file is None:
        raise VapidConfigurationError("VAPID key is not configured")
    return _b64url(_private_public_bytes(_load_private_key(settings.vapid_private_key_file)))
