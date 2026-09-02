from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from alert_hub.settings import Settings


class VapidConfigurationError(ValueError):
    pass


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def vapid_public_key(settings: Settings) -> str:
    if settings.vapid_public_key:
        return settings.vapid_public_key.strip()
    if settings.vapid_public_key_file is not None:
        try:
            value = settings.vapid_public_key_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise VapidConfigurationError("unable to read VAPID public key file") from exc
        if not value:
            raise VapidConfigurationError("VAPID public key file is empty")
        return value
    if settings.vapid_private_key_file is None:
        raise VapidConfigurationError("VAPID key is not configured")
    try:
        private_data = settings.vapid_private_key_file.read_bytes()
        private_key = serialization.load_pem_private_key(private_data, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise VapidConfigurationError("unable to load VAPID private key") from exc
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise VapidConfigurationError("VAPID private key must use the P-256 curve")
    encoded = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return _b64url(encoded)
