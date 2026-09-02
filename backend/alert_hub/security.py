from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, cast

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65_536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# A valid hash generated with the active parameters. Login verifies this when the
# username is absent so database existence does not skip the expensive Argon2 path.
DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$MJZsn8OxajWE8s7kgK2EUg$"
    "Qy1EnIK7yHq3l9ruUgPZabscijdpU/K5bJ36X2xRr7s"
)


class TokenError(ValueError):
    pass


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def random_token(bytes_count: int = 32) -> str:
    return secrets.token_urlsafe(bytes_count)


def hash_token(token: str, secret: str, purpose: str) -> str:
    message = f"{purpose}\0{token}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed token") from exc


def encode_access_token(
    user_id: str,
    session_id: str,
    signing_key: str,
    ttl_seconds: int,
    *,
    now: int | None = None,
) -> str:
    issued_at = int(time.time()) if now is None else now
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "sid": session_id,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
        "iss": "alert_hub",
        "jti": random_token(12),
    }
    encoded_header = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(signing_key.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64encode(signature)}"


def decode_access_token(token: str, signing_key: str, *, now: int | None = None) -> dict[str, Any]:
    try:
        header_part, payload_part, signature_part = token.split(".")
    except ValueError as exc:
        raise TokenError("malformed token") from exc
    signing_input = f"{header_part}.{payload_part}"
    expected = hmac.new(signing_key.encode(), signing_input.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64decode(signature_part)):
        raise TokenError("invalid token signature")
    try:
        header = json.loads(_b64decode(header_part))
        payload = json.loads(_b64decode(payload_part))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TokenError("malformed token payload") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenError("malformed token payload")
    if header != {"alg": "HS256", "typ": "JWT"} or payload.get("iss") != "alert_hub":
        raise TokenError("unsupported token")
    current = int(time.time()) if now is None else now
    if not isinstance(payload.get("exp"), int) or payload["exp"] <= current:
        raise TokenError("token expired")
    if not isinstance(payload.get("sub"), str) or not isinstance(payload.get("sid"), str):
        raise TokenError("invalid token claims")
    return cast(dict[str, Any], payload)
