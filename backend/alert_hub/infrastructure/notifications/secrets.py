from __future__ import annotations

from typing import Any

from alert_hub.infrastructure.db.models import NotificationChannel, PushSubscription
from alert_hub.infrastructure.encryption import EncryptionError, EnvelopeCipher


def decrypt_channel_config(channel: NotificationChannel, cipher: EnvelopeCipher) -> dict[str, Any]:
    """Decrypt a channel configuration only at a provider-facing boundary."""

    if not channel.encrypted_config:
        return {}
    value = cipher.decrypt_json(
        channel.encrypted_config,
        context=f"channel:{channel.id}:config",
    )
    if not isinstance(value, dict):
        raise EncryptionError("channel configuration must be a JSON object")
    return {str(key): item for key, item in value.items()}


def decrypt_push_subscription(
    subscription: PushSubscription, cipher: EnvelopeCipher
) -> tuple[str, str, str]:
    """Decrypt endpoint material immediately before Web Push delivery."""

    values: list[str] = []
    for name, envelope in (
        ("endpoint", subscription.endpoint),
        ("p256dh", subscription.p256dh),
        ("auth", subscription.auth),
    ):
        try:
            values.append(
                cipher.decrypt(
                    envelope,
                    context=f"push_subscription:{subscription.id}:{name}",
                ).decode()
            )
        except UnicodeDecodeError as exc:
            raise EncryptionError("push subscription material is not UTF-8") from exc
    return values[0], values[1], values[2]
