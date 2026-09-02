from __future__ import annotations

from alert_hub.application.notifications import ProviderRegistry
from alert_hub.infrastructure.notifications.generic_webhook import GenericWebhookProvider
from alert_hub.infrastructure.notifications.http import HttpxTransport
from alert_hub.infrastructure.notifications.smtp import SmtplibTransport, SMTPProvider
from alert_hub.infrastructure.notifications.telegram import TelegramProvider
from alert_hub.infrastructure.notifications.web_push import PyWebPushTransport, WebPushProvider
from alert_hub.settings import Settings


def build_provider_registry(settings: Settings) -> ProviderRegistry:
    http = HttpxTransport()
    timeout = settings.notification_provider_timeout_seconds
    return ProviderRegistry(
        {
            "generic_webhook": GenericWebhookProvider(
                http,
                timeout_seconds=timeout,
                allow_http=settings.allow_http_webhooks,
                allow_private=settings.allow_private_webhooks,
            ),
            "telegram": TelegramProvider(http, timeout_seconds=timeout),
            "smtp": SMTPProvider(SmtplibTransport(), timeout_seconds=timeout),
            "web_push": WebPushProvider(
                PyWebPushTransport(),
                private_key_path=settings.vapid_private_key_file,
                subject=settings.vapid_subject,
                ttl_seconds=settings.web_push_ttl_seconds,
                timeout_seconds=timeout,
            ),
        }
    )
