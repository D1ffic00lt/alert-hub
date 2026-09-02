from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from typing import Any, Protocol

from alert_hub.application.notifications import (
    DeliveryResult,
    DeliveryTarget,
    NotificationMessage,
)
from alert_hub.infrastructure.notifications.smtp_templates import (
    SMTPTemplateError,
    render_smtp_templates,
)


class SMTPRetryableError(Exception):
    pass


class SMTPPermanentError(Exception):
    pass


class SMTPTransport(Protocol):
    async def send(
        self, config: dict[str, Any], message: EmailMessage, *, timeout_seconds: float
    ) -> None: ...


class SmtplibTransport:
    async def send(
        self, config: dict[str, Any], message: EmailMessage, *, timeout_seconds: float
    ) -> None:
        await asyncio.to_thread(self._send_sync, config, message, timeout_seconds)

    @staticmethod
    def _send_sync(config: dict[str, Any], message: EmailMessage, timeout_seconds: float) -> None:
        host = str(config["host"])
        port = int(config.get("port") or 587)
        mode = str(config.get("tls") or "starttls").lower()
        if mode not in {"starttls", "implicit", "ssl", "smtps"}:
            raise SMTPPermanentError
        smtp_class = smtplib.SMTP_SSL if mode in {"implicit", "ssl", "smtps"} else smtplib.SMTP
        try:
            with smtp_class(host, port, timeout=timeout_seconds) as client:
                if mode == "starttls":
                    client.starttls(context=ssl.create_default_context())
                username = config.get("username")
                if username:
                    client.login(str(username), str(config.get("password") or ""))
                client.send_message(message)
        except (
            smtplib.SMTPAuthenticationError,
            smtplib.SMTPNotSupportedError,
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
        ) as exc:
            raise SMTPPermanentError from exc
        except smtplib.SMTPResponseException as exc:
            if 400 <= exc.smtp_code < 500:
                raise SMTPRetryableError from exc
            raise SMTPPermanentError from exc
        except (TimeoutError, smtplib.SMTPServerDisconnected, OSError) as exc:
            raise SMTPRetryableError from exc


class SMTPProvider:
    def __init__(self, transport: SMTPTransport, *, timeout_seconds: float) -> None:
        self._transport = transport
        self._timeout_seconds = timeout_seconds

    async def send(self, message: NotificationMessage, target: DeliveryTarget) -> DeliveryResult:
        config = dict(target.config)
        required = ("host", "port", "from", "to")
        if any(config.get(field) is None or config.get(field) == "" for field in required):
            return DeliveryResult("permanent", "not_configured", "missing_configuration")
        mode = str(config.get("tls") or "starttls").lower()
        if mode not in {"starttls", "implicit", "ssl", "smtps"}:
            return DeliveryResult("permanent", "not_configured", "invalid_tls_mode")
        recipients = config["to"]
        if isinstance(recipients, str):
            recipient_list = [item.strip() for item in recipients.split(",") if item.strip()]
        elif isinstance(recipients, list):
            recipient_list = [str(item).strip() for item in recipients if str(item).strip()]
        else:
            recipient_list = []
        if not recipient_list:
            return DeliveryResult("permanent", "not_configured", "missing_recipients")
        try:
            subject, body = render_smtp_templates(config, message)
        except SMTPTemplateError:
            return DeliveryResult("permanent", "not_configured", "invalid_template")
        email = EmailMessage()
        app_name = message.app_name.replace("\r", " ").replace("\n", " ").strip()
        configured_from = str(config["from"])
        display_name, sender_address = parseaddr(configured_from)
        sender = (
            formataddr((app_name, sender_address))
            if sender_address and not display_name
            else configured_from
        )
        try:
            email["Subject"] = subject
            email["From"] = sender
            email["To"] = ", ".join(recipient_list)
        except ValueError:
            return DeliveryResult("permanent", "not_configured", "invalid_mail_header")
        email.set_content(body)
        try:
            await self._transport.send(config, email, timeout_seconds=self._timeout_seconds)
        except SMTPRetryableError:
            return DeliveryResult("retryable", "transport_error", "provider_unavailable")
        except SMTPPermanentError:
            return DeliveryResult("permanent", "rejected", "provider_rejected")
        return DeliveryResult("succeeded", "accepted")
