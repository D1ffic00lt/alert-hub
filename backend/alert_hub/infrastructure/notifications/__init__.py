"""Notification provider adapters and their injectable transport boundaries."""

from alert_hub.infrastructure.notifications.registry import build_provider_registry

__all__ = ["build_provider_registry"]
