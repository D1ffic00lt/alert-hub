from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from alert_hub.domain.monitoring import (
    DEFAULT_ALERT_HUB_JOB_GLOBS,
    DEFAULT_KEY_JOB_GLOBS,
)
from alert_hub.infrastructure.db.models import ApplicationSetting
from alert_hub.settings import Settings

MONITORING_SETTINGS_ID = "monitoring"


@dataclass(frozen=True, slots=True)
class MonitoringSettingsSnapshot:
    grafana_url: str | None
    key_job_globs: list[str]
    alert_hub_job_globs: list[str]


def monitoring_settings_snapshot(
    db: Session,
    runtime_settings: Settings,
) -> MonitoringSettingsSnapshot:
    stored = db.get(ApplicationSetting, MONITORING_SETTINGS_ID)
    if stored is None:
        return MonitoringSettingsSnapshot(
            grafana_url=runtime_settings.grafana_url,
            key_job_globs=list(DEFAULT_KEY_JOB_GLOBS),
            alert_hub_job_globs=list(DEFAULT_ALERT_HUB_JOB_GLOBS),
        )
    return MonitoringSettingsSnapshot(
        grafana_url=stored.grafana_url,
        key_job_globs=list(stored.key_job_globs),
        alert_hub_job_globs=list(stored.alert_hub_job_globs),
    )
