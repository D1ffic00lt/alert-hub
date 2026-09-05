from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import admin_user, current_user, get_db, get_settings
from alert_hub.application.auth import add_audit
from alert_hub.application.incidents import append_cluster_event
from alert_hub.application.monitoring_settings import (
    MONITORING_SETTINGS_ID,
    MonitoringSettingsSnapshot,
    monitoring_settings_snapshot,
)
from alert_hub.domain.monitoring import normalize_grafana_url, normalize_job_globs
from alert_hub.infrastructure.db.base import utc_now
from alert_hub.infrastructure.db.models import ApplicationSetting, User
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/application-settings", tags=["application-settings"])


class ApplicationSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grafana_url: str | None = Field(default=None, max_length=2_048)
    key_job_globs: list[str] | None = Field(default=None, min_length=1, max_length=32)
    alert_hub_job_globs: list[str] | None = Field(default=None, min_length=1, max_length=32)

    @field_validator("grafana_url")
    @classmethod
    def validate_grafana_url(cls, value: str | None) -> str | None:
        return normalize_grafana_url(value, https_only=True)

    @field_validator("key_job_globs", "alert_hub_job_globs")
    @classmethod
    def validate_job_globs(cls, value: list[str] | None, info: Any) -> list[str]:
        if value is None:
            raise ValueError(f"{info.field_name} must not be null")
        return normalize_job_globs(value, field_name=info.field_name)

    @model_validator(mode="after")
    def require_change(self) -> ApplicationSettingsPatch:
        if not self.model_fields_set:
            raise ValueError("at least one application setting is required")
        return self


def _response(snapshot: MonitoringSettingsSnapshot) -> dict[str, Any]:
    return {
        "grafana_url": snapshot.grafana_url,
        "key_job_globs": snapshot.key_job_globs,
        "alert_hub_job_globs": snapshot.alert_hub_job_globs,
    }


def _replicated_payload(stored: ApplicationSetting) -> dict[str, Any]:
    return {
        "grafana_url": stored.grafana_url,
        "key_job_globs": stored.key_job_globs,
        "alert_hub_job_globs": stored.alert_hub_job_globs,
        "created_at": stored.created_at.isoformat(),
        "updated_at": stored.updated_at.isoformat(),
    }


@router.get("")
def get_application_settings(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(current_user),
) -> dict[str, Any]:
    del user
    return _response(monitoring_settings_snapshot(db, settings))


@router.patch("")
def update_application_settings(
    payload: ApplicationSettingsPatch,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    current = monitoring_settings_snapshot(db, settings)
    stored = db.get(ApplicationSetting, MONITORING_SETTINGS_ID)
    now = utc_now()
    if stored is None:
        stored = ApplicationSetting(
            id=MONITORING_SETTINGS_ID,
            grafana_url=current.grafana_url,
            key_job_globs=current.key_job_globs,
            alert_hub_job_globs=current.alert_hub_job_globs,
            created_at=now,
            updated_at=now,
        )
        db.add(stored)
    changed_fields = payload.model_fields_set
    if "grafana_url" in changed_fields:
        stored.grafana_url = payload.grafana_url
    if "key_job_globs" in changed_fields:
        assert payload.key_job_globs is not None
        stored.key_job_globs = payload.key_job_globs
    if "alert_hub_job_globs" in changed_fields:
        assert payload.alert_hub_job_globs is not None
        stored.alert_hub_job_globs = payload.alert_hub_job_globs
    stored.updated_at = now
    db.flush()
    append_cluster_event(
        db,
        settings,
        entity_type="application_setting",
        entity_id=MONITORING_SETTINGS_ID,
        operation="upsert",
        payload=_replicated_payload(stored),
    )
    add_audit(
        db,
        settings,
        "application_settings_updated",
        actor_user_id=user.id,
        entity_type="application_setting",
        entity_id=MONITORING_SETTINGS_ID,
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changed_fields)},
    )
    db.commit()
    return _response(monitoring_settings_snapshot(db, settings))
