from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from alert_hub.domain.heartbeats import heartbeat_window
from alert_hub.infrastructure.request_security import normalize_cidrs


class BootstrapRequest(BaseModel):
    bootstrap_token: str
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=1024)
    device_name: str = Field(default="Bootstrap device", max_length=255)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)
    device_name: str = Field(default="Browser", max_length=255)


class UserResponse(BaseModel):
    id: str
    username: str
    is_admin: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuthResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    csrf_token: str
    user: UserResponse


SourceKind = Literal["alertmanager", "generic_json", "heartbeat"]


class SourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    kind: SourceKind
    enabled: bool = True
    region: str | None = Field(default=None, max_length=128)
    config: dict[str, Any] = Field(default_factory=dict)
    allowed_cidrs: list[str] = Field(default_factory=list, max_length=256)

    @field_validator("allowed_cidrs", mode="before")
    @classmethod
    def validate_allowed_cidrs(cls, value: Any) -> list[str]:
        if not isinstance(value, list):
            raise ValueError("allowed_cidrs must be a list")
        return normalize_cidrs(value)

    @field_validator("config")
    @classmethod
    def validate_heartbeat(cls, value: dict[str, Any], info: Any) -> dict[str, Any]:
        if info.data.get("kind") == "heartbeat":
            heartbeat_window(value)
        return value


class SourcePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    enabled: bool | None = None
    region: str | None = Field(default=None, max_length=128)
    config: dict[str, Any] | None = None
    allowed_cidrs: list[str] | None = Field(default=None, max_length=256)

    @field_validator("allowed_cidrs", mode="before")
    @classmethod
    def validate_allowed_cidrs(cls, value: Any) -> list[str] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("allowed_cidrs must be a list")
        return normalize_cidrs(value)


class SourceResponse(BaseModel):
    id: str
    name: str
    kind: SourceKind
    enabled: bool
    region: str | None
    config: dict[str, Any]
    allowed_cidrs: list[str]
    created_at: datetime
    updated_at: datetime


class SourceCreatedResponse(SourceResponse):
    token: str
    webhook_url: str
    example: str


class IncidentActionRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


IncidentStatusFilter = Literal["active", "open", "acknowledged", "resolved", "silenced"]
IncidentSeverity = Literal["info", "warning", "critical", "unknown"]
IncidentBulkAction = Literal["acknowledge", "resolve", "silence"]


class IncidentBulkFilters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IncidentStatusFilter | None = None
    severity: IncidentSeverity | None = None
    source_id: str | None = Field(default=None, min_length=1, max_length=36)
    q: str | None = Field(default=None, max_length=200)
    alertname: str | None = Field(default=None, min_length=1, max_length=200)
    prometheus_datasource_id: str | None = Field(default=None, min_length=1, max_length=36)


class IncidentBulkActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: IncidentBulkAction
    selection_mode: Literal["ids", "filter"]
    incident_ids: list[str] = Field(default_factory=list, max_length=500)
    excluded_incident_ids: list[str] = Field(default_factory=list, max_length=500)
    filters: IncidentBulkFilters | None = None
    reason: str | None = Field(default=None, max_length=2000)

    @field_validator("incident_ids", "excluded_incident_ids")
    @classmethod
    def validate_incident_ids(cls, value: list[str]) -> list[str]:
        normalized = [incident_id.strip() for incident_id in value]
        if any(not incident_id or len(incident_id) > 36 for incident_id in normalized):
            raise ValueError("incident IDs must contain 1 to 36 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("incident IDs must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_selection(self) -> IncidentBulkActionRequest:
        if self.selection_mode == "ids":
            if not self.incident_ids:
                raise ValueError("incident_ids is required for ids selection")
            if self.excluded_incident_ids or self.filters is not None:
                raise ValueError("ids selection does not accept filters or exclusions")
        else:
            if self.incident_ids:
                raise ValueError("filter selection does not accept incident_ids")
            if self.filters is None:
                raise ValueError("filters is required for filter selection")
        return self


class IncidentBulkActionItem(BaseModel):
    incident_id: str
    outcome: Literal["updated", "unchanged", "not_found", "conflict"]
    status: Literal["open", "acknowledged", "resolved", "silenced"] | None = None
    detail: str | None = None


class IncidentBulkActionResponse(BaseModel):
    action: IncidentBulkAction
    selection_mode: Literal["ids", "filter"]
    matched: int
    updated: int
    unchanged: int
    failed: int
    results: list[IncidentBulkActionItem]


class IncidentCommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=10_000)


class SyncQueryRequest(BaseModel):
    cursor: dict[str, int] = Field(default_factory=dict)
    limit: int | None = Field(default=None, ge=1, le=1_000)

    @field_validator("cursor")
    @classmethod
    def validate_cursor(cls, value: dict[str, int]) -> dict[str, int]:
        if any(not key or seq < 0 for key, seq in value.items()):
            raise ValueError("cursor keys must be non-empty and sequences non-negative")
        return value
