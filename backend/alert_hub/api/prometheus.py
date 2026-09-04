from __future__ import annotations

import base64
from typing import Any, Literal, cast

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import admin_user, get_db, get_envelope_cipher, get_settings
from alert_hub.application.auth import add_audit
from alert_hub.application.incidents import append_cluster_event
from alert_hub.application.prometheus import credentials_context, decrypt_credentials
from alert_hub.infrastructure.db.base import new_id, utc_now
from alert_hub.infrastructure.db.models import PrometheusDatasource, User
from alert_hub.infrastructure.encryption import EncryptionError, EnvelopeCipher
from alert_hub.infrastructure.prometheus import (
    PrometheusClient,
    PrometheusHTTPClient,
    PrometheusQueryError,
)
from alert_hub.infrastructure.url_safety import Resolver, UnsafeURL
from alert_hub.settings import Settings

router = APIRouter(prefix="/api/v1/prometheus-datasources", tags=["prometheus-datasources"])


class DatasourceCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_type: Literal["none", "bearer", "basic"] = "none"
    bearer_token: SecretStr | None = Field(default=None, min_length=1, max_length=8_192)
    username: SecretStr | None = Field(default=None, min_length=1, max_length=255)
    password: SecretStr | None = Field(default=None, min_length=1, max_length=8_192)

    @model_validator(mode="after")
    def validate_mode(self) -> DatasourceCredentials:
        token = self.bearer_token.get_secret_value() if self.bearer_token else None
        username = self.username.get_secret_value() if self.username else None
        password = self.password.get_secret_value() if self.password else None
        for value in (token, username, password):
            if value is not None and ("\r" in value or "\n" in value):
                raise ValueError("credentials must not contain line breaks")
        if self.auth_type == "bearer":
            if not token or any(character.isspace() for character in token):
                raise ValueError("bearer authentication requires a token without whitespace")
            if username is not None or password is not None:
                raise ValueError("bearer authentication does not accept basic credentials")
        elif self.auth_type == "basic":
            if not username or not password:
                raise ValueError("basic authentication requires username and password")
            if ":" in username:
                raise ValueError("basic authentication username must not contain a colon")
            if token is not None:
                raise ValueError("basic authentication does not accept a bearer token")
        elif any(value is not None for value in (token, username, password)):
            raise ValueError("auth_type none does not accept credentials")
        return self

    def encrypted_value(self) -> dict[str, str]:
        if self.auth_type == "bearer":
            assert self.bearer_token is not None
            return {
                "auth_type": "bearer",
                "bearer_token": self.bearer_token.get_secret_value(),
            }
        if self.auth_type == "basic":
            assert self.username is not None and self.password is not None
            return {
                "auth_type": "basic",
                "username": self.username.get_secret_value(),
                "password": self.password.get_secret_value(),
            }
        return {"auth_type": "none"}


class PrometheusDatasourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2_048)
    node_id: str | None = Field(default=None, max_length=128)
    region: str | None = Field(default=None, max_length=128)
    reachability_label_mode: Literal["canonical", "server"] = "canonical"
    enabled: bool = True
    credentials: DatasourceCredentials | None = Field(
        default=None,
        validation_alias=AliasChoices("credentials", "auth"),
    )


class PrometheusDatasourcePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: str | None = Field(default=None, min_length=1, max_length=2_048)
    node_id: str | None = Field(default=None, max_length=128)
    region: str | None = Field(default=None, max_length=128)
    reachability_label_mode: Literal["canonical", "server"] | None = None
    enabled: bool | None = None
    credentials: DatasourceCredentials | None = Field(
        default=None,
        validation_alias=AliasChoices("credentials", "auth"),
    )


def get_prometheus_client(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> PrometheusClient:
    override = getattr(request.app.state, "prometheus_client", None)
    if override is not None:
        return cast(PrometheusClient, override)
    transport = cast(
        httpx.AsyncBaseTransport | None,
        getattr(request.app.state, "prometheus_http_transport", None),
    )
    resolver = cast(
        Resolver,
        getattr(request.app.state, "prometheus_resolver", None),
    )
    if resolver is None:
        return PrometheusHTTPClient(settings, transport=transport)
    return PrometheusHTTPClient(settings, transport=transport, resolver=resolver)


def _credentials_summary(
    datasource: PrometheusDatasource,
    cipher: EnvelopeCipher,
) -> tuple[str, bool, list[str], bool]:
    if datasource.encrypted_credentials is None:
        return "none", False, [], True
    try:
        value = decrypt_credentials(datasource, cipher)
    except EncryptionError:
        return "unknown", True, [], False
    auth_type = str(value.get("auth_type") or "unknown")
    fields = {
        "bearer": ["bearer_token"],
        "basic": ["username", "password"],
    }.get(auth_type, [])
    return auth_type, auth_type != "none", fields, True


def datasource_response(
    datasource: PrometheusDatasource,
    cipher: EnvelopeCipher,
) -> dict[str, Any]:
    auth_type, configured, fields, available = _credentials_summary(datasource, cipher)
    return {
        "id": datasource.id,
        "name": datasource.name,
        "url": datasource.url,
        "node_id": datasource.node_id,
        "region": datasource.region,
        "reachability_label_mode": datasource.reachability_label_mode,
        "enabled": datasource.enabled,
        "auth_type": auth_type,
        "credentials_configured": configured,
        "configured_fields": fields,
        "credentials_available": available,
        "created_at": datasource.created_at,
        "updated_at": datasource.updated_at,
    }


def _replicated_payload(datasource: PrometheusDatasource) -> dict[str, Any]:
    return {
        "name": datasource.name,
        "url": datasource.url,
        "node_id": datasource.node_id,
        "region": datasource.region,
        "reachability_label_mode": datasource.reachability_label_mode,
        "enabled": datasource.enabled,
        "encrypted_credentials": (
            base64.b64encode(datasource.encrypted_credentials).decode()
            if datasource.encrypted_credentials is not None
            else None
        ),
        "created_at": datasource.created_at.isoformat(),
        "updated_at": datasource.updated_at.isoformat(),
    }


def _active_datasource(db: Session, datasource_id: str) -> PrometheusDatasource:
    datasource = db.get(PrometheusDatasource, datasource_id)
    if datasource is None:
        raise HTTPException(status_code=404, detail="Prometheus datasource not found")
    return datasource


def _encrypted_credentials(
    datasource_id: str,
    credentials: DatasourceCredentials | None,
    cipher: EnvelopeCipher,
) -> bytes | None:
    if credentials is None or credentials.auth_type == "none":
        return None
    return cipher.encrypt_json(
        credentials.encrypted_value(),
        context=credentials_context(datasource_id),
    )


@router.get("")
def list_prometheus_datasources(
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    user: User = Depends(admin_user),
) -> list[dict[str, Any]]:
    del user
    datasources = db.scalars(
        select(PrometheusDatasource).order_by(PrometheusDatasource.name, PrometheusDatasource.id)
    ).all()
    return [datasource_response(datasource, cipher) for datasource in datasources]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_prometheus_datasource(
    payload: PrometheusDatasourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    try:
        url = prometheus.validate_url(payload.url)
    except UnsafeURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    datasource_id = new_id()
    datasource = PrometheusDatasource(
        id=datasource_id,
        name=payload.name.strip(),
        url=url,
        node_id=payload.node_id,
        region=payload.region,
        reachability_label_mode=payload.reachability_label_mode,
        enabled=payload.enabled,
        encrypted_credentials=_encrypted_credentials(datasource_id, payload.credentials, cipher),
    )
    db.add(datasource)
    db.flush()
    append_cluster_event(
        db,
        settings,
        entity_type="prometheus_datasource",
        entity_id=datasource.id,
        operation="upsert",
        payload=_replicated_payload(datasource),
    )
    add_audit(
        db,
        settings,
        "prometheus_datasource_created",
        actor_user_id=user.id,
        entity_type="prometheus_datasource",
        entity_id=datasource.id,
        request_id=getattr(request.state, "request_id", None),
        details={"auth_type": payload.credentials.auth_type if payload.credentials else "none"},
    )
    db.commit()
    return datasource_response(datasource, cipher)


@router.patch("/{datasource_id}")
def update_prometheus_datasource(
    datasource_id: str,
    payload: PrometheusDatasourcePatch,
    request: Request,
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    datasource = _active_datasource(db, datasource_id)
    changes = payload.model_dump(exclude_unset=True, exclude={"credentials"})
    if payload.name is not None:
        datasource.name = payload.name.strip()
    if payload.url is not None:
        try:
            datasource.url = prometheus.validate_url(payload.url)
        except UnsafeURL as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    if "node_id" in payload.model_fields_set:
        datasource.node_id = payload.node_id
    if "region" in payload.model_fields_set:
        datasource.region = payload.region
    if payload.reachability_label_mode is not None:
        datasource.reachability_label_mode = payload.reachability_label_mode
    if payload.enabled is not None:
        datasource.enabled = payload.enabled
    if "credentials" in payload.model_fields_set:
        datasource.encrypted_credentials = _encrypted_credentials(
            datasource.id, payload.credentials, cipher
        )
        changes["credentials"] = "updated"
    datasource.updated_at = utc_now()
    append_cluster_event(
        db,
        settings,
        entity_type="prometheus_datasource",
        entity_id=datasource.id,
        operation="upsert",
        payload=_replicated_payload(datasource),
    )
    add_audit(
        db,
        settings,
        "prometheus_datasource_updated",
        actor_user_id=user.id,
        entity_type="prometheus_datasource",
        entity_id=datasource.id,
        request_id=getattr(request.state, "request_id", None),
        details={"fields": sorted(changes)},
    )
    db.commit()
    return datasource_response(datasource, cipher)


@router.delete("/{datasource_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_prometheus_datasource(
    datasource_id: str,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> None:
    datasource = _active_datasource(db, datasource_id)
    datasource.enabled = False
    datasource.updated_at = utc_now()
    append_cluster_event(
        db,
        settings,
        entity_type="prometheus_datasource",
        entity_id=datasource.id,
        operation="tombstone",
        payload=_replicated_payload(datasource),
    )
    add_audit(
        db,
        settings,
        "prometheus_datasource_deleted",
        actor_user_id=user.id,
        entity_type="prometheus_datasource",
        entity_id=datasource.id,
        request_id=getattr(request.state, "request_id", None),
    )
    db.delete(datasource)
    db.commit()


@router.post("/{datasource_id}/test")
async def test_prometheus_datasource(
    datasource_id: str,
    request: Request,
    db: Session = Depends(get_db),
    cipher: EnvelopeCipher = Depends(get_envelope_cipher),
    prometheus: PrometheusClient = Depends(get_prometheus_client),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin_user),
) -> dict[str, Any]:
    datasource = _active_datasource(db, datasource_id)
    actor_user_id = user.id
    target_url = datasource.url
    try:
        credentials = decrypt_credentials(datasource, cipher)
    except EncryptionError as exc:
        add_audit(
            db,
            settings,
            "prometheus_datasource_test_failed",
            actor_user_id=actor_user_id,
            entity_type="prometheus_datasource",
            entity_id=datasource_id,
            request_id=getattr(request.state, "request_id", None),
            details={"code": "credentials_unavailable"},
        )
        db.commit()
        raise HTTPException(
            status_code=502,
            detail={"code": "credentials_unavailable", "message": str(exc)},
        ) from exc
    db.close()
    try:
        samples = await prometheus.query(target_url, credentials, "connection_test")
    except PrometheusQueryError as exc:
        code = exc.code
        detail = exc.detail
        add_audit(
            db,
            settings,
            "prometheus_datasource_test_failed",
            actor_user_id=actor_user_id,
            entity_type="prometheus_datasource",
            entity_id=datasource_id,
            request_id=getattr(request.state, "request_id", None),
            details={"code": code},
        )
        db.commit()
        raise HTTPException(status_code=502, detail={"code": code, "message": detail}) from exc
    add_audit(
        db,
        settings,
        "prometheus_datasource_test_succeeded",
        actor_user_id=actor_user_id,
        entity_type="prometheus_datasource",
        entity_id=datasource_id,
        request_id=getattr(request.state, "request_id", None),
        details={"samples": len(samples)},
    )
    db.commit()
    return {"status": "ok", "query": "connection_test", "samples": len(samples)}
