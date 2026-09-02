from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from alert_hub.infrastructure.db.models import PrometheusDatasource
from alert_hub.infrastructure.encryption import EncryptionError, EnvelopeCipher
from alert_hub.infrastructure.prometheus import (
    FixedQueryName,
    PrometheusClient,
    PrometheusQueryError,
    VectorSample,
)


def credentials_context(datasource_id: str) -> str:
    return f"prometheus_datasource:{datasource_id}:credentials"


def decrypt_credentials(
    datasource: PrometheusDatasource,
    cipher: EnvelopeCipher,
) -> dict[str, Any]:
    if datasource.encrypted_credentials is None:
        return {"auth_type": "none"}
    value = cipher.decrypt_json(
        datasource.encrypted_credentials,
        context=credentials_context(datasource.id),
    )
    if not isinstance(value, dict):
        raise EncryptionError("Prometheus datasource credentials are invalid")
    return {str(key): item for key, item in value.items()}


@dataclass(frozen=True, slots=True)
class DatasourceQueryResult:
    datasource_id: str
    datasource_name: str
    samples: list[VectorSample]


@dataclass(frozen=True, slots=True)
class DatasourceQueryFailure:
    datasource_id: str
    datasource_name: str
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class DatasourceQueryTarget:
    datasource_id: str
    datasource_name: str
    url: str
    credentials: dict[str, Any]


def prepare_enabled_datasources(
    db: Session,
    cipher: EnvelopeCipher | None,
) -> tuple[list[DatasourceQueryTarget], list[DatasourceQueryFailure], int]:
    datasources = db.scalars(
        select(PrometheusDatasource)
        .where(PrometheusDatasource.enabled.is_(True))
        .order_by(PrometheusDatasource.name, PrometheusDatasource.id)
    ).all()
    if not datasources:
        return [], [], 0
    targets: list[DatasourceQueryTarget] = []
    failures: list[DatasourceQueryFailure] = []
    for datasource in datasources:
        if cipher is None and datasource.encrypted_credentials is not None:
            failures.append(
                DatasourceQueryFailure(
                    datasource.id,
                    datasource.name,
                    "credentials_unavailable",
                    "Encrypted datasource credentials are unavailable on this node",
                )
            )
            continue
        try:
            credentials = (
                decrypt_credentials(datasource, cipher)
                if cipher is not None
                else {"auth_type": "none"}
            )
        except EncryptionError:
            failures.append(
                DatasourceQueryFailure(
                    datasource.id,
                    datasource.name,
                    "credentials_unavailable",
                    "Datasource credentials could not be decrypted on this node",
                )
            )
            continue
        targets.append(
            DatasourceQueryTarget(
                datasource.id,
                datasource.name,
                datasource.url,
                credentials,
            )
        )
    return targets, failures, len(datasources)


async def query_datasource_targets(
    targets: list[DatasourceQueryTarget],
    client: PrometheusClient,
    query_name: FixedQueryName,
) -> tuple[list[DatasourceQueryResult], list[DatasourceQueryFailure]]:
    async def query_one(
        target: DatasourceQueryTarget,
    ) -> DatasourceQueryResult | DatasourceQueryFailure:
        try:
            samples = await client.query(target.url, target.credentials, query_name)
        except PrometheusQueryError as exc:
            return DatasourceQueryFailure(
                target.datasource_id,
                target.datasource_name,
                exc.code,
                exc.detail,
            )
        return DatasourceQueryResult(target.datasource_id, target.datasource_name, samples)

    raw_results = await asyncio.gather(*(query_one(target) for target in targets))
    successes = [item for item in raw_results if isinstance(item, DatasourceQueryResult)]
    failures = [item for item in raw_results if isinstance(item, DatasourceQueryFailure)]
    return successes, failures
