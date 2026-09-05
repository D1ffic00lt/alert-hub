from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from alert_hub.api.dependencies import current_user, get_db
from alert_hub.application.statistics import (
    StatisticsSnapshotCache,
    StatisticsWindow,
    StatisticsWorkloadExceeded,
    statistics_snapshot,
)
from alert_hub.infrastructure.db.models import User

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics-summary"])


class StatisticsTotalsResponse(BaseModel):
    incidents_started: int
    incidents_resolved: int
    active_incidents: int
    active_critical: int
    acknowledgement_rate: float | None
    resolution_rate: float | None
    mean_time_to_acknowledge_seconds: float | None
    mean_time_to_resolve_seconds: float | None
    deliveries: int
    deliveries_succeeded: int
    deliveries_failed: int
    delivery_success_rate: float | None


class StatisticsTimelineResponse(BaseModel):
    starts_at: datetime
    incidents_started: int
    incidents_resolved: int
    deliveries_succeeded: int
    deliveries_failed: int


class StatisticsSeverityResponse(BaseModel):
    severity: str
    count: int


class StatisticsSourceResponse(BaseModel):
    source_id: str
    name: str
    region: str | None
    count: int


class StatisticsChannelResponse(BaseModel):
    channel_id: str
    name: str
    kind: str
    total: int
    succeeded: int
    failed: int
    success_rate: float | None


class StatisticsResponse(BaseModel):
    window: StatisticsWindow
    generated_at: datetime
    starts_at: datetime
    ends_at: datetime
    bucket_seconds: int
    totals: StatisticsTotalsResponse
    timeline: list[StatisticsTimelineResponse]
    severities: list[StatisticsSeverityResponse]
    sources: list[StatisticsSourceResponse]
    channels: list[StatisticsChannelResponse]


@router.get("/statistics", response_model=StatisticsResponse)
def metrics_statistics(
    request: Request,
    window: StatisticsWindow = Query(default="24h"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> StatisticsResponse:
    del user
    cache: StatisticsSnapshotCache = request.app.state.statistics_snapshot_cache

    try:
        # This GET-only dependency Session has no pending writes. Reusing it avoids
        # holding one pool checkout for auth while waiting for a second checkout.
        snapshot = cache.get_or_compute(window, lambda: statistics_snapshot(db, window))
    except StatisticsWorkloadExceeded as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return StatisticsResponse.model_validate(snapshot)
