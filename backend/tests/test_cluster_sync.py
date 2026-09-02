from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from alert_hub.domain.events import utc_now
from alert_hub.infrastructure.db.models import ClusterEvent

CLUSTER_HEADERS = {"Authorization": "Bearer test-cluster-key-with-enough-entropy"}


def _event(origin: str, sequence: int, *, occurred_offset: int) -> ClusterEvent:
    return ClusterEvent(
        event_id=f"{origin}-{sequence}",
        origin_node_id=origin,
        origin_seq=sequence,
        entity_type="regression",
        entity_id=f"entity-{origin}",
        operation="updated",
        occurred_at=utc_now() + timedelta(seconds=occurred_offset),
        payload_json={"sequence": sequence},
    )


def _all_pages(
    client: TestClient, *, limit: int
) -> tuple[list[dict[str, object]], dict[str, int], list[bool]]:
    # The application registers its own node metadata as origin sequence 1.
    cursor: dict[str, int] = {"test-node": 1}
    events: list[dict[str, object]] = []
    has_more_values: list[bool] = []

    for _ in range(20):
        response = client.post(
            "/internal/v1/sync/events/query",
            headers=CLUSTER_HEADERS,
            json={"cursor": cursor, "limit": limit},
        )
        assert response.status_code == 200, response.text
        page = response.json()
        events.extend(page["events"])
        cursor = page["cursor"]
        has_more_values.append(page["has_more"])
        if not page["has_more"]:
            return events, cursor, has_more_values

    raise AssertionError("sync pagination did not terminate")


def test_sync_pagination_does_not_skip_older_timestamp_with_higher_sequence(
    client: TestClient, app
) -> None:
    with app.state.session_factory.begin() as db:
        db.add_all(
            [
                _event("origin-a", 1, occurred_offset=60),
                _event("origin-a", 2, occurred_offset=0),
            ]
        )

    events, cursor, has_more_values = _all_pages(client, limit=1)

    assert [event["origin_seq"] for event in events] == [1, 2]
    assert cursor == {"test-node": 1, "origin-a": 2}
    assert has_more_values == [True, False]


def test_sync_pagination_advances_each_origin_without_cross_origin_skips(
    client: TestClient, app
) -> None:
    with app.state.session_factory.begin() as db:
        db.add_all(
            [
                _event("origin-a", 1, occurred_offset=40),
                _event("origin-a", 2, occurred_offset=20),
                _event("origin-b", 1, occurred_offset=30),
                _event("origin-b", 2, occurred_offset=10),
            ]
        )

    events, cursor, has_more_values = _all_pages(client, limit=2)

    assert [(event["origin_node_id"], event["origin_seq"]) for event in events] == [
        ("origin-a", 1),
        ("origin-b", 1),
        ("origin-a", 2),
        ("origin-b", 2),
    ]
    assert cursor == {"test-node": 1, "origin-a": 2, "origin-b": 2}
    assert has_more_values == [True, False]
