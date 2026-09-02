from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from alert_hub.domain.events import rendezvous_rank

_OPERATORS = {
    "=": "equals",
    "==": "equals",
    "equals": "equals",
    "!=": "not_equals",
    "not_equals": "not_equals",
    "=~": "regex",
    "regex": "regex",
    "!~": "not_regex",
    "not_regex": "not_regex",
    "exists": "exists",
    "not_exists": "not_exists",
}


@dataclass(frozen=True, slots=True)
class LabelMatcher:
    name: str
    operator: str = "equals"
    value: str = ""

    def __post_init__(self) -> None:
        name = self.name.strip()
        operator = _OPERATORS.get(self.operator.strip().lower())
        if not name or len(name) > 255:
            raise ValueError("label matcher name must contain 1-255 characters")
        if operator is None:
            raise ValueError("unsupported label matcher operator")
        if len(self.value) > 1_024:
            raise ValueError("label matcher value is too long")
        if operator in {"regex", "not_regex"}:
            if len(self.value) > 256:
                raise ValueError("label matcher regex is too long")
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError("label matcher regex is invalid") from exc
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "operator", operator)

    def matches(self, labels: Mapping[str, Any]) -> bool:
        present = self.name in labels
        actual = str(labels[self.name]) if present else ""
        if self.operator == "exists":
            return present
        if self.operator == "not_exists":
            return not present
        if self.operator == "equals":
            return present and actual == self.value
        if self.operator == "not_equals":
            return not present or actual != self.value
        if self.operator == "regex":
            return present and re.fullmatch(self.value, actual) is not None
        if self.operator == "not_regex":
            return not present or re.fullmatch(self.value, actual) is None
        return False

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "operator": self.operator, "value": self.value}


def parse_matcher(value: Mapping[str, Any]) -> LabelMatcher:
    return LabelMatcher(
        name=str(value.get("name") or value.get("key") or ""),
        operator=str(value.get("operator") or "equals"),
        value=str(value.get("value") or ""),
    )


@dataclass(frozen=True, slots=True)
class RouteRule:
    route_id: str
    priority: int = 0
    source_filter: frozenset[str] = field(default_factory=frozenset)
    severity_filter: frozenset[str] = field(default_factory=frozenset)
    label_matchers: tuple[LabelMatcher, ...] = ()
    channel_ids: tuple[str, ...] = ()
    continue_matching: bool = False

    def matches(self, source_id: str, severity: str, labels: Mapping[str, Any]) -> bool:
        if self.source_filter and source_id not in self.source_filter:
            return False
        if self.severity_filter and severity not in self.severity_filter:
            return False
        return all(matcher.matches(labels) for matcher in self.label_matchers)


def select_channel_ids(
    routes: Iterable[RouteRule],
    *,
    source_id: str,
    severity: str,
    labels: Mapping[str, Any],
) -> list[str]:
    selected: list[str] = []
    ordered = sorted(routes, key=lambda route: (route.priority, route.route_id))
    for route in ordered:
        if not route.matches(source_id, severity, labels):
            continue
        for channel_id in route.channel_ids:
            if channel_id not in selected:
                selected.append(channel_id)
        if not route.continue_matching:
            break
    return selected


@dataclass(frozen=True, slots=True)
class NodeCandidate:
    node_id: str
    region: str
    enabled_roles: frozenset[str] = field(default_factory=frozenset)


def eligible_node_ids(
    candidates: Sequence[NodeCandidate], eligibility: Mapping[str, Any]
) -> list[str]:
    allowed_nodes = {str(item) for item in eligibility.get("node_ids", [])}
    allowed_regions = {str(item) for item in eligibility.get("regions", [])}
    return [
        candidate.node_id
        for candidate in candidates
        if (not candidate.enabled_roles or "notify" in candidate.enabled_roles)
        and (not allowed_nodes or candidate.node_id in allowed_nodes)
        and (not allowed_regions or candidate.region in allowed_regions)
    ]


def rank_delivery_nodes(
    event_id: str,
    channel_id: str,
    candidates: Sequence[NodeCandidate],
    eligibility: Mapping[str, Any],
) -> list[str]:
    eligible = eligible_node_ids(candidates, eligibility)
    return rendezvous_rank(f"{event_id}\0{channel_id}", eligible)


def failover_delay_seconds(rank: int, base_delay_seconds: float) -> float:
    if rank < 0:
        raise ValueError("delivery rank must be non-negative")
    if base_delay_seconds < 0:
        raise ValueError("failover base delay must be non-negative")
    return rank * base_delay_seconds
