#!/usr/bin/env python3
"""Verify the committed minimum OpenAPI path/method contract."""

from __future__ import annotations

import json
import sys
from importlib import import_module
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "backend"))
app = import_module("alert_hub.main").app

schema = app.openapi()
paths = schema.get("paths", {})
contract_path = REPOSITORY / "docs" / "openapi-contract.json"
contract = json.loads(contract_path.read_text(encoding="utf-8"))
failures: list[str] = []
for path, required_methods in contract["required_paths"].items():
    actual_methods = {method.lower() for method in paths.get(path, {})}
    for method in required_methods:
        if method.lower() not in actual_methods:
            failures.append(f"{method.upper()} {path}")

checks_models = {
    "/api/v1/checks": "ChecksListResponse",
    "/api/v1/checks/summary": "ChecksSummaryResponse",
    "/api/v1/checks/{check_id}": "CheckDetailResponse",
}
components = schema.get("components", {}).get("schemas", {})
for path, model_name in checks_models.items():
    operation = paths.get(path, {}).get("get", {})
    for response_status in ("200", "503"):
        response_schema = (
            operation.get("responses", {})
            .get(response_status, {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        if response_schema.get("$ref") != f"#/components/schemas/{model_name}":
            failures.append(f"{response_status} GET {path} must use {model_name}")
    if model_name not in components:
        failures.append(f"OpenAPI component {model_name}")
    required_statuses = {"200", "401", "422", "503"}
    if path.endswith("{check_id}"):
        required_statuses.add("404")
    if not required_statuses <= set(operation.get("responses", {})):
        failures.append(f"GET {path} response statuses")

checks_states = {"ready", "empty", "stale", "unavailable", "disabled"}
for model_name in checks_models.values():
    data_state = components.get(model_name, {}).get("properties", {}).get("data_state", {})
    if set(data_state.get("enum", [])) != checks_states:
        failures.append(f"{model_name}.data_state enum")

for model_name, nullable_fields in {
    "ChecksListResponse": {"snapshot_id", "fetched_at", "evaluated_at", "total"},
    "ChecksSummaryResponse": {"total", "up", "degraded", "down", "stale", "unknown"},
    "CheckDetailResponse": {"check", "last_known"},
    "CheckResultResponse": {"source", "scenario", "variant", "target", "success", "last_run_at"},
}.items():
    properties = components.get(model_name, {}).get("properties", {})
    for field in nullable_fields:
        variants = properties.get(field, {}).get("anyOf", [])
        if not any(variant.get("type") == "null" for variant in variants):
            failures.append(f"{model_name}.{field} must be nullable")
if failures:
    raise SystemExit(f"OpenAPI contract failures: {', '.join(failures)}")


def route_paths(router: object) -> set[str]:
    result: set[str] = set()
    for route in getattr(router, "routes", []):
        path = getattr(route, "path", "")
        if path:
            result.add(path)
        original_router = getattr(route, "original_router", None)
        if original_router is not None:
            result.update(route_paths(original_router))
    return result


runtime_paths = route_paths(app)
for operational_path in ("/health/live", "/health/ready", "/health/deep", "/metrics"):
    if operational_path not in runtime_paths:
        raise SystemExit(f"Runtime route is missing: {operational_path}")

# Serialization itself catches unsupported custom schema values. Sort for
# deterministic behavior even though the full generated document is not stored.
json.dumps(schema, sort_keys=True, ensure_ascii=False)
print(f"OpenAPI contract verified ({len(paths)} documented paths)")
