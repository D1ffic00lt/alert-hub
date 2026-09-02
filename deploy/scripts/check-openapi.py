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
if failures:
    raise SystemExit(f"OpenAPI is missing required operations: {', '.join(failures)}")


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
