from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


def heartbeat_window(config: Mapping[str, Any]) -> tuple[float, float]:
    """Return a finite positive interval and non-negative grace period."""

    try:
        interval = float(config.get("interval_seconds", 60))
        grace = float(config.get("grace_seconds", 30))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("heartbeat interval and grace must be finite numbers") from exc
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("interval_seconds must be a finite positive number")
    if not math.isfinite(grace) or grace < 0:
        raise ValueError("grace_seconds must be a finite non-negative number")
    return interval, grace
