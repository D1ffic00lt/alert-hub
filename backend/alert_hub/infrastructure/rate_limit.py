from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after: int
    remaining: int


@dataclass(slots=True)
class _Bucket:
    count: int
    expires_at: float
    last_seen: float
    limit: int
    window_seconds: float


class LocalRateLimiter:
    """Bounded, process-local fixed-window limiter.

    This deliberately makes no cluster-global guarantee. Each node protects its own
    expensive request boundary, and keys are evicted deterministically at capacity.
    """

    def __init__(
        self,
        *,
        max_keys: int,
        cleanup_interval_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be positive")
        if cleanup_interval_seconds <= 0:
            raise ValueError("cleanup_interval_seconds must be positive")
        self.max_keys = max_keys
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self._clock = clock
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._last_cleanup = clock()
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._buckets)

    def _cleanup(self, now: float, *, force: bool = False) -> None:
        if not force and now - self._last_cleanup < self.cleanup_interval_seconds:
            return
        expired = [key for key, bucket in self._buckets.items() if bucket.expires_at <= now]
        for key in expired:
            del self._buckets[key]
        self._last_cleanup = now

    def cleanup(self) -> int:
        """Remove expired keys and return the current size (useful for deterministic tests)."""

        with self._lock:
            self._cleanup(self._clock(), force=True)
            return len(self._buckets)

    def check(
        self,
        scope: str,
        key: str,
        *,
        limit: int,
        window_seconds: float,
    ) -> RateLimitDecision:
        if limit < 1 or window_seconds <= 0:
            raise ValueError("limit and window_seconds must be positive")
        now = self._clock()
        bucket_key = (scope, key)
        with self._lock:
            self._cleanup(now)
            bucket = self._buckets.get(bucket_key)
            if bucket is None and len(self._buckets) >= self.max_keys:
                self._cleanup(now, force=True)
            if bucket is None and len(self._buckets) >= self.max_keys:
                bucket_key = (scope, "<overflow>")
                bucket = self._buckets.get(bucket_key)
                if bucket is None:
                    victim = min(
                        self._buckets,
                        key=lambda candidate: (
                            self._buckets[candidate].last_seen,
                            candidate[0],
                            candidate[1],
                        ),
                    )
                    del self._buckets[victim]
            if (
                bucket is None
                or bucket.expires_at <= now
                or bucket.limit != limit
                or bucket.window_seconds != window_seconds
            ):
                bucket = _Bucket(
                    count=0,
                    expires_at=now + window_seconds,
                    last_seen=now,
                    limit=limit,
                    window_seconds=window_seconds,
                )
                self._buckets[bucket_key] = bucket
            bucket.last_seen = now
            if bucket.count >= limit:
                retry_after = max(1, math.ceil(bucket.expires_at - now))
                return RateLimitDecision(False, retry_after, 0)
            bucket.count += 1
            return RateLimitDecision(True, 0, max(0, limit - bucket.count))
