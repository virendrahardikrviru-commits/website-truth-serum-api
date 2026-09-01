"""Bounded in-process sliding-window rate limiter (V1-H3).

A lightweight, dependency-free limiter for the scan endpoint. It is bounded
(the number of tracked keys is capped and oldest entries are evicted), it is
safe under concurrency (a lock serializes mutation), and it supports clock
injection for deterministic tests.

Limitations (documented):
- In-process only: limits are per worker/process, not global. A multi-process
  deployment must provide its own shared limiter.
- Client identity comes from the direct connection peer (``request.client``).
  Forwarded headers (e.g. ``X-Forwarded-For``) are intentionally NOT trusted;
  behind a reverse proxy all clients share the proxy IP and are throttled as a
  single group unless a trusted-forwarding solution is added.
"""

import collections
import os
import threading
import time
from typing import Callable, Optional

DEFAULT_MAX_REQUESTS = 30
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_MAX_KEYS = 10_000


class SlidingWindowRateLimiter:
    """Sliding-window limiter keyed by an arbitrary string (e.g. client IP)."""

    def __init__(
        self,
        max_requests: Optional[int] = None,
        window_seconds: Optional[float] = None,
        max_keys: Optional[int] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._max_requests = max_requests if max_requests is not None else DEFAULT_MAX_REQUESTS
        self._window = window_seconds if window_seconds is not None else DEFAULT_WINDOW_SECONDS
        self._max_keys = max_keys if max_keys is not None else DEFAULT_MAX_KEYS
        self._clock = clock
        self._buckets: "collections.OrderedDict[str, collections.deque]" = (
            collections.OrderedDict()
        )
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Record a request for ``key``; True if within the limit, False if
        the sliding window is full."""
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._max_keys:
                    # Bound memory: evict the oldest tracked key.
                    self._buckets.popitem(last=False)
                bucket = collections.deque()
                self._buckets[key] = bucket
            while bucket and now - bucket[0] >= self._window:
                bucket.popleft()
            self._buckets.move_to_end(key)
            if len(bucket) >= self._max_requests:
                return False
            bucket.append(now)
            return True

    def size(self) -> int:
        with self._lock:
            return len(self._buckets)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def build_scan_rate_limiter() -> SlidingWindowRateLimiter:
    """Build the scan-endpoint limiter from environment configuration."""
    return SlidingWindowRateLimiter(
        max_requests=_env_int("SCAN_RATE_LIMIT", DEFAULT_MAX_REQUESTS),
        window_seconds=_env_int("SCAN_RATE_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS),
    )
