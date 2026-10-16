"""Per-user rate limiting for job creation, in the style of the login throttle.

Like :class:`app.api.auth.LoginThrottle`, this is a bounded, in-process limiter
for the single-process local deployment: counters live in this process only, so
a deployment with several API processes or replicas counts each of them
separately. A shared store would be needed to bound the total across processes.
"""

import threading
import time
from collections import deque

from fastapi import HTTPException, status

from app.core.config import get_settings


class JobRateLimiter:
    """Bounded per-process limiter for job creation, keyed by user id."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        settings = get_settings()
        now = time.monotonic()
        cutoff = now - settings.job_rate_window_seconds
        with self._lock:
            # Expired keys are removed to bound storage for the local app.
            for existing in list(self._events):
                if self._events[existing][-1] <= cutoff:
                    del self._events[existing]
            if key not in self._events and len(self._events) >= 10000:
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Try again later")
            events = self._events.setdefault(key, deque())
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= settings.job_rate_limit:
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Too many jobs requested. Try again later.",
                    headers={"Retry-After": str(settings.job_rate_window_seconds)},
                )
            events.append(now)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


job_rate_limiter = JobRateLimiter()


def check_job_rate_limit(key: str) -> None:
    """Raise 429 when ``key`` has created too many jobs inside the window."""
    job_rate_limiter.check(key)


def reset() -> None:
    """Drop every counter. For tests."""
    job_rate_limiter.reset()
