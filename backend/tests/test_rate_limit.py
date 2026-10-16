"""Unit tests for the in-process per-user job rate limiter.

No database is involved; the limiter is exercised directly with a fake clock
and small settings so the window can be advanced without sleeping.
"""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core import rate_limit
from app.core.config import Settings
from app.core.rate_limit import JobRateLimiter, check_job_rate_limit, reset


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _limiter(monkeypatch, *, limit: int, window: int) -> JobRateLimiter:
    settings = SimpleNamespace(job_rate_limit=limit, job_rate_window_seconds=window)
    monkeypatch.setattr(rate_limit, "get_settings", lambda: settings)
    return JobRateLimiter()


def test_allows_up_to_the_limit_then_raises_429(monkeypatch):
    limiter = _limiter(monkeypatch, limit=3, window=60)
    for _ in range(3):
        limiter.check("user-1")
    with pytest.raises(HTTPException) as exc:
        limiter.check("user-1")
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "60"


def test_window_expiry_resets_the_counter(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(rate_limit.time, "monotonic", clock)
    limiter = _limiter(monkeypatch, limit=2, window=10)
    limiter.check("user-1")
    limiter.check("user-1")
    with pytest.raises(HTTPException):
        limiter.check("user-1")
    clock.now += 10
    # The earlier attempts are now outside the window, so the key is allowed.
    limiter.check("user-1")


def test_distinct_keys_are_independent(monkeypatch):
    limiter = _limiter(monkeypatch, limit=1, window=60)
    limiter.check("user-1")
    limiter.check("user-2")
    for key in ("user-1", "user-2"):
        with pytest.raises(HTTPException) as exc:
            limiter.check(key)
        assert exc.value.status_code == 429


def test_the_module_callable_and_reset_use_the_shared_limiter(monkeypatch):
    settings = SimpleNamespace(job_rate_limit=1, job_rate_window_seconds=60)
    monkeypatch.setattr(rate_limit, "get_settings", lambda: settings)
    reset()
    check_job_rate_limit("user-1")
    with pytest.raises(HTTPException) as exc:
        check_job_rate_limit("user-1")
    assert exc.value.status_code == 429
    reset()
    check_job_rate_limit("user-1")


def test_defaults_are_present_and_generous():
    assert Settings.model_fields["job_rate_limit"].default == 60
    assert Settings.model_fields["job_rate_window_seconds"].default == 60
    assert Settings.model_fields["require_separate_approver"].default is False
