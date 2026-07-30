"""Unit tests for the in-memory fallback rate limiter.

Covers the sliding-window accounting used when Redis is unavailable, including
window expiry, the periodic cleanup that keeps `requests` from growing without
bound, and thread safety under concurrent callers.
"""
from datetime import datetime, timedelta, timezone
from threading import Thread

import pytest

from terravault.infrastructure.rate_limiter import FallbackRateLimiter


pytestmark = pytest.mark.unit


class FrozenClock:
    """Advanceable stand-in for `datetime.now`, so window expiry needs no sleep."""

    def __init__(self, start: datetime):
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    def __call__(self, tz=None):  # noqa: ARG002 - matches datetime.now signature
        return self.now


@pytest.fixture
def frozen_clock(monkeypatch):
    """Pin the limiter's clock so tests control the sliding window directly."""
    clock = FrozenClock(datetime(2026, 1, 1, tzinfo=timezone.utc))

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock(tz)

    monkeypatch.setattr(
        "terravault.infrastructure.rate_limiter.datetime", _FrozenDatetime
    )
    return clock


# ---------------------------------------------------------------------------
# check_rate_limit
# ---------------------------------------------------------------------------

def test_allows_requests_up_to_the_limit():
    limiter = FallbackRateLimiter(max_requests=3, window_seconds=60)

    assert [limiter.check_rate_limit("10.0.0.1") for _ in range(3)] == [True] * 3


def test_blocks_the_request_that_exceeds_the_limit():
    limiter = FallbackRateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        limiter.check_rate_limit("10.0.0.1")

    assert limiter.check_rate_limit("10.0.0.1") is False


def test_limits_are_tracked_per_client():
    limiter = FallbackRateLimiter(max_requests=2, window_seconds=60)
    limiter.check_rate_limit("10.0.0.1")
    limiter.check_rate_limit("10.0.0.1")

    # A different IP has its own budget and is unaffected by the first one.
    assert limiter.check_rate_limit("10.0.0.1") is False
    assert limiter.check_rate_limit("10.0.0.2") is True


def test_requests_outside_the_window_stop_counting(frozen_clock):
    limiter = FallbackRateLimiter(max_requests=2, window_seconds=60)
    limiter.check_rate_limit("10.0.0.1")
    limiter.check_rate_limit("10.0.0.1")
    assert limiter.check_rate_limit("10.0.0.1") is False

    frozen_clock.advance(61)

    assert limiter.check_rate_limit("10.0.0.1") is True


def test_requests_inside_the_window_still_count(frozen_clock):
    limiter = FallbackRateLimiter(max_requests=2, window_seconds=60)
    limiter.check_rate_limit("10.0.0.1")
    limiter.check_rate_limit("10.0.0.1")

    frozen_clock.advance(59)

    assert limiter.check_rate_limit("10.0.0.1") is False


# ---------------------------------------------------------------------------
# get_remaining
# ---------------------------------------------------------------------------

def test_remaining_starts_at_the_configured_maximum():
    limiter = FallbackRateLimiter(max_requests=5, window_seconds=60)

    assert limiter.get_remaining("10.0.0.1") == 5


def test_remaining_decreases_with_each_request():
    limiter = FallbackRateLimiter(max_requests=5, window_seconds=60)
    limiter.check_rate_limit("10.0.0.1")
    limiter.check_rate_limit("10.0.0.1")

    assert limiter.get_remaining("10.0.0.1") == 3


def test_remaining_never_goes_below_zero():
    limiter = FallbackRateLimiter(max_requests=1, window_seconds=60)
    for _ in range(5):
        limiter.check_rate_limit("10.0.0.1")

    assert limiter.get_remaining("10.0.0.1") == 0


def test_remaining_recovers_once_the_window_passes(frozen_clock):
    limiter = FallbackRateLimiter(max_requests=2, window_seconds=60)
    limiter.check_rate_limit("10.0.0.1")
    assert limiter.get_remaining("10.0.0.1") == 1

    frozen_clock.advance(61)

    assert limiter.get_remaining("10.0.0.1") == 2


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

def test_reset_clears_a_single_client_only():
    limiter = FallbackRateLimiter(max_requests=1, window_seconds=60)
    limiter.check_rate_limit("10.0.0.1")
    limiter.check_rate_limit("10.0.0.2")

    limiter.reset("10.0.0.1")

    assert limiter.check_rate_limit("10.0.0.1") is True
    assert limiter.check_rate_limit("10.0.0.2") is False


def test_reset_without_an_ip_clears_every_client():
    limiter = FallbackRateLimiter(max_requests=1, window_seconds=60)
    limiter.check_rate_limit("10.0.0.1")
    limiter.check_rate_limit("10.0.0.2")

    limiter.reset()

    assert limiter.check_rate_limit("10.0.0.1") is True
    assert limiter.check_rate_limit("10.0.0.2") is True


def test_reset_on_an_unknown_ip_is_a_no_op():
    limiter = FallbackRateLimiter(max_requests=1, window_seconds=60)

    limiter.reset("203.0.113.9")

    assert limiter.check_rate_limit("203.0.113.9") is True


# ---------------------------------------------------------------------------
# Periodic cleanup (every 100 checks) — guards unbounded memory growth
# ---------------------------------------------------------------------------

def test_periodic_cleanup_drops_clients_whose_window_expired(frozen_clock):
    limiter = FallbackRateLimiter(max_requests=1000, window_seconds=60)
    limiter.check_rate_limit("10.0.0.99")
    assert "10.0.0.99" in limiter.requests

    # Move past the window, then drive the check counter to a multiple of 100
    # so _cleanup_locked runs. The 99 checks below belong to a different IP.
    frozen_clock.advance(61)
    for _ in range(99):
        limiter.check_rate_limit("10.0.0.1")

    assert "10.0.0.99" not in limiter.requests


def test_periodic_cleanup_keeps_clients_still_inside_the_window(frozen_clock):
    limiter = FallbackRateLimiter(max_requests=1000, window_seconds=600)
    limiter.check_rate_limit("10.0.0.99")

    frozen_clock.advance(60)
    for _ in range(99):
        limiter.check_rate_limit("10.0.0.1")

    assert "10.0.0.99" in limiter.requests


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_concurrent_checks_never_exceed_the_limit():
    """The lock must make the count exact, not merely approximate."""
    limiter = FallbackRateLimiter(max_requests=50, window_seconds=60)
    granted: list[bool] = []
    threads = [
        Thread(target=lambda: granted.append(limiter.check_rate_limit("10.0.0.1")))
        for _ in range(200)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(granted) == 50
    assert len(granted) == 200
