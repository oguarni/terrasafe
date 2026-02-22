"""Tests for the FallbackRateLimiter module."""
import pytest
from datetime import datetime, timezone

from terrasafe.infrastructure.rate_limiter import FallbackRateLimiter


@pytest.mark.unit
class TestFallbackRateLimiter:
    """Unit tests for FallbackRateLimiter."""

    def test_allows_requests_under_limit(self):
        """Requests under the limit should be allowed."""
        limiter = FallbackRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.check_rate_limit("192.168.1.1") is True

    def test_blocks_requests_over_limit(self):
        """Requests over the limit should be blocked."""
        limiter = FallbackRateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            assert limiter.check_rate_limit("192.168.1.1") is True
        assert limiter.check_rate_limit("192.168.1.1") is False

    def test_separate_limits_per_ip(self):
        """Each IP should have its own rate limit."""
        limiter = FallbackRateLimiter(max_requests=2, window_seconds=60)
        assert limiter.check_rate_limit("10.0.0.1") is True
        assert limiter.check_rate_limit("10.0.0.1") is True
        assert limiter.check_rate_limit("10.0.0.1") is False
        # Different IP should still be allowed
        assert limiter.check_rate_limit("10.0.0.2") is True

    def test_get_remaining(self):
        """get_remaining should return correct remaining count."""
        limiter = FallbackRateLimiter(max_requests=5, window_seconds=60)
        assert limiter.get_remaining("10.0.0.1") == 5
        limiter.check_rate_limit("10.0.0.1")
        assert limiter.get_remaining("10.0.0.1") == 4
        limiter.check_rate_limit("10.0.0.1")
        assert limiter.get_remaining("10.0.0.1") == 3

    def test_get_remaining_unknown_ip(self):
        """get_remaining for unknown IP should return max."""
        limiter = FallbackRateLimiter(max_requests=10, window_seconds=60)
        assert limiter.get_remaining("unknown.ip") == 10

    def test_reset_specific_ip(self):
        """Resetting a specific IP should only clear that IP."""
        limiter = FallbackRateLimiter(max_requests=2, window_seconds=60)
        limiter.check_rate_limit("10.0.0.1")
        limiter.check_rate_limit("10.0.0.2")
        limiter.reset("10.0.0.1")
        assert limiter.get_remaining("10.0.0.1") == 2
        assert limiter.get_remaining("10.0.0.2") == 1

    def test_reset_all(self):
        """Resetting all should clear all tracking."""
        limiter = FallbackRateLimiter(max_requests=2, window_seconds=60)
        limiter.check_rate_limit("10.0.0.1")
        limiter.check_rate_limit("10.0.0.2")
        limiter.reset()
        assert limiter.get_remaining("10.0.0.1") == 2
        assert limiter.get_remaining("10.0.0.2") == 2

    def test_cleanup_old_entries(self):
        """cleanup_old_entries should not error and should clean stale data."""
        limiter = FallbackRateLimiter(max_requests=10, window_seconds=1)
        limiter.check_rate_limit("10.0.0.1")
        # Manually age the entry
        import time
        time.sleep(1.1)
        limiter.cleanup_old_entries()
        assert limiter.get_remaining("10.0.0.1") == 10

    def test_periodic_cleanup_on_check(self):
        """Internal cleanup should trigger every 100 checks."""
        limiter = FallbackRateLimiter(max_requests=200, window_seconds=60)
        for i in range(100):
            limiter.check_rate_limit(f"ip-{i}")
        # The 100th check triggers _cleanup_locked internally — no crash
        assert limiter.check_rate_limit("final-ip") is True

    def test_reset_nonexistent_ip(self):
        """Resetting a non-existent IP should not error."""
        limiter = FallbackRateLimiter(max_requests=5, window_seconds=60)
        limiter.reset("does.not.exist")  # Should not raise
