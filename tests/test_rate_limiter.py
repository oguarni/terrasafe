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


