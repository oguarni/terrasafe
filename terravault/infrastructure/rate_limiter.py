"""Fallback in-memory rate limiter for when Redis is unavailable"""
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from threading import Lock

logger = logging.getLogger(__name__)


class FallbackRateLimiter:
    """
    In-memory rate limiter fallback for when Redis is unavailable.

    Uses a sliding window approach to track request counts per client IP.
    Thread-safe for concurrent requests.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """
        Initialize the fallback rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in the time window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.requests: Dict[str, List[datetime]] = defaultdict(list)
        self.lock = Lock()
        self._check_count: int = 0
        logger.info(
            "Fallback rate limiter initialized: %s requests per %ss window",
            max_requests, window_seconds
        )

    def check_rate_limit(self, client_ip: str) -> bool:
        """
        Check if a client has exceeded their rate limit.

        Args:
            client_ip: Client IP address

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        with self.lock:
            now = datetime.now(timezone.utc)

            # Periodically clean all stale entries to prevent memory growth
            self._check_count += 1
            if self._check_count % 100 == 0:
                self._cleanup_locked(now)

            # Clean old requests outside the time window for this client
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if now - req_time < self.window
            ]

            # Check if limit exceeded
            if len(self.requests[client_ip]) >= self.max_requests:
                logger.warning(
                    "Rate limit exceeded for %s: %s requests in window",
                    client_ip, len(self.requests[client_ip])
                )
                return False

            # Record this request
            self.requests[client_ip].append(now)
            return True

    def _cleanup_locked(self, now: datetime) -> None:
        """Remove all stale entries. Must be called while holding self.lock."""
        for ip in list(self.requests.keys()):
            self.requests[ip] = [
                req_time for req_time in self.requests[ip]
                if now - req_time < self.window
            ]
            if not self.requests[ip]:
                del self.requests[ip]

    def get_remaining(self, client_ip: str) -> int:
        """
        Get remaining requests for a client.

        Args:
            client_ip: Client IP address

        Returns:
            Number of remaining requests in current window
        """
        with self.lock:
            now = datetime.now(timezone.utc)

            # Clean old requests
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if now - req_time < self.window
            ]

            return max(0, self.max_requests - len(self.requests[client_ip]))

    def reset(self, client_ip: Optional[str] = None):
        """
        Reset rate limit tracking.

        Args:
            client_ip: Client IP to reset, or None to reset all
        """
        with self.lock:
            if client_ip:
                self.requests.pop(client_ip, None)
                logger.info("Rate limit reset for %s", client_ip)
            else:
                self.requests.clear()
                logger.info("Rate limit reset for all clients")
