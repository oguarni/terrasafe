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
        logger.info(
            f"Fallback rate limiter initialized: {max_requests} requests "
            f"per {window_seconds}s window"
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

            # Clean old requests outside the time window
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if now - req_time < self.window
            ]

            # Check if limit exceeded
            if len(self.requests[client_ip]) >= self.max_requests:
                logger.warning(
                    f"Rate limit exceeded for {client_ip}: "
                    f"{len(self.requests[client_ip])} requests in window"
                )
                return False

            # Record this request
            self.requests[client_ip].append(now)
            return True

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
                logger.info(f"Rate limit reset for {client_ip}")
            else:
                self.requests.clear()
                logger.info("Rate limit reset for all clients")

    def cleanup_old_entries(self):
        """
        Cleanup old entries to prevent memory leaks.
        Should be called periodically.
        """
        with self.lock:
            now = datetime.now(timezone.utc)
            cleaned = 0

            # Remove empty entries and old timestamps
            for client_ip in list(self.requests.keys()):
                old_count = len(self.requests[client_ip])
                self.requests[client_ip] = [
                    req_time for req_time in self.requests[client_ip]
                    if now - req_time < self.window
                ]

                # Remove entry if no requests in window
                if not self.requests[client_ip]:
                    del self.requests[client_ip]
                    cleaned += 1

            if cleaned > 0:
                logger.debug(f"Cleaned {cleaned} old rate limit entries")
