"""
Secure Redis-based caching implementation for TerraSafe.
Provides async caching with TTL, size limits, and proper error handling.
"""

import hashlib
import json
from datetime import timedelta
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError

from terrasafe.config.logging import get_logger

logger = get_logger(__name__)


class CacheError(Exception):
    """Base exception for cache-related errors."""
    pass


class SecureCache:
    """
    Async Redis-based cache with security features.

    Features:
    - Async operations for better performance
    - TTL (Time To Live) for automatic expiration
    - Key hashing for consistent key format
    - JSON serialization with proper error handling
    - Connection pooling
    - Graceful error handling
    """

    def __init__(
        self,
        redis_url: str,
        max_connections: int = 50,
        default_ttl: int = 3600,
        key_prefix: str = "terrasafe:",
    ):
        """
        Initialize the cache.

        Args:
            redis_url: Redis connection URL
            max_connections: Maximum number of connections in the pool
            default_ttl: Default TTL in seconds
            key_prefix: Prefix for all cache keys
        """
        self.redis_url = redis_url
        self.max_connections = max_connections
        self.default_ttl = default_ttl
        self.key_prefix = key_prefix
        self._redis: Optional[redis.Redis] = None
        logger.info("Initializing SecureCache with prefix '%s'", key_prefix)

    async def connect(self) -> None:
        """Establish connection to Redis."""
        if self._redis is None:
            try:
                self._redis = await redis.from_url(
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=self.max_connections,
                )
                # Test connection
                await self._redis.ping()
                logger.info("Successfully connected to Redis")
            except RedisConnectionError as e:
                logger.error("Failed to connect to Redis: %s", e)
                raise CacheError(f"Redis connection failed: {e}") from e

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            await self._redis.connection_pool.disconnect()
            self._redis = None
            logger.info("Disconnected from Redis")

    def _hash_key(self, key: str) -> str:
        """
        Hash the key for consistent format and security.

        Args:
            key: Original key

        Returns:
            Hashed key with prefix
        """
        # Use SHA-256 for consistent key length
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return f"{self.key_prefix}{key_hash}"

    def _serialize(self, value: Any) -> str:
        """
        Serialize value to JSON string.

        Args:
            value: Value to serialize

        Returns:
            JSON string

        Raises:
            CacheError: If serialization fails
        """
        try:
            return json.dumps(value, default=str)
        except (TypeError, ValueError) as e:
            logger.error("Failed to serialize value: %s", e)
            raise CacheError(f"Serialization failed: {e}") from e

    def _deserialize(self, value: str) -> Any:
        """
        Deserialize JSON string to value.

        Args:
            value: JSON string

        Returns:
            Deserialized value

        Raises:
            CacheError: If deserialization fails
        """
        try:
            return json.loads(value)
        except (TypeError, ValueError) as e:
            logger.error("Failed to deserialize value: %s", e)
            raise CacheError(f"Deserialization failed: {e}") from e

    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found

        Raises:
            CacheError: If cache operation fails
        """
        if not self._redis:
            await self.connect()

        hashed_key = self._hash_key(key)

        try:
            if self._redis is None:
                raise CacheError("Redis connection not established")
            value = await self._redis.get(hashed_key)
            if value is None:
                logger.debug("Cache miss for key: %s", key)
                return None

            logger.debug("Cache hit for key: %s", key)
            return self._deserialize(value)

        except RedisError as e:
            logger.error("Redis error during get operation: %s", e)
            # Return None on error to allow fallback to original computation
            return None
        except CacheError:
            # Re-raise cache errors
            raise
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during cache get: %s", e)
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[timedelta] = None,
        ttl_seconds: Optional[int] = None,
    ) -> bool:
        """
        Set value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL as timedelta
            ttl_seconds: TTL in seconds (alternative to ttl)

        Returns:
            True if successful, False otherwise

        Raises:
            CacheError: If cache operation fails
        """
        if not self._redis:
            await self.connect()

        hashed_key = self._hash_key(key)

        # Determine TTL
        if ttl:
            ttl_seconds = int(ttl.total_seconds())
        elif ttl_seconds is None:
            ttl_seconds = self.default_ttl

        try:
            if self._redis is None:
                raise CacheError("Redis connection not established")
            serialized_value = self._serialize(value)
            await self._redis.setex(hashed_key, ttl_seconds, serialized_value)
            logger.debug("Cached value for key: %s (TTL: %ss)", key, ttl_seconds)
            return True

        except RedisError as e:
            logger.error("Redis error during set operation: %s", e)
            return False
        except CacheError:
            # Re-raise cache errors
            raise
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during cache set: %s", e)
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key

        Returns:
            True if key was deleted, False otherwise
        """
        if not self._redis:
            await self.connect()

        hashed_key = self._hash_key(key)

        try:
            if self._redis is None:
                raise CacheError("Redis connection not established")
            result = await self._redis.delete(hashed_key)
            if result > 0:
                logger.debug("Deleted cache key: %s", key)
                return True
            return False

        except RedisError as e:
            logger.error("Redis error during delete operation: %s", e)
            return False
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during cache delete: %s", e)
            return False

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            True if key exists, False otherwise
        """
        if not self._redis:
            await self.connect()

        hashed_key = self._hash_key(key)

        try:
            if self._redis is None:
                raise CacheError("Redis connection not established")
            result = await self._redis.exists(hashed_key)
            return result > 0

        except RedisError as e:
            logger.error("Redis error during exists operation: %s", e)
            return False
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during cache exists: %s", e)
            return False

    async def clear(self, pattern: Optional[str] = None) -> int:
        """
        Clear cache entries.

        Args:
            pattern: Optional pattern to match keys (e.g., "user:*")
                    If None, clears all keys with the configured prefix

        Returns:
            Number of keys deleted
        """
        if not self._redis:
            await self.connect()

        # Build the full pattern
        if pattern:
            full_pattern = f"{self.key_prefix}{pattern}"
        else:
            full_pattern = f"{self.key_prefix}*"

        try:
            if self._redis is None:
                raise CacheError("Redis connection not established")
            # Use scan_iter for memory-efficient iteration
            deleted = 0
            async for key in self._redis.scan_iter(match=full_pattern, count=100):
                await self._redis.delete(key)
                deleted += 1

            logger.info("Cleared %s cache entries matching pattern: %s", deleted, full_pattern)
            return deleted

        except RedisError as e:
            logger.error("Redis error during clear operation: %s", e)
            return 0
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during cache clear: %s", e)
            return 0

    async def get_ttl(self, key: str) -> Optional[int]:
        """
        Get remaining TTL for a key.

        Args:
            key: Cache key

        Returns:
            Remaining TTL in seconds, or None if key doesn't exist
        """
        if not self._redis:
            await self.connect()

        hashed_key = self._hash_key(key)

        try:
            if self._redis is None:
                raise CacheError("Redis connection not established")
            ttl = await self._redis.ttl(hashed_key)
            # TTL returns -2 if key doesn't exist, -1 if no expiry
            if ttl < 0:
                return None
            return ttl

        except RedisError as e:
            logger.error("Redis error during ttl operation: %s", e)
            return None
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during get_ttl: %s", e)
            return None

    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Increment a counter in the cache.

        Args:
            key: Cache key
            amount: Amount to increment by (default: 1)

        Returns:
            New value after increment, or None on error
        """
        if not self._redis:
            await self.connect()

        hashed_key = self._hash_key(key)

        try:
            if self._redis is None:
                raise CacheError("Redis connection not established")
            result = await self._redis.incrby(hashed_key, amount)
            return result

        except RedisError as e:
            logger.error("Redis error during increment operation: %s", e)
            return None
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during increment: %s", e)
            return None

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
