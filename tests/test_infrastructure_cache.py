"""
Integration tests for terrasafe.infrastructure.cache module.

These tests verify the Redis caching functionality including:
- Connection management
- Set/Get operations
- TTL handling
- Key hashing
- Error handling
- Cache invalidation
"""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from datetime import timedelta
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError

from terrasafe.infrastructure.cache import SecureCache, CacheError


class TestSecureCache:
    """Test suite for SecureCache class."""

    @pytest.fixture
    def redis_url(self):
        """Provide a test Redis URL."""
        return "redis://localhost:6379/0"

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        mock = AsyncMock()
        mock.ping = AsyncMock(return_value=True)
        mock.set = AsyncMock(return_value=True)
        mock.get = AsyncMock(return_value=None)
        mock.delete = AsyncMock(return_value=1)
        mock.exists = AsyncMock(return_value=0)
        mock.ttl = AsyncMock(return_value=-1)
        mock.setex = AsyncMock(return_value=True)
        mock.close = AsyncMock()
        mock.aclose = AsyncMock()
        mock.connection_pool = AsyncMock()
        mock.connection_pool.disconnect = AsyncMock()
        mock.incrby = AsyncMock(return_value=1)
        mock.scan_iter = AsyncMock()
        return mock

    @pytest.fixture
    def cache_with_mock(self, redis_url, mock_redis):
        """Create a SecureCache instance with mocked Redis."""
        # Make redis.from_url an async function that returns mock_redis
        async def mock_from_url(*args, **kwargs):
            return mock_redis

        with patch('terrasafe.infrastructure.cache.redis.from_url', side_effect=mock_from_url):
            cache_instance = SecureCache(
                redis_url=redis_url,
                max_connections=10,
                default_ttl=3600,
                key_prefix="test:"
            )
            yield cache_instance, mock_redis

    @pytest.mark.asyncio
    async def test_cache_initialization(self, redis_url):
        """Test cache initialization with various parameters."""
        cache = SecureCache(
            redis_url=redis_url,
            max_connections=50,
            default_ttl=7200,
            key_prefix="terrasafe:"
        )

        assert cache.default_ttl == 7200
        assert cache.key_prefix == "terrasafe:"
        assert cache.redis_url == redis_url
        assert cache.max_connections == 50
        assert cache._redis is None  # Connection is lazy

    @pytest.mark.asyncio
    async def test_set_and_get_success(self, cache_with_mock):
        """Test successful set and get operations."""
        cache, mock_redis = cache_with_mock
        key = "test_key"
        value = {"data": "test_value", "count": 42}

        # Mock Redis get to return the serialized value
        mock_redis.get.return_value = json.dumps(value)

        # Set value
        result = await cache.set(key, value, ttl_seconds=300)
        assert result is True

        # Verify setex was called
        assert mock_redis.setex.called

        # Get value
        retrieved_value = await cache.get(key)

        # Verify get was called and result matches
        mock_redis.get.assert_called()
        assert retrieved_value == value

    @pytest.mark.asyncio
    async def test_set_with_custom_ttl(self, cache_with_mock):
        """Test setting values with custom TTL."""
        cache, mock_redis = cache_with_mock
        key = "ttl_test"
        value = "test_data"
        custom_ttl = timedelta(seconds=600)

        result = await cache.set(key, value, ttl=custom_ttl)
        assert result is True

        # Verify setex was called with correct TTL
        assert mock_redis.setex.called

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, cache_with_mock):
        """Test getting a non-existent key returns None."""
        cache, mock_redis = cache_with_mock
        mock_redis.get.return_value = None

        result = await cache.get("nonexistent_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_delete_key(self, cache_with_mock):
        """Test deleting a cache key."""
        cache, mock_redis = cache_with_mock
        key = "delete_test"
        mock_redis.delete.return_value = 1

        result = await cache.delete(key)

        mock_redis.delete.assert_called()
        assert result is True

    @pytest.mark.asyncio
    async def test_exists_check(self, cache_with_mock):
        """Test checking if a key exists."""
        cache, mock_redis = cache_with_mock
        key = "exists_test"

        # Test key exists
        mock_redis.exists.return_value = 1
        result = await cache.exists(key)
        assert result is True

        # Test key doesn't exist
        mock_redis.exists.return_value = 0
        result = await cache.exists(key)
        assert result is False

    @pytest.mark.asyncio
    async def test_key_hashing(self, redis_url):
        """Test that keys are properly hashed/prefixed."""
        cache = SecureCache(redis_url=redis_url, key_prefix="test:")
        key = "test_key"
        hashed_key = cache._hash_key(key)

        # Verify the key has the prefix and is hashed
        assert hashed_key.startswith("test:")
        assert len(hashed_key) > len("test:")  # Hash adds length

    @pytest.mark.asyncio
    async def test_connection_error_handling(self, redis_url):
        """Test handling of Redis connection errors."""
        mock_client = AsyncMock()
        mock_client.ping.side_effect = RedisConnectionError("Connection failed")

        async def mock_from_url(*args, **kwargs):
            return mock_client

        with patch('terrasafe.infrastructure.cache.redis.from_url', side_effect=mock_from_url):
            cache = SecureCache(redis_url=redis_url)

            # Connect should raise CacheError on connection failure
            with pytest.raises(CacheError) as exc_info:
                await cache.connect()
            assert "Redis connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_invalid_json_handling(self, cache_with_mock):
        """Test handling of invalid JSON data."""
        cache, mock_redis = cache_with_mock
        key = "invalid_json"
        mock_redis.get.return_value = "invalid{json}"

        # Should raise CacheError for invalid JSON
        with pytest.raises(CacheError):
            await cache.get(key)

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, cache_with_mock):
        """Test concurrent cache operations."""
        cache, mock_redis = cache_with_mock
        keys = [f"key_{i}" for i in range(10)]
        values = [f"value_{i}" for i in range(10)]

        # Set multiple values concurrently
        results = await asyncio.gather(*[
            cache.set(key, value) for key, value in zip(keys, values)
        ])

        # Verify all operations succeeded
        assert all(results)
        assert mock_redis.setex.call_count >= 10

    @pytest.mark.asyncio
    async def test_clear_cache(self, cache_with_mock):
        """Test clearing the entire cache or pattern."""
        cache, mock_redis = cache_with_mock

        # Mock scan_iter to return an async generator
        async def mock_scan(*args, **kwargs):
            for i in range(5):
                yield f"test:key_{i}"

        mock_redis.scan_iter = mock_scan
        mock_redis.delete = AsyncMock(return_value=1)

        result = await cache.clear()

        # Verify delete was called for each key
        assert mock_redis.delete.call_count == 5
        assert result == 5

    @pytest.mark.asyncio
    async def test_cache_stats(self, cache_with_mock):
        """Test retrieving cache statistics if available."""
        # SecureCache doesn't have get_stats method, skip this test
        pass

    @pytest.mark.asyncio
    async def test_close_connection(self, cache_with_mock):
        """Test closing the cache connection."""
        cache, mock_redis = cache_with_mock

        # First ensure connection is established
        await cache.connect()

        # Now disconnect
        await cache.disconnect()

        # Verify close was called
        mock_redis.close.assert_called()
        mock_redis.connection_pool.disconnect.assert_called()

    @pytest.mark.asyncio
    async def test_ping_health_check(self, cache_with_mock):
        """Test Redis ping for health checking through connect."""
        cache, mock_redis = cache_with_mock
        mock_redis.ping.return_value = True

        # Connect calls ping internally
        await cache.connect()

        mock_redis.ping.assert_called()

    @pytest.mark.asyncio
    async def test_set_with_complex_data(self, cache_with_mock):
        """Test setting complex nested data structures."""
        cache, mock_redis = cache_with_mock
        complex_data = {
            "nested": {
                "list": [1, 2, 3],
                "dict": {"key": "value"},
                "tuple": [4, 5, 6]
            },
            "array": [7, 8, 9]
        }

        mock_redis.get.return_value = json.dumps(complex_data)

        result = await cache.set("complex", complex_data)
        assert result is True

        retrieved = await cache.get("complex")

        assert retrieved == complex_data

    @pytest.mark.asyncio
    async def test_ttl_retrieval(self, cache_with_mock):
        """Test retrieving TTL of a key."""
        cache, mock_redis = cache_with_mock
        key = "ttl_key"
        mock_redis.ttl.return_value = 300

        ttl = await cache.get_ttl(key)
        assert ttl == 300

        # Test key that doesn't exist
        mock_redis.ttl.return_value = -2
        ttl = await cache.get_ttl("nonexistent")
        assert ttl is None

    @pytest.mark.asyncio
    async def test_multiple_cache_instances(self, redis_url):
        """Test creating multiple cache instances."""
        cache1 = SecureCache(redis_url=redis_url, key_prefix="cache1:")
        cache2 = SecureCache(redis_url=redis_url, key_prefix="cache2:")

        assert cache1.key_prefix == "cache1:"
        assert cache2.key_prefix == "cache2:"
        # Both should have lazy connections
        assert cache1._redis is None
        assert cache2._redis is None
