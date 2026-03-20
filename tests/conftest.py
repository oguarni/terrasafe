"""
Pytest configuration and shared fixtures for all tests.

This file sets up the test environment and provides common fixtures
that are available to all test modules.
"""
import os
import pytest

# Set up environment variables before any imports
# This prevents validation errors when modules are imported
# Must happen before get_settings() is ever called (it's @lru_cache'd)
os.environ['TERRASAFE_API_KEY_HASH'] = '$2b$12$c4dkSX9x2RbksUcaTWgpAuGc3YbAGhwYiiHI6pLiSBviheWuzrWLi'
os.environ['TERRASAFE_ENVIRONMENT'] = 'development'
os.environ['TERRASAFE_DATABASE_URL'] = 'postgresql+asyncpg://test:test@localhost:5432/test'
os.environ['TERRASAFE_REDIS_URL'] = 'redis://localhost:6379'
os.environ['TERRASAFE_LOG_LEVEL'] = 'INFO'

# Clear any previously cached settings so they pick up test env vars
from terrasafe.config.settings import get_settings  # noqa: E402
get_settings.cache_clear()


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """
    Session-scoped fixture that sets up the test environment.
    This runs once at the beginning of the test session.
    """
    # Environment is already set up above
    yield
    # Teardown (if needed)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    Reset the rate limiter state before each test.
    This prevents rate limit errors when running the full test suite.
    """
    try:
        # Import here to avoid triggering full API initialization in pure unit tests
        from terrasafe.api import app

        # Reset rate limiter if it exists
        if hasattr(app.state, 'limiter'):
            try:
                # Clear the in-memory storage for the rate limiter
                app.state.limiter.reset()
            except (AttributeError, Exception):
                # If reset method doesn't exist or fails, try clearing storage directly
                try:
                    if hasattr(app.state.limiter, '_storage'):
                        app.state.limiter._storage.storage.clear()
                except (AttributeError, Exception):
                    pass  # Rate limiter might not be configured
    except Exception:
        pass  # API may not be available in pure unit test contexts

    yield
