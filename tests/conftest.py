"""
Pytest configuration and shared fixtures for all tests.

This file sets up the test environment and provides common fixtures
that are available to all test modules.
"""
import os
import pytest

# Set up environment variables before any imports
# This prevents validation errors when modules are imported
os.environ['TERRASAFE_API_KEY_HASH'] = 'REDACTED_HASH'
os.environ['TERRASAFE_ENVIRONMENT'] = 'development'
os.environ['TERRASAFE_DATABASE_URL'] = 'postgresql+asyncpg://test:test@localhost:5432/test'
os.environ['TERRASAFE_REDIS_URL'] = 'redis://localhost:6379'
os.environ['TERRASAFE_LOG_LEVEL'] = 'INFO'


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """
    Session-scoped fixture that sets up the test environment.
    This runs once at the beginning of the test session.
    """
    # Environment is already set up above
    yield
    # Teardown (if needed)
