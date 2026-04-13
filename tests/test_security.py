"""
Security tests for TerraSafe.

Tests API key validation, path traversal protection, and settings validation.
"""

import pytest
from fastapi.testclient import TestClient

from terrasafe.api import app, hash_api_key, verify_api_key_hash
from terrasafe.infrastructure.parser import (
    HCLParser,
    TerraformParseError,
)
from terrasafe.config.settings import Settings


class TestAPIKeySecurity:
    """Test API key hashing and validation."""

    def test_api_key_hashing(self):
        """Test that API keys are properly hashed with bcrypt."""
        api_key = "test-api-key-12345"
        hashed = hash_api_key(api_key)

        # Check hash format (bcrypt hashes are 60 characters)
        assert len(hashed) == 60
        assert hashed.startswith("$2b$")

        # Verify the hash
        assert verify_api_key_hash(api_key, hashed) is True

        # Verify wrong key fails
        assert verify_api_key_hash("wrong-key", hashed) is False

class TestPathTraversalProtection:
    """Test path traversal attack protection."""

    def test_parser_path_traversal_attempt(self):
        """Test that parser rejects ../ path traversal attempts."""
        parser = HCLParser()

        with pytest.raises(TerraformParseError):
            parser.parse("../../../etc/passwd")


class TestSettingsValidation:
    """Test settings validation and security."""

    def test_settings_rejects_placeholder_api_key(self):
        """Test that settings rejects placeholder API key values."""
        with pytest.raises(ValueError) as exc_info:
            Settings(api_key_hash="change-me")

        assert "placeholder" in str(exc_info.value).lower()

    def test_settings_rejects_short_api_key_hash(self):
        """Test that settings rejects short API key hashes."""
        with pytest.raises(ValueError) as exc_info:
            Settings(api_key_hash="tooshort")

        assert "too short" in str(exc_info.value).lower()


class TestCorrelationID:
    """Test correlation ID middleware."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_correlation_id_generated_if_missing(self, client):
        """Test that correlation ID is generated if not provided."""
        response = client.get("/health")

        assert "X-Correlation-ID" in response.headers
        assert len(response.headers["X-Correlation-ID"]) > 0

    def test_correlation_id_preserved_if_provided(self, client):
        """Test that provided correlation ID is preserved."""
        test_correlation_id = "test-correlation-123"

        response = client.get(
            "/health",
            headers={"X-Correlation-ID": test_correlation_id}
        )

        assert response.headers["X-Correlation-ID"] == test_correlation_id
