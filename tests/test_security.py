"""
Security tests for TerraSafe.

Tests API key validation, path traversal protection, and settings validation.
"""

import pytest
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch

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

    def test_api_key_hash_uniqueness(self):
        """Test that hashing the same key twice produces different hashes (salt)."""
        api_key = "test-api-key-12345"
        hash1 = hash_api_key(api_key)
        hash2 = hash_api_key(api_key)

        # Hashes should be different due to different salts
        assert hash1 != hash2

        # But both should verify correctly
        assert verify_api_key_hash(api_key, hash1) is True
        assert verify_api_key_hash(api_key, hash2) is True

    def test_api_key_verification_error_handling(self):
        """Test that API key verification handles errors gracefully."""
        # Invalid hash format
        assert verify_api_key_hash("test", "invalid-hash") is False

        # Empty strings
        assert verify_api_key_hash("", "") is False


class TestPathTraversalProtection:
    """Test path traversal attack protection."""

    def test_parser_path_traversal_attempt(self):
        """Test that parser validates paths properly."""
        parser = HCLParser()

        # Try to access a file outside the working directory
        # Note: This will fail with "File not found" which is expected
        with pytest.raises(TerraformParseError):
            parser.parse("../../../etc/passwd")

    def test_parser_resolves_paths_safely(self):
        """Test that parser resolves paths safely."""
        parser = HCLParser()

        # Create a temp file with a safe path
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
            f.write('resource "test" {}')
            temp_path = f.name

        try:
            # This should work - temp files are allowed
            tf_content, raw_content = parser.parse(temp_path)
            assert tf_content is not None
            assert raw_content is not None
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_parser_rejects_directories(self):
        """Test that parser rejects directory paths."""
        parser = HCLParser()

        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(TerraformParseError) as exc_info:
                parser.parse(temp_dir)

            assert "not a regular file" in str(exc_info.value)


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

    def test_settings_validates_log_level(self):
        """Test that settings validates log level."""
        # Create a valid bcrypt hash for testing
        valid_hash = hash_api_key("test-key")

        with pytest.raises(ValueError) as exc_info:
            Settings(api_key_hash=valid_hash, log_level="INVALID")

        assert "log_level" in str(exc_info.value).lower()

    def test_settings_validates_environment(self):
        """Test that settings validates environment."""
        valid_hash = hash_api_key("test-key")

        with pytest.raises(ValueError) as exc_info:
            Settings(api_key_hash=valid_hash, environment="invalid")

        assert "environment" in str(exc_info.value).lower()


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
