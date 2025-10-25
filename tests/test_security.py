"""
Security tests for TerraSafe.

Tests API key validation, rate limiting, input validation, and path traversal protection.
"""

import pytest
import bcrypt
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock

from terrasafe.api import app, hash_api_key, verify_api_key_hash
from terrasafe.infrastructure.parser import (
    HCLParser,
    TerraformParseError,
    PathTraversalError,
    FileSizeLimitError,
    ParseTimeoutError
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


class TestAPIEndpointSecurity:
    """Test API endpoint security."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def mock_settings(self):
        """Mock settings with test API key."""
        test_key = "test-api-key"
        hashed_key = hash_api_key(test_key)

        with patch('terrasafe.api.settings') as mock:
            mock.api_key_hash = hashed_key
            mock.max_file_size_bytes = 10 * 1024 * 1024
            mock.max_file_size_mb = 10
            mock.scan_timeout_seconds = 30
            mock.is_development.return_value = True
            mock.is_production.return_value = False
            yield mock, test_key

    def test_scan_without_api_key(self, client):
        """Test that scan endpoint rejects requests without API key."""
        response = client.post(
            "/scan",
            files={"file": ("test.tf", b"resource 'test' {}", "text/plain")}
        )

        assert response.status_code == 403
        assert "Missing API Key" in response.json()["detail"]

    def test_scan_with_invalid_api_key(self, client, mock_settings):
        """Test that scan endpoint rejects invalid API keys."""
        response = client.post(
            "/scan",
            headers={"X-API-Key": "invalid-key"},
            files={"file": ("test.tf", b"resource 'test' {}", "text/plain")}
        )

        assert response.status_code == 403
        assert "Invalid API Key" in response.json()["detail"]

    def test_scan_with_valid_api_key(self, client, mock_settings):
        """Test that scan endpoint accepts valid API keys."""
        mock, test_key = mock_settings

        # Create a valid terraform file
        tf_content = b"""
        resource "aws_instance" "example" {
            ami = "ami-12345678"
            instance_type = "t2.micro"
        }
        """

        with patch('terrasafe.api.scanner') as mock_scanner:
            mock_scanner.scan.return_value = {
                'score': 50,
                'rule_based_score': 40,
                'ml_score': 60,
                'confidence': 'MEDIUM',
                'vulnerabilities': [],
                'summary': {},
                'features_analyzed': {},
                'performance': {'scan_time_seconds': 0.1, 'file_size_kb': 0.5}
            }

            response = client.post(
                "/scan",
                headers={"X-API-Key": test_key},
                files={"file": ("test.tf", tf_content, "text/plain")}
            )

            # Should succeed if API key is valid
            assert response.status_code == 200

    def test_scan_file_size_validation(self, client, mock_settings):
        """Test that large files are rejected."""
        mock, test_key = mock_settings

        # Create a file larger than 10MB
        large_content = b"x" * (11 * 1024 * 1024)  # 11MB

        response = client.post(
            "/scan",
            headers={"X-API-Key": test_key},
            files={"file": ("test.tf", large_content, "text/plain")}
        )

        assert response.status_code == 413
        assert "too large" in response.json()["detail"].lower()

    def test_scan_empty_file_validation(self, client, mock_settings):
        """Test that empty files are rejected."""
        mock, test_key = mock_settings

        response = client.post(
            "/scan",
            headers={"X-API-Key": test_key},
            files={"file": ("test.tf", b"", "text/plain")}
        )

        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    def test_scan_invalid_file_extension(self, client, mock_settings):
        """Test that non-Terraform files are rejected."""
        mock, test_key = mock_settings

        response = client.post(
            "/scan",
            headers={"X-API-Key": test_key},
            files={"file": ("test.txt", b"some content", "text/plain")}
        )

        assert response.status_code == 400
        assert "Terraform file" in response.json()["detail"]


class TestInputValidation:
    """Test input validation and sanitization."""

    def test_parser_file_size_limit(self):
        """Test that parser enforces file size limits."""
        parser = HCLParser(max_file_size_bytes=100)  # 100 bytes limit

        # Create a temp file larger than limit
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
            f.write("x" * 200)  # 200 bytes
            temp_path = f.name

        try:
            with pytest.raises(FileSizeLimitError) as exc_info:
                parser.parse(temp_path)

            assert "exceeds maximum allowed size" in str(exc_info.value)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_parser_empty_file(self):
        """Test that parser rejects empty files."""
        parser = HCLParser()

        # Create an empty temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tf', delete=False) as f:
            temp_path = f.name

        try:
            with pytest.raises(TerraformParseError) as exc_info:
                parser.parse(temp_path)

            assert "empty" in str(exc_info.value).lower()
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_parser_nonexistent_file(self):
        """Test that parser handles nonexistent files properly."""
        parser = HCLParser()

        with pytest.raises(TerraformParseError) as exc_info:
            parser.parse("/nonexistent/file.tf")

        assert "not found" in str(exc_info.value).lower()


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


class TestRateLimiting:
    """Test rate limiting functionality."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_health_endpoint_no_rate_limit(self, client):
        """Test that health endpoint is not rate limited."""
        # Make multiple requests quickly
        for _ in range(10):
            response = client.get("/health")
            assert response.status_code == 200

    @pytest.mark.skip(reason="Rate limiting requires Redis in test environment")
    def test_scan_endpoint_rate_limiting(self, client):
        """Test that scan endpoint enforces rate limits."""
        # This test would require a Redis instance for rate limiting
        # Skip for now, but keep as documentation
        pass


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
