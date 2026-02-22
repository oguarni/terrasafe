"""Tests for the input validation module."""
import pytest

from terrasafe.infrastructure.validation import (
    validate_file_hash,
    validate_scan_id,
    sanitize_filename,
)


@pytest.mark.unit
class TestValidateFileHash:
    """Tests for validate_file_hash."""

    def test_valid_hash(self):
        """A valid SHA-256 hash should be returned lowercase."""
        valid_hash = "a" * 64
        assert validate_file_hash(valid_hash) == valid_hash

    def test_uppercase_hash_normalized(self):
        """Uppercase hashes should be normalized to lowercase."""
        upper_hash = "A" * 64
        assert validate_file_hash(upper_hash) == "a" * 64

    def test_invalid_length(self):
        """Hashes with wrong length should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid SHA-256"):
            validate_file_hash("abc123")

    def test_non_hex_characters(self):
        """Hashes with non-hex characters should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid SHA-256"):
            validate_file_hash("g" * 64)

    def test_non_string_input(self):
        """Non-string input should raise TypeError."""
        with pytest.raises(TypeError, match="must be string"):
            validate_file_hash(12345)  # type: ignore[arg-type]

    def test_empty_string(self):
        """Empty string should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid SHA-256"):
            validate_file_hash("")


@pytest.mark.unit
class TestValidateScanId:
    """Tests for validate_scan_id."""

    def test_valid_uuid(self):
        """A valid UUID should be returned lowercase."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_scan_id(uuid) == uuid

    def test_uppercase_uuid_normalized(self):
        """Uppercase UUIDs should be normalized to lowercase."""
        uuid = "550E8400-E29B-41D4-A716-446655440000"
        assert validate_scan_id(uuid) == uuid.lower()

    def test_invalid_uuid(self):
        """Invalid UUID format should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid UUID"):
            validate_scan_id("not-a-uuid")

    def test_empty_string(self):
        """Empty string should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid UUID"):
            validate_scan_id("")


@pytest.mark.unit
class TestSanitizeFilename:
    """Tests for sanitize_filename."""

    def test_normal_filename(self):
        """Normal filenames should pass through unchanged."""
        assert sanitize_filename("main.tf") == "main.tf"

    def test_path_traversal_removal(self):
        """Path traversal attempts should be stripped."""
        result = sanitize_filename("../../../etc/passwd")
        assert "../" not in result
        assert result == "etc_passwd"

    def test_nested_path_traversal(self):
        """Nested path traversal patterns should be handled."""
        result = sanitize_filename("....//....//etc/passwd")
        assert "../" not in result

    def test_special_characters_replaced(self):
        """Special characters should be replaced with underscores."""
        result = sanitize_filename("file name (1).tf")
        assert result == "file_name__1_.tf"

    def test_max_length(self):
        """Filenames exceeding 255 chars should be truncated."""
        long_name = "a" * 300
        result = sanitize_filename(long_name)
        assert len(result) == 255

    def test_backslash_traversal(self):
        """Windows-style path traversal should also be stripped."""
        result = sanitize_filename("..\\\\..\\\\file.tf")
        assert "..\\\\" not in result
