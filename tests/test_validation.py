"""Tests for the input-validation helpers."""
import pytest

from terravault.infrastructure.validation import (
    sanitize_filename,
    validate_file_hash,
    validate_scan_id,
)


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# validate_file_hash
# ---------------------------------------------------------------------------

def test_validate_file_hash_returns_lowercase_for_valid_sha256():
    valid_hash = "a" * 64

    assert validate_file_hash(valid_hash) == valid_hash


@pytest.mark.parametrize(
    "bad_hash",
    [
        pytest.param("abc123", id="wrong_length"),
        pytest.param("g" * 64, id="non_hex_characters"),
    ],
)
def test_validate_file_hash_rejects_non_sha256_inputs(bad_hash):
    with pytest.raises(ValueError, match="Invalid SHA-256"):
        validate_file_hash(bad_hash)


# ---------------------------------------------------------------------------
# validate_scan_id
# ---------------------------------------------------------------------------

def test_validate_scan_id_accepts_canonical_uuid():
    uuid = "550e8400-e29b-41d4-a716-446655440000"

    assert validate_scan_id(uuid) == uuid


def test_validate_scan_id_rejects_non_uuid_input():
    with pytest.raises(ValueError, match="Invalid UUID"):
        validate_scan_id("not-a-uuid")


# ---------------------------------------------------------------------------
# sanitize_filename
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected",
    [
        pytest.param("main.tf", "main.tf", id="normal_filename_passes_through"),
        pytest.param("../../../etc/passwd", "etc_passwd", id="path_traversal_stripped"),
        pytest.param("file name (1).tf", "file_name__1_.tf", id="special_chars_replaced"),
    ],
)
def test_sanitize_filename_normalizes_inputs(raw, expected):
    assert sanitize_filename(raw) == expected


def test_sanitize_filename_truncates_names_exceeding_255_chars():
    result = sanitize_filename("a" * 300)

    assert len(result) == 255
