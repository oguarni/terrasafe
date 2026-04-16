"""Security tests — API key handling, path traversal, settings validation, correlation IDs."""
import pytest
from fastapi.testclient import TestClient

from terrasafe.api import app, hash_api_key, verify_api_key_hash
from terrasafe.config.settings import Settings
from terrasafe.infrastructure.parser import HCLParser, TerraformParseError


# ---------------------------------------------------------------------------
# API key hashing
# ---------------------------------------------------------------------------

def test_hash_api_key_produces_60_char_bcrypt_digest():
    hashed = hash_api_key("test-api-key-12345")

    assert len(hashed) == 60
    assert hashed.startswith("$2b$")


@pytest.mark.parametrize(
    "candidate, expected",
    [
        pytest.param("test-api-key-12345", True, id="correct_key_verifies"),
        pytest.param("wrong-key", False, id="wrong_key_rejected"),
    ],
)
def test_verify_api_key_hash_accepts_only_the_matching_key(candidate, expected):
    hashed = hash_api_key("test-api-key-12345")

    assert verify_api_key_hash(candidate, hashed) is expected


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

def test_parser_rejects_relative_path_traversal_attempts():
    parser = HCLParser()

    with pytest.raises(TerraformParseError):
        parser.parse("../../../etc/passwd")


# ---------------------------------------------------------------------------
# Settings validation — parametrized across rejection reasons
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_hash, expected_fragment",
    [
        pytest.param("change-me", "placeholder", id="placeholder_value_rejected"),
        pytest.param("tooshort", "too short", id="short_hash_rejected"),
    ],
)
def test_settings_rejects_invalid_api_key_hash(bad_hash, expected_fragment):
    with pytest.raises(ValueError, match=expected_fragment):
        Settings(api_key_hash=bad_hash)


# ---------------------------------------------------------------------------
# Correlation ID middleware
# ---------------------------------------------------------------------------

@pytest.fixture
def plain_client():
    return TestClient(app)


def test_correlation_id_is_generated_when_client_omits_header(plain_client):
    response = plain_client.get("/health")

    assert "X-Correlation-ID" in response.headers
    assert len(response.headers["X-Correlation-ID"]) > 0


def test_correlation_id_is_echoed_back_when_client_supplies_one(plain_client):
    correlation_id = "test-correlation-123"

    response = plain_client.get("/health", headers={"X-Correlation-ID": correlation_id})

    assert response.headers["X-Correlation-ID"] == correlation_id
