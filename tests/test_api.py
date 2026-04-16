"""API integration tests — exercise the real FastAPI pipeline via TestClient."""
import pytest


# ---------------------------------------------------------------------------
# Health / metrics
# ---------------------------------------------------------------------------

def test_health_endpoint_returns_healthy_status(api_client):
    response = api_client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_metrics_endpoint_exposes_scan_counter_when_available(api_client):
    response = api_client.get("/metrics")

    assert response.status_code in (200, 503)
    if response.status_code == 200:
        assert "terrasafe_scans_total" in response.text


# ---------------------------------------------------------------------------
# Authentication — parametrized across the two failure modes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "headers, expected_detail_fragment",
    [
        pytest.param({}, "Missing API Key", id="missing_key"),
        pytest.param({"X-API-Key": "invalid-api-key-12345"}, "Invalid API Key", id="invalid_key"),
    ],
)
def test_scan_rejects_requests_without_valid_api_key(
    api_client, vulnerable_tf, headers, expected_detail_fragment
):
    response = api_client.post(
        "/scan",
        files={"file": ("test.tf", vulnerable_tf, "text/plain")},
        headers=headers,
    )

    assert response.status_code == 403
    assert expected_detail_fragment in response.json()["detail"]


# ---------------------------------------------------------------------------
# Scan behaviour — high/low risk on real Terraform content
# ---------------------------------------------------------------------------

def test_scan_vulnerable_file_returns_high_risk_score(api_client, api_headers, vulnerable_tf):
    response = api_client.post(
        "/scan",
        files={"file": ("vulnerable.tf", vulnerable_tf, "text/plain")},
        headers=api_headers,
    )

    assert response.status_code == 200
    data = response.json()
    assert data["score"] >= 70
    assert len(data["vulnerabilities"]) > 0


def test_scan_secure_file_returns_low_risk_score(api_client, api_headers, secure_tf):
    response = api_client.post(
        "/scan",
        files={"file": ("secure.tf", secure_tf, "text/plain")},
        headers=api_headers,
    )

    assert response.status_code == 200
    assert response.json()["score"] <= 30


# ---------------------------------------------------------------------------
# Upload validation — parametrized across invalid-file scenarios
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "filename, content, expected_status, expected_detail_fragment",
    [
        pytest.param("test.txt", b"not terraform", 400, "Terraform file", id="wrong_extension"),
        pytest.param("empty.tf", b"", 400, "empty", id="empty_body"),
    ],
)
def test_scan_rejects_invalid_uploads(
    api_client, api_headers, filename, content, expected_status, expected_detail_fragment
):
    response = api_client.post(
        "/scan",
        files={"file": (filename, content, "text/plain")},
        headers=api_headers,
    )

    assert response.status_code == expected_status
    assert expected_detail_fragment.lower() in response.json()["detail"].lower()


def test_scan_rejects_file_exceeding_configured_size_limit(
    api_client, api_headers, mock_api_settings
):
    mock_api_settings.max_file_size_bytes = 100
    mock_api_settings.max_file_size_mb = 0.0001

    response = api_client.post(
        "/scan",
        files={"file": ("large.tf", b"x" * 200, "text/plain")},
        headers=api_headers,
    )

    assert response.status_code == 413
    detail = response.json()["detail"]
    assert "File too large" in detail
    assert "0.0001MB" in detail
