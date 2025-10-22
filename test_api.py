#!/usr/bin/env python3
"""API integration tests"""
import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from terrasafe.api import app


@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


def test_health_endpoint(client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_scan_vulnerable_file(client):
    """Test scanning a vulnerable Terraform file"""
    file_path = Path("test_files/vulnerable.tf")
    if file_path.exists():
        with open(file_path, "rb") as f:
            response = client.post(
                "/scan",
                files={"file": ("vulnerable.tf", f, "text/plain")}
            )
        assert response.status_code == 200
        data = response.json()
        assert data["score"] >= 70  # High risk expected
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) > 0
    else:
        pytest.skip("test_files/vulnerable.tf not found")


def test_scan_secure_file(client):
    """Test scanning a secure Terraform file"""
    file_path = Path("test_files/secure.tf")
    if file_path.exists():
        with open(file_path, "rb") as f:
            response = client.post(
                "/scan",
                files={"file": ("secure.tf", f, "text/plain")}
            )
        assert response.status_code == 200
        data = response.json()
        assert data["score"] <= 30  # Low risk expected
    else:
        pytest.skip("test_files/secure.tf not found")


def test_metrics_endpoint(client):
    """Test Prometheus metrics endpoint"""
    response = client.get("/metrics")
    # Metrics may not be available if prometheus_client is not installed
    assert response.status_code in [200, 503]
    if response.status_code == 200:
        assert "terrasafe_scans_total" in response.text


def test_api_docs_endpoint(client):
    """Test API documentation endpoint"""
    response = client.get("/api/docs")
    assert response.status_code == 200
    data = response.json()
    assert "endpoints" in data
    assert "/health" in data["endpoints"]
    assert "/scan" in data["endpoints"]
    assert "/metrics" in data["endpoints"]


def test_invalid_file_type(client):
    """Test uploading invalid file type"""
    response = client.post(
        "/scan",
        files={"file": ("test.txt", b"not terraform", "text/plain")}
    )
    assert response.status_code == 400
    assert "must be a .tf Terraform file" in response.json()["detail"]


def test_scan_response_structure(client):
    """Test that scan response has expected structure"""
    file_path = Path("test_files/vulnerable.tf")
    if file_path.exists():
        with open(file_path, "rb") as f:
            response = client.post(
                "/scan",
                files={"file": ("vulnerable.tf", f, "text/plain")}
            )
        assert response.status_code == 200
        data = response.json()

        # Check required fields
        assert "score" in data
        assert "rule_based_score" in data
        assert "ml_score" in data
        assert "confidence" in data
        assert "vulnerabilities" in data
        assert "summary" in data
        assert "features_analyzed" in data
        assert "performance" in data

        # Check that vulnerabilities have required fields
        if data["vulnerabilities"]:
            vuln = data["vulnerabilities"][0]
            assert "severity" in vuln
            assert "points" in vuln
            assert "message" in vuln
            assert "resource" in vuln
            assert "remediation" in vuln
    else:
        pytest.skip("test_files/vulnerable.tf not found")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
