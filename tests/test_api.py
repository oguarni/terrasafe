#!/usr/bin/env python3
"""API integration tests with comprehensive coverage"""
import os
import pytest
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from io import BytesIO

from terrasafe.api import app, hash_api_key


# Generate a consistent test API key for all tests
TEST_API_KEY = "test-api-key-for-testing-12345678"
TEST_API_KEY_HASH = hash_api_key(TEST_API_KEY)

# Embedded Terraform file content (no external file dependencies)
# Credentials loaded from environment variables for security
VULNERABLE_TF_CONTENT = f"""# Vulnerable Terraform configuration for testing
# This file contains multiple security issues

resource "aws_security_group" "web_sg" {{
  name        = "web-security-group"
  description = "Web server security group"

  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: Open SSH access from internet
  }}

  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # CRITICAL: Open HTTP access from internet
  }}
}}

resource "aws_db_instance" "main_db" {{
  allocated_storage       = 20
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  db_name                = "mydb"
  username               = "{os.environ.get('API_USERNAME', 'admin')}"
  password               = "{os.environ.get('API_PASSWORD', 'default_test_password')}"  # CRITICAL: Hardcoded password
  storage_encrypted      = false           # HIGH: Unencrypted RDS instance
  backup_retention_period = 0
  skip_final_snapshot    = true
}}

resource "aws_ebs_volume" "data_volume" {{
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false  # HIGH: Unencrypted EBS volume

  tags = {{
    Name = "DataVolume"
  }}
}}

resource "aws_s3_bucket_public_access_block" "public_bucket" {{
  bucket = aws_s3_bucket.main_bucket.id

  block_public_acls       = false  # HIGH: Public access enabled
  block_public_policy     = false  # HIGH: Public policy allowed
  ignore_public_acls      = false  # HIGH: Public ACLs not ignored
  restrict_public_buckets = false  # HIGH: Public buckets not restricted
}}

resource "aws_s3_bucket" "main_bucket" {{
  bucket = "my-vulnerable-bucket"

  tags = {{
    Environment = "test"
  }}
}}
""".encode('utf-8')

SECURE_TF_CONTENT = b"""# Secure Terraform configuration for testing
# This file follows security best practices

resource "aws_security_group" "web_sg" {
  name        = "web-security-group"
  description = "Web server security group"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restricted to private network
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]  # SSH restricted to specific subnet
  }
}

resource "aws_db_instance" "main_db" {
  allocated_storage       = 20
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  db_name                = "mydb"
  username               = "admin"
  password               = var.db_password  # Using variable instead of hardcoded
  storage_encrypted      = true             # Encryption enabled
  backup_retention_period = 7
  skip_final_snapshot    = false

  tags = {
    Environment = "production"
    Encrypted   = "true"
  }
}

resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = true  # Encryption enabled

  tags = {
    Name      = "SecureDataVolume"
    Encrypted = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.main_bucket.id

  block_public_acls       = true  # Block public ACLs
  block_public_policy     = true  # Block public policies
  ignore_public_acls      = true  # Ignore public ACLs
  restrict_public_buckets = true  # Restrict public buckets
}

resource "aws_s3_bucket" "main_bucket" {
  bucket = "my-secure-bucket"

  tags = {
    Environment = "production"
    Security    = "enhanced"
  }
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}
"""


@pytest.fixture
def mock_settings():
    """Mock settings with test API key hash"""
    with patch('terrasafe.api.settings') as mock:
        mock.api_key_hash = TEST_API_KEY_HASH
        mock.allowed_hosts = "*"
        mock.max_file_size_bytes = 10 * 1024 * 1024  # 10MB
        mock.max_file_size_mb = 10
        mock.scan_timeout_seconds = 60
        mock.is_development.return_value = True
        mock.is_production.return_value = False
        mock.environment = "test"
        yield mock


@pytest.fixture
def client(mock_settings):
    """Create test client with mocked authentication"""
    return TestClient(app)


@pytest.fixture
def api_headers():
    """Return headers with API key for authenticated requests"""
    return {"X-API-Key": TEST_API_KEY}


# ============================================================================
# HEALTH AND DOCUMENTATION ENDPOINTS
# ============================================================================

def test_health_endpoint(client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


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


# ============================================================================
# AUTHENTICATION TESTS (HIGH PRIORITY)
# ============================================================================

def test_scan_missing_api_key(client):
    """Test that scan endpoint returns 403 when API key is missing"""
    response = client.post(
        "/scan",
        files={"file": ("test.tf", VULNERABLE_TF_CONTENT, "text/plain")}
        # No X-API-Key header
    )
    assert response.status_code == 403
    assert "Missing API Key" in response.json()["detail"]


def test_scan_invalid_api_key(client):
    """Test that scan endpoint returns 403 when API key is invalid"""
    response = client.post(
        "/scan",
        files={"file": ("test.tf", VULNERABLE_TF_CONTENT, "text/plain")},
        headers={"X-API-Key": "invalid-api-key-12345"}
    )
    assert response.status_code == 403
    assert "Invalid API Key" in response.json()["detail"]


def test_scan_empty_api_key(client):
    """Test that scan endpoint returns 403 when API key is empty"""
    response = client.post(
        "/scan",
        files={"file": ("test.tf", VULNERABLE_TF_CONTENT, "text/plain")},
        headers={"X-API-Key": ""}
    )
    assert response.status_code == 403
    # Empty string is treated as missing
    assert "Missing API Key" in response.json()["detail"] or "Invalid API Key" in response.json()["detail"]


# ============================================================================
# SCAN FUNCTIONALITY TESTS
# ============================================================================

def test_scan_vulnerable_file(client, api_headers):
    """Test scanning a vulnerable Terraform file with embedded content"""
    response = client.post(
        "/scan",
        files={"file": ("vulnerable.tf", VULNERABLE_TF_CONTENT, "text/plain")},
        headers=api_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["score"] >= 70  # High risk expected
    assert "vulnerabilities" in data
    assert len(data["vulnerabilities"]) > 0


def test_scan_secure_file(client, api_headers):
    """Test scanning a secure Terraform file with embedded content"""
    response = client.post(
        "/scan",
        files={"file": ("secure.tf", SECURE_TF_CONTENT, "text/plain")},
        headers=api_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["score"] <= 30  # Low risk expected


def test_invalid_file_type(client, api_headers):
    """Test uploading invalid file type"""
    response = client.post(
        "/scan",
        files={"file": ("test.txt", b"not terraform", "text/plain")},
        headers=api_headers
    )
    assert response.status_code == 400
    assert "Terraform file" in response.json()["detail"]


def test_empty_file(client, api_headers):
    """Test uploading empty file"""
    response = client.post(
        "/scan",
        files={"file": ("empty.tf", b"", "text/plain")},
        headers=api_headers
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_scan_response_structure(client, api_headers):
    """Test that scan response has expected structure"""
    response = client.post(
        "/scan",
        files={"file": ("vulnerable.tf", VULNERABLE_TF_CONTENT, "text/plain")},
        headers=api_headers
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


# ============================================================================
# FILE SIZE AND TIMEOUT TESTS (MEDIUM PRIORITY)
# ============================================================================

def test_file_size_limit_exceeded(client, api_headers, mock_settings):
    """Test that files exceeding max_file_size_bytes return 413 error"""
    # Set a small file size limit for testing
    mock_settings.max_file_size_bytes = 100  # 100 bytes
    mock_settings.max_file_size_mb = 0.0001

    # Create a large file (larger than 100 bytes)
    large_content = b"x" * 200

    response = client.post(
        "/scan",
        files={"file": ("large.tf", large_content, "text/plain")},
        headers=api_headers
    )
    assert response.status_code == 413
    assert "File too large" in response.json()["detail"]
    assert "0.0001MB" in response.json()["detail"]


def test_scan_timeout(client, api_headers, mock_settings):
    """Test that scans exceeding timeout limit return 504 error"""
    # Set a very short timeout for testing
    mock_settings.scan_timeout_seconds = 0.1  # 100ms timeout

    # Mock the scanner.scan to take longer than timeout
    def slow_scan(filepath):
        time.sleep(0.2)  # Sleep 200ms (exceeds 100ms timeout)
        return {"score": 50}

    with patch('terrasafe.api.scanner.scan', side_effect=slow_scan):
        response = client.post(
            "/scan",
            files={"file": ("slow.tf", VULNERABLE_TF_CONTENT, "text/plain")},
            headers=api_headers
        )
        assert response.status_code == 504
        assert "timeout" in response.json()["detail"].lower()
        assert "0.1" in response.json()["detail"]


# ============================================================================
# CONCURRENCY TESTS (MEDIUM PRIORITY)
# ============================================================================

def test_concurrent_scan_requests(client, api_headers, mock_settings):
    """
    Test that the API handles concurrent scan requests correctly.
    Verifies thread safety and absence of race conditions.
    Rate limiting may affect some requests (expected behavior).
    """
    # Increase rate limit for concurrency test
    mock_settings.rate_limit_requests = 100
    mock_settings.rate_limit_window_seconds = 60

    def make_scan_request(i):
        """Helper function to make a single scan request"""
        response = client.post(
            "/scan",
            files={"file": (f"test_{i}.tf", VULNERABLE_TF_CONTENT, "text/plain")},
            headers=api_headers
        )
        return response.status_code, response.json()

    # Send 5 concurrent requests (reduced to avoid rate limiting)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(make_scan_request, i) for i in range(5)]
        results = [future.result() for future in futures]

    # Count successful and rate-limited requests
    successful_requests = 0
    rate_limited_requests = 0

    for status_code, data in results:
        if status_code == 200:
            successful_requests += 1
            assert "score" in data
            assert data["score"] >= 0
            # Verify response structure integrity
            assert "vulnerabilities" in data
            assert "rule_based_score" in data
            assert "ml_score" in data
        elif status_code == 429:
            # Rate limiting is expected and acceptable
            rate_limited_requests += 1
            assert "error" in data or "detail" in data
        else:
            pytest.fail(f"Unexpected status code {status_code}: {data}")

    # At least some requests should succeed (not all rate limited)
    assert successful_requests > 0, "All requests were rate limited"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
