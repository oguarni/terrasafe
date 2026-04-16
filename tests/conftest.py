"""Pytest configuration and shared fixtures.

Env vars are set *before* any terrasafe import because ``get_settings`` is
``lru_cache``d and snapshots them on first use.
"""
import io
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

os.environ['TERRASAFE_API_KEY_HASH'] = '$2b$12$c4dkSX9x2RbksUcaTWgpAuGc3YbAGhwYiiHI6pLiSBviheWuzrWLi'
os.environ['TERRASAFE_ENVIRONMENT'] = 'development'
os.environ['TERRASAFE_DATABASE_URL'] = 'postgresql+asyncpg://test:test@localhost:5432/test'
os.environ['TERRASAFE_REDIS_URL'] = 'redis://localhost:6379'
os.environ['TERRASAFE_LOG_LEVEL'] = 'INFO'

from terrasafe.config.settings import get_settings  # noqa: E402

get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Session setup / per-test rate-limiter reset
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    yield


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear the FastAPI rate limiter so sibling tests don't hit 429s."""
    try:
        from terrasafe.api import app
        limiter = getattr(app.state, 'limiter', None)
        if limiter is None:
            yield
            return
        try:
            limiter.reset()
        except Exception:
            storage = getattr(limiter, '_storage', None)
            if storage is not None and hasattr(storage, 'storage'):
                storage.storage.clear()
    except Exception:
        pass
    yield


# ---------------------------------------------------------------------------
# Terraform content fixtures (used by API + parser tests)
# ---------------------------------------------------------------------------

VULNERABLE_TF_CONTENT = b"""# Vulnerable Terraform configuration for testing
resource "aws_security_group" "web_sg" {
  name        = "web-security-group"
  description = "Web server security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main_db" {
  allocated_storage       = 20
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  db_name                = "mydb"
  username               = "test_user"
  password               = "test_placeholder_not_real"
  storage_encrypted      = false
  backup_retention_period = 0
  skip_final_snapshot    = true
}

resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false

  tags = {
    Name = "DataVolume"
  }
}

resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.main_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket" "main_bucket" {
  bucket = "my-vulnerable-bucket"

  tags = {
    Environment = "test"
  }
}
"""

SECURE_TF_CONTENT = b"""# Secure Terraform configuration for testing
resource "aws_security_group" "web_sg" {
  name        = "web-security-group"
  description = "Web server security group"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
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
  password               = var.db_password
  storage_encrypted      = true
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
  encrypted         = true

  tags = {
    Name      = "SecureDataVolume"
    Encrypted = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.main_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
def vulnerable_tf():
    return VULNERABLE_TF_CONTENT


@pytest.fixture
def secure_tf():
    return SECURE_TF_CONTENT


# ---------------------------------------------------------------------------
# API fixtures
# ---------------------------------------------------------------------------

TEST_API_KEY = "test-api-key-for-testing-12345678"


@pytest.fixture
def api_key():
    return TEST_API_KEY


@pytest.fixture
def api_key_hash():
    from terrasafe.api import hash_api_key
    return hash_api_key(TEST_API_KEY)


@pytest.fixture
def mock_api_settings(api_key_hash):
    """Patch ``terrasafe.api.settings`` with values tuned for the test client."""
    with patch('terrasafe.api.settings') as mock:
        mock.api_key_hash = api_key_hash
        mock.allowed_hosts = "*"
        mock.max_file_size_bytes = 10 * 1024 * 1024
        mock.max_file_size_mb = 10
        mock.scan_timeout_seconds = 60
        mock.is_development.return_value = True
        mock.is_production.return_value = False
        mock.environment = "test"
        yield mock


@pytest.fixture
def api_client(mock_api_settings):
    from fastapi.testclient import TestClient
    from terrasafe.api import app
    return TestClient(app)


@pytest.fixture
def api_headers(api_key):
    return {"X-API-Key": api_key}


# ---------------------------------------------------------------------------
# CLI fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scan_result_factory():
    """Factory producing CLI-shaped scan result dicts for mocking ``_build_scanner``."""
    def _factory(score: int = 50, filepath: str = "test.tf") -> dict:
        return {
            "file": filepath,
            "score": score,
            "rule_based_score": score,
            "ml_score": float(score),
            "confidence": "HIGH",
            "vulnerabilities": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "features_analyzed": {
                "open_ports": 0,
                "hardcoded_secrets": 0,
                "public_access": 0,
                "unencrypted_storage": 0,
                "total_resources": 1,
            },
            "performance": {"scan_time_seconds": 0.1, "file_size_kb": 1.0, "from_cache": False},
        }
    return _factory


@pytest.fixture
def error_result_factory():
    def _factory(filepath: str = "bad.tf") -> dict:
        return {"score": -1, "error": "Parse error", "file": filepath}
    return _factory


@pytest.fixture
def run_cli():
    """Invoke ``terrasafe.cli.main`` with patched argv/scanner.

    Returns ``(stdout, stderr, exit_code)``. The history-persistence call is
    patched through a ``MagicMock`` stored on ``run_cli.save_spy`` so tests
    can assert whether the CLI would have persisted results.
    """
    save_spy = MagicMock()

    def _invoke(argv, mock_results):
        from terrasafe import cli

        scanner = MagicMock()
        if isinstance(mock_results, list):
            scanner.scan.side_effect = mock_results
        else:
            scanner.scan.return_value = mock_results

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        with patch.object(sys, 'argv', ['terrasafe'] + argv), \
             patch.object(cli, '_build_scanner', return_value=scanner), \
             patch('sys.stdout', stdout_buf), \
             patch('sys.stderr', stderr_buf), \
             patch('terrasafe.cli._save_history', save_spy):
            try:
                cli.main()
                exit_code = 0
            except SystemExit as exc:
                exit_code = exc.code if exc.code is not None else 0

        return stdout_buf.getvalue(), stderr_buf.getvalue(), exit_code

    _invoke.save_spy = save_spy
    return _invoke


# ---------------------------------------------------------------------------
# Security rule engine fixture (shared across rule test modules)
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    from terrasafe.domain.security_rules import SecurityRuleEngine
    return SecurityRuleEngine()


# ---------------------------------------------------------------------------
# SARIF fixtures
# ---------------------------------------------------------------------------

VULN_HIGH = {
    "severity": "HIGH",
    "points": 20,
    "message": "Hardcoded password detected",
    "resource": "aws_db_instance.main",
    "remediation": "Use AWS Secrets Manager instead.",
}
VULN_CRITICAL = {
    "severity": "CRITICAL",
    "points": 30,
    "message": "Open security group on port 22",
    "resource": "aws_security_group.web",
    "remediation": "Restrict SSH access to known IP ranges.",
}
VULN_MEDIUM = {
    "severity": "MEDIUM",
    "points": 10,
    "message": "S3 bucket allows public read",
    "resource": "aws_s3_bucket.data",
    "remediation": "Set acl to private.",
}


@pytest.fixture
def vuln_samples():
    return {"critical": VULN_CRITICAL, "high": VULN_HIGH, "medium": VULN_MEDIUM}
