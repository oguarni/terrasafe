#!/usr/bin/env python3
"""
Unit tests for TerraSafe security scanner.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from contextlib import ExitStack

# Clean Architecture imports - SOLID compliant
from terrasafe.domain.models import Severity
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.infrastructure.parser import HCLParser, TerraformParseError
from terrasafe.infrastructure.ml_model import MLPredictor
from terrasafe.application.scanner import IntelligentSecurityScanner


# ============================================================================
# SHARED TEST FIXTURES AND UTILITIES
# ============================================================================


# Import scoring weights from the scanner module to avoid hardcoding
# If scanner module doesn't export these, we define fallback constants
try:
    # Try to import from scanner configuration
    from terrasafe.application.scanner import RULE_WEIGHT, ML_WEIGHT
except ImportError:
    # Fallback: Define constants based on current implementation
    # These should match the scanner's actual weights
    RULE_WEIGHT = 0.6
    ML_WEIGHT = 0.4


def calculate_expected_score(rule_score: int, ml_score: float) -> int:
    """
    Calculate expected final score using the same formula as the scanner.
    This decouples tests from hardcoded score calculations.

    Args:
        rule_score: Rule-based score (0-100)
        ml_score: ML-based score (0-100)

    Returns:
        Final weighted score (0-100)
    """
    return int(RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score)


# ============================================================================
# PYTEST FIXTURES
# ============================================================================

@pytest.fixture
def rule_engine():
    """Fixture providing a SecurityRuleEngine instance."""
    return SecurityRuleEngine()


@pytest.fixture
def mock_scanner_components():
    """Fixture providing mocked scanner dependencies."""
    return {
        'parser': Mock(),
        'rule_analyzer': Mock(),
        'ml_predictor': Mock()
    }


@pytest.fixture
def scanner_with_mocks(mock_scanner_components):
    """Fixture providing an IntelligentSecurityScanner with mocked dependencies."""
    return IntelligentSecurityScanner(
        parser=mock_scanner_components['parser'],
        rule_analyzer=mock_scanner_components['rule_analyzer'],
        ml_predictor=mock_scanner_components['ml_predictor']
    )


@pytest.fixture
def real_scanner():
    """Fixture providing an IntelligentSecurityScanner with real components."""
    return IntelligentSecurityScanner(
        parser=HCLParser(),
        rule_analyzer=SecurityRuleEngine(),
        ml_predictor=MLPredictor()
    )


@pytest.fixture
def temp_model_dir():
    """Fixture providing a temporary directory for model storage."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


# ============================================================================
# TEST INTELLIGENT SECURITY SCANNER WITH MOCKED DEPENDENCIES
# ============================================================================

def test_scan_parse_error(scanner_with_mocks, mock_scanner_components):
    """Test scan handling parse errors"""
    test_file = "invalid.tf"
    mock_parser = mock_scanner_components['parser']
    mock_rule_analyzer = mock_scanner_components['rule_analyzer']
    mock_ml_predictor = mock_scanner_components['ml_predictor']

    mock_parser.parse.side_effect = TerraformParseError("Invalid syntax")

    with ExitStack() as stack:
        stack.enter_context(patch('pathlib.Path.exists', return_value=True))
        stack.enter_context(patch('pathlib.Path.is_file', return_value=True))
        mock_stat = stack.enter_context(patch('pathlib.Path.stat'))
        mock_stat.return_value.st_size = 1024
        mock_stat.return_value.st_mtime = 1234567890.0
        stack.enter_context(patch('builtins.open', mock_open(read_data=b"invalid terraform content")))
        results = scanner_with_mocks.scan(test_file)

    assert results['score'] == -1
    assert 'error' in results
    assert 'Invalid syntax' in results['error']
    mock_rule_analyzer.analyze.assert_not_called()
    mock_ml_predictor.predict_risk.assert_not_called()


def test_scan_file_not_found_error(scanner_with_mocks, mock_scanner_components):
    """Test scan handling file not found errors."""
    test_file = "nonexistent.tf"
    mock_parser = mock_scanner_components['parser']

    with ExitStack() as stack:
        stack.enter_context(patch('pathlib.Path.exists', return_value=True))
        stack.enter_context(patch('pathlib.Path.is_file', return_value=True))
        mock_stat = stack.enter_context(patch('pathlib.Path.stat'))
        mock_stat.side_effect = FileNotFoundError(
            f"[Errno 2] No such file or directory: '{test_file}'"
        )
        results = scanner_with_mocks.scan(test_file)

    assert results['score'] == -1
    assert 'error' in results
    assert 'File not found' in results['error']
    mock_parser.parse.assert_not_called()


# ============================================================================
# TEST INTELLIGENT SECURITY SCANNER - INTEGRATION TESTS
# ============================================================================

def test_scan_vulnerable_test_file(real_scanner):
    """Integration test scanning the actual vulnerable test file"""
    filepath = "test_files/vulnerable.tf"
    if not Path(filepath).exists():
        pytest.skip("test_files/vulnerable.tf not found")

    results = real_scanner.scan(filepath)

    # Should successfully scan
    assert results['score'] != -1

    # Should find vulnerabilities (vulnerable file should have high score)
    assert results['score'] > 30
    assert len(results['vulnerabilities']) > 0

    # Check result structure
    assert 'rule_based_score' in results
    assert 'ml_score' in results
    assert 'confidence' in results
    assert 'performance' in results


def test_scan_secure_test_file(real_scanner):
    """Integration test scanning the actual secure test file"""
    filepath = "test_files/secure.tf"
    if not Path(filepath).exists():
        pytest.skip("test_files/secure.tf not found")

    results = real_scanner.scan(filepath)

    # Should successfully scan
    assert results['score'] != -1

    # Should have low score (secure configuration)
    assert results['score'] <= 50

    # Check result structure
    assert 'rule_based_score' in results
    assert 'ml_score' in results
    assert 'confidence' in results


# ============================================================================
# TEST CACHE EVICTION AND EDGE CASES
# ============================================================================

@pytest.mark.unit
def test_scan_cache_hit_returns_from_cache_true(scanner_with_mocks, mock_scanner_components):
    """Scanning same file twice returns from_cache=True on second call."""
    scanner = scanner_with_mocks
    mock_parser = mock_scanner_components['parser']
    mock_rule_analyzer = mock_scanner_components['rule_analyzer']
    mock_ml_predictor = mock_scanner_components['ml_predictor']

    mock_parser.parse.return_value = ({}, "")
    mock_rule_analyzer.analyze.return_value = []
    mock_ml_predictor.predict_risk.return_value = (10.0, "LOW")

    with ExitStack() as stack:
        stack.enter_context(patch('pathlib.Path.exists', return_value=True))
        stack.enter_context(patch('pathlib.Path.is_file', return_value=True))
        mock_stat = stack.enter_context(patch('pathlib.Path.stat'))
        mock_stat.return_value.st_size = 50
        mock_stat.return_value.st_mtime = 1234567890.0
        stack.enter_context(patch('builtins.open', mock_open(read_data=b'resource "aws_instance" "x" {}')))
        result1 = scanner.scan("myfile.tf")
        result2 = scanner.scan("myfile.tf")

    assert result1['performance']['from_cache'] is False
    assert result2['performance']['from_cache'] is True


# ============================================================================
# TEST SECURITY RULE ENGINE - ADDITIONAL COVERAGE
# ============================================================================

@pytest.mark.unit
def test_detect_rdp_port_3389(rule_engine):
    """RDP port 3389 open to internet triggers CRITICAL vulnerability."""
    tf_content = {
        'resource': [{'aws_security_group': [{'rdp_sg': {'ingress': [
            {'from_port': 3389, 'to_port': 3389, 'protocol': 'tcp', 'cidr_blocks': ['0.0.0.0/0']}
        ]}}]}]
    }
    vulns = rule_engine.check_open_security_groups(tf_content)
    rdp_vulns = [v for v in vulns if 'RDP' in v.message]
    assert len(rdp_vulns) == 1
    assert rdp_vulns[0].severity == Severity.CRITICAL
    assert rdp_vulns[0].points == 30


@pytest.mark.unit
def test_detect_hardcoded_api_key(rule_engine):
    """api_key = 'AKIA...' triggers CRITICAL vulnerability."""
    raw_content = 'api_key = "AKIAIOSFODNN7EXAMPLE"'
    vulns = rule_engine.check_hardcoded_secrets(raw_content)
    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "API key" in vulns[0].message


