"""
Unit tests for CLI formatter module - Testing presentation layer
"""
import pytest
from terrasafe.cli_formatter import format_results_for_display


@pytest.mark.unit
class TestCLIFormatter:
    """Test suite for CLI formatter functions"""

    def test_format_error_results(self):
        """Test formatting of error results"""
        results = {
            'score': -1,
            'error': 'File not found',
            'file': 'test.tf'
        }
        output = format_results_for_display(results)
        assert '❌ Error scanning file: File not found' in output

    def test_format_critical_risk_results(self):
        """Test formatting of critical risk results includes key data points"""
        results = {
            'score': 95,
            'file': 'vulnerable.tf',
            'rule_based_score': 90,
            'ml_score': 100.0,
            'confidence': 'HIGH',
            'vulnerabilities': [
                {
                    'message': 'Critical vulnerability',
                    'resource': 'aws_s3_bucket.example',
                    'remediation': 'Enable encryption'
                }
            ]
        }
        output = format_results_for_display(results)
        # Verify risk tier classification
        assert 'CRITICAL RISK' in output
        # Verify all score components are present (content, not exact format)
        assert '95' in output
        assert '90' in output
        assert '100.0' in output
        assert 'HIGH' in output
        # Verify vulnerability details surface
        assert 'Critical vulnerability' in output
        assert 'aws_s3_bucket.example' in output

    def test_format_medium_risk_results(self):
        """Test formatting of medium risk range (boundary: 40 <= score < 70)"""
        results = {
            'score': 50,
            'file': 'mixed.tf',
            'rule_based_score': 40,
            'ml_score': 65.0,
            'confidence': 'MEDIUM',
            'vulnerabilities': [
                {
                    'message': 'Unencrypted storage',
                    'resource': 'aws_ebs_volume.data',
                    'remediation': 'Enable encryption'
                }
            ]
        }
        output = format_results_for_display(results)
        assert 'MEDIUM RISK' in output
        assert '50' in output
        assert 'Unencrypted storage' in output

    def test_format_no_vulnerabilities(self):
        """Test formatting when no vulnerabilities found"""
        results = {
            'score': 10,
            'file': 'secure.tf',
            'rule_based_score': 5,
            'ml_score': 15.0,
            'confidence': 'HIGH',
            'vulnerabilities': []
        }
        output = format_results_for_display(results)
        assert 'No security issues detected' in output
        assert 'properly configured' in output
