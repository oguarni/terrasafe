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
        """Test formatting of critical risk results"""
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
        assert '🚨 CRITICAL RISK' in output
        assert 'Final Risk Score: 95/100' in output
        assert 'Rule-based Score: 90/100' in output
        assert 'ML Anomaly Score: 100.0/100' in output
        assert 'Confidence: HIGH' in output
        assert 'Critical vulnerability' in output

    def test_format_low_risk_results(self):
        """Test formatting of low risk results"""
        results = {
            'score': 20,
            'file': 'secure.tf',
            'rule_based_score': 15,
            'ml_score': 25.0,
            'confidence': 'HIGH',
            'vulnerabilities': []
        }
        output = format_results_for_display(results)
        assert '✅ LOW RISK' in output
        assert 'Final Risk Score: 20/100' in output

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
        assert '✅ No security issues detected!' in output
        assert 'All resources properly configured' in output

    def test_format_multiple_vulnerabilities(self):
        """Test formatting with multiple vulnerabilities"""
        results = {
            'score': 80,
            'file': 'test.tf',
            'rule_based_score': 75,
            'ml_score': 85.0,
            'confidence': 'HIGH',
            'vulnerabilities': [
                {
                    'message': 'Hardcoded password detected',
                    'resource': 'aws_db_instance.example',
                    'remediation': 'Use AWS Secrets Manager'
                },
                {
                    'message': 'Public S3 bucket',
                    'resource': 'aws_s3_bucket.data',
                    'remediation': 'Restrict bucket access'
                }
            ]
        }
        output = format_results_for_display(results)
        assert '🚨 Detected Vulnerabilities:' in output
        assert 'Hardcoded password detected' in output
        assert 'Public S3 bucket' in output
        assert 'Use AWS Secrets Manager' in output
        assert 'Restrict bucket access' in output


