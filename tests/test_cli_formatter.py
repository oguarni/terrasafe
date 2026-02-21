"""
Unit tests for CLI formatter module - Testing presentation layer
"""
import pytest
from terrasafe.cli_formatter import (
    format_results_for_display,
    _determine_risk_status,
    _format_features,
    _format_performance,
    _format_vulnerabilities,
    _format_no_issues,
)


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

    def test_format_high_risk_results(self):
        """Test formatting of high risk results"""
        results = {
            'score': 75,
            'file': 'test.tf',
            'rule_based_score': 70,
            'ml_score': 80.0,
            'confidence': 'MEDIUM',
            'vulnerabilities': []
        }
        output = format_results_for_display(results)
        assert '❌ HIGH RISK' in output
        assert 'Final Risk Score: 75/100' in output

    def test_format_medium_risk_results(self):
        """Test formatting of medium risk results"""
        results = {
            'score': 50,
            'file': 'test.tf',
            'rule_based_score': 45,
            'ml_score': 55.0,
            'confidence': 'MEDIUM',
            'vulnerabilities': []
        }
        output = format_results_for_display(results)
        assert '⚠️  MEDIUM RISK' in output
        assert 'Final Risk Score: 50/100' in output

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

    def test_format_with_features(self):
        """Test formatting with feature analysis"""
        results = {
            'score': 50,
            'file': 'test.tf',
            'rule_based_score': 45,
            'ml_score': 55.0,
            'confidence': 'MEDIUM',
            'features_analyzed': {
                'open_ports': 2,
                'hardcoded_secrets': 1,
                'public_access': 0,
                'unencrypted_storage': 1
            },
            'vulnerabilities': []
        }
        output = format_results_for_display(results)
        assert '🔬 Feature Analysis:' in output
        assert 'Open Ports: 2' in output
        assert 'Hardcoded Secrets: 1' in output
        assert 'Public Access: 0' in output
        assert 'Unencrypted Storage: 1' in output

    def test_format_with_performance(self):
        """Test formatting with performance metrics"""
        results = {
            'score': 30,
            'file': 'test.tf',
            'rule_based_score': 25,
            'ml_score': 35.0,
            'confidence': 'HIGH',
            'performance': {
                'scan_time_seconds': 0.125,
                'file_size_kb': 2.5
            },
            'vulnerabilities': []
        }
        output = format_results_for_display(results)
        assert '⏱️  Performance:' in output
        assert 'Scan Time: 0.125s' in output
        assert 'File Size: 2.5 KB' in output

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


@pytest.mark.unit
class TestHelperFunctions:
    """Test suite for helper functions"""

    def test_determine_risk_status_critical(self):
        """Test critical risk status determination"""
        status, color = _determine_risk_status(95)
        assert status == "🚨 CRITICAL RISK"
        assert color == "\033[91m"

    def test_determine_risk_status_high(self):
        """Test high risk status determination"""
        status, color = _determine_risk_status(75)
        assert status == "❌ HIGH RISK"
        assert color == "\033[91m"

    def test_determine_risk_status_medium(self):
        """Test medium risk status determination"""
        status, color = _determine_risk_status(50)
        assert status == "⚠️  MEDIUM RISK"
        assert color == "\033[93m"

    def test_determine_risk_status_low(self):
        """Test low risk status determination"""
        status, color = _determine_risk_status(25)
        assert status == "✅ LOW RISK"
        assert color == "\033[92m"

    def test_determine_risk_status_boundary_90(self):
        """Test boundary case at score 90"""
        status, color = _determine_risk_status(90)
        assert status == "🚨 CRITICAL RISK"

    def test_determine_risk_status_boundary_70(self):
        """Test boundary case at score 70"""
        status, color = _determine_risk_status(70)
        assert status == "❌ HIGH RISK"

    def test_determine_risk_status_boundary_40(self):
        """Test boundary case at score 40"""
        status, color = _determine_risk_status(40)
        assert status == "⚠️  MEDIUM RISK"

    def test_format_features_helper(self):
        """Test feature formatting helper"""
        features = {
            'open_ports': 3,
            'hardcoded_secrets': 2,
            'public_access': 1,
            'unencrypted_storage': 0
        }
        output = _format_features(features)
        assert any('Open Ports: 3' in line for line in output)
        assert any('Hardcoded Secrets: 2' in line for line in output)

    def test_format_performance_helper(self):
        """Test performance formatting helper"""
        perf = {
            'scan_time_seconds': 1.5,
            'file_size_kb': 10.2
        }
        output = _format_performance(perf)
        assert any('Scan Time: 1.5s' in line for line in output)
        assert any('File Size: 10.2 KB' in line for line in output)

    def test_format_vulnerabilities_with_remediation(self):
        """Test vulnerability formatting with remediation"""
        vulns = [
            {
                'message': 'Security issue',
                'resource': 'aws_instance.web',
                'remediation': 'Apply fix'
            }
        ]
        output = _format_vulnerabilities(vulns)
        assert any('Security issue' in line for line in output)
        assert any('aws_instance.web' in line for line in output)
        assert any('Apply fix' in line for line in output)

    def test_format_vulnerabilities_without_remediation(self):
        """Test vulnerability formatting without remediation"""
        vulns = [
            {
                'message': 'Security issue',
                'resource': 'aws_instance.web'
            }
        ]
        output = _format_vulnerabilities(vulns)
        assert any('Security issue' in line for line in output)
        # Should not crash when remediation is missing

    def test_format_no_issues_helper(self):
        """Test no issues formatting helper"""
        output = _format_no_issues()
        assert any('No security issues detected' in line for line in output)
        assert any('All resources properly configured' in line for line in output)
