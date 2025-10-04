#!/usr/bin/env python3
"""
Unit tests for TerraSafe security scanner
Tests individual components and integration

Test Structure:
- TestSecurityRuleEngine: Tests rule-based vulnerability detection (5 tests)
- TestIntelligentSecurityScanner: Unit tests with mocked dependencies (10 tests)
- TestIntelligentSecurityScannerIntegration: Integration tests with real components (3 tests)
- TestModelManager: Tests ML model persistence (2 tests)
- TestVulnerabilityDataclass: Tests data structures (2 tests)
- TestHCLParser: Tests Terraform file parsing (2 tests)
- TestMLPredictor: Tests ML prediction functionality (2 tests)

Total: 25+ comprehensive tests covering all major components
"""

import unittest
import numpy as np
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

# Clean Architecture imports - SOLID compliant
from terrasafe.domain.models import Vulnerability, Severity
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.infrastructure.parser import HCLParser, TerraformParseError
from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor, ModelNotTrainedError
from terrasafe.application.scanner import IntelligentSecurityScanner


class TestSecurityRuleEngine(unittest.TestCase):
    """Test the rule-based detection engine"""
    
    def setUp(self):
        self.engine = SecurityRuleEngine()
    
    def test_detect_open_ssh_port(self):
        """Test detection of open SSH port to internet"""
        tf_content = {
            'resource': [{'aws_security_group': [{'test_sg': {'ingress': [{'from_port': 22, 'to_port': 22, 'protocol': 'tcp', 'cidr_blocks': ['0.0.0.0/0']}]}}]}]
        }
        vulnerabilities = self.engine.analyze(tf_content, "")
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.CRITICAL)
        self.assertIn('SSH', vulnerabilities[0].message.upper())

    def test_detect_hardcoded_password(self):
        """Test detection of hardcoded passwords"""
        raw_content = 'resource "aws_db_instance" "test" { password = "hardcoded123" }'
        vulnerabilities = self.engine.analyze({}, raw_content)
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.CRITICAL)
        
    def test_detect_unencrypted_rds(self):
        """Test detection of unencrypted RDS instances"""
        tf_content = {
            'resource': [{'aws_db_instance': [{'test_db': {'engine': 'mysql', 'storage_encrypted': False}}]}]
        }
        vulnerabilities = self.engine.analyze(tf_content, "")
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.HIGH)
        self.assertIn('unencrypted', vulnerabilities[0].message.lower())
        
    def test_detect_public_s3_bucket(self):
        """Test detection of public S3 buckets"""
        tf_content = {
            'resource': [{'aws_s3_bucket_public_access_block': [{'test_bucket': {
                'block_public_acls': False,
                'block_public_policy': False,
                'ignore_public_acls': False,
                'restrict_public_buckets': False
            }}]}]
        }
        vulnerabilities = self.engine.analyze(tf_content, "")
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0].severity, Severity.HIGH)
        
    def test_no_vulnerabilities_secure_config(self):
        """Test that secure configurations don't trigger false positives"""
        tf_content = {
            'resource': [{'aws_db_instance': [{'secure_db': {'engine': 'mysql', 'storage_encrypted': True}}]}]
        }
        vulnerabilities = self.engine.analyze(tf_content, "")
        self.assertEqual(len(vulnerabilities), 0)


class TestIntelligentSecurityScanner(unittest.TestCase):
    """Test scanner with proper mocking"""
    
    def setUp(self):
        # Mock all dependencies
        self.mock_parser = Mock()
        self.mock_rule_analyzer = Mock()
        self.mock_ml_predictor = Mock()
        
        self.scanner = IntelligentSecurityScanner(
            parser=self.mock_parser,
            rule_analyzer=self.mock_rule_analyzer,
            ml_predictor=self.mock_ml_predictor
        )
    
    def test_scan_successful(self):
        """Test successful scan with mocked components"""
        # Arrange
        test_file = "test.tf"
        tf_content = {"resource": []}
        raw_content = "resource {}"
        
        self.mock_parser.parse.return_value = (tf_content, raw_content)
        
        vulnerabilities = [
            Vulnerability(Severity.HIGH, 20, "Test vuln", "resource1")
        ]
        self.mock_rule_analyzer.analyze.return_value = vulnerabilities
        
        self.mock_ml_predictor.predict_risk.return_value = (45.5, "MEDIUM")
        
        # Act
        with patch('pathlib.Path.stat') as mock_stat:
            mock_stat.return_value.st_size = 1024
            results = self.scanner.scan(test_file)
        
        # Assert
        self.assertEqual(results['file'], test_file)
        self.assertEqual(results['rule_based_score'], 20)
        self.assertEqual(results['ml_score'], 45.5)
        self.assertEqual(results['confidence'], "MEDIUM")
        self.assertEqual(results['score'], 30)  # 0.6 * 20 + 0.4 * 45.5 = 30.2 → 30
        
        # Verify mocks were called
        self.mock_parser.parse.assert_called_once_with(test_file)
        self.mock_rule_analyzer.analyze.assert_called_once_with(tf_content, raw_content)
        self.mock_ml_predictor.predict_risk.assert_called_once()
    
    def test_scan_parse_error(self):
        """Test scan handling parse errors"""
        # Arrange
        test_file = "invalid.tf"
        self.mock_parser.parse.side_effect = TerraformParseError("Invalid syntax")
        
        # Act
        results = self.scanner.scan(test_file)
        
        # Assert
        self.assertEqual(results['score'], -1)
        self.assertIn('error', results)
        self.assertIn('Invalid syntax', results['error'])
        
        # Verify rule analyzer and ML predictor were not called
        self.mock_rule_analyzer.analyze.assert_not_called()
        self.mock_ml_predictor.predict_risk.assert_not_called()
    
    def test_scan_file_not_found_error(self):
        """Test scan handling file not found errors"""
        # Arrange
        test_file = "nonexistent.tf"
        self.mock_parser.parse.side_effect = TerraformParseError("File not found: nonexistent.tf")
        
        # Act
        results = self.scanner.scan(test_file)
        
        # Assert
        self.assertEqual(results['score'], -1)
        self.assertIn('error', results)
        self.assertIn('File not found', results['error'])
    
    def test_scan_unexpected_error(self):
        """Test scan handling unexpected errors"""
        # Arrange
        test_file = "test.tf"
        self.mock_parser.parse.side_effect = Exception("Unexpected error")
        
        # Act
        results = self.scanner.scan(test_file)
        
        # Assert
        self.assertEqual(results['score'], -1)
        self.assertIn('error', results)
        self.assertIn('An unexpected error occurred', results['error'])
    
    def test_feature_extraction(self):
        """Test feature extraction isolation"""
        vulnerabilities = [
            Vulnerability(Severity.CRITICAL, 30, "Open security group - SSH port 22 exposed to internet", "sg1"),
            Vulnerability(Severity.CRITICAL, 30, "Hardcoded password detected", "db1"),
            Vulnerability(Severity.HIGH, 20, "S3 bucket with public access enabled", "bucket1"),
            Vulnerability(Severity.HIGH, 20, "Unencrypted RDS instance", "db2")
        ]
        
        features = self.scanner._extract_features(vulnerabilities)
        
        # Expected: [1 open_port, 1 secret, 1 public_access, 1 unencrypted, 5 resources]
        expected = np.array([[1, 1, 1, 1, 5]])
        np.testing.assert_array_equal(features, expected)
        
    def test_vulnerability_summarization(self):
        """Test vulnerability severity summarization"""
        vulnerabilities = [
            Vulnerability(Severity.CRITICAL, 30, "Critical issue", "resource1"),
            Vulnerability(Severity.CRITICAL, 30, "Another critical", "resource2"),
            Vulnerability(Severity.HIGH, 20, "High issue", "resource3"),
            Vulnerability(Severity.MEDIUM, 10, "Medium issue", "resource4")
        ]
        
        summary = self.scanner._summarize_vulns(vulnerabilities)
        
        self.assertEqual(summary['critical'], 2)
        self.assertEqual(summary['high'], 1)
        self.assertEqual(summary['medium'], 1)
        self.assertEqual(summary['low'], 0)
        
    def test_vulnerability_to_dict(self):
        """Test converting vulnerability to dictionary"""
        vuln = Vulnerability(Severity.HIGH, 20, "Test vulnerability", "test_resource", "Fix this")
        vuln_dict = self.scanner._vulnerability_to_dict(vuln)
        
        expected = {
            'severity': 'HIGH',
            'points': 20,
            'message': 'Test vulnerability',
            'resource': 'test_resource',
            'remediation': 'Fix this'
        }
        
        self.assertEqual(vuln_dict, expected)
            
    def test_format_features(self):
        """Test feature formatting"""
        features = np.array([[2, 1, 0, 3, 10]])
        formatted = self.scanner._format_features(features)
        
        expected = {
            'open_ports': 2,
            'hardcoded_secrets': 1,
            'public_access': 0,
            'unencrypted_storage': 3,
            'total_resources': 10
        }
        
        self.assertEqual(formatted, expected)
    
    def test_complex_scan_scenario(self):
        """Test complex scan with multiple vulnerabilities"""
        # Arrange
        test_file = "complex.tf"
        tf_content = {"resource": [{"aws_security_group": []}]}
        raw_content = "complex terraform content"
        
        self.mock_parser.parse.return_value = (tf_content, raw_content)
        
        vulnerabilities = [
            Vulnerability(Severity.CRITICAL, 30, "Critical SSH issue", "sg1"),
            Vulnerability(Severity.HIGH, 20, "High RDS issue", "db1"),
            Vulnerability(Severity.MEDIUM, 10, "Medium S3 issue", "s3")
        ]
        self.mock_rule_analyzer.analyze.return_value = vulnerabilities
        
        self.mock_ml_predictor.predict_risk.return_value = (75.0, "HIGH")
        
        # Act
        with patch('pathlib.Path.stat') as mock_stat:
            mock_stat.return_value.st_size = 2048
            results = self.scanner.scan(test_file)
        
        # Assert
        self.assertEqual(results['file'], test_file)
        self.assertEqual(results['rule_based_score'], 60)  # 30 + 20 + 10
        self.assertEqual(results['ml_score'], 75.0)
        self.assertEqual(results['confidence'], "HIGH")
        self.assertEqual(results['score'], 66)  # 0.6 * 60 + 0.4 * 75 = 66
        self.assertEqual(len(results['vulnerabilities']), 3)
        self.assertIn('performance', results)
        self.assertIn('scan_time_seconds', results['performance'])
        self.assertIn('file_size_kb', results['performance'])


class TestIntelligentSecurityScannerIntegration(unittest.TestCase):
    """Integration tests using real components"""
    
    def setUp(self):
        # Create real components for integration testing
        self.parser = HCLParser()
        self.rule_analyzer = SecurityRuleEngine()
        self.ml_predictor = MLPredictor()
        
        self.scanner = IntelligentSecurityScanner(
            parser=self.parser,
            rule_analyzer=self.rule_analyzer,
            ml_predictor=self.ml_predictor
        )
    
    def test_scan_vulnerable_test_file(self):
        """Integration test scanning the actual vulnerable test file"""
        filepath = "test_files/vulnerable.tf"
        if Path(filepath).exists():
            results = self.scanner.scan(filepath)
            
            # Should successfully scan
            self.assertNotEqual(results['score'], -1)
            
            # Should find vulnerabilities (vulnerable file should have high score)
            self.assertGreater(results['score'], 30)
            self.assertGreater(len(results['vulnerabilities']), 0)
            
            # Check result structure
            self.assertIn('rule_based_score', results)
            self.assertIn('ml_score', results)
            self.assertIn('confidence', results)
            self.assertIn('performance', results)
            
    def test_scan_secure_test_file(self):
        """Integration test scanning the actual secure test file"""
        filepath = "test_files/secure.tf"
        if Path(filepath).exists():
            results = self.scanner.scan(filepath)
            
            # Should successfully scan
            self.assertNotEqual(results['score'], -1)
            
            # Should have low score (secure configuration)
            self.assertLessEqual(results['score'], 50)
            
            # Check result structure
            self.assertIn('rule_based_score', results)
            self.assertIn('ml_score', results)
            self.assertIn('confidence', results)
    
    def test_scan_mixed_test_file(self):
        """Integration test scanning mixed security configuration"""
        filepath = "test_files/mixed.tf"
        if Path(filepath).exists():
            results = self.scanner.scan(filepath)
            
            # Should successfully scan
            self.assertNotEqual(results['score'], -1)
            
            # Mixed file should have moderate score
            self.assertGreater(results['score'], 20)
            self.assertLess(results['score'], 80)
            
            # Check result structure
            self.assertIn('rule_based_score', results)
            self.assertIn('ml_score', results)
            self.assertIn('confidence', results)


class TestModelManager(unittest.TestCase):
    """Test ML model persistence and loading"""
    
    def setUp(self):
        # Use a temporary directory for testing
        self.temp_dir = tempfile.mkdtemp()
        self.manager = ModelManager(self.temp_dir)
    
    def tearDown(self):
        # Clean up temporary files
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_model_exists_false_initially(self):
        """Test that model_exists returns False when no model is saved"""
        self.assertFalse(self.manager.model_exists())
    
    def test_save_and_load_model(self):
        """Test saving and loading a model"""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        # Create dummy model and scaler
        model = IsolationForest(random_state=42)
        scaler = StandardScaler()
        metadata = {'test': 'data'}
        
        # Fit with dummy data
        dummy_data = np.array([[1, 2, 3], [4, 5, 6]])
        scaler.fit(dummy_data)
        model.fit(scaler.transform(dummy_data))
        
        # Save
        self.manager.save_model(model, scaler, metadata)
        self.assertTrue(self.manager.model_exists())
        
        # Load
        loaded_model, loaded_scaler = self.manager.load_model()
        
        # Test that loaded objects work
        test_data = np.array([[2, 3, 4]])
        scaled_test = loaded_scaler.transform(test_data)
        prediction = loaded_model.predict(scaled_test)
        
        self.assertEqual(len(prediction), 1)


class TestVulnerabilityDataclass(unittest.TestCase):
    """Test the Vulnerability dataclass"""
    
    def test_vulnerability_creation(self):
        """Test creating a vulnerability"""
        vuln = Vulnerability(
            severity=Severity.HIGH,
            points=20,
            message="Test vulnerability",
            resource="test_resource",
            remediation="Fix this"
        )
        
        self.assertEqual(vuln.severity, Severity.HIGH)
        self.assertEqual(vuln.points, 20)
        self.assertEqual(vuln.message, "Test vulnerability")
        self.assertEqual(vuln.resource, "test_resource")
        self.assertEqual(vuln.remediation, "Fix this")
    
    def test_vulnerability_default_remediation(self):
        """Test vulnerability with default empty remediation"""
        vuln = Vulnerability(
            severity=Severity.LOW,
            points=5,
            message="Minor issue",
            resource="resource1"
        )
        
        self.assertEqual(vuln.remediation, "")


class TestHCLParser(unittest.TestCase):
    """Test HCL parsing functionality"""
    
    def setUp(self):
        self.parser = HCLParser()
    
    def test_parse_nonexistent_file(self):
        """Test parsing a non-existent file raises error"""
        with self.assertRaises(TerraformParseError):
            self.parser.parse("nonexistent.tf")
    
    def test_parse_existing_file(self):
        """Test parsing an existing terraform file"""
        filepath = "test_files/secure.tf"
        if Path(filepath).exists():
            tf_content, raw_content = self.parser.parse(filepath)
            
            self.assertIsInstance(tf_content, dict)
            self.assertIsInstance(raw_content, str)
            self.assertGreater(len(raw_content), 0)


class TestMLPredictor(unittest.TestCase):
    """Test ML prediction functionality"""
    
    def setUp(self):
        self.predictor = MLPredictor()
    
    def test_predict_risk_with_features(self):
        """Test risk prediction with feature array"""
        # Test with different feature patterns
        low_risk_features = np.array([[0, 0, 0, 0, 5]])
        high_risk_features = np.array([[3, 2, 2, 3, 20]])
        
        low_score, low_conf = self.predictor.predict_risk(low_risk_features)
        high_score, high_conf = self.predictor.predict_risk(high_risk_features)
        
        # Scores should be in valid range
        self.assertGreaterEqual(low_score, 0)
        self.assertLessEqual(low_score, 100)
        self.assertGreaterEqual(high_score, 0)
        self.assertLessEqual(high_score, 100)
        
        # Confidence should be valid
        self.assertIn(low_conf, ["HIGH", "MEDIUM", "LOW"])
        self.assertIn(high_conf, ["HIGH", "MEDIUM", "LOW"])
    
    def test_predict_risk_edge_cases(self):
        """Test risk prediction with edge case inputs"""
        # Empty features
        empty_features = np.array([[0, 0, 0, 0, 0]])
        score, confidence = self.predictor.predict_risk(empty_features)
        
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertIn(confidence, ["HIGH", "MEDIUM", "LOW"])


if __name__ == '__main__':
    unittest.main()