"""
Unit tests for main CLI entry point
"""
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import pytest
from terrasafe.cli import main


@pytest.mark.unit
class TestMainCLI:
    """Test suite for main CLI entry point"""

    def test_main_missing_arguments(self, capsys):
        """Test main with no arguments"""
        with patch.object(sys, 'argv', ['terrasafe']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert 'Usage:' in captured.out

    def test_main_too_many_arguments(self, capsys):
        """Test main with too many arguments"""
        with patch.object(sys, 'argv', ['terrasafe', 'file1.tf', 'file2.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    def test_main_successful_low_risk_scan(
        self, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main with successful low risk scan"""
        # Setup mocks
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': 20,
            'file': 'secure.tf',
            'rule_based_score': 15,
            'ml_score': 25.0,
            'confidence': 'HIGH',
            'vulnerabilities': []
        }
        mock_format.return_value = "Formatted output"

        # Mock Path
        mock_path_instance = Mock()
        mock_path_instance.stem = 'secure'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'secure.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0  # Low risk = exit 0

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    def test_main_high_risk_scan(
        self, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main with high risk scan"""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': 75,
            'file': 'vulnerable.tf',
            'rule_based_score': 70,
            'ml_score': 80.0,
            'confidence': 'HIGH',
            'vulnerabilities': [{'message': 'Issue', 'resource': 'aws_s3'}]
        }
        mock_format.return_value = "Formatted output"

        mock_path_instance = Mock()
        mock_path_instance.stem = 'vulnerable'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'vulnerable.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1  # High risk = exit 1

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    def test_main_critical_risk_scan(
        self, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main with critical risk scan"""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': 95,
            'file': 'critical.tf',
            'rule_based_score': 90,
            'ml_score': 100.0,
            'confidence': 'HIGH',
            'vulnerabilities': [
                {'message': 'Critical issue', 'resource': 'aws_db'}
            ]
        }
        mock_format.return_value = "Formatted output"

        mock_path_instance = Mock()
        mock_path_instance.stem = 'critical'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'critical.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 3  # Critical risk = exit 3

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    def test_main_scan_error(
        self, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main with scan error"""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': -1,
            'error': 'File not found',
            'file': 'missing.tf'
        }
        mock_format.return_value = "Error output"

        mock_path_instance = Mock()
        mock_path_instance.stem = 'missing'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'missing.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2  # Scan error = exit 2

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    @patch('terrasafe.cli.logger')
    def test_main_json_write_error(
        self, mock_logger, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main when JSON write fails"""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': 20,
            'file': 'test.tf',
            'rule_based_score': 15,
            'ml_score': 25.0,
            'confidence': 'HIGH',
            'vulnerabilities': []
        }
        mock_format.return_value = "Output"

        # Make file writing raise an exception
        mock_file.side_effect = IOError("Write failed")

        mock_path_instance = Mock()
        mock_path_instance.stem = 'test'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'test.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            # Should still exit successfully even if JSON write fails
            assert exc_info.value.code == 0
            # Should log the error
            mock_logger.error.assert_called()

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open, read_data='{"scans": []}')
    @patch('terrasafe.cli.Path')
    def test_main_appends_to_existing_history(
        self, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main appends to existing scan history"""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': 30,
            'file': 'test.tf',
            'rule_based_score': 25,
            'ml_score': 35.0,
            'confidence': 'MEDIUM',
            'vulnerabilities': []
        }
        mock_format.return_value = "Output"

        # Create mock path objects
        mock_scan_result_path = Mock()
        mock_scan_result_path.stem = 'test'

        mock_history_path = Mock()
        mock_history_path.exists.return_value = True

        # Make Path return different objects for different calls
        def path_side_effect(arg):
            if 'scan_results' in str(arg):
                return mock_scan_result_path
            else:
                return mock_history_path

        mock_path_class.side_effect = path_side_effect

        with patch.object(sys, 'argv', ['terrasafe', 'test.tf']):
            with pytest.raises(SystemExit):
                main()

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    def test_main_creates_new_history(
        self, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main creates new scan history if not exists"""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': 25,
            'file': 'test.tf',
            'rule_based_score': 20,
            'ml_score': 30.0,
            'confidence': 'HIGH',
            'vulnerabilities': []
        }
        mock_format.return_value = "Output"

        mock_path_instance = Mock()
        mock_path_instance.stem = 'test'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'test.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display')
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    def test_main_medium_risk_boundary(
        self, mock_path_class, mock_file, mock_format, mock_scanner_class, mock_predictor_class
    ):
        """Test main with medium risk at boundary (69)"""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': 69,
            'file': 'test.tf',
            'rule_based_score': 65,
            'ml_score': 73.0,
            'confidence': 'MEDIUM',
            'vulnerabilities': []
        }
        mock_format.return_value = "Output"

        mock_path_instance = Mock()
        mock_path_instance.stem = 'test'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'test.tf']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0  # Below 70 = exit 0
