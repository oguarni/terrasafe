"""Unit tests for main CLI entry point — exit code contract."""
import sys
from unittest.mock import Mock, patch, mock_open
import pytest
from terrasafe.cli import main


@pytest.mark.unit
class TestMainCLI:
    def test_missing_arguments_exits_2(self, capsys):
        with patch.object(sys, 'argv', ['terrasafe']):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 2

    @pytest.mark.parametrize("score,expected_exit", [
        (20, 0),    # low risk
        (75, 1),    # high risk
        (95, 3),    # critical
        (-1, 2),    # scan error
    ])
    @patch('terrasafe.cli.MLPredictor')
    @patch('terrasafe.cli.IntelligentSecurityScanner')
    @patch('terrasafe.cli.format_results_for_display', return_value="output")
    @patch('builtins.open', new_callable=mock_open)
    @patch('terrasafe.cli.Path')
    def test_exit_code_matches_risk_level(
        self, mock_path_class, mock_file, mock_format,
        mock_scanner_class, mock_predictor_class,
        score, expected_exit,
    ):
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.return_value = {
            'score': score,
            'file': 'test.tf',
            'rule_based_score': score,
            'ml_score': float(max(score, 0)),
            'confidence': 'HIGH',
            'vulnerabilities': [],
            'error': 'not found' if score < 0 else None,
        }
        mock_path_instance = Mock()
        mock_path_instance.stem = 'test'
        mock_path_instance.exists.return_value = False
        mock_path_class.return_value = mock_path_instance

        with patch.object(sys, 'argv', ['terrasafe', 'test.tf']):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == expected_exit
