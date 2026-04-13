#!/usr/bin/env python3
"""
Unit tests for IntelligentSecurityScanner error handling.

Integration-level scan tests (vulnerable.tf → high score, secure.tf → low score)
live in test_api.py where they exercise the full HTTP pipeline.
"""

import pytest
from unittest.mock import Mock

from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.infrastructure.parser import HCLParser, TerraformParseError
from terrasafe.infrastructure.ml_model import MLPredictor
from terrasafe.application.scanner import IntelligentSecurityScanner


# ============================================================================
# SCANNER ERROR-PATH UNIT TESTS
# ============================================================================


def test_scan_parse_error(tmp_path):
    """Scanner returns score=-1 and skips ML when the parser raises TerraformParseError."""
    invalid_file = tmp_path / "invalid.tf"
    invalid_file.write_text("this is { definitely not valid HCL")

    mock_rule_analyzer = Mock(spec=SecurityRuleEngine)
    mock_ml_predictor = Mock(spec=MLPredictor)

    scanner = IntelligentSecurityScanner(
        parser=HCLParser(),
        rule_analyzer=mock_rule_analyzer,
        ml_predictor=mock_ml_predictor,
    )

    results = scanner.scan(str(invalid_file))

    assert results["score"] == -1
    assert "error" in results
    assert "Invalid HCL/JSON syntax" in results["error"]
    mock_rule_analyzer.analyze.assert_not_called()
    mock_ml_predictor.predict_risk.assert_not_called()


def test_scan_file_not_found_error(tmp_path):
    """Scanner returns score=-1 with a descriptive error for missing files."""
    missing_file = str(tmp_path / "nonexistent.tf")

    scanner = IntelligentSecurityScanner(
        parser=HCLParser(),
        rule_analyzer=Mock(spec=SecurityRuleEngine),
        ml_predictor=Mock(spec=MLPredictor),
    )

    results = scanner.scan(missing_file)

    assert results["score"] == -1
    assert "error" in results
    assert "not found" in results["error"].lower() or "File not found" in results["error"]
