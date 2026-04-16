"""Unit tests for ``IntelligentSecurityScanner`` error paths.

Happy-path scan behaviour is exercised end-to-end via the FastAPI client in
``test_api.py``; this module covers the failure branches that must short-circuit
the pipeline before rule analysis and ML prediction run.
"""
from unittest.mock import Mock

import pytest

from terrasafe.application.scanner import IntelligentSecurityScanner
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.infrastructure.ml_model import MLPredictor
from terrasafe.infrastructure.parser import HCLParser


pytestmark = pytest.mark.unit


@pytest.fixture
def mock_rule_analyzer():
    return Mock(spec=SecurityRuleEngine)


@pytest.fixture
def mock_ml_predictor():
    return Mock(spec=MLPredictor)


@pytest.fixture
def scanner(mock_rule_analyzer, mock_ml_predictor):
    return IntelligentSecurityScanner(
        parser=HCLParser(),
        rule_analyzer=mock_rule_analyzer,
        ml_predictor=mock_ml_predictor,
    )


@pytest.mark.parametrize(
    "scenario, file_content, expected_error_fragment",
    [
        pytest.param(
            "parse_error",
            "this is { definitely not valid HCL",
            "Invalid HCL/JSON syntax",
            id="invalid_hcl_short_circuits_pipeline",
        ),
        pytest.param(
            "missing_file",
            None,
            "not found",
            id="missing_file_short_circuits_pipeline",
        ),
    ],
)
def test_scanner_returns_error_result_without_invoking_downstream_stages(
    tmp_path,
    scanner,
    mock_rule_analyzer,
    mock_ml_predictor,
    scenario,
    file_content,
    expected_error_fragment,
):
    if file_content is None:
        target = str(tmp_path / "nonexistent.tf")
    else:
        tf_file = tmp_path / "invalid.tf"
        tf_file.write_text(file_content)
        target = str(tf_file)

    results = scanner.scan(target)

    assert results["score"] == -1
    assert expected_error_fragment.lower() in results["error"].lower()
    mock_rule_analyzer.analyze.assert_not_called()
    mock_ml_predictor.predict_risk.assert_not_called()
