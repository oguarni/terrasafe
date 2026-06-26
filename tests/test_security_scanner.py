"""Unit tests for ``IntelligentSecurityScanner`` error paths.

Happy-path scan behaviour is exercised end-to-end via the FastAPI client in
``test_api.py``; this module covers the failure branches that must short-circuit
the pipeline before rule analysis and ML prediction run.
"""
from unittest.mock import Mock

import pytest

from pydantic import ValidationError

from terravault.application.scanner import IntelligentSecurityScanner
from terravault.config.settings import Settings, get_settings
from terravault.domain.models import Severity, Vulnerability
from terravault.domain.security_rules import SecurityRuleEngine
from terravault.infrastructure.ml_model import MLPredictor
from terravault.infrastructure.parser import HCLParser


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


def test_default_weights_come_from_settings(scanner):
    """A scanner with no explicit weights inherits the configured defaults."""
    settings = get_settings()
    assert scanner.rule_weight == settings.rule_weight
    assert scanner.ml_weight == settings.ml_weight


def test_custom_weights_change_final_score(tmp_path, mock_rule_analyzer, mock_ml_predictor):
    """The hybrid score must honour per-scanner weight overrides."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "b" {\n  bucket = "demo"\n}\n')
    mock_rule_analyzer.analyze.return_value = [
        Vulnerability(
            severity=Severity.CRITICAL, points=30,
            message="m", resource="r", remediation="fix",
        )
    ]
    mock_ml_predictor.predict_risk.return_value = (80.0, "LOW")

    rules_only = IntelligentSecurityScanner(
        HCLParser(), mock_rule_analyzer, mock_ml_predictor,
        rule_weight=1.0, ml_weight=0.0,
    )
    hybrid = IntelligentSecurityScanner(
        HCLParser(), mock_rule_analyzer, mock_ml_predictor,
        rule_weight=0.6, ml_weight=0.4,
    )

    # rule_score = 30 (single critical), ml_score = 80 (mocked)
    assert rules_only.scan(str(tf_file))["score"] == 30
    assert hybrid.scan(str(tf_file))["score"] == int(0.6 * 30 + 0.4 * 80)


def test_settings_accept_valid_custom_weights():
    """Weights that sum to 1.0 are accepted."""
    settings = Settings(rule_weight=0.8, ml_weight=0.2)
    assert settings.rule_weight == 0.8
    assert settings.ml_weight == 0.2


def test_settings_reject_weights_not_summing_to_one():
    """Weights that do not sum to 1.0 are rejected at construction."""
    with pytest.raises(ValidationError):
        Settings(rule_weight=0.7, ml_weight=0.4)
