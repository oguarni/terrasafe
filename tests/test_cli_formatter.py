"""Unit tests for the CLI presentation layer."""
import pytest

from terravault.cli_formatter import format_results_for_display


pytestmark = pytest.mark.unit


def test_error_result_surfaces_error_message():
    result = {"score": -1, "error": "File not found", "file": "test.tf"}

    output = format_results_for_display(result)

    assert "Error scanning file" in output
    assert "File not found" in output


@pytest.mark.parametrize(
    "score, rule_score, ml_score, confidence, vulnerabilities, expected_tier, extra_markers",
    [
        pytest.param(
            95, 90, 100.0, "HIGH",
            [{
                "message": "Critical vulnerability",
                "resource": "aws_s3_bucket.example",
                "remediation": "Enable encryption",
            }],
            "CRITICAL RISK",
            ["95", "90", "100.0", "HIGH", "Critical vulnerability", "aws_s3_bucket.example"],
            id="critical_tier",
        ),
        pytest.param(
            50, 40, 65.0, "MEDIUM",
            [{
                "message": "Unencrypted storage",
                "resource": "aws_ebs_volume.data",
                "remediation": "Enable encryption",
            }],
            "MEDIUM RISK",
            ["50", "Unencrypted storage"],
            id="medium_tier",
        ),
    ],
)
def test_formatter_renders_risk_tier_and_key_fields(
    score, rule_score, ml_score, confidence, vulnerabilities, expected_tier, extra_markers
):
    result = {
        "score": score,
        "file": "sample.tf",
        "rule_based_score": rule_score,
        "ml_score": ml_score,
        "confidence": confidence,
        "vulnerabilities": vulnerabilities,
    }

    output = format_results_for_display(result)

    assert expected_tier in output
    for marker in extra_markers:
        assert marker in output


def test_formatter_reports_clean_config_when_no_vulnerabilities():
    result = {
        "score": 10,
        "file": "secure.tf",
        "rule_based_score": 5,
        "ml_score": 15.0,
        "confidence": "HIGH",
        "vulnerabilities": [],
    }

    output = format_results_for_display(result)

    assert "No security issues detected" in output
    assert "properly configured" in output
