"""Tests for SARIF 2.1.0 output formatter."""
import json

import pytest

from terravault.sarif_formatter import results_to_sarif


pytestmark = pytest.mark.unit


def _sarif_of(*file_results) -> dict:
    return json.loads(results_to_sarif(list(file_results)))


def test_empty_results_still_emit_schema_compliant_envelope():
    sarif = _sarif_of()

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1


def test_parse_error_results_do_not_produce_sarif_findings():
    error_result = {"score": -1, "error": "Parse error", "file": "bad.tf"}

    sarif = _sarif_of(error_result)

    assert sarif["runs"][0]["results"] == []


def test_single_vulnerability_emits_one_rule_and_one_result(vuln_samples):
    file_result = {"score": 50, "file": "main.tf", "vulnerabilities": [vuln_samples["high"]]}

    run = _sarif_of(file_result)["runs"][0]

    assert len(run["results"]) == 1
    assert len(run["tool"]["driver"]["rules"]) == 1


@pytest.mark.parametrize(
    "severity_key, expected_level",
    [
        pytest.param("critical", "error", id="critical_maps_to_error"),
    ],
)
def test_severity_maps_to_sarif_level(vuln_samples, severity_key, expected_level):
    file_result = {"score": 90, "file": "a.tf", "vulnerabilities": [vuln_samples[severity_key]]}

    result_entry = _sarif_of(file_result)["runs"][0]["results"][0]

    assert result_entry["level"] == expected_level


def test_same_vulnerability_across_files_deduplicates_rule_but_keeps_results(vuln_samples):
    r1 = {"score": 50, "file": "a.tf", "vulnerabilities": [vuln_samples["high"]]}
    r2 = {"score": 50, "file": "b.tf", "vulnerabilities": [vuln_samples["high"]]}

    run = _sarif_of(r1, r2)["runs"][0]

    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
