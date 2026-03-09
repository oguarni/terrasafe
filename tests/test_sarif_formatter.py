"""Tests for SARIF 2.1.0 formatter."""
import json
import pytest

from terrasafe.sarif_formatter import results_to_sarif


VULN_HIGH = {
    "severity": "HIGH",
    "points": 20,
    "message": "Hardcoded password detected",
    "resource": "aws_db_instance.main",
    "remediation": "Use AWS Secrets Manager instead.",
}
VULN_CRITICAL = {
    "severity": "CRITICAL",
    "points": 30,
    "message": "Open security group on port 22",
    "resource": "aws_security_group.web",
    "remediation": "Restrict SSH access to known IP ranges.",
}
VULN_MEDIUM = {
    "severity": "MEDIUM",
    "points": 10,
    "message": "S3 bucket allows public read",
    "resource": "aws_s3_bucket.data",
    "remediation": "Set acl to private.",
}


@pytest.mark.unit
class TestSarifSchema:
    def test_top_level_structure(self):
        sarif = json.loads(results_to_sarif([]))
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_tool_driver_present(self):
        sarif = json.loads(results_to_sarif([]))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "TerraSafe"
        assert "version" in driver
        assert "rules" in driver

    def test_empty_results(self):
        sarif = json.loads(results_to_sarif([]))
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_error_result_skipped(self):
        error_result = {"score": -1, "error": "Parse error", "file": "bad.tf"}
        sarif = json.loads(results_to_sarif([error_result]))
        assert sarif["runs"][0]["results"] == []

    def test_single_file_single_vuln(self):
        file_result = {
            "score": 50,
            "file": "main.tf",
            "vulnerabilities": [VULN_HIGH],
        }
        sarif = json.loads(results_to_sarif([file_result]))
        run = sarif["runs"][0]
        assert len(run["results"]) == 1
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_severity_mapping_critical(self):
        file_result = {"score": 90, "file": "a.tf", "vulnerabilities": [VULN_CRITICAL]}
        sarif = json.loads(results_to_sarif([file_result]))
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_severity_mapping_high(self):
        file_result = {"score": 70, "file": "a.tf", "vulnerabilities": [VULN_HIGH]}
        sarif = json.loads(results_to_sarif([file_result]))
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_severity_mapping_medium(self):
        file_result = {"score": 40, "file": "a.tf", "vulnerabilities": [VULN_MEDIUM]}
        sarif = json.loads(results_to_sarif([file_result]))
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_severity_mapping_low(self):
        vuln_low = {**VULN_MEDIUM, "severity": "LOW"}
        file_result = {"score": 10, "file": "a.tf", "vulnerabilities": [vuln_low]}
        sarif = json.loads(results_to_sarif([file_result]))
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_severity_mapping_info(self):
        vuln_info = {**VULN_MEDIUM, "severity": "INFO"}
        file_result = {"score": 5, "file": "a.tf", "vulnerabilities": [vuln_info]}
        sarif = json.loads(results_to_sarif([file_result]))
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_rule_deduplication(self):
        """Same message on two files should produce one rule, two results."""
        r1 = {"score": 50, "file": "a.tf", "vulnerabilities": [VULN_HIGH]}
        r2 = {"score": 50, "file": "b.tf", "vulnerabilities": [VULN_HIGH]}
        sarif = json.loads(results_to_sarif([r1, r2]))
        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 2

    def test_multiple_vulns_multiple_rules(self):
        file_result = {
            "score": 80,
            "file": "main.tf",
            "vulnerabilities": [VULN_CRITICAL, VULN_HIGH, VULN_MEDIUM],
        }
        sarif = json.loads(results_to_sarif([file_result]))
        run = sarif["runs"][0]
        assert len(run["results"]) == 3
        assert len(run["tool"]["driver"]["rules"]) == 3

    def test_artifact_location_present(self):
        file_result = {"score": 50, "file": "modules/main.tf", "vulnerabilities": [VULN_HIGH]}
        sarif = json.loads(results_to_sarif([file_result]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "modules/main.tf"

    def test_result_includes_rule_id(self):
        file_result = {"score": 50, "file": "a.tf", "vulnerabilities": [VULN_HIGH]}
        sarif = json.loads(results_to_sarif([file_result]))
        result = sarif["runs"][0]["results"][0]
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert result["ruleId"] == rule["id"]

    def test_output_is_valid_json(self):
        file_result = {"score": 50, "file": "a.tf", "vulnerabilities": [VULN_HIGH]}
        raw = results_to_sarif([file_result])
        # Must not raise
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)
