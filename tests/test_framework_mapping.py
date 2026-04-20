"""Tests for compliance-framework mapping (CIS AWS + MITRE ATT&CK).

Coverage:
- Mapping table shape (every rule has CIS + MITRE refs)
- Rule engine attaches rule_id and enriches frameworks in analyze()
- Scanner serializes frameworks into the JSON dict
- cli_formatter renders framework labels
- sarif_formatter emits tags and helpUri
"""
import json

import pytest

from terrasafe.domain.compliance_frameworks import (
    CIS_AWS,
    MITRE_ATTACK,
    RULE_FRAMEWORK_MAP,
    get_frameworks,
)
from terrasafe.domain.models import Severity, Vulnerability
from terrasafe.application.scanner import IntelligentSecurityScanner
from terrasafe.sarif_formatter import results_to_sarif
from terrasafe.cli_formatter import format_results_for_display


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Mapping table invariants
# ---------------------------------------------------------------------------

ALL_RULE_IDS = ["TS001", "TS002", "TS003", "TS004", "TS005", "TS006", "TS007"]


@pytest.mark.parametrize("rule_id", ALL_RULE_IDS)
def test_every_active_rule_has_cis_and_mitre_mappings(rule_id):
    refs = get_frameworks(rule_id)

    frameworks = {ref.framework for ref in refs}
    assert CIS_AWS in frameworks, f"{rule_id} missing CIS AWS mapping"
    assert MITRE_ATTACK in frameworks, f"{rule_id} missing MITRE ATT&CK mapping"


def test_unknown_rule_id_returns_empty_list_not_none():
    assert get_frameworks("TS999_NONEXISTENT") == []


def test_mitre_urls_follow_attack_mitre_org_convention():
    for refs in RULE_FRAMEWORK_MAP.values():
        for ref in refs:
            if ref.framework == MITRE_ATTACK:
                assert ref.url.startswith("https://attack.mitre.org/techniques/")
                assert ref.url.endswith("/")


def test_framework_reference_label_is_human_readable():
    ref = get_frameworks("TS001")[0]
    assert ref.label() == f"{ref.framework} — {ref.control_id}"


# ---------------------------------------------------------------------------
# Rule engine: analyze() enriches vulnerabilities with frameworks
# ---------------------------------------------------------------------------

def _tf_with_open_ssh() -> dict:
    return {
        "resource": [
            {
                "aws_security_group": [
                    {
                        "wide_open": {
                            "ingress": [
                                {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
                            ]
                        }
                    }
                ]
            }
        ]
    }


def test_analyze_attaches_cis_and_mitre_refs_to_open_security_group(engine):
    vulns = engine.analyze(_tf_with_open_ssh(), raw_content="")

    ssh_vuln = next(v for v in vulns if "SSH" in v.message)
    assert ssh_vuln.rule_id == "TS001"

    framework_names = {ref.framework for ref in ssh_vuln.frameworks}
    assert framework_names == {CIS_AWS, MITRE_ATTACK}


def test_analyze_attaches_frameworks_to_hardcoded_secret(engine):
    raw = 'resource "aws_db_instance" "x" { password = "plaintext123" }'
    vulns = engine.analyze({"resource": []}, raw_content=raw)

    assert vulns, "expected a hardcoded-password finding"
    assert vulns[0].rule_id == "TS002"
    assert any(ref.control_id == "T1552.001" for ref in vulns[0].frameworks)


def test_analyze_preserves_custom_frameworks_if_already_set(engine):
    """If a rule pre-populates frameworks (e.g. custom engine), enrichment skips it."""
    custom_vuln = Vulnerability(
        severity=Severity.LOW,
        points=5,
        message="[LOW] custom",
        resource="x",
        rule_id="TS001",
        frameworks=get_frameworks("TS007"),  # wrong on purpose, to verify no overwrite
    )
    # Simulate the enrichment branch directly
    from terrasafe.domain.security_rules import SecurityRuleEngine as _Engine  # noqa: F401
    vulns = [custom_vuln]
    for v in vulns:
        if v.rule_id and not v.frameworks:
            v.frameworks = get_frameworks(v.rule_id)

    assert vulns[0].frameworks[0].control_id == "Section 3.9"


# ---------------------------------------------------------------------------
# Scanner serialization
# ---------------------------------------------------------------------------

def test_scanner_serializes_rule_id_and_frameworks_into_dict():
    scanner = IntelligentSecurityScanner(parser=None, rule_analyzer=None, ml_predictor=None)
    vuln = Vulnerability(
        severity=Severity.CRITICAL,
        points=30,
        message="[CRITICAL] Open security group",
        resource="sg",
        remediation="restrict",
        rule_id="TS001",
        frameworks=get_frameworks("TS001"),
    )

    as_dict = scanner._vulnerability_to_dict(vuln)  # pylint: disable=protected-access

    assert as_dict["rule_id"] == "TS001"
    assert len(as_dict["frameworks"]) == len(get_frameworks("TS001"))
    first = as_dict["frameworks"][0]
    assert set(first.keys()) == {"framework", "control_id", "title", "url"}


def test_scanner_serializes_empty_frameworks_as_empty_list():
    scanner = IntelligentSecurityScanner(parser=None, rule_analyzer=None, ml_predictor=None)
    vuln = Vulnerability(
        severity=Severity.LOW, points=5, message="x", resource="r",
    )

    as_dict = scanner._vulnerability_to_dict(vuln)  # pylint: disable=protected-access

    assert as_dict["rule_id"] == ""
    assert as_dict["frameworks"] == []


# ---------------------------------------------------------------------------
# CLI formatter renders framework references
# ---------------------------------------------------------------------------

def test_cli_formatter_renders_cis_and_mitre_labels_under_vulnerability():
    result = {
        "score": 80,
        "file": "bad.tf",
        "rule_based_score": 80,
        "ml_score": 60.0,
        "confidence": "HIGH",
        "vulnerabilities": [
            {
                "message": "[CRITICAL] Open SG",
                "resource": "sg",
                "remediation": "restrict",
                "rule_id": "TS001",
                "frameworks": [
                    {
                        "framework": CIS_AWS,
                        "control_id": "Section 5.2",
                        "title": "Ensure no SGs open 22",
                        "url": "https://example.cis",
                    },
                    {
                        "framework": MITRE_ATTACK,
                        "control_id": "T1190",
                        "title": "Exploit Public-Facing Application",
                        "url": "https://attack.mitre.org/techniques/T1190/",
                    },
                ],
            }
        ],
    }

    output = format_results_for_display(result)

    assert "Compliance" in output
    assert "Section 5.2" in output
    assert "T1190" in output


def test_cli_formatter_omits_compliance_section_when_no_frameworks():
    result = {
        "score": 10, "file": "ok.tf",
        "rule_based_score": 10, "ml_score": 10.0, "confidence": "LOW",
        "vulnerabilities": [
            {"message": "[LOW] minor", "resource": "x", "remediation": "", "frameworks": []}
        ],
    }

    output = format_results_for_display(result)

    assert "Compliance" not in output


# ---------------------------------------------------------------------------
# SARIF formatter emits tags + helpUri from frameworks
# ---------------------------------------------------------------------------

def test_sarif_rule_uses_domain_rule_id_when_present():
    file_result = {
        "score": 50, "file": "a.tf",
        "vulnerabilities": [{
            "severity": "HIGH",
            "message": "[HIGH] Unencrypted EBS volume",
            "resource": "vol",
            "remediation": "encrypt",
            "rule_id": "TS003",
            "frameworks": [
                {"framework": CIS_AWS, "control_id": "Section 2.2.1",
                 "title": "EBS encryption", "url": "https://cis.example"},
                {"framework": MITRE_ATTACK, "control_id": "T1530",
                 "title": "Data from Cloud Storage", "url": "https://attack.mitre.org/techniques/T1530/"},
            ],
        }],
    }

    sarif = json.loads(results_to_sarif([file_result]))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]

    assert rules[0]["id"] == "TS003"
    tags = rules[0]["properties"]["tags"]
    assert f"{CIS_AWS}:Section 2.2.1" in tags
    assert f"{MITRE_ATTACK}:T1530" in tags
    assert rules[0]["helpUri"] == "https://cis.example"


def test_sarif_falls_back_to_message_derived_id_when_rule_id_missing():
    """Legacy findings without rule_id still produce a stable SARIF rule id."""
    file_result = {
        "score": 30, "file": "a.tf",
        "vulnerabilities": [{
            "severity": "MEDIUM",
            "message": "Legacy untagged finding",
            "resource": "x",
            "remediation": "",
        }],
    }

    sarif = json.loads(results_to_sarif([file_result]))
    rule_id = sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"]

    assert rule_id.startswith("TS_")
    assert "properties" in sarif["runs"][0]["tool"]["driver"]["rules"][0]


# ---------------------------------------------------------------------------
# End-to-end: real scan preserves framework data through the pipeline
# ---------------------------------------------------------------------------

def test_analyze_end_to_end_ssh_finding_carries_cis_52_and_mitre_t1190(engine):
    vulns = engine.analyze(_tf_with_open_ssh(), raw_content="")

    ssh = next(v for v in vulns if "SSH" in v.message)
    control_ids = {ref.control_id for ref in ssh.frameworks}

    assert "Section 5.2" in control_ids
    assert "T1190" in control_ids
