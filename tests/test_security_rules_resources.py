"""Tests for the resource-exposure rules on ``SecurityRuleEngine``.

Covers the detection rules added to broaden cloud-misconfiguration coverage:
- publicly accessible RDS instances
- unrestricted security-group egress
- EC2 instances allowing IMDSv1 (no IMDSv2 enforcement)
- EC2 instances that auto-assign a public IP

Each rule is exercised on both its triggering and non-triggering shapes so the
detection logic stays fully covered.
"""
import pytest

from terravault.domain.models import Severity
from terravault.domain.security_rules import SecurityRuleEngine


pytestmark = pytest.mark.unit


def _resources(resource_type: str, name: str, config: dict) -> dict:
    """Wrap a single named resource in parsed-HCL structure."""
    return {"resource": [{resource_type: [{name: config}]}]}


# ---------------------------------------------------------------------------
# _truthy — HCL boolean normalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value, expected",
    [
        pytest.param(True, True, id="bool_true"),
        pytest.param(False, False, id="bool_false"),
        pytest.param("true", True, id="str_true"),
        pytest.param("True", True, id="str_true_mixed_case"),
        pytest.param("false", False, id="str_false"),
        pytest.param(1, True, id="int_truthy"),
        pytest.param(0, False, id="int_falsy"),
    ],
)
def test_truthy_normalises_hcl_booleans(value, expected):
    assert SecurityRuleEngine._truthy(value) is expected


# ---------------------------------------------------------------------------
# check_public_rds
# ---------------------------------------------------------------------------

def test_public_rds_flagged_as_critical(engine):
    tf = _resources("aws_db_instance", "main_db", {"publicly_accessible": True})

    vulns = engine.check_public_rds(tf)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL
    assert "Publicly accessible RDS" in vulns[0].message
    assert vulns[0].resource == "main_db"


def test_public_rds_string_true_is_flagged(engine):
    tf = _resources("aws_db_instance", "main_db", {"publicly_accessible": "true"})

    assert len(engine.check_public_rds(tf)) == 1


@pytest.mark.parametrize(
    "config",
    [
        pytest.param({"publicly_accessible": False}, id="explicitly_private"),
        pytest.param({"storage_encrypted": True}, id="attribute_absent"),
    ],
)
def test_private_rds_is_silent(engine, config):
    assert engine.check_public_rds(_resources("aws_db_instance", "db", config)) == []


def test_public_rds_handles_empty_content(engine):
    assert engine.check_public_rds({}) == []


# ---------------------------------------------------------------------------
# check_unrestricted_egress
# ---------------------------------------------------------------------------

def test_unrestricted_egress_ipv4_is_low(engine):
    tf = _resources("aws_security_group", "sg", {"egress": [{"cidr_blocks": ["0.0.0.0/0"]}]})

    vulns = engine.check_unrestricted_egress(tf)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.LOW
    assert "Unrestricted egress" in vulns[0].message
    assert "0.0.0.0/0" in vulns[0].message


def test_unrestricted_egress_accepts_single_block_dict(engine):
    # HCL may parse a lone egress block as a dict rather than a list.
    tf = _resources("aws_security_group", "sg", {"egress": {"ipv6_cidr_blocks": ["::/0"]}})

    vulns = engine.check_unrestricted_egress(tf)

    assert len(vulns) == 1
    assert "::/0" in vulns[0].message


def test_unrestricted_egress_skips_non_dict_rule(engine):
    tf = _resources("aws_security_group", "sg", {"egress": ["not-a-dict"]})

    assert engine.check_unrestricted_egress(tf) == []


def test_scoped_egress_is_silent(engine):
    tf = _resources("aws_security_group", "sg", {"egress": [{"cidr_blocks": ["10.0.0.0/8"]}]})

    assert engine.check_unrestricted_egress(tf) == []


def test_unrestricted_egress_handles_empty_content(engine):
    assert engine.check_unrestricted_egress({}) == []


# ---------------------------------------------------------------------------
# check_imdsv2_required
# ---------------------------------------------------------------------------

def test_imdsv2_required_is_silent(engine):
    tf = _resources("aws_instance", "web", {"metadata_options": {"http_tokens": "required"}})

    assert engine.check_imdsv2_required(tf) == []


def test_imdsv2_required_accepts_list_wrapped_block(engine):
    tf = _resources("aws_instance", "web", {"metadata_options": [{"http_tokens": "required"}]})

    assert engine.check_imdsv2_required(tf) == []


def test_imdsv1_optional_tokens_is_high(engine):
    tf = _resources("aws_instance", "web", {"metadata_options": {"http_tokens": "optional"}})

    vulns = engine.check_imdsv2_required(tf)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "IMDSv1" in vulns[0].message


def test_imdsv1_missing_metadata_block_is_high(engine):
    tf = _resources("aws_instance", "web", {"ami": "ami-123"})

    vulns = engine.check_imdsv2_required(tf)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH


def test_imdsv2_handles_empty_metadata_list(engine):
    tf = _resources("aws_instance", "web", {"metadata_options": []})

    assert len(engine.check_imdsv2_required(tf)) == 1


def test_imdsv2_handles_empty_content(engine):
    assert engine.check_imdsv2_required({}) == []


# ---------------------------------------------------------------------------
# check_public_instance
# ---------------------------------------------------------------------------

def test_public_instance_is_low(engine):
    tf = _resources("aws_instance", "web", {"associate_public_ip_address": True})

    vulns = engine.check_public_instance(tf)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.LOW
    assert "public IP" in vulns[0].message


@pytest.mark.parametrize(
    "config",
    [
        pytest.param({"associate_public_ip_address": False}, id="explicitly_private"),
        pytest.param({"ami": "ami-123"}, id="attribute_absent"),
    ],
)
def test_private_instance_is_silent(engine, config):
    assert engine.check_public_instance(_resources("aws_instance", "web", config)) == []


def test_public_instance_handles_empty_content(engine):
    assert engine.check_public_instance({}) == []


# ---------------------------------------------------------------------------
# analyze() wiring — new rules must run as part of the aggregate
# ---------------------------------------------------------------------------

def test_analyze_includes_new_resource_rules(engine):
    tf = {
        "resource": [
            {"aws_db_instance": [{"db": {"publicly_accessible": True}}]},
            {"aws_security_group": [{"sg": {"egress": [{"cidr_blocks": ["0.0.0.0/0"]}]}}]},
            {"aws_instance": [{"web": {"associate_public_ip_address": True}}]},
        ]
    }

    messages = " ".join(v.message for v in engine.analyze(tf, ""))

    assert "Publicly accessible RDS" in messages
    assert "Unrestricted egress" in messages
    assert "IMDSv1" in messages          # aws_instance has no IMDSv2 enforcement
    assert "public IP" in messages
