"""Tests for network-exposure and hardcoded-secret rules on ``SecurityRuleEngine``.

These cover the detection-correctness fixes:
- IPv6 ``::/0`` exposure (previously a silent false-negative)
- Port *range* coverage of sensitive ports (previously bypassed exact-match)
- Hardcoded-secret false-positives on interpolated / referenced values
"""
import pytest

from terravault.domain.models import Severity


pytestmark = pytest.mark.unit


def _sg(ingress: dict) -> dict:
    """Wrap a single ingress block in a parsed-HCL security-group resource."""
    return {"resource": [{"aws_security_group": [{"sg": {"ingress": [ingress]}}]}]}


# ---------------------------------------------------------------------------
# check_open_security_groups — exposure scope (IPv4 / IPv6) and port ranges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ingress, expected_severity, message_fragment",
    [
        pytest.param(
            {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
            Severity.CRITICAL, "SSH port 22",
            id="ipv4_ssh_is_critical",
        ),
        pytest.param(
            {"from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["::/0"]},
            Severity.CRITICAL, "SSH port 22",
            id="ipv6_ssh_is_critical",
        ),
        pytest.param(
            {"from_port": 3389, "to_port": 3389, "ipv6_cidr_blocks": ["::/0"]},
            Severity.CRITICAL, "RDP port 3389",
            id="ipv6_rdp_is_critical",
        ),
        pytest.param(
            {"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]},
            Severity.CRITICAL, "SSH port 22",
            id="wide_range_covering_ssh_is_critical",
        ),
        pytest.param(
            {"from_port": 3380, "to_port": 3400, "cidr_blocks": ["0.0.0.0/0"]},
            Severity.CRITICAL, "RDP port 3389",
            id="range_covering_rdp_is_critical",
        ),
        pytest.param(
            {"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]},
            Severity.MEDIUM, "HTTP/HTTPS",
            id="web_port_is_medium",
        ),
        pytest.param(
            {"from_port": 9200, "to_port": 9200, "cidr_blocks": ["0.0.0.0/0"]},
            Severity.HIGH, "Port 9200",
            id="other_port_is_high",
        ),
    ],
)
def test_open_security_group_severity(engine, ingress, expected_severity, message_fragment):
    vulns = engine.check_open_security_groups(_sg(ingress))

    assert len(vulns) == 1
    assert vulns[0].severity == expected_severity
    assert message_fragment in vulns[0].message
    assert "exposed to internet" in vulns[0].message


@pytest.mark.parametrize(
    "ingress",
    [
        pytest.param({"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}, id="private_ipv4"),
        pytest.param(
            {"from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["2001:db8::/32"]},
            id="scoped_ipv6",
        ),
        pytest.param({"from_port": 443, "to_port": 443}, id="no_cidr_at_all"),
    ],
)
def test_non_internet_ingress_is_silent(engine, ingress):
    assert engine.check_open_security_groups(_sg(ingress)) == []


def test_missing_to_port_defaults_to_from_port(engine):
    vulns = engine.check_open_security_groups(
        _sg({"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]})
    )

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.CRITICAL


def test_open_security_groups_handles_empty_content(engine):
    assert engine.check_open_security_groups({}) == []


# ---------------------------------------------------------------------------
# check_hardcoded_secrets — literals flagged, references ignored
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, should_flag",
    [
        pytest.param('password = "hardcoded123"', True, id="literal_password_flagged"),
        pytest.param('api_key = "AKIAEXAMPLE12345"', True, id="literal_api_key_flagged"),
        pytest.param('token = "ghp_realtokenvalue"', True, id="literal_token_flagged"),
        pytest.param('password = "${var.db_password}"', False, id="interpolated_var_ignored"),
        pytest.param('password = "prefix-${var.x}"', False, id="partial_interpolation_ignored"),
        pytest.param('secret_key = "${data.aws_ssm.k.value}"', False, id="data_reference_ignored"),
        pytest.param('password = "var.db_password"', False, id="bare_var_reference_ignored"),
        pytest.param('password = "local.secret"', False, id="bare_local_reference_ignored"),
    ],
)
def test_hardcoded_secret_detection(engine, raw, should_flag):
    vulns = engine.check_hardcoded_secrets(raw)

    assert bool(vulns) is should_flag
    if should_flag:
        assert all(v.severity == Severity.CRITICAL for v in vulns)
