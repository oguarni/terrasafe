"""Tests for logging + VPC flow log rules on ``SecurityRuleEngine``."""
from unittest.mock import patch

import pytest

from terravault.domain.models import Severity


pytestmark = pytest.mark.unit


VPC_RESOURCE = {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]}
DB_RESOURCE = {'aws_db_instance': [{'db': {'engine': 'mysql', 'storage_encrypted': True}}]}
CLOUDTRAIL_RESOURCE = {'aws_cloudtrail': [{'trail': {'name': 'my-trail', 's3_bucket_name': 'my-bucket'}}]}
FLOW_LOG_RESOURCE = {'aws_flow_log': [{'fl': {'vpc_id': 'aws_vpc.main.id', 'traffic_type': 'ALL'}}]}


# ---------------------------------------------------------------------------
# check_missing_logging
# ---------------------------------------------------------------------------

def test_missing_logging_flagged_high_when_no_trail_present(engine):
    tf_content = {"resource": [VPC_RESOURCE, DB_RESOURCE]}

    vulns = engine.check_missing_logging(tf_content)

    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert "missing logging" in vulns[0].message.lower()


def test_missing_logging_is_silent_when_cloudtrail_present(engine):
    tf_content = {"resource": [VPC_RESOURCE, CLOUDTRAIL_RESOURCE]}

    assert engine.check_missing_logging(tf_content) == []


# ---------------------------------------------------------------------------
# check_missing_vpc_flow_logs — parametrized across configurations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "resources, expected_count, expected_severity",
    [
        pytest.param([VPC_RESOURCE], 1, Severity.MEDIUM, id="vpc_without_flow_log_is_medium"),
        pytest.param([VPC_RESOURCE, FLOW_LOG_RESOURCE], 0, None, id="vpc_with_flow_log_silent"),
        pytest.param([DB_RESOURCE], 0, None, id="no_vpc_rule_does_not_apply"),
    ],
)
def test_vpc_flow_log_rule_covers_all_configurations(
    engine, resources, expected_count, expected_severity
):
    tf_content = {"resource": resources}

    vulns = engine.check_missing_vpc_flow_logs(tf_content)

    assert len(vulns) == expected_count
    if expected_severity is not None:
        assert vulns[0].severity == expected_severity
        assert "flow log" in vulns[0].message.lower()


# ---------------------------------------------------------------------------
# Severity overrides applied through analyze()
# ---------------------------------------------------------------------------

def test_severity_override_remaps_missing_logging_from_high_to_medium(engine):
    tf_content = {"resource": [VPC_RESOURCE]}
    mock_settings = type("S", (), {"severity_overrides": {"missing_logging": "MEDIUM"}})()

    with patch("terravault.domain.security_rules.get_settings", return_value=mock_settings):
        vulns = engine.analyze(tf_content, "")

    logging_vulns = [v for v in vulns if "missing logging" in v.message.lower()]
    assert len(logging_vulns) == 1
    assert logging_vulns[0].severity == Severity.MEDIUM
