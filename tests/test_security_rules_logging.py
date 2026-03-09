#!/usr/bin/env python3
"""
Unit tests for the new logging and VPC flow log security rules.

Covers:
- check_missing_logging() — various configurations
- check_missing_vpc_flow_logs() — various configurations
- Severity overrides applied through analyze()
- Boundary cases (empty tf_content)
"""

import pytest
from unittest.mock import patch

from terrasafe.domain.models import Severity
from terrasafe.domain.security_rules import SecurityRuleEngine


@pytest.fixture
def engine():
    """Provide a SecurityRuleEngine for each test."""
    return SecurityRuleEngine()


# ---------------------------------------------------------------------------
# check_missing_logging
# ---------------------------------------------------------------------------

def test_missing_logging_no_logging_resources(engine):
    """Infrastructure resources but no CloudTrail/CloudWatch → HIGH vuln."""
    tf_content = {
        'resource': [
            {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]},
            {'aws_db_instance': [{'db': {'engine': 'mysql', 'storage_encrypted': True}}]},
        ]
    }
    vulns = engine.check_missing_logging(tf_content)
    assert len(vulns) == 1
    assert vulns[0].severity == Severity.HIGH
    assert 'missing logging' in vulns[0].message.lower()


def test_missing_logging_with_cloudtrail_present(engine):
    """CloudTrail present → no vuln."""
    tf_content = {
        'resource': [
            {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]},
            {'aws_cloudtrail': [{'trail': {'name': 'my-trail', 's3_bucket_name': 'my-bucket'}}]},
        ]
    }
    vulns = engine.check_missing_logging(tf_content)
    assert vulns == []


def test_missing_logging_with_cloudwatch_log_group_present(engine):
    """CloudWatch log group present → no vuln."""
    tf_content = {
        'resource': [
            {'aws_security_group': [{'sg': {'ingress': []}}]},
            {'aws_cloudwatch_log_group': [{'lg': {'name': '/app/logs'}}]},
        ]
    }
    vulns = engine.check_missing_logging(tf_content)
    assert vulns == []


def test_missing_logging_empty_tf_content(engine):
    """Empty tf_content (no 'resource' key) → no vuln."""
    vulns = engine.check_missing_logging({})
    assert vulns == []


def test_missing_logging_resources_are_only_logging(engine):
    """Only logging resources present (no infra to monitor) → no vuln."""
    tf_content = {
        'resource': [
            {'aws_cloudtrail': [{'trail': {'name': 'trail', 's3_bucket_name': 'b'}}]},
            {'aws_cloudwatch_log_group': [{'lg': {'name': '/logs'}}]},
        ]
    }
    vulns = engine.check_missing_logging(tf_content)
    assert vulns == []


# ---------------------------------------------------------------------------
# check_missing_vpc_flow_logs
# ---------------------------------------------------------------------------

def test_missing_vpc_flow_logs_vpc_without_flow_log(engine):
    """aws_vpc present but no aws_flow_log → MEDIUM vuln."""
    tf_content = {
        'resource': [
            {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]},
        ]
    }
    vulns = engine.check_missing_vpc_flow_logs(tf_content)
    assert len(vulns) == 1
    assert vulns[0].severity == Severity.MEDIUM
    assert 'flow log' in vulns[0].message.lower()


def test_missing_vpc_flow_logs_vpc_with_flow_log(engine):
    """aws_vpc + aws_flow_log present → no vuln."""
    tf_content = {
        'resource': [
            {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]},
            {'aws_flow_log': [{'fl': {'vpc_id': 'aws_vpc.main.id', 'traffic_type': 'ALL'}}]},
        ]
    }
    vulns = engine.check_missing_vpc_flow_logs(tf_content)
    assert vulns == []


def test_missing_vpc_flow_logs_no_vpc_at_all(engine):
    """No aws_vpc resource → no vuln (rule does not apply)."""
    tf_content = {
        'resource': [
            {'aws_db_instance': [{'db': {'engine': 'mysql', 'storage_encrypted': True}}]},
        ]
    }
    vulns = engine.check_missing_vpc_flow_logs(tf_content)
    assert vulns == []


def test_missing_vpc_flow_logs_empty_tf_content(engine):
    """Empty tf_content → no vuln."""
    vulns = engine.check_missing_vpc_flow_logs({})
    assert vulns == []


# ---------------------------------------------------------------------------
# Severity overrides via analyze()
# ---------------------------------------------------------------------------

def test_severity_override_missing_logging_to_medium(engine):
    """severity_overrides remaps missing_logging from HIGH → MEDIUM."""
    tf_content = {
        'resource': [
            {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]},
        ]
    }
    mock_settings = type('S', (), {'severity_overrides': {'missing_logging': 'MEDIUM'}})()
    with patch('terrasafe.domain.security_rules.get_settings', return_value=mock_settings):
        vulns = engine.analyze(tf_content, "")

    logging_vulns = [v for v in vulns if 'missing logging' in v.message.lower()]
    assert len(logging_vulns) == 1
    assert logging_vulns[0].severity == Severity.MEDIUM


def test_severity_override_missing_flow_logs_to_high(engine):
    """severity_overrides remaps missing_flow_logs from MEDIUM → HIGH."""
    tf_content = {
        'resource': [
            {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]},
            {'aws_cloudtrail': [{'trail': {'name': 'trail', 's3_bucket_name': 'b'}}]},
        ]
    }
    mock_settings = type('S', (), {'severity_overrides': {'missing_flow_logs': 'HIGH'}})()
    with patch('terrasafe.domain.security_rules.get_settings', return_value=mock_settings):
        vulns = engine.analyze(tf_content, "")

    flow_vulns = [v for v in vulns if 'flow log' in v.message.lower()]
    assert len(flow_vulns) == 1
    assert flow_vulns[0].severity == Severity.HIGH


def test_no_severity_override_applied_when_empty(engine):
    """Empty severity_overrides dict → original severities unchanged."""
    tf_content = {
        'resource': [
            {'aws_vpc': [{'main': {'cidr_block': '10.0.0.0/16'}}]},
        ]
    }
    mock_settings = type('S', (), {'severity_overrides': {}})()
    with patch('terrasafe.domain.security_rules.get_settings', return_value=mock_settings):
        vulns = engine.analyze(tf_content, "")

    logging_vulns = [v for v in vulns if 'missing logging' in v.message.lower()]
    flow_vulns = [v for v in vulns if 'flow log' in v.message.lower()]
    assert all(v.severity == Severity.HIGH for v in logging_vulns)
    assert all(v.severity == Severity.MEDIUM for v in flow_vulns)
