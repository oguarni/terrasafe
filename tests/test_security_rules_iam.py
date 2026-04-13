"""Tests for SecurityRuleEngine.check_iam_policies()"""
import json
import pytest

from terrasafe.domain.models import Severity
from terrasafe.domain.security_rules import SecurityRuleEngine


@pytest.mark.unit
class TestCheckIamPolicies:
    """Unit tests for IAM policy vulnerability detection."""

    def setup_method(self):
        self.engine = SecurityRuleEngine()

    def _make_tf(self, policy_doc: dict, policy_name: str = "test_policy") -> dict:
        """Build a minimal tf_content dict with an aws_iam_role_policy resource."""
        return {
            "resource": [
                {
                    "aws_iam_role_policy": [
                        {
                            policy_name: {
                                "policy": json.dumps(policy_doc)
                            }
                        }
                    ]
                }
            ]
        }

    # ------------------------------------------------------------------
    # Boundary / structural cases
    # ------------------------------------------------------------------

    def test_no_resource_key_returns_empty(self):
        """Missing 'resource' key → no vulnerabilities."""
        result = self.engine.check_iam_policies({})
        assert result == []

    # ------------------------------------------------------------------
    # Wildcard action detection
    # ------------------------------------------------------------------

    def test_wildcard_action_detected_as_critical(self):
        """'Action': '*' → 1 CRITICAL vulnerability."""
        policy_doc = {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-bucket"}]
        }
        result = self.engine.check_iam_policies(self._make_tf(policy_doc))
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL
        assert "wildcard" in result[0].message.lower()

    def test_compact_wildcard_action_detected(self):
        """Compact JSON format (no spaces after colon) → detection still works."""
        tf_content = {
            "resource": [
                {
                    "aws_iam_role_policy": [
                        {
                            "compact_policy": {
                                "policy": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket"}]}'
                            }
                        }
                    ]
                }
            ]
        }
        result = self.engine.check_iam_policies(tf_content)
        wildcards = [v for v in result if "wildcard" in v.message.lower()]
        assert len(wildcards) >= 1

    # ------------------------------------------------------------------
    # Full admin access detection
    # ------------------------------------------------------------------

    def test_full_admin_access_emits_two_criticals(self):
        """Action='*' AND Resource='*' → 2 CRITICAL vulns (both checks fire)."""
        policy_doc = {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
        result = self.engine.check_iam_policies(self._make_tf(policy_doc))
        assert len(result) == 2
        assert all(v.severity == Severity.CRITICAL for v in result)
        messages = [v.message for v in result]
        assert any("wildcard" in m.lower() for m in messages)
        assert any("full admin" in m.lower() for m in messages)

    def test_resource_wildcard_alone_does_not_trigger_admin_check(self):
        """Resource='*' without Action='*' → no admin vuln (only explicit action wildcard triggers)."""
        policy_doc = {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        }
        result = self.engine.check_iam_policies(self._make_tf(policy_doc))
        assert result == []

    # ------------------------------------------------------------------
    # Safe policies
    # ------------------------------------------------------------------

    def test_specific_policy_no_vulns(self):
        """A properly scoped IAM policy → no vulnerabilities."""
        policy_doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }
        result = self.engine.check_iam_policies(self._make_tf(policy_doc))
        assert result == []

    # ------------------------------------------------------------------
    # Multiple policies
    # ------------------------------------------------------------------

    def test_multiple_policies_only_bad_one_flagged(self):
        """Two policies in the same resource block — only the insecure one is flagged."""
        bad_policy_doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        good_policy_doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]})
        tf_content = {
            "resource": [
                {
                    "aws_iam_role_policy": [
                        {
                            "bad_policy": {"policy": bad_policy_doc},
                            "good_policy": {"policy": good_policy_doc},
                        }
                    ]
                }
            ]
        }
        result = self.engine.check_iam_policies(tf_content)
        assert len(result) == 2  # wildcard action + full admin for bad_policy only
        assert all(v.resource == "bad_policy" for v in result)
