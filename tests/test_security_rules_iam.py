"""Tests for ``SecurityRuleEngine.check_iam_policies``."""
import json

import pytest

from terravault.domain.models import Severity


pytestmark = pytest.mark.unit


def _tf_policy(policy_doc: dict, policy_name: str = "test_policy") -> dict:
    """Build a minimal ``tf_content`` dict holding one ``aws_iam_role_policy``."""
    return {
        "resource": [
            {
                "aws_iam_role_policy": [
                    {policy_name: {"policy": json.dumps(policy_doc)}}
                ]
            }
        ]
    }


# ---------------------------------------------------------------------------
# Wildcard / admin detection — parametrized across policy shapes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "policy_doc, expected_count, expected_message_fragments",
    [
        pytest.param(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::my-bucket"}]},
            1,
            ["wildcard"],
            id="wildcard_action_only_emits_one_critical",
        ),
        pytest.param(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            2,
            ["wildcard", "full admin"],
            id="full_admin_emits_two_criticals",
        ),
    ],
)
def test_wildcard_policies_are_flagged_as_critical(
    engine, policy_doc, expected_count, expected_message_fragments
):
    results = engine.check_iam_policies(_tf_policy(policy_doc))

    assert len(results) == expected_count
    assert all(v.severity == Severity.CRITICAL for v in results)
    messages = " ".join(v.message.lower() for v in results)
    for fragment in expected_message_fragments:
        assert fragment in messages


@pytest.mark.parametrize(
    "policy_doc",
    [
        pytest.param(
            {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
            id="resource_wildcard_alone_does_not_trigger",
        ),
        pytest.param(
            {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }]
            },
            id="specific_action_and_resource_is_safe",
        ),
    ],
)
def test_scoped_policies_produce_no_vulnerabilities(engine, policy_doc):
    assert engine.check_iam_policies(_tf_policy(policy_doc)) == []


def test_mixed_good_and_bad_policies_flag_only_the_insecure_one(engine):
    bad_doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    good_doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]})
    tf_content = {
        "resource": [
            {
                "aws_iam_role_policy": [
                    {
                        "bad_policy": {"policy": bad_doc},
                        "good_policy": {"policy": good_doc},
                    }
                ]
            }
        ]
    }

    results = engine.check_iam_policies(tf_content)

    assert len(results) == 2
    assert all(v.resource == "bad_policy" for v in results)
