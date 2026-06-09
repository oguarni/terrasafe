"""Unit tests for the structural feature extractor.

These lock in the property that makes the hybrid model genuinely hybrid: ML
features are derived from the *parsed infrastructure*, not from the rule
findings, so the model can react to structure the deterministic rules ignore.
"""
import hcl2
import pytest

from terravault.application.feature_extraction import (
    FEATURE_BOUNDS,
    FEATURE_NAMES,
    NUM_FEATURES,
    StructuralFeatureExtractor,
)
from terravault.domain.security_rules import SecurityRuleEngine


pytestmark = [pytest.mark.unit, pytest.mark.ml]


@pytest.fixture
def extractor():
    return StructuralFeatureExtractor()


def _features(raw: str) -> dict:
    """Parse inline HCL and return the named structural feature vector."""
    tf_content = hcl2.loads(raw)
    vector = StructuralFeatureExtractor().extract(tf_content, raw)
    assert vector.shape == (1, NUM_FEATURES)
    return dict(zip(FEATURE_NAMES, vector[0]))


def test_layout_constants_are_consistent():
    assert len(FEATURE_NAMES) == NUM_FEATURES
    assert len(FEATURE_BOUNDS) == NUM_FEATURES


def test_empty_content_yields_secure_neutral_vector(extractor):
    feats = dict(zip(FEATURE_NAMES, extractor.extract({}, "")[0]))
    assert feats["resource_count"] == 0
    # Ratios default to 1.0 (fully secure) when nothing applies.
    assert feats["encryption_coverage"] == 1.0
    assert feats["secret_parametrization"] == 1.0


def test_counts_resources_types_and_iam():
    raw = """
    resource "aws_iam_role" "r" { name = "r" }
    resource "aws_iam_policy" "p" { name = "p" }
    resource "aws_s3_bucket" "b" { bucket = "b" }
    """
    feats = _features(raw)
    assert feats["resource_count"] == 3
    assert feats["resource_type_diversity"] == 3
    assert feats["iam_resource_count"] == 2


def test_encryption_coverage_is_a_partial_ratio():
    raw = """
    resource "aws_ebs_volume" "a" { encrypted = true }
    resource "aws_ebs_volume" "b" { encrypted = false }
    """
    feats = _features(raw)
    assert feats["encryption_coverage"] == pytest.approx(0.5)


def test_logging_resources_are_counted():
    raw = """
    resource "aws_cloudtrail" "t" { name = "t" }
    resource "aws_cloudwatch_log_group" "g" { name = "g" }
    resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }
    """
    feats = _features(raw)
    assert feats["logging_resource_count"] == 2


def test_public_ingress_and_public_attributes_raise_exposure():
    raw = """
    resource "aws_security_group" "sg" {
      ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
    resource "aws_instance" "web" {
      associate_public_ip_address = true
    }
    """
    feats = _features(raw)
    assert feats["ingress_rule_count"] == 1
    assert feats["public_exposure_count"] == 2  # one public ingress + one public IP


def test_secret_parametrization_separates_literals_from_variables():
    hardcoded = 'resource "aws_db_instance" "d" { password = "hunter2" }'
    parametrized = 'resource "aws_db_instance" "d" { password = var.db_password }'
    assert _features(hardcoded)["secret_parametrization"] == pytest.approx(0.0)
    assert _features(parametrized)["secret_parametrization"] == pytest.approx(1.0)


def test_features_are_independent_of_the_rule_engine():
    """A rule-clean but structurally exposed config must still register.

    ``aws_instance`` with a public IP is not covered by any of the 7 rules, so
    the rule engine returns no findings — yet the structural extractor records
    the public exposure. This is the behaviour that lets the ML surface risks
    outside the fixed rule catalogue. A CloudWatch log group is included so the
    missing-logging rule stays silent and the config is genuinely rule-clean.
    """
    raw = """
    resource "aws_instance" "web" { associate_public_ip_address = true }
    resource "aws_cloudwatch_log_group" "g" { name = "g" }
    """
    tf_content = hcl2.loads(raw)

    findings = SecurityRuleEngine().analyze(tf_content, raw)
    assert findings == []  # rules see nothing

    feats = dict(zip(FEATURE_NAMES, StructuralFeatureExtractor().extract(tf_content, raw)[0]))
    assert feats["public_exposure_count"] == 1  # structure still captured
