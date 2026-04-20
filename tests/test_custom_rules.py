"""Tests for the YAML-backed custom rule extensibility engine.

Covers: loader validation, operator semantics, rule-to-resource matching,
integration with SecurityRuleEngine, and CLI wiring.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from terrasafe.domain.models import Severity, Vulnerability
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.infrastructure.custom_rules import (
    Condition,
    CustomRule,
    CustomRuleEngine,
    CustomRuleError,
    Operator,
    _evaluate_condition,
    _resolve_attribute,
    load_rules_file,
)


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path: Path, body: str, name: str = "rules.yml") -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    return path


def _make_condition(attribute: str, operator: Operator, value=None) -> Condition:
    return Condition(attribute=attribute, operator=operator, value=value)


# ---------------------------------------------------------------------------
# Attribute resolution
# ---------------------------------------------------------------------------


class TestResolveAttribute:
    """Dot-path traversal over HCL2-shaped dicts."""

    def test_returns_scalar_at_top_level(self):
        actual = _resolve_attribute({"encrypted": False}, "encrypted")

        assert actual is False

    def test_unwraps_single_element_list_leaf(self):
        # HCL2 emits single blocks as one-element lists.
        actual = _resolve_attribute({"versioning": [{"enabled": True}]}, "versioning.enabled")

        assert actual is True

    def test_walks_into_nested_dict(self):
        actual = _resolve_attribute({"tags": {"Owner": "ops"}}, "tags.Owner")

        assert actual == "ops"

    def test_returns_missing_sentinel_for_absent_path(self):
        from terrasafe.infrastructure.custom_rules import _MISSING

        actual = _resolve_attribute({"foo": 1}, "bar.baz")

        assert actual is _MISSING

    def test_returns_missing_when_intermediate_is_scalar(self):
        from terrasafe.infrastructure.custom_rules import _MISSING

        actual = _resolve_attribute({"name": "x"}, "name.inner")

        assert actual is _MISSING


# ---------------------------------------------------------------------------
# Operators — parameterized table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "attribute, operator, value, resource, expected",
    [
        # equals / not_equals
        ("encrypted", Operator.EQUALS, True, {"encrypted": True}, True),
        ("encrypted", Operator.EQUALS, True, {"encrypted": False}, False),
        ("encrypted", Operator.NOT_EQUALS, True, {"encrypted": False}, True),
        # in / not_in
        ("region", Operator.IN, ["us-east-1", "us-west-2"], {"region": "us-east-1"}, True),
        ("region", Operator.IN, ["us-east-1"], {"region": "eu-west-1"}, False),
        ("region", Operator.NOT_IN, ["us-east-1"], {"region": "eu-west-1"}, True),
        # contains / not_contains on strings
        ("policy", Operator.CONTAINS, "Action:*", {"policy": "Action:*"}, True),
        ("policy", Operator.NOT_CONTAINS, "*", {"policy": "GetObject"}, True),
        # contains on lists
        ("cidr_blocks", Operator.CONTAINS, "0.0.0.0/0",
         {"cidr_blocks": ["10.0.0.0/8", "0.0.0.0/0"]}, True),
        ("cidr_blocks", Operator.NOT_CONTAINS, "0.0.0.0/0",
         {"cidr_blocks": ["10.0.0.0/8"]}, True),
        # regex
        ("instance_class", Operator.REGEX, r"^db\.t3",
         {"instance_class": "db.t3.micro"}, True),
        ("instance_class", Operator.REGEX, r"^db\.t3",
         {"instance_class": "db.m4.large"}, False),
        # exists / missing
        ("tags.Owner", Operator.EXISTS, None, {"tags": {"Owner": "x"}}, True),
        ("tags.Owner", Operator.MISSING, None, {"tags": {}}, True),
        ("tags.Owner", Operator.MISSING, None, {"tags": {"Owner": "x"}}, False),
        # numeric comparisons
        ("size", Operator.GREATER_THAN, 100, {"size": 200}, True),
        ("size", Operator.GREATER_THAN, 100, {"size": 50}, False),
        ("size", Operator.LESS_THAN, 100, {"size": 50}, True),
    ],
)
def test_operator_evaluation(attribute, operator, value, resource, expected):
    condition = _make_condition(attribute, operator, value)

    result = _evaluate_condition(condition, resource)

    assert result is expected


def test_regex_invalid_pattern_returns_false_without_raising():
    condition = _make_condition("name", Operator.REGEX, "[unclosed")

    result = _evaluate_condition(condition, {"name": "anything"})

    assert result is False


def test_numeric_operators_return_false_on_non_numeric_value():
    condition = _make_condition("size", Operator.GREATER_THAN, 10)

    result = _evaluate_condition(condition, {"size": "not-a-number"})

    assert result is False


def test_missing_attribute_makes_non_presence_operators_return_false():
    condition = _make_condition("missing_field", Operator.EQUALS, True)

    result = _evaluate_condition(condition, {"other": 1})

    assert result is False


# ---------------------------------------------------------------------------
# Rule-level match semantics
# ---------------------------------------------------------------------------


def _rule(conditions, match="all", **overrides) -> CustomRule:
    return CustomRule(
        id=overrides.get("id", "TEST-1"),
        name=overrides.get("name", "Test rule"),
        severity=overrides.get("severity", Severity.HIGH),
        resource_type=overrides.get("resource_type", "aws_s3_bucket"),
        match=match,
        conditions=conditions,
        remediation=overrides.get("remediation", ""),
    )


class TestRuleMatchSemantics:
    """match: all vs match: any across two conditions."""

    @pytest.fixture
    def resource_config(self):
        return {"encrypted": False, "versioning": [{"enabled": False}]}

    def test_match_all_requires_every_condition_to_hold(self, resource_config):
        rule = _rule(
            [
                _make_condition("encrypted", Operator.EQUALS, False),
                _make_condition("versioning.enabled", Operator.EQUALS, False),
            ],
            match="all",
        )
        engine = CustomRuleEngine([rule])

        assert engine._rule_matches(rule, resource_config) is True

    def test_match_all_fails_when_one_condition_fails(self, resource_config):
        rule = _rule(
            [
                _make_condition("encrypted", Operator.EQUALS, False),
                _make_condition("versioning.enabled", Operator.EQUALS, True),  # does not hold
            ],
            match="all",
        )
        engine = CustomRuleEngine([rule])

        assert engine._rule_matches(rule, resource_config) is False

    def test_match_any_fires_when_a_single_condition_holds(self, resource_config):
        rule = _rule(
            [
                _make_condition("encrypted", Operator.EQUALS, True),  # fails
                _make_condition("versioning.enabled", Operator.EQUALS, False),  # holds
            ],
            match="any",
        )
        engine = CustomRuleEngine([rule])

        assert engine._rule_matches(rule, resource_config) is True

    def test_match_any_requires_at_least_one_hit(self, resource_config):
        rule = _rule(
            [
                _make_condition("encrypted", Operator.EQUALS, True),
                _make_condition("versioning.enabled", Operator.EQUALS, True),
            ],
            match="any",
        )
        engine = CustomRuleEngine([rule])

        assert engine._rule_matches(rule, resource_config) is False


# ---------------------------------------------------------------------------
# YAML loader validation
# ---------------------------------------------------------------------------


class TestLoadRulesFile:
    """Validation and error reporting for YAML loading."""

    def test_loads_valid_rule_file(self, tmp_path):
        path = _write_yaml(
            tmp_path,
            """
            version: "1.0"
            rules:
              - id: T-1
                name: Test rule
                severity: MEDIUM
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: versioning.enabled
                    operator: equals
                    value: true
            """,
        )

        rules = load_rules_file(path)

        assert len(rules) == 1
        assert rules[0].id == "T-1"
        assert rules[0].severity is Severity.MEDIUM
        assert rules[0].match == "all"  # default

    def test_loads_severity_case_insensitively(self, tmp_path):
        path = _write_yaml(
            tmp_path,
            """
            rules:
              - id: T-1
                name: Test
                severity: critical
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: foo
                    operator: exists
            """,
        )

        rules = load_rules_file(path)

        assert rules[0].severity is Severity.CRITICAL

    def test_missing_file_raises_custom_rule_error(self, tmp_path):
        with pytest.raises(CustomRuleError, match="not found"):
            load_rules_file(tmp_path / "does-not-exist.yml")

    def test_invalid_yaml_raises_custom_rule_error(self, tmp_path):
        path = tmp_path / "bad.yml"
        path.write_text("rules: [\n  - id: broken\n", encoding="utf-8")

        with pytest.raises(CustomRuleError, match="Invalid YAML"):
            load_rules_file(path)

    def test_empty_file_raises(self, tmp_path):
        path = tmp_path / "empty.yml"
        path.write_text("", encoding="utf-8")

        with pytest.raises(CustomRuleError, match="empty"):
            load_rules_file(path)

    def test_top_level_scalar_raises(self, tmp_path):
        path = tmp_path / "scalar.yml"
        path.write_text("'just a string'", encoding="utf-8")

        with pytest.raises(CustomRuleError, match="mapping"):
            load_rules_file(path)

    def test_missing_required_field_raises(self, tmp_path):
        path = _write_yaml(
            tmp_path,
            """
            rules:
              - name: Missing id
                severity: HIGH
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: x
                    operator: exists
            """,
        )

        with pytest.raises(CustomRuleError):
            load_rules_file(path)

    def test_invalid_severity_raises(self, tmp_path):
        path = _write_yaml(
            tmp_path,
            """
            rules:
              - id: T-1
                name: Test
                severity: BOGUS
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: x
                    operator: exists
            """,
        )

        with pytest.raises(CustomRuleError):
            load_rules_file(path)

    def test_invalid_operator_raises(self, tmp_path):
        path = _write_yaml(
            tmp_path,
            """
            rules:
              - id: T-1
                name: Test
                severity: HIGH
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: x
                    operator: does_not_exist
            """,
        )

        with pytest.raises(CustomRuleError):
            load_rules_file(path)

    def test_empty_conditions_raises(self, tmp_path):
        path = _write_yaml(
            tmp_path,
            """
            rules:
              - id: T-1
                name: Test
                severity: HIGH
                resource_type: aws_s3_bucket
                conditions: []
            """,
        )

        with pytest.raises(CustomRuleError):
            load_rules_file(path)

    def test_duplicate_rule_ids_raises(self, tmp_path):
        path = _write_yaml(
            tmp_path,
            """
            rules:
              - id: T-1
                name: A
                severity: HIGH
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: x
                    operator: exists
              - id: T-1
                name: B
                severity: HIGH
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: y
                    operator: exists
            """,
        )

        with pytest.raises(CustomRuleError, match="duplicate rule ids"):
            load_rules_file(path)


class TestEngineLoadFromPath:
    """Directory and dispatch loading."""

    def test_from_directory_loads_all_yaml_files(self, tmp_path):
        _write_yaml(
            tmp_path,
            """
            rules:
              - id: A-1
                name: A
                severity: HIGH
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: x
                    operator: exists
            """,
            name="a.yml",
        )
        _write_yaml(
            tmp_path,
            """
            rules:
              - id: B-1
                name: B
                severity: LOW
                resource_type: aws_instance
                conditions:
                  - attribute: y
                    operator: exists
            """,
            name="b.yaml",
        )

        engine = CustomRuleEngine.from_directory(tmp_path)

        ids = sorted(r.id for r in engine.rules)
        assert ids == ["A-1", "B-1"]

    def test_from_directory_missing_raises(self, tmp_path):
        with pytest.raises(CustomRuleError):
            CustomRuleEngine.from_directory(tmp_path / "nope")

    def test_from_directory_rejects_cross_file_id_collision(self, tmp_path):
        body = """
        rules:
          - id: DUP-1
            name: A
            severity: HIGH
            resource_type: aws_s3_bucket
            conditions:
              - attribute: x
                operator: exists
        """
        _write_yaml(tmp_path, body, name="first.yml")
        _write_yaml(tmp_path, body, name="second.yml")

        with pytest.raises(CustomRuleError, match="Duplicate rule id"):
            CustomRuleEngine.from_directory(tmp_path)

    def test_from_path_dispatches_to_file_or_directory(self, tmp_path):
        file_path = _write_yaml(
            tmp_path,
            """
            rules:
              - id: F-1
                name: via file
                severity: HIGH
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: x
                    operator: exists
            """,
            name="single.yml",
        )

        via_file = CustomRuleEngine.from_path(file_path)
        via_dir = CustomRuleEngine.from_path(tmp_path)

        assert len(via_file) == 1
        assert len(via_dir) == 1


# ---------------------------------------------------------------------------
# analyze() — full rule/resource matrix
# ---------------------------------------------------------------------------


@pytest.fixture
def tf_content_with_unversioned_bucket():
    # Mirrors the python-hcl2 shape: resource is a list of dicts, each mapping
    # resource_type -> list -> { resource_name: {...} }
    return {
        "resource": [
            {
                "aws_s3_bucket": [
                    {
                        "insecure": {
                            "bucket": "insecure-bucket",
                            "versioning": [{"enabled": False}],
                        },
                        "secure": {
                            "bucket": "secure-bucket",
                            "versioning": [{"enabled": True}],
                        },
                    }
                ]
            }
        ]
    }


@pytest.fixture
def bucket_versioning_rule():
    return _rule(
        [_make_condition("versioning.enabled", Operator.EQUALS, False)],
        id="ORG-S3-001",
        name="S3 buckets must enable versioning",
        severity=Severity.HIGH,
        remediation="Enable bucket versioning.",
    )


class TestAnalyze:
    def test_flags_only_the_resource_that_violates_the_rule(
        self, tf_content_with_unversioned_bucket, bucket_versioning_rule
    ):
        engine = CustomRuleEngine([bucket_versioning_rule])

        vulns = engine.analyze(tf_content_with_unversioned_bucket)

        assert len(vulns) == 1
        assert vulns[0].resource == "insecure"
        assert vulns[0].severity is Severity.HIGH
        assert "ORG-S3-001" in vulns[0].message
        assert vulns[0].remediation == "Enable bucket versioning."

    def test_skips_rules_when_resource_type_does_not_match(
        self, tf_content_with_unversioned_bucket
    ):
        rule = _rule(
            [_make_condition("anything", Operator.EXISTS)],
            resource_type="aws_instance",
        )
        engine = CustomRuleEngine([rule])

        assert engine.analyze(tf_content_with_unversioned_bucket) == []

    def test_returns_empty_when_no_rules_configured(self, tf_content_with_unversioned_bucket):
        engine = CustomRuleEngine([])

        assert engine.analyze(tf_content_with_unversioned_bucket) == []

    def test_returns_empty_when_no_resources_in_tf(self, bucket_versioning_rule):
        engine = CustomRuleEngine([bucket_versioning_rule])

        assert engine.analyze({}) == []
        assert engine.analyze({"resource": []}) == []

    def test_applies_custom_points_override(self, tf_content_with_unversioned_bucket):
        rule = CustomRule(
            id="ORG-PTS-1",
            name="pts override",
            severity=Severity.HIGH,
            points=7,
            resource_type="aws_s3_bucket",
            conditions=[_make_condition("versioning.enabled", Operator.EQUALS, False)],
        )
        engine = CustomRuleEngine([rule])

        [vuln] = engine.analyze(tf_content_with_unversioned_bucket)

        assert vuln.points == 7

    def test_default_points_come_from_severity(self, tf_content_with_unversioned_bucket):
        rule = _rule(
            [_make_condition("versioning.enabled", Operator.EQUALS, False)],
            severity=Severity.MEDIUM,
        )
        engine = CustomRuleEngine([rule])

        [vuln] = engine.analyze(tf_content_with_unversioned_bucket)

        # MEDIUM default is POINTS_MEDIUM = 10
        assert vuln.points == 10


# ---------------------------------------------------------------------------
# Integration: SecurityRuleEngine + CustomRuleEngine
# ---------------------------------------------------------------------------


class TestSecurityRuleEngineIntegration:
    def test_custom_vulnerabilities_are_appended_to_built_in_findings(
        self, tf_content_with_unversioned_bucket, bucket_versioning_rule
    ):
        custom_engine = CustomRuleEngine([bucket_versioning_rule])
        engine = SecurityRuleEngine(custom_rule_engine=custom_engine)

        vulns = engine.analyze(tf_content_with_unversioned_bucket, raw_content="")

        custom_hits = [v for v in vulns if "ORG-S3-001" in v.message]
        assert len(custom_hits) == 1
        assert isinstance(custom_hits[0], Vulnerability)

    def test_built_in_engine_unchanged_when_no_custom_engine(self):
        # Baseline: no custom engine → behaves exactly as before.
        engine = SecurityRuleEngine()

        vulns = engine.analyze({"resource": []}, raw_content="")

        assert vulns == []


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCliCustomRulesFlag:
    def test_cli_loads_custom_rules_file(self, tmp_path, run_cli, scan_result_factory):
        rules_path = _write_yaml(
            tmp_path,
            """
            rules:
              - id: CLI-1
                name: CLI rule
                severity: LOW
                resource_type: aws_s3_bucket
                conditions:
                  - attribute: versioning.enabled
                    operator: equals
                    value: false
            """,
        )
        target = tmp_path / "config.tf"
        target.write_text("# placeholder", encoding="utf-8")

        _, _, exit_code = run_cli(
            ["--custom-rules", str(rules_path), "--no-history", str(target)],
            scan_result_factory(score=20, filepath=str(target)),
        )

        assert exit_code == 0

    def test_cli_rejects_bad_rule_path_with_nonzero_exit(self, tmp_path, capsys, monkeypatch):
        # run_cli patches _build_scanner, so exercise main() directly here to
        # let the real _build_scanner propagate CustomRuleError → sys.exit(2).
        import sys as _sys

        from terrasafe import cli

        target = tmp_path / "config.tf"
        target.write_text("# placeholder", encoding="utf-8")
        missing_rules = tmp_path / "missing.yml"

        monkeypatch.setattr(
            _sys,
            "argv",
            [
                "terrasafe",
                "--custom-rules",
                str(missing_rules),
                "--no-history",
                str(target),
            ],
        )

        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()
