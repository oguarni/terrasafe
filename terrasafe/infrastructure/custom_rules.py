"""Custom rule extensibility for TerraSafe.

Loads user-defined YAML rules and evaluates them against parsed HCL
resources. The engine is intentionally declarative — organizations can
express policies without touching Python code.

A rule file looks like:

    version: "1.0"
    rules:
      - id: ORG-S3-001
        name: S3 buckets must enable versioning
        severity: HIGH
        resource_type: aws_s3_bucket
        match: all            # any | all (default: all)
        conditions:
          - attribute: versioning.enabled
            operator: equals
            value: true
            negate: true       # fires when equality does NOT hold
        remediation: "Enable versioning { enabled = true } on the bucket."

Supported operators: equals, not_equals, in, not_in, contains,
not_contains, regex, exists, missing, greater_than, less_than.
"""
from __future__ import annotations

import logging
import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..domain.models import Severity, Vulnerability
from ..domain.security_rules import (
    POINTS_CRITICAL,
    POINTS_HIGH,
    POINTS_INFO,
    POINTS_LOW,
    POINTS_MEDIUM,
)

logger = logging.getLogger(__name__)


class CustomRuleError(Exception):
    """Raised when a custom rule file is missing, malformed, or invalid."""


class Operator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    EXISTS = "exists"
    MISSING = "missing"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"


_DEFAULT_POINTS: Dict[Severity, int] = {
    Severity.CRITICAL: POINTS_CRITICAL,
    Severity.HIGH: POINTS_HIGH,
    Severity.MEDIUM: POINTS_MEDIUM,
    Severity.LOW: POINTS_LOW,
    Severity.INFO: POINTS_INFO,
}

_MISSING = object()


class Condition(BaseModel):
    """One predicate against a resource attribute."""

    model_config = ConfigDict(extra="forbid")

    attribute: str = Field(min_length=1)
    operator: Operator
    value: Any = None

    @field_validator("attribute")
    @classmethod
    def _strip_attribute(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("attribute must be non-empty")
        return stripped


class CustomRule(BaseModel):
    """A single organizational security rule."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str = ""
    severity: Severity
    points: Optional[int] = Field(default=None, ge=0, le=100)
    resource_type: str = Field(min_length=1)
    match: str = "all"
    conditions: List[Condition] = Field(min_length=1)
    remediation: str = ""

    @field_validator("match")
    @classmethod
    def _validate_match(cls, v: str) -> str:
        lowered = v.lower()
        if lowered not in {"any", "all"}:
            raise ValueError("match must be 'any' or 'all'")
        return lowered

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.upper()
        return v

    def resolved_points(self) -> int:
        if self.points is not None:
            return self.points
        return _DEFAULT_POINTS[self.severity]


class CustomRuleSet(BaseModel):
    """Top-level container for a YAML rule document."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    rules: List[CustomRule] = Field(min_length=1)


def _resolve_attribute(node: Any, path: str) -> Any:
    """Walk a dotted path through the parsed HCL structure.

    Returns the ``_MISSING`` sentinel when the path does not exist. Lists are
    unwrapped by taking the first element unless further tokens are still to
    come, in which case every list element is searched and the first matching
    subtree wins. This mirrors how HCL2 emits single-block attributes as
    one-element lists.
    """
    current: Any = node
    for token in path.split("."):
        if current is _MISSING:
            return _MISSING
        if isinstance(current, list):
            found = _MISSING
            for item in current:
                if isinstance(item, dict) and token in item:
                    found = item[token]
                    break
            if found is _MISSING:
                return _MISSING
            current = found
        elif isinstance(current, dict):
            if token not in current:
                return _MISSING
            current = current[token]
        else:
            return _MISSING
    if isinstance(current, list) and len(current) == 1:
        return current[0]
    return current


def _evaluate_condition(condition: Condition, resource_config: Any) -> bool:
    actual = _resolve_attribute(resource_config, condition.attribute)
    expected = condition.value
    op = condition.operator

    if op is Operator.EXISTS:
        return actual is not _MISSING
    if op is Operator.MISSING:
        return actual is _MISSING

    if actual is _MISSING:
        return False

    if op is Operator.EQUALS:
        return bool(actual == expected)
    if op is Operator.NOT_EQUALS:
        return bool(actual != expected)
    if op is Operator.IN:
        return isinstance(expected, Iterable) and not isinstance(expected, (str, bytes)) and actual in expected
    if op is Operator.NOT_IN:
        return isinstance(expected, Iterable) and not isinstance(expected, (str, bytes)) and actual not in expected
    if op is Operator.CONTAINS:
        if isinstance(actual, (list, tuple, set)):
            return expected in actual
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        return False
    if op is Operator.NOT_CONTAINS:
        if isinstance(actual, (list, tuple, set)):
            return expected not in actual
        if isinstance(actual, str) and isinstance(expected, str):
            return expected not in actual
        return False
    if op is Operator.REGEX:
        if not isinstance(actual, str) or not isinstance(expected, str):
            return False
        try:
            return re.search(expected, actual) is not None
        except re.error as exc:
            logger.warning("Invalid regex %r in custom rule: %s", expected, exc)
            return False
    if op in (Operator.GREATER_THAN, Operator.LESS_THAN):
        try:
            a_val = float(actual)  # type: ignore[arg-type]
            b_val = float(expected)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        return a_val > b_val if op is Operator.GREATER_THAN else a_val < b_val
    return False


class CustomRuleEngine:
    """Evaluates a set of :class:`CustomRule` against parsed HCL."""

    def __init__(self, rules: Optional[List[CustomRule]] = None):
        self.rules: List[CustomRule] = list(rules or [])

    def __len__(self) -> int:
        return len(self.rules)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "CustomRuleEngine":
        return cls(load_rules_file(path))

    @classmethod
    def from_directory(cls, path: Union[str, Path]) -> "CustomRuleEngine":
        directory = Path(path)
        if not directory.is_dir():
            raise CustomRuleError(f"Custom rules directory not found: {directory}")
        collected: List[CustomRule] = []
        seen_ids: Dict[str, Path] = {}
        for yml in sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))):
            for rule in load_rules_file(yml):
                if rule.id in seen_ids:
                    raise CustomRuleError(
                        f"Duplicate rule id '{rule.id}' in {yml} "
                        f"(first defined in {seen_ids[rule.id]})"
                    )
                seen_ids[rule.id] = yml
                collected.append(rule)
        return cls(collected)

    @classmethod
    def from_path(cls, path: Union[str, Path]) -> "CustomRuleEngine":
        target = Path(path)
        if target.is_dir():
            return cls.from_directory(target)
        return cls.from_file(target)

    def analyze(self, tf_content: Dict[str, Any]) -> List[Vulnerability]:
        """Run every rule against every resource in ``tf_content``.

        Iterates over the HCL2-shaped ``tf_content['resource']`` blocks and
        emits a :class:`Vulnerability` for each rule that matches a resource
        instance.
        """
        if not self.rules:
            return []
        resources = tf_content.get("resource") if isinstance(tf_content, dict) else None
        if not resources:
            return []

        vulns: List[Vulnerability] = []
        for block in resources:
            if not isinstance(block, dict):
                continue
            for resource_type, entries in block.items():
                items = entries if isinstance(entries, list) else [entries]
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    for resource_name, resource_config in item.items():
                        for rule in self.rules:
                            if rule.resource_type != resource_type:
                                continue
                            if self._rule_matches(rule, resource_config):
                                vulns.append(self._build_vuln(rule, resource_name))
        return vulns

    def _rule_matches(self, rule: CustomRule, resource_config: Any) -> bool:
        checks = (_evaluate_condition(c, resource_config) for c in rule.conditions)
        if rule.match == "any":
            return any(checks)
        return all(checks)

    def _build_vuln(self, rule: CustomRule, resource_name: str) -> Vulnerability:
        message = f"[{rule.severity.value}] {rule.name} ({rule.id})"
        remediation = rule.remediation or rule.description
        return Vulnerability(
            severity=rule.severity,
            points=rule.resolved_points(),
            message=message,
            resource=resource_name,
            remediation=remediation,
        )


def load_rules_file(path: Union[str, Path]) -> List[CustomRule]:
    """Parse and validate a single YAML rules file."""
    source = Path(path)
    if not source.is_file():
        raise CustomRuleError(f"Custom rules file not found: {source}")
    try:
        with source.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise CustomRuleError(f"Invalid YAML in {source}: {exc}") from exc

    if data is None:
        raise CustomRuleError(f"{source}: file is empty")
    if not isinstance(data, dict):
        raise CustomRuleError(f"{source}: top-level document must be a mapping")

    try:
        ruleset = CustomRuleSet(**data)
    except ValidationError as exc:
        raise CustomRuleError(f"{source}: {exc}") from exc

    ids = [rule.id for rule in ruleset.rules]
    duplicates = sorted({rid for rid in ids if ids.count(rid) > 1})
    if duplicates:
        raise CustomRuleError(f"{source}: duplicate rule ids {duplicates}")

    logger.info("Loaded %d custom rule(s) from %s", len(ruleset.rules), source)
    return ruleset.rules
