"""Structural feature extraction - Application layer.

Extracts security-relevant *structural* features directly from parsed
Terraform, independent of the deterministic rule-engine output. This is what
makes the hybrid model genuinely hybrid: the Isolation Forest scores the
*shape* of the infrastructure (size, network exposure, encryption coverage,
logging posture, secret hygiene) rather than re-counting the findings the
rules already produced. As a result the ML signal can flag anomalous
configurations that fall outside the fixed 7-rule catalogue.

Keep ``FEATURE_NAMES``, ``FEATURE_BOUNDS`` and the secure-baseline generator in
``infrastructure/ml_model.py`` in sync — they all describe the same vector.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Tuple

import numpy as np

# Feature vector layout. Order is load-bearing: extraction, validation bounds,
# the trained scaler, and the baseline generator all index by this order.
FEATURE_NAMES: Tuple[str, ...] = (
    "resource_count",            # total resources declared
    "resource_type_diversity",   # distinct resource types
    "ingress_rule_count",        # inbound network rules (attack surface breadth)
    "public_exposure_count",     # resources/rules exposed to the public internet
    "iam_resource_count",        # IAM principals/policies (privilege surface)
    "encryption_coverage",       # fraction of encryptable storage encrypted (1.0 if none)
    "logging_resource_count",    # audit/observability resources present
    "secret_parametrization",    # fraction of sensitive values pulled from vars (1.0 if none)
)

# Inclusive (min, max) clip bounds per feature, same order as FEATURE_NAMES.
# Counts are clipped well above any realistic single-file value; the two ratio
# features are bounded to [0, 1].
FEATURE_BOUNDS: Tuple[Tuple[float, float], ...] = (
    (0.0, 10000.0),  # resource_count
    (0.0, 200.0),    # resource_type_diversity
    (0.0, 1000.0),   # ingress_rule_count
    (0.0, 1000.0),   # public_exposure_count
    (0.0, 1000.0),   # iam_resource_count
    (0.0, 1.0),      # encryption_coverage
    (0.0, 1000.0),   # logging_resource_count
    (0.0, 1.0),      # secret_parametrization
)

NUM_FEATURES = len(FEATURE_NAMES)

# Encryptable storage types -> the attribute that, when truthy, marks the
# resource as encrypted at rest.
_ENCRYPTABLE_TYPES: Dict[str, str] = {
    "aws_db_instance": "storage_encrypted",
    "aws_rds_cluster": "storage_encrypted",
    "aws_ebs_volume": "encrypted",
    "aws_efs_file_system": "encrypted",
}

# Resources that provide audit logging / traffic visibility.
_LOGGING_TYPES = frozenset({
    "aws_cloudtrail",
    "aws_cloudwatch_log_group",
    "aws_flow_log",
})

# Boolean attributes that place a resource directly on the public internet.
_PUBLIC_BOOL_ATTRS = (
    "publicly_accessible",
    "associate_public_ip_address",
    "map_public_ip_on_launch",
)

_PUBLIC_CIDRS = ("0.0.0.0/0", "::/0")

# Sensitive assignments of the form ``key = <value>`` in the raw HCL. Used to
# measure how many secrets come from variables vs. hardcoded literals. The
# value is captured as either a quoted string or a bare token (e.g. ``var.x``);
# no line anchors, so it matches both block-style and inline HCL.
_SECRET_ASSIGNMENT_RE = re.compile(
    r'(?i)(?:password|api_key|secret_key|token|secret)\s*=\s*'
    r'("(?:[^"\\]|\\.)*"|[^\s,}]+)'
)


def _is_true(value: Any) -> bool:
    """Interpret an HCL attribute value as a boolean (handles list-wrapping)."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return False


def _as_dict(config: Any) -> Dict[str, Any]:
    """Normalise a resource body to a dict (hcl2 sometimes list-wraps blocks)."""
    if isinstance(config, list):
        config = config[0] if config and isinstance(config[0], dict) else {}
    return config if isinstance(config, dict) else {}


def _iter_resources(tf_content: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """Yield ``(resource_type, resource_body)`` for every declared resource."""
    if not isinstance(tf_content, dict):
        return
    resources = tf_content.get("resource", [])
    if isinstance(resources, dict):
        resources = [resources]
    if not isinstance(resources, list):
        return
    for block in resources:
        if not isinstance(block, dict):
            continue
        for rtype, named in block.items():
            named_items = named if isinstance(named, list) else [named]
            for named_item in named_items:
                if not isinstance(named_item, dict):
                    continue
                for _name, body in named_item.items():
                    yield rtype, _as_dict(body)


def _ingress_blocks(body: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the ingress rule blocks declared on a security group body."""
    ingress = body.get("ingress", [])
    if isinstance(ingress, dict):
        return [ingress]
    if isinstance(ingress, list):
        return [item for item in ingress if isinstance(item, dict)]
    return []


def _ingress_is_public(ingress: Dict[str, Any]) -> bool:
    """True if an ingress rule opens to a public CIDR (0.0.0.0/0 or ::/0)."""
    cidrs = ingress.get("cidr_blocks", []) or ingress.get("ipv6_cidr_blocks", [])
    if isinstance(cidrs, str):
        cidrs = [cidrs]
    if not isinstance(cidrs, list):
        return False
    return any(cidr in _PUBLIC_CIDRS for cidr in cidrs)


def _secret_parametrization(raw_content: str) -> float:
    """Fraction of sensitive assignments sourced from variables, not literals.

    A quoted literal with no interpolation (e.g. ``password = "hunter2"``) is
    hardcoded; ``var.x``, ``local.x`` or ``"${...}"`` references are
    parametrized. Returns 1.0 when no sensitive assignments exist.
    """
    rhs_values = _SECRET_ASSIGNMENT_RE.findall(raw_content)
    if not rhs_values:
        return 1.0
    hardcoded = 0
    for rhs in rhs_values:
        stripped = rhs.strip()
        if stripped.startswith('"') and "${" not in stripped:
            hardcoded += 1
    return (len(rhs_values) - hardcoded) / len(rhs_values)


class StructuralFeatureExtractor:
    """Builds the structural feature vector consumed by the ML predictor."""

    def extract(self, tf_content: Dict[str, Any], raw_content: str) -> np.ndarray:
        """Return a ``(1, NUM_FEATURES)`` float array of structural features."""
        resource_count = 0
        resource_types: set[str] = set()
        ingress_rule_count = 0
        public_exposure = 0
        iam_resource_count = 0
        logging_resource_count = 0
        encryptable_total = 0
        encryptable_secure = 0

        for rtype, body in _iter_resources(tf_content):
            resource_count += 1
            resource_types.add(rtype)

            if rtype.startswith("aws_iam_"):
                iam_resource_count += 1
            if rtype in _LOGGING_TYPES:
                logging_resource_count += 1

            if rtype in _ENCRYPTABLE_TYPES:
                encryptable_total += 1
                if _is_true(body.get(_ENCRYPTABLE_TYPES[rtype])):
                    encryptable_secure += 1

            if any(_is_true(body.get(attr)) for attr in _PUBLIC_BOOL_ATTRS):
                public_exposure += 1

            if rtype == "aws_security_group":
                for ingress in _ingress_blocks(body):
                    ingress_rule_count += 1
                    if _ingress_is_public(ingress):
                        public_exposure += 1

        encryption_coverage = (
            encryptable_secure / encryptable_total if encryptable_total else 1.0
        )

        features = np.array([[
            resource_count,
            len(resource_types),
            ingress_rule_count,
            public_exposure,
            iam_resource_count,
            encryption_coverage,
            logging_resource_count,
            _secret_parametrization(raw_content),
        ]], dtype=np.float64)

        return features
