"""Tool-neutral vulnerability taxonomy and per-tool rule-id mappings.

The comparison is fair only if every tool's findings are projected onto the same
set of security *concepts*. ``TAXONOMY`` is that shared set (it mirrors
``dataset/build_corpus.py``). Each ``*_MAP`` translates a tool's native rule id
into a taxonomy category; ids that are not present are intentionally ignored
(either out-of-taxonomy concerns such as "add a description to this SG rule", or
TerraVault's whole-configuration ``MISSING_LOGGING`` heuristic that has no
per-resource equivalent).

Mappings were built by harvesting the rule ids each tool emits on the labelled
corpus (``python -m evaluation.runners``) and assigning each to the category of
the case(s) it fires on. ``IGNORED_*`` lists the noise rules we saw and dropped
on purpose, so the audit in ``evaluate.py`` can assert that every observed id is
accounted for — nothing is dropped silently.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

TAXONOMY: List[str] = [
    "PUBLIC_INGRESS",
    "UNRESTRICTED_EGRESS",
    "UNENCRYPTED_RDS",
    "UNENCRYPTED_EBS",
    "PUBLIC_RDS",
    "IMDSV1",
    "IAM_WILDCARD",
    "PUBLIC_S3",
    "MISSING_VPC_FLOW_LOGS",
    "PUBLIC_INSTANCE",
    "HARDCODED_SECRET",
]

# ---------------------------------------------------------------------------
# TerraVault: native finding message -> category (substring match, in order).
# ---------------------------------------------------------------------------
_TERRAVAULT_RULES = [
    ("Unrestricted egress", "UNRESTRICTED_EGRESS"),
    ("exposed to internet", "PUBLIC_INGRESS"),
    ("HTTP/HTTPS port", "PUBLIC_INGRESS"),
    ("Open security group", "PUBLIC_INGRESS"),
    ("Unencrypted RDS", "UNENCRYPTED_RDS"),
    ("Unencrypted EBS", "UNENCRYPTED_EBS"),
    ("Publicly accessible RDS", "PUBLIC_RDS"),
    ("IMDSv1", "IMDSV1"),
    ("IAM policy", "IAM_WILDCARD"),
    ("S3 bucket with public", "PUBLIC_S3"),
    ("Missing VPC flow logs", "MISSING_VPC_FLOW_LOGS"),
    ("auto-assigns a public IP", "PUBLIC_INSTANCE"),
    ("Hardcoded", "HARDCODED_SECRET"),
    # "[HIGH] Missing logging" -> intentionally unmapped (out of shared taxonomy)
]


def terravault_category(message: str) -> Optional[str]:
    for needle, cat in _TERRAVAULT_RULES:
        if needle in message:
            return cat
    return None


# ---------------------------------------------------------------------------
# Checkov (CKV_AWS_* / CKV2_AWS_* / CKV_SECRET_*) -> category.
# ---------------------------------------------------------------------------
CHECKOV_MAP: Dict[str, str] = {
    # public ingress (port-specific rules)
    "CKV_AWS_24": "PUBLIC_INGRESS",   # SSH 22 open
    "CKV_AWS_25": "PUBLIC_INGRESS",   # RDP 3389 open
    "CKV_AWS_260": "PUBLIC_INGRESS",  # ingress 0.0.0.0/0 to port 80
    "CKV_AWS_277": "PUBLIC_INGRESS",  # ingress 0.0.0.0/0 to sensitive ports
    # egress
    "CKV_AWS_382": "UNRESTRICTED_EGRESS",
    # encryption
    "CKV_AWS_16": "UNENCRYPTED_RDS",
    "CKV_AWS_3": "UNENCRYPTED_EBS",
    # public endpoints
    "CKV_AWS_17": "PUBLIC_RDS",
    "CKV_AWS_88": "PUBLIC_INSTANCE",
    # metadata service
    "CKV_AWS_79": "IMDSV1",
    # s3 public access block
    "CKV_AWS_53": "PUBLIC_S3",
    "CKV_AWS_54": "PUBLIC_S3",
    "CKV_AWS_55": "PUBLIC_S3",
    "CKV_AWS_56": "PUBLIC_S3",
    "CKV2_AWS_6": "PUBLIC_S3",
    # vpc flow logs
    "CKV2_AWS_11": "MISSING_VPC_FLOW_LOGS",
    # iam wildcards
    "CKV_AWS_1": "IAM_WILDCARD",
    "CKV_AWS_49": "IAM_WILDCARD",
    "CKV_AWS_62": "IAM_WILDCARD",
    "CKV_AWS_63": "IAM_WILDCARD",
    "CKV_AWS_111": "IAM_WILDCARD",
    "CKV_AWS_286": "IAM_WILDCARD",
    "CKV_AWS_287": "IAM_WILDCARD",
    "CKV_AWS_288": "IAM_WILDCARD",
    "CKV_AWS_289": "IAM_WILDCARD",
    "CKV_AWS_290": "IAM_WILDCARD",
    "CKV_AWS_355": "IAM_WILDCARD",   # wildcard (*) resource for restrictable actions
    "CKV2_AWS_40": "IAM_WILDCARD",   # policy grants full IAM privileges
}
# Filled/verified from harvest in evaluate.py audit.
CHECKOV_SECRET_PREFIX = "CKV_SECRET_"  # any secrets-framework finding -> HARDCODED_SECRET

# ---------------------------------------------------------------------------
# tfsec (long_id) -> category.
# ---------------------------------------------------------------------------
TFSEC_MAP: Dict[str, str] = {
    "aws-ec2-no-public-ingress-sgr": "PUBLIC_INGRESS",
    "aws-vpc-no-public-ingress-sgr": "PUBLIC_INGRESS",
    "aws-ec2-no-public-egress-sgr": "UNRESTRICTED_EGRESS",
    "aws-vpc-no-public-egress-sgr": "UNRESTRICTED_EGRESS",
    "aws-rds-encrypt-instance-storage-data": "UNENCRYPTED_RDS",
    "aws-ec2-enable-volume-encryption": "UNENCRYPTED_EBS",
    "aws-ebs-encryption-customer-key": "UNENCRYPTED_EBS",
    "aws-rds-no-public-db-access": "PUBLIC_RDS",
    "aws-rds-enable-public-access": "PUBLIC_RDS",
    "aws-ec2-enforce-http-token-imds": "IMDSV1",
    "aws-iam-no-policy-wildcards": "IAM_WILDCARD",
    "aws-s3-block-public-acls": "PUBLIC_S3",
    "aws-s3-block-public-policy": "PUBLIC_S3",
    "aws-s3-ignore-public-acls": "PUBLIC_S3",
    "aws-s3-no-public-buckets": "PUBLIC_S3",
    "aws-s3-specify-public-access-block": "PUBLIC_S3",
    "aws-ec2-require-vpc-flow-logs-for-all-vpcs": "MISSING_VPC_FLOW_LOGS",
    "aws-ec2-no-public-ip": "PUBLIC_INSTANCE",
    "aws-ec2-no-public-ip-subnet": "PUBLIC_INSTANCE",
    "general-secrets-sensitive-in-attribute": "HARDCODED_SECRET",
    "general-secrets-sensitive-in-variable": "HARDCODED_SECRET",
}

# ---------------------------------------------------------------------------
# Terrascan (AC_AWS_* rule ids) -> category. Opaque ids; filled from harvest.
# ---------------------------------------------------------------------------
TERRASCAN_MAP: Dict[str, str] = {
    "AC_AWS_0227": "PUBLIC_INGRESS",         # port22OpenToInternet
    "AC_AWS_0229": "PUBLIC_INGRESS",         # port443OpenToInternet
    "AC_AWS_0230": "PUBLIC_INGRESS",         # port3389OpenToInternet
    "AC_AWS_0275": "PUBLIC_INGRESS",         # portWideOpenToPublic
    "AC_AWS_0058": "UNENCRYPTED_RDS",        # rdsHasStorageEncrypted
    "AC_AWS_0054": "PUBLIC_RDS",             # rdsPubliclyAccessible
    "AC_AWS_0479": "IMDSV1",                 # ec2UsingIMDSv1
    "AC_AWS_0369": "MISSING_VPC_FLOW_LOGS",  # vpcFlowLogsNotEnabled
}
# Intentionally NOT mapped: AC_AWS_0320 / AC_AWS_0322 (networkPortXExposedToprivate)
# flag ports reachable even from *private* CIDRs and fire on hardened cases, so
# they are not equivalent to the public-internet PUBLIC_INGRESS concept. Terrascan
# (v1.19.x bundled AWS policies) has no rule that fires specifically on unencrypted
# EBS, the S3 public-access-block pattern, IAM wildcard policy documents, open
# egress, public instance IPs, or hardcoded secrets in this corpus.


def map_rule_ids(tool: str, rule_ids: List[str]) -> Set[str]:
    """Project a tool's raw rule ids onto the shared taxonomy."""
    cats: Set[str] = set()
    for rid in rule_ids:
        cat = _single(tool, rid)
        if cat:
            cats.add(cat)
    return cats


def _single(tool: str, rid: str) -> Optional[str]:
    if tool == "checkov":
        if rid.startswith(CHECKOV_SECRET_PREFIX):
            return "HARDCODED_SECRET"
        return CHECKOV_MAP.get(rid)
    if tool == "tfsec":
        return TFSEC_MAP.get(rid)
    if tool == "terrascan":
        if rid in TERRASCAN_MAP:
            return TERRASCAN_MAP[rid]
        return None
    return None
