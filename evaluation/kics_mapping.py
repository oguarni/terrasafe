"""Audited mapping from KICS (Checkmarx) query fixtures to TerraVault's taxonomy.

This is the scientific core of the third-party-corpus evaluation (harness
extension "A.2"). It exists to retire the construct-validity threat named in the
manuscript: on the home corpus the same author wrote the rules, the cases *and*
the labels, so a perfect score could just mean "the author tested exactly what
they built". Here the corpus and its positive/negative labels come from a source
we did not write.

Why KICS specifically
---------------------
KICS is **not** one of the four tools under comparison (TerraVault, Checkov,
tfsec, Terrascan). Its per-query ``test/positive*.tf`` / ``test/negative*.tf``
fixtures are therefore foreign to *every* tool in the benchmark — no tool has a
home-field advantage from being evaluated on its own test suite (which is why we
do **not** use Checkov's/tfsec's/Terrascan's own fixtures). The labels — which
file is a positive vs. negative example of a security concept — are authored by
the KICS maintainers, so the taxonomy↔rules↔labels circularity is broken.

What ``tv_scope`` means (and why the report splits on it)
--------------------------------------------------------
Each included query is mapped to one of TerraVault's 11 taxonomy categories, and
records ``tv_scope`` — the exact AWS resource type(s) TerraVault's rule for that
category inspects (read off ``domain/security_rules.py``). A fixture is *in
TerraVault's scope* iff it declares at least one of those resource types. When a
KICS fixture exercises a **sibling** resource TerraVault never claimed to cover
(e.g. ``aws_rds_cluster`` for RDS encryption, when TerraVault's rule targets
``aws_db_instance``), a miss is a *resource-coverage gap by design*, not a
detection failure. The two are reported separately so neither is hidden and the
home-corpus 100/100/100 is bounded honestly rather than flattered.

``EXCLUDED`` records every near-miss query we deliberately drop, each with a
reason — the same "nothing is dropped silently" discipline as the ``IGNORED_*``
lists in ``taxonomy.py``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List


@dataclass(frozen=True)
class KicsQuery:
    """One KICS query directory mapped onto the shared TerraVault taxonomy.

    Attributes:
        directory: query folder under ``assets/queries/terraform/aws``.
        category: the TerraVault taxonomy category this concept maps to.
        tv_scope: AWS resource types TerraVault's rule for ``category`` inspects.
            A fixture counts as *in scope* iff it declares one of these; misses
            on out-of-scope fixtures are coverage gaps, not failures.
        note: provenance / caveat surfaced in the audit and report.
    """

    directory: str
    category: str
    tv_scope: FrozenSet[str]
    note: str = ""


# ---------------------------------------------------------------------------
# Included queries. Six categories land cleanly in TerraVault's scope; two
# (UNENCRYPTED_RDS, IAM_WILDCARD) are included precisely because KICS exercises a
# sibling resource TerraVault does not cover, which is the finding worth
# reporting — the external-validity boundary of the home result.
# ---------------------------------------------------------------------------
INCLUDED: List[KicsQuery] = [
    # -- cleanly in TerraVault's rule scope --------------------------------
    KicsQuery(
        "unrestricted_security_group_ingress", "PUBLIC_INGRESS",
        frozenset({"aws_security_group"}),
        "TerraVault reads inline `ingress` on `aws_security_group`; KICS also "
        "ships `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule` "
        "fixtures, which fall out of scope and surface as a coverage gap.",
    ),
    KicsQuery(
        "ebs_volume_encryption_disabled", "UNENCRYPTED_EBS",
        frozenset({"aws_ebs_volume"}),
        "Direct match: `aws_ebs_volume { encrypted = false }`.",
    ),
    KicsQuery(
        "rds_db_instance_publicly_accessible", "PUBLIC_RDS",
        frozenset({"aws_db_instance"}),
        "Direct match on `aws_db_instance { publicly_accessible = true }`; the "
        "module-based fixtures are excluded by the builder (unparseable).",
    ),
    KicsQuery(
        "instance_uses_metadata_service_IMDSv1", "IMDSV1",
        frozenset({"aws_instance"}),
        "TerraVault checks `aws_instance` metadata_options.http_tokens only; "
        "KICS `negative3`/`negative6` mitigate via http_endpoint=disabled, "
        "which TerraVault ignores -> expected false positive (real limitation). "
        "aws_launch_template / aws_launch_configuration fixtures are out of scope.",
    ),
    KicsQuery(
        "ec2_instance_has_public_ip", "PUBLIC_INSTANCE",
        frozenset({"aws_instance"}),
        "Direct match on `aws_instance { associate_public_ip_address = true }`.",
    ),
    KicsQuery(
        "s3_bucket_allows_public_acl", "PUBLIC_S3",
        frozenset({"aws_s3_bucket_public_access_block"}),
        "TerraVault flags a bucket-level public_access_block with any of the "
        "four protections false; KICS single-flag negatives may still leave "
        "other flags false -> expected false positives on those negatives.",
    ),
    KicsQuery(
        "s3_bucket_without_ignore_public_acl", "PUBLIC_S3",
        frozenset({"aws_s3_bucket_public_access_block"}),
        "ignore_public_acls=false sub-check of the public_access_block concept.",
    ),
    KicsQuery(
        "s3_bucket_without_restriction_of_public_bucket", "PUBLIC_S3",
        frozenset({"aws_s3_bucket_public_access_block"}),
        "restrict_public_buckets=false sub-check; account-level "
        "`aws_s3_account_public_access_block` variants are out of scope.",
    ),
    KicsQuery(
        "s3_bucket_with_public_policy", "PUBLIC_S3",
        frozenset({"aws_s3_bucket_public_access_block"}),
        "block_public_policy=false sub-check; account-level and module variants "
        "fall out of scope.",
    ),
    # -- included to measure the coverage boundary (sibling resource) -------
    KicsQuery(
        "rds_storage_not_encrypted", "UNENCRYPTED_RDS",
        frozenset({"aws_db_instance"}),
        "KICS fixtures use `aws_rds_cluster`; TerraVault's encryption rule "
        "targets `aws_db_instance`. Every fixture is therefore out of scope: "
        "the honest finding is that KICS does not exercise TerraVault's RDS "
        "rule at all, and instance-only checkers cannot fire here.",
    ),
    KicsQuery(
        "iam_policy_grants_full_permissions", "IAM_WILDCARD",
        frozenset({"aws_iam_role_policy"}),
        "KICS uses `aws_iam_policy` / `aws_iam_user_policy` with "
        '`Action:[list] + Resource:"*"`; TerraVault checks `aws_iam_role_policy` '
        'documents for the literal `"Action": "*"`. Double mismatch (resource '
        "type + wildcard shape) -> out of scope, a coverage boundary.",
    ),
]


# ---------------------------------------------------------------------------
# Deliberately excluded near-miss queries, each with a reason. Kept here so the
# builder's audit can assert we considered them and the choice is reviewable.
# ---------------------------------------------------------------------------
EXCLUDED: Dict[str, str] = {
    "vpc_flowlogs_disabled":
        "Concept mismatch: KICS requires the aws_flow_log to *reference this "
        "VPC* (reference-integrity) and its positives all declare an "
        "aws_flow_log; TerraVault's rule checks flow-log *presence*, so a "
        "presence check cannot reproduce KICS's labels for any tool.",
    "hardcoded_aws_access_key":
        "Detection-surface mismatch: KICS flags secrets in `user_data`; "
        "TerraVault regexes password=/api_key=/secret_key=/token=. Fixtures are "
        "largely external modules and none use the attributes TerraVault scans.",
    "hardcoded_aws_access_key_in_lambda":
        "Detection-surface mismatch: KICS flags keys in aws_lambda_function "
        "environment blocks, outside TerraVault's password/token regex surface.",
    "rds_database_cluster_not_encrypted":
        "Redundant with rds_storage_not_encrypted (also aws_rds_cluster); "
        "omitted to avoid double-counting the same sibling-resource gap.",
    "s3_bucket_allows_public_acl_via_acl_attribute":
        "Different S3 sub-concept (ACL grant) than TerraVault's "
        "public_access_block scope; excluded to keep PUBLIC_S3 aligned.",
    "s3_bucket_public_acl_overridden_by_public_access_block":
        "Tests interaction semantics between ACL and PAB, not a plain "
        "public-exposure label; ambiguous ground truth.",
}


def query_index() -> Dict[str, KicsQuery]:
    """Return ``directory -> KicsQuery`` for the included queries."""
    return {q.directory: q for q in INCLUDED}


def categories_covered() -> List[str]:
    """Distinct taxonomy categories the foreign corpus can exercise."""
    seen: List[str] = []
    for q in INCLUDED:
        if q.category not in seen:
            seen.append(q.category)
    return seen
