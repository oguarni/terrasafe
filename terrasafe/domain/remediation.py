"""Auto-remediation engine - generates HCL patches for detected vulnerabilities.

The engine mutates raw HCL text via regex substitutions so that original
formatting, comments, and attribute ordering are preserved. Parsed tf_content
is consulted only for structural checks (e.g. whether ``aws_vpc`` is declared)
so that snippets can be appended at the end of the file when a resource is
missing entirely.

Fix strategies by rule:
    - open_security_groups: 0.0.0.0/0 -> 10.0.0.0/8 placeholder (manual followup)
    - hardcoded_secrets: literal string -> var.* reference + variable block
    - unencrypted_storage (RDS/EBS): storage_encrypted/encrypted flip false -> true
    - public_s3: block_public_* / restrict_public_* flip false -> true
    - iam_wildcards: "*" -> "REPLACE_ME" placeholder (manual followup)
    - missing_logging: append aws_cloudtrail stub
    - missing_flow_logs: append aws_flow_log stub wired to first aws_vpc
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


SAFE_INTERNAL_CIDR = '"10.0.0.0/8"'
S3_PUBLIC_SETTINGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
SECRET_ATTRIBUTES = (
    ("password", "db_password"),
    ("api_key", "api_key"),
    ("secret_key", "secret_key"),
    ("token", "token"),
)


@dataclass
class RemediationPatch:
    """A single automated fix applied to HCL content."""
    rule: str
    description: str
    resource: str = ""
    manual_followup: bool = False


@dataclass
class RemediationResult:
    """Aggregate result of running the remediation engine on a file."""
    patched_content: str
    patches: List[RemediationPatch] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.patches)


class RemediationEngine:
    """Generate and apply HCL fixes for detected vulnerabilities."""

    def fix(self, raw_content: str, tf_content: Dict) -> RemediationResult:
        """Return a ``RemediationResult`` with patched content + applied patches."""
        content = raw_content
        patches: List[RemediationPatch] = []

        for step in (
            self._fix_open_cidr,
            self._fix_unencrypted_rds,
            self._fix_unencrypted_ebs,
            self._fix_public_s3,
            self._fix_hardcoded_secrets,
            self._fix_iam_wildcards,
        ):
            content, step_patches = step(content)
            patches.extend(step_patches)

        content, step_patches = self._append_missing_logging(content, tf_content)
        patches.extend(step_patches)

        content, step_patches = self._append_missing_flow_logs(content, tf_content)
        patches.extend(step_patches)

        return RemediationResult(patched_content=content, patches=patches)

    def _fix_open_cidr(self, content: str) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        pattern = re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]')

        def replace(_match: re.Match) -> str:
            patches.append(RemediationPatch(
                rule="open_security_groups",
                description='Replaced "0.0.0.0/0" with "10.0.0.0/8" placeholder',
                resource="aws_security_group",
                manual_followup=True,
            ))
            return f'cidr_blocks = [{SAFE_INTERNAL_CIDR}]  # TODO: narrow to your internal CIDR range'

        return pattern.sub(replace, content), patches

    def _fix_unencrypted_rds(self, content: str) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        pattern = re.compile(r'(storage_encrypted\s*=\s*)false\b')

        def replace(match: re.Match) -> str:
            patches.append(RemediationPatch(
                rule="unencrypted_storage",
                description="Enabled storage_encrypted on RDS instance",
                resource="aws_db_instance",
            ))
            return f"{match.group(1)}true"

        return pattern.sub(replace, content), patches

    def _fix_unencrypted_ebs(self, content: str) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        # Match only line-start `encrypted = false` so we don't touch
        # storage_encrypted or nested Statement fields.
        pattern = re.compile(r'(^\s*encrypted\s*=\s*)false\b', re.MULTILINE)

        def replace(match: re.Match) -> str:
            patches.append(RemediationPatch(
                rule="unencrypted_storage",
                description="Enabled encrypted on EBS volume",
                resource="aws_ebs_volume",
            ))
            return f"{match.group(1)}true"

        return pattern.sub(replace, content), patches

    def _fix_public_s3(self, content: str) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        new_content = content
        for setting in S3_PUBLIC_SETTINGS:
            pattern = re.compile(rf"({setting}\s*=\s*)false\b")

            def replace(match: re.Match, s: str = setting) -> str:
                patches.append(RemediationPatch(
                    rule="public_s3",
                    description=f"Set {s} = true on S3 public access block",
                    resource="aws_s3_bucket_public_access_block",
                ))
                return f"{match.group(1)}true"

            new_content = pattern.sub(replace, new_content)
        return new_content, patches

    def _fix_hardcoded_secrets(self, content: str) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        new_content = content
        variables_needed: List[str] = []

        for key, var_name in SECRET_ATTRIBUTES:
            pattern = re.compile(rf'({key}\s*=\s*)"([^"]+)"', re.IGNORECASE)

            def replace(match: re.Match, k: str = key, vn: str = var_name) -> str:
                value = match.group(2)
                if value.startswith("${") or value.startswith("var."):
                    return match.group(0)
                if vn not in variables_needed:
                    variables_needed.append(vn)
                patches.append(RemediationPatch(
                    rule="hardcoded_secrets",
                    description=f"Replaced hardcoded {k} with var.{vn}",
                    resource="Configuration",
                    manual_followup=True,
                ))
                return f"{match.group(1)}var.{vn}"

            new_content = pattern.sub(replace, new_content)

        for var_name in variables_needed:
            if not re.search(rf'variable\s+"{re.escape(var_name)}"\s*\{{', new_content):
                new_content = self._ensure_trailing_newline(new_content)
                new_content += (
                    f'\nvariable "{var_name}" {{\n'
                    f'  description = "Injected by terrasafe --fix; populate via TF_VAR or tfvars."\n'
                    f'  type        = string\n'
                    f'  sensitive   = true\n'
                    f'}}\n'
                )

        return new_content, patches

    def _fix_iam_wildcards(self, content: str) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        new_content = content

        json_pattern = re.compile(r'("Action"\s*:\s*)"\*"')
        if json_pattern.search(new_content):
            new_content = json_pattern.sub(r'\1"REPLACE_ME:specific-action"', new_content)
            patches.append(RemediationPatch(
                rule="iam_wildcards",
                description='Replaced wildcard "Action": "*" with placeholder',
                resource="aws_iam_role_policy",
                manual_followup=True,
            ))

        hcl_pattern = re.compile(r'(\bAction\s*=\s*)"\*"')
        if hcl_pattern.search(new_content):
            new_content = hcl_pattern.sub(r'\1"REPLACE_ME:specific-action"', new_content)
            patches.append(RemediationPatch(
                rule="iam_wildcards",
                description='Replaced wildcard Action = "*" with placeholder',
                resource="aws_iam_role_policy",
                manual_followup=True,
            ))

        return new_content, patches

    def _append_missing_logging(
        self, content: str, tf_content: Dict
    ) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        all_types = self._collect_resource_types(tf_content)
        if not all_types:
            return content, patches

        has_logging = "aws_cloudtrail" in all_types or "aws_cloudwatch_log_group" in all_types
        non_logging = all_types - {"aws_cloudtrail", "aws_cloudwatch_log_group"}
        if has_logging or not non_logging:
            return content, patches

        snippet = (
            "\n# Added by terrasafe --fix: audit logging (missing_logging rule)\n"
            'resource "aws_cloudtrail" "terrasafe_audit" {\n'
            '  name                          = "terrasafe-audit-trail"\n'
            '  s3_bucket_name                = "REPLACE_WITH_EXISTING_BUCKET"  # TODO\n'
            "  include_global_service_events = true\n"
            "  is_multi_region_trail         = true\n"
            "  enable_log_file_validation    = true\n"
            "}\n"
        )
        patches.append(RemediationPatch(
            rule="missing_logging",
            description="Appended aws_cloudtrail stub — configure s3_bucket_name",
            resource="aws_cloudtrail",
            manual_followup=True,
        ))
        return self._ensure_trailing_newline(content) + snippet, patches

    def _append_missing_flow_logs(
        self, content: str, tf_content: Dict
    ) -> Tuple[str, List[RemediationPatch]]:
        patches: List[RemediationPatch] = []
        all_types = self._collect_resource_types(tf_content)
        if "aws_vpc" not in all_types or "aws_flow_log" in all_types:
            return content, patches

        vpc_names = self._collect_vpc_names(tf_content)
        first_vpc = vpc_names[0] if vpc_names else "main"

        snippet = (
            "\n# Added by terrasafe --fix: VPC flow logs (missing_flow_logs rule)\n"
            'resource "aws_cloudwatch_log_group" "terrasafe_flow_logs" {\n'
            '  name              = "/aws/vpc/flowlogs"\n'
            "  retention_in_days = 90\n"
            "}\n\n"
            'resource "aws_flow_log" "terrasafe_main" {\n'
            f"  vpc_id          = aws_vpc.{first_vpc}.id\n"
            "  log_destination = aws_cloudwatch_log_group.terrasafe_flow_logs.arn\n"
            '  traffic_type    = "ALL"\n'
            "}\n"
        )
        patches.append(RemediationPatch(
            rule="missing_flow_logs",
            description=f"Appended aws_flow_log wired to aws_vpc.{first_vpc}",
            resource="aws_flow_log",
            manual_followup=True,
        ))
        return self._ensure_trailing_newline(content) + snippet, patches

    @staticmethod
    def _collect_resource_types(tf_content: Dict) -> set:
        types: set = set()
        for block in tf_content.get("resource", []) or []:
            if isinstance(block, dict):
                types.update(block.keys())
        return types

    @staticmethod
    def _collect_vpc_names(tf_content: Dict) -> List[str]:
        names: List[str] = []
        for block in tf_content.get("resource", []) or []:
            if not isinstance(block, dict) or "aws_vpc" not in block:
                continue
            vpc_data = block["aws_vpc"]
            if isinstance(vpc_data, dict):
                names.extend(vpc_data.keys())
            elif isinstance(vpc_data, list):
                for item in vpc_data:
                    if isinstance(item, dict):
                        names.extend(item.keys())
        return names

    @staticmethod
    def _ensure_trailing_newline(content: str) -> str:
        if content and not content.endswith("\n"):
            return content + "\n"
        return content
