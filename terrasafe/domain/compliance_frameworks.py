"""Compliance framework references for security rules.

Maps TerraSafe rule identifiers to established industry controls:
- CIS AWS Foundations Benchmark v1.4.0
- MITRE ATT&CK v14

Each rule may cite multiple controls across frameworks. New frameworks
(NIST 800-53, PCI DSS, SOC 2) can be added as dataclass entries without
touching rule logic.
"""
from dataclasses import dataclass
from typing import Dict, List, Tuple

CIS_AWS = "CIS AWS Foundations Benchmark v1.4.0"
MITRE_ATTACK = "MITRE ATT&CK v14"


@dataclass(frozen=True)
class FrameworkReference:
    """A single compliance control reference."""
    framework: str
    control_id: str
    title: str
    url: str

    def label(self) -> str:
        return f"{self.framework} — {self.control_id}"


def _cis(control_id: str, title: str) -> FrameworkReference:
    return FrameworkReference(
        framework=CIS_AWS,
        control_id=f"Section {control_id}",
        title=title,
        url="https://www.cisecurity.org/benchmark/amazon_web_services",
    )


def _mitre(technique_id: str, title: str) -> FrameworkReference:
    return FrameworkReference(
        framework=MITRE_ATTACK,
        control_id=technique_id,
        title=title,
        url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    )


RULE_FRAMEWORK_MAP: Dict[str, Tuple[FrameworkReference, ...]] = {
    "TS001": (
        _cis("5.2", "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server admin ports"),
        _mitre("T1190", "Exploit Public-Facing Application"),
        _mitre("T1133", "External Remote Services"),
    ),
    "TS002": (
        _cis("1.4", "Ensure no root account access key exists"),
        _mitre("T1552.001", "Unsecured Credentials: Credentials In Files"),
    ),
    "TS003": (
        _cis("2.2.1", "Ensure EBS volume encryption is enabled"),
        _cis("2.3.1", "Ensure that encryption is enabled for RDS instances"),
        _mitre("T1530", "Data from Cloud Storage Object"),
    ),
    "TS004": (
        _cis("2.1.5", "Ensure that S3 Buckets are configured with 'Block public access'"),
        _mitre("T1530", "Data from Cloud Storage Object"),
    ),
    "TS005": (
        _cis("1.16", "Ensure IAM policies are attached only to groups or roles"),
        _cis("1.22", "Ensure IAM policies that allow full admin privileges are not attached"),
        _mitre("T1078.004", "Valid Accounts: Cloud Accounts"),
        _mitre("T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    ),
    "TS006": (
        _cis("3.1", "Ensure CloudTrail is enabled in all regions"),
        _mitre("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    ),
    "TS007": (
        _cis("3.9", "Ensure VPC flow logging is enabled in all VPCs"),
        _mitre("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    ),
}


def get_frameworks(rule_id: str) -> List[FrameworkReference]:
    """Return framework references for a rule, or an empty list if unmapped."""
    return list(RULE_FRAMEWORK_MAP.get(rule_id, ()))
