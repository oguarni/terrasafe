"""Security rules engine - Domain logic for vulnerability detection"""
import re
from typing import List, Dict
from .models import Vulnerability, Severity
from ..config.settings import get_settings


# Constants for severity points (Clean Code: No magic numbers)
POINTS_CRITICAL = 30
POINTS_HIGH = 20
POINTS_MEDIUM = 10
POINTS_LOW = 5
POINTS_INFO = 2

# Network exposure constants
SSH_PORT = 22
RDP_PORT = 3389
WEB_PORTS = (80, 443)
OPEN_IPV4 = "0.0.0.0/0"  # any IPv4 address
OPEN_IPV6 = "::/0"       # any IPv6 address


class SecurityRuleEngine:
    """Rule-based security detection engine following SRP"""

    @staticmethod
    def _iter_named_resources(tf_content: Dict, resource_type: str):
        """Yield (name, config) for every resource of ``resource_type``.

        Normalises the HCL list/dict ambiguity so callers never repeat the
        ``isinstance`` dance.
        """
        for resource in tf_content.get('resource', []):
            if resource_type not in resource:
                continue
            block = resource[resource_type]
            items = block if isinstance(block, list) else [block]
            for item in items:
                if isinstance(item, dict):
                    yield from item.items()

    @staticmethod
    def _open_scopes(ingress: Dict) -> List[str]:
        """Return the internet-open CIDR scopes on an ingress rule.

        Covers both IPv4 (``0.0.0.0/0``) and IPv6 (``::/0``) — a rule open over
        IPv6 only is just as reachable as one open over IPv4.
        """
        scopes = []
        if OPEN_IPV4 in (ingress.get('cidr_blocks') or []):
            scopes.append(OPEN_IPV4)
        if OPEN_IPV6 in (ingress.get('ipv6_cidr_blocks') or []):
            scopes.append(OPEN_IPV6)
        return scopes

    @staticmethod
    def _port_range(ingress: Dict) -> tuple:
        """Normalise (from_port, to_port) to a sorted int tuple; (0, 0) on bad input."""
        raw_from = ingress.get('from_port', 0)
        raw_to = ingress.get('to_port', raw_from)
        try:
            low, high = int(raw_from), int(raw_to)
        except (TypeError, ValueError):
            return 0, 0
        return (low, high) if low <= high else (high, low)

    def _classify_open_ingress(self, ingress: Dict, sg_name: str):
        """Return a Vulnerability for an internet-open ingress rule, or None.

        Severity is decided by whether the port *range* covers a sensitive port,
        so wide ranges (e.g. 0-65535) are still caught as CRITICAL rather than
        slipping past an exact-match check.
        """
        scopes = self._open_scopes(ingress)
        if not scopes:
            return None

        low, high = self._port_range(ingress)
        scope = " / ".join(scopes)
        port_label = str(low) if low == high else f"{low}-{high}"

        if low <= SSH_PORT <= high:
            return Vulnerability(
                severity=Severity.CRITICAL, points=POINTS_CRITICAL,
                message=f"[CRITICAL] Open security group - SSH port 22 exposed to internet ({scope})",
                resource=sg_name,
                remediation="Restrict SSH access to specific IP ranges",
            )
        if low <= RDP_PORT <= high:
            return Vulnerability(
                severity=Severity.CRITICAL, points=POINTS_CRITICAL,
                message=f"[CRITICAL] Open security group - RDP port 3389 exposed to internet ({scope})",
                resource=sg_name,
                remediation="Restrict RDP access to specific IP ranges",
            )
        if any(low <= web_port <= high for web_port in WEB_PORTS):
            return Vulnerability(
                severity=Severity.MEDIUM, points=POINTS_MEDIUM,
                message=f"[MEDIUM] HTTP/HTTPS port {port_label} exposed to internet ({scope})",
                resource=sg_name,
                remediation="Consider using a CDN or WAF for public web services",
            )
        return Vulnerability(
            severity=Severity.HIGH, points=POINTS_HIGH,
            message=f"[HIGH] Port {port_label} exposed to internet ({scope})",
            resource=sg_name,
            remediation="Restrict access to specific IP ranges",
        )

    def check_open_security_groups(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for security groups open to the internet over IPv4 or IPv6."""
        vulns: List[Vulnerability] = []

        if 'resource' not in tf_content:
            return vulns

        for sg_name, sg_config in self._iter_named_resources(tf_content, 'aws_security_group'):
            ingress_rules = sg_config.get('ingress', [])
            if isinstance(ingress_rules, dict):
                ingress_rules = [ingress_rules]
            for ingress in ingress_rules:
                if not isinstance(ingress, dict):
                    continue
                vuln = self._classify_open_ingress(ingress, sg_name)
                if vuln is not None:
                    vulns.append(vuln)

        return vulns

    # Quoted values that are really references, not literal secrets.
    _REFERENCE_PREFIXES = ('var.', 'local.', 'data.', 'module.', 'each.', 'count.')

    @classmethod
    def _is_parametrized(cls, value: str) -> bool:
        """True if a quoted value is a Terraform reference, not a literal secret.

        Excludes ``${...}`` interpolations anywhere in the value (so partial
        interpolations like ``"prefix-${var.x}"`` are not false-positives) and
        bare references such as ``var.x`` or ``data.y.z``.
        """
        if '${' in value:
            return True
        return value.startswith(cls._REFERENCE_PREFIXES)

    def check_hardcoded_secrets(self, raw_content: str) -> List[Vulnerability]:
        """Check for hardcoded passwords and secrets using regex"""
        vulns = []

        # Pattern for hardcoded passwords (not variables)
        # This is a regex pattern for detection, not a credential
        password_pattern = r'password\s*=\s*"([^"]+)"'  # nosec B105
        matches = re.finditer(password_pattern, raw_content, re.IGNORECASE)

        for match in matches:
            password_value = match.group(1)
            # Skip if it's a variable reference / interpolation
            if not self._is_parametrized(password_value):
                vulns.append(Vulnerability(
                    severity=Severity.CRITICAL,
                    points=POINTS_CRITICAL,
                    message="[CRITICAL] Hardcoded password detected",
                    resource="Database/Instance",
                    remediation="Use variables or secrets manager for sensitive data"
                ))

        # Check for API keys and tokens (regex patterns for detection, not credentials)
        secret_patterns = [
            (r'api_key\s*=\s*"([^"]+)"', "API key"),  # nosec B105
            (r'secret_key\s*=\s*"([^"]+)"', "Secret key"),  # nosec B105
            (r'token\s*=\s*"([^"]+)"', "Token")  # nosec B105
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, raw_content, re.IGNORECASE)
            for match in matches:
                value = match.group(1)
                if not self._is_parametrized(value):
                    vulns.append(Vulnerability(
                        severity=Severity.CRITICAL,
                        points=POINTS_CRITICAL,
                        message=f"[CRITICAL] Hardcoded {secret_type} detected",
                        resource="Configuration",
                        remediation="Use environment variables or secrets manager"
                    ))

        return vulns

    def check_encryption(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for unencrypted storage resources"""
        vulns: List[Vulnerability] = []

        if 'resource' not in tf_content:
            return vulns

        for resource in tf_content.get('resource', []):
            # Check RDS instances
            if 'aws_db_instance' in resource:
                db_list = resource['aws_db_instance']
                if isinstance(db_list, list):
                    db_items = db_list
                else:
                    db_items = [db_list]

                for db_item in db_items:
                    if isinstance(db_item, dict):
                        for db_name, db_config in db_item.items():
                            if not db_config.get('storage_encrypted', False):
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=POINTS_HIGH,
                                    message="[HIGH] Unencrypted RDS instance",
                                    resource=db_name,
                                    remediation="Enable storage_encrypted = true"
                                ))

            # Check EBS volumes
            if 'aws_ebs_volume' in resource:
                vol_list = resource['aws_ebs_volume']
                if isinstance(vol_list, list):
                    vol_items = vol_list
                else:
                    vol_items = [vol_list]

                for vol_item in vol_items:
                    if isinstance(vol_item, dict):
                        for vol_name, vol_config in vol_item.items():
                            if not vol_config.get('encrypted', False):
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=POINTS_HIGH,
                                    message="[HIGH] Unencrypted EBS volume",
                                    resource=vol_name,
                                    remediation="Enable encrypted = true"
                                ))

        return vulns

    def check_public_s3(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for public S3 bucket configurations"""
        vulns: List[Vulnerability] = []

        if 'resource' not in tf_content:
            return vulns

        for resource in tf_content.get('resource', []):
            if 'aws_s3_bucket_public_access_block' in resource:
                bucket_list = resource['aws_s3_bucket_public_access_block']
                if isinstance(bucket_list, list):
                    bucket_items = bucket_list
                else:
                    bucket_items = [bucket_list]

                for bucket_item in bucket_items:
                    if isinstance(bucket_item, dict):
                        for bucket_name, config in bucket_item.items():
                            public_settings = [
                                ('block_public_acls', config.get('block_public_acls', True)),
                                ('block_public_policy', config.get('block_public_policy', True)),
                                ('ignore_public_acls', config.get('ignore_public_acls', True)),
                                ('restrict_public_buckets', config.get('restrict_public_buckets', True))
                            ]

                            public_count = sum(1 for _, value in public_settings if not value)

                            if public_count >= 3:
                                vulns.append(Vulnerability(
                                    severity=Severity.HIGH,
                                    points=POINTS_HIGH,
                                    message="[HIGH] S3 bucket with public access enabled",
                                    resource=bucket_name,
                                    remediation="Enable all public access blocks"
                                ))
                            elif public_count > 0:
                                vulns.append(Vulnerability(
                                    severity=Severity.MEDIUM,
                                    points=POINTS_MEDIUM,
                                    message="[MEDIUM] S3 bucket with partial public access",
                                    resource=bucket_name,
                                    remediation="Review and restrict public access settings"
                                ))

        return vulns

    def check_iam_policies(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for overly permissive IAM policies"""
        vulns: List[Vulnerability] = []

        if 'resource' not in tf_content:
            return vulns

        for resource in tf_content.get('resource', []):
            # Check IAM role policies
            if 'aws_iam_role_policy' in resource:
                policy_list = resource['aws_iam_role_policy']
                if isinstance(policy_list, list):
                    policy_items = policy_list
                else:
                    policy_items = [policy_list]

                for policy_item in policy_items:
                    if isinstance(policy_item, dict):
                        for policy_name, policy_config in policy_item.items():
                            policy_doc = str(policy_config.get('policy', ''))

                            # Check for wildcard permissions
                            if '"Action": "*"' in policy_doc or '"Action":"*"' in policy_doc:
                                vulns.append(Vulnerability(
                                    severity=Severity.CRITICAL,
                                    points=POINTS_CRITICAL,
                                    message="[CRITICAL] IAM policy with wildcard actions (*)",
                                    resource=policy_name,
                                    remediation="Restrict IAM actions to specific permissions"
                                ))

                            # Check for full admin access
                            if '"Resource": "*"' in policy_doc or '"Resource":"*"' in policy_doc:
                                if '"Action": "*"' in policy_doc or '"Action":"*"' in policy_doc:
                                    vulns.append(Vulnerability(
                                        severity=Severity.CRITICAL,
                                        points=POINTS_CRITICAL,
                                        message="[CRITICAL] IAM policy with full admin access",
                                        resource=policy_name,
                                        remediation="Apply principle of least privilege"
                                    ))

        return vulns

    def check_missing_logging(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for missing CloudTrail/CloudWatch logging resources.

        If infrastructure resources exist but no logging resources are present,
        flag as HIGH severity.
        """
        vulns: List[Vulnerability] = []

        if 'resource' not in tf_content:
            return vulns

        resources = tf_content.get('resource', [])
        all_resource_types = set()
        for resource_block in resources:
            all_resource_types.update(resource_block.keys())

        # Only flag if there are infrastructure resources to log
        infra_types = all_resource_types - {'aws_cloudtrail', 'aws_cloudwatch_log_group'}
        has_infra = bool(infra_types)
        has_logging = 'aws_cloudtrail' in all_resource_types or 'aws_cloudwatch_log_group' in all_resource_types

        if has_infra and not has_logging:
            vulns.append(Vulnerability(
                severity=Severity.HIGH,
                points=POINTS_HIGH,
                message="[HIGH] Missing logging - no CloudTrail or CloudWatch log group detected",
                resource="Logging",
                remediation="Add aws_cloudtrail or aws_cloudwatch_log_group to enable audit logging"
            ))

        return vulns

    def check_missing_vpc_flow_logs(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for VPC resources without corresponding flow logs.

        If an aws_vpc resource exists but no aws_flow_log is found, flag as MEDIUM.
        """
        vulns: List[Vulnerability] = []

        if 'resource' not in tf_content:
            return vulns

        resources = tf_content.get('resource', [])
        all_resource_types = set()
        for resource_block in resources:
            all_resource_types.update(resource_block.keys())

        has_vpc = 'aws_vpc' in all_resource_types
        has_flow_log = 'aws_flow_log' in all_resource_types

        if has_vpc and not has_flow_log:
            vulns.append(Vulnerability(
                severity=Severity.MEDIUM,
                points=POINTS_MEDIUM,
                message="[MEDIUM] Missing VPC flow logs - aws_vpc present but no aws_flow_log detected",
                resource="VPC",
                remediation="Add an aws_flow_log resource to enable VPC traffic logging"
            ))

        return vulns

    def analyze(self, tf_content: Dict, raw_content: str) -> List[Vulnerability]:
        """Run all security checks"""
        all_vulns = []

        # Run all checks
        all_vulns.extend(self.check_open_security_groups(tf_content))
        all_vulns.extend(self.check_hardcoded_secrets(raw_content))
        all_vulns.extend(self.check_encryption(tf_content))
        all_vulns.extend(self.check_public_s3(tf_content))
        all_vulns.extend(self.check_iam_policies(tf_content))
        all_vulns.extend(self.check_missing_logging(tf_content))
        all_vulns.extend(self.check_missing_vpc_flow_logs(tf_content))

        # Apply severity overrides from config
        overrides = get_settings().severity_overrides
        if overrides:
            severity_map = {s.value: s for s in Severity}
            rule_key_map = {
                'missing_logging': '[HIGH] Missing logging',
                'missing_flow_logs': '[MEDIUM] Missing VPC flow logs',
            }
            for vuln in all_vulns:
                for rule_name, override_level in overrides.items():
                    fragment = rule_key_map.get(rule_name)
                    if fragment and fragment in vuln.message:
                        new_severity = severity_map.get(override_level.upper())
                        if new_severity:
                            vuln.severity = new_severity

        return all_vulns
