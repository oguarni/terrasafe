"""Security rules engine - Domain logic for vulnerability detection"""
import re
from typing import List, Dict
from .models import Vulnerability, Severity
from .compliance_frameworks import get_frameworks
from ..config.settings import get_settings


# Constants for severity points (Clean Code: No magic numbers)
POINTS_CRITICAL = 30
POINTS_HIGH = 20
POINTS_MEDIUM = 10
POINTS_LOW = 5
POINTS_INFO = 2


class SecurityRuleEngine:
    """Rule-based security detection engine following SRP"""

    def check_open_security_groups(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for security groups with open access (0.0.0.0/0)"""
        vulns: List[Vulnerability] = []

        if 'resource' not in tf_content:
            return vulns

        for resource in tf_content.get('resource', []):
            if 'aws_security_group' in resource:
                sg_list = resource['aws_security_group']
                # Handle both list and dict formats
                if isinstance(sg_list, list):
                    sg_items = sg_list
                else:
                    sg_items = [sg_list]

                for sg_item in sg_items:
                    if isinstance(sg_item, dict):
                        for sg_name, sg_config in sg_item.items():
                            # Check ingress rules
                            for ingress in sg_config.get('ingress', []):
                                cidr_blocks = ingress.get('cidr_blocks', [])
                                from_port = ingress.get('from_port', 0)

                                if '0.0.0.0/0' in cidr_blocks:
                                    if from_port == 22:
                                        vulns.append(Vulnerability(
                                            severity=Severity.CRITICAL,
                                            points=POINTS_CRITICAL,
                                            message="[CRITICAL] Open security group - SSH port 22 exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict SSH access to specific IP ranges",
                                            rule_id="TS001"
                                        ))
                                    elif from_port == 3389:
                                        vulns.append(Vulnerability(
                                            severity=Severity.CRITICAL,
                                            points=POINTS_CRITICAL,
                                            message=(
                                                "[CRITICAL] Open security group - RDP port 3389 "
                                                "exposed to internet"
                                            ),
                                            resource=sg_name,
                                            remediation="Restrict RDP access to specific IP ranges",
                                            rule_id="TS001"
                                        ))
                                    elif from_port in (80, 443):
                                        vulns.append(Vulnerability(
                                            severity=Severity.MEDIUM,
                                            points=POINTS_MEDIUM,
                                            message=f"[MEDIUM] HTTP/HTTPS port {from_port} open to internet",
                                            resource=sg_name,
                                            remediation="Consider using a CDN or WAF for public web services",
                                            rule_id="TS001"
                                        ))
                                    else:
                                        vulns.append(Vulnerability(
                                            severity=Severity.HIGH,
                                            points=POINTS_HIGH,
                                            message=f"[HIGH] Port {from_port} exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict access to specific IP ranges",
                                            rule_id="TS001"
                                        ))

        return vulns

    def check_hardcoded_secrets(self, raw_content: str) -> List[Vulnerability]:
        """Check for hardcoded passwords and secrets using regex"""
        vulns = []

        # Pattern for hardcoded passwords (not variables)
        # This is a regex pattern for detection, not a credential
        password_pattern = r'password\s*=\s*"([^"]+)"'  # nosec B105
        matches = re.finditer(password_pattern, raw_content, re.IGNORECASE)

        for match in matches:
            password_value = match.group(1)
            # Skip if it's a variable reference
            if not password_value.startswith('var.') and not password_value.startswith('${'):
                vulns.append(Vulnerability(
                    severity=Severity.CRITICAL,
                    points=POINTS_CRITICAL,
                    message="[CRITICAL] Hardcoded password detected",
                    resource="Database/Instance",
                    remediation="Use variables or secrets manager for sensitive data",
                    rule_id="TS002"
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
                if not value.startswith('var.') and not value.startswith('${'):
                    vulns.append(Vulnerability(
                        severity=Severity.CRITICAL,
                        points=POINTS_CRITICAL,
                        message=f"[CRITICAL] Hardcoded {secret_type} detected",
                        resource="Configuration",
                        remediation="Use environment variables or secrets manager",
                        rule_id="TS002"
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
                                    remediation="Enable storage_encrypted = true",
                                    rule_id="TS003"
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
                                    remediation="Enable encrypted = true",
                                    rule_id="TS003"
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
                                    remediation="Enable all public access blocks",
                                    rule_id="TS004"
                                ))
                            elif public_count > 0:
                                vulns.append(Vulnerability(
                                    severity=Severity.MEDIUM,
                                    points=POINTS_MEDIUM,
                                    message="[MEDIUM] S3 bucket with partial public access",
                                    resource=bucket_name,
                                    remediation="Review and restrict public access settings",
                                    rule_id="TS004"
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
                                    remediation="Restrict IAM actions to specific permissions",
                                    rule_id="TS005"
                                ))

                            # Check for full admin access
                            if '"Resource": "*"' in policy_doc or '"Resource":"*"' in policy_doc:
                                if '"Action": "*"' in policy_doc or '"Action":"*"' in policy_doc:
                                    vulns.append(Vulnerability(
                                        severity=Severity.CRITICAL,
                                        points=POINTS_CRITICAL,
                                        message="[CRITICAL] IAM policy with full admin access",
                                        resource=policy_name,
                                        remediation="Apply principle of least privilege",
                                        rule_id="TS005"
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
                remediation="Add aws_cloudtrail or aws_cloudwatch_log_group to enable audit logging",
                rule_id="TS006"
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
                remediation="Add an aws_flow_log resource to enable VPC traffic logging",
                rule_id="TS007"
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

        # Enrich with industry framework references (CIS, MITRE ATT&CK)
        for vuln in all_vulns:
            if vuln.rule_id and not vuln.frameworks:
                vuln.frameworks = get_frameworks(vuln.rule_id)

        return all_vulns
