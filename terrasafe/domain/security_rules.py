"""Security rules engine - Domain logic for vulnerability detection"""
import re
from typing import List, Dict, Any
from .models import Vulnerability, Severity


# Constants for severity points (Clean Code: No magic numbers)
POINTS_CRITICAL = 30
POINTS_HIGH = 20
POINTS_MEDIUM = 10
POINTS_LOW = 5


class SecurityRuleEngine:
    """Rule-based security detection engine following SRP"""

    def check_open_security_groups(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for security groups with open access (0.0.0.0/0)"""
        vulns = []

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
                                            message=f"[CRITICAL] Open security group - SSH port 22 exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict SSH access to specific IP ranges"
                                        ))
                                    elif from_port == 3389:
                                        vulns.append(Vulnerability(
                                            severity=Severity.CRITICAL,
                                            points=POINTS_CRITICAL,
                                            message=f"[CRITICAL] Open security group - RDP port 3389 exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict RDP access to specific IP ranges"
                                        ))
                                    elif from_port == 80 or from_port == 443:
                                        vulns.append(Vulnerability(
                                            severity=Severity.MEDIUM,
                                            points=POINTS_MEDIUM,
                                            message=f"[MEDIUM] HTTP/HTTPS port {from_port} open to internet",
                                            resource=sg_name,
                                            remediation="Consider using a CDN or WAF for public web services"
                                        ))
                                    else:
                                        vulns.append(Vulnerability(
                                            severity=Severity.HIGH,
                                            points=POINTS_HIGH,
                                            message=f"[HIGH] Port {from_port} exposed to internet",
                                            resource=sg_name,
                                            remediation="Restrict access to specific IP ranges"
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
                    message=f"[CRITICAL] Hardcoded password detected",
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
                if not value.startswith('var.') and not value.startswith('${'):
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
        vulns = []

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
                                    message=f"[HIGH] Unencrypted RDS instance",
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
                                    message=f"[HIGH] Unencrypted EBS volume",
                                    resource=vol_name,
                                    remediation="Enable encrypted = true"
                                ))

        return vulns

    def check_public_s3(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for public S3 bucket configurations"""
        vulns = []

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
                                    message=f"[HIGH] S3 bucket with public access enabled",
                                    resource=bucket_name,
                                    remediation="Enable all public access blocks"
                                ))
                            elif public_count > 0:
                                vulns.append(Vulnerability(
                                    severity=Severity.MEDIUM,
                                    points=POINTS_MEDIUM,
                                    message=f"[MEDIUM] S3 bucket with partial public access",
                                    resource=bucket_name,
                                    remediation="Review and restrict public access settings"
                                ))

        return vulns

    def check_iam_policies(self, tf_content: Dict) -> List[Vulnerability]:
        """Check for overly permissive IAM policies"""
        vulns = []

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
                                    message=f"[CRITICAL] IAM policy with wildcard actions (*)",
                                    resource=policy_name,
                                    remediation="Restrict IAM actions to specific permissions"
                                ))

                            # Check for full admin access
                            if '"Resource": "*"' in policy_doc or '"Resource":"*"' in policy_doc:
                                if '"Action": "*"' in policy_doc or '"Action":"*"' in policy_doc:
                                    vulns.append(Vulnerability(
                                        severity=Severity.CRITICAL,
                                        points=POINTS_CRITICAL,
                                        message=f"[CRITICAL] IAM policy with full admin access",
                                        resource=policy_name,
                                        remediation="Apply principle of least privilege"
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

        return all_vulns
