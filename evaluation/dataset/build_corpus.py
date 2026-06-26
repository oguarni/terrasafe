#!/usr/bin/env python3
"""Generate the labelled Terraform benchmark corpus for TerraVault evaluation.

Single source of truth: each case carries its Terraform body *and* its
ground-truth labels together, so the two never drift. Running this module
materialises ``cases/<id>.tf`` plus ``ground_truth.yaml`` next to it.

The taxonomy is tool-neutral: every category is a security *concept* that
TerraVault, Checkov, tfsec and Terrascan can all be mapped onto by rule id,
which is what makes the cross-tool comparison fair. ``MISSING_LOGGING``
(TerraVault's whole-configuration "no CloudTrail/CloudWatch" heuristic) is
deliberately *excluded* from the shared taxonomy and handled separately, because
the per-resource scanners have no equivalent file-level check — counting it would
bias the comparison.

Each positive case isolates a single category (other attributes are hardened) so
that a finding for that category is unambiguous; negative cases are fully
hardened and exercise false-positive resistance; combo cases bundle several
issues to mimic a realistic module.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import yaml

# ---------------------------------------------------------------------------
# Tool-neutral taxonomy (the shared categories used for the head-to-head).
# ---------------------------------------------------------------------------
TAXONOMY: List[str] = [
    "PUBLIC_INGRESS",          # security group inbound open to the internet
    "UNRESTRICTED_EGRESS",     # security group outbound open to the internet
    "UNENCRYPTED_RDS",         # RDS instance without storage encryption
    "UNENCRYPTED_EBS",         # EBS volume without encryption
    "PUBLIC_RDS",              # RDS instance with a public endpoint
    "IMDSV1",                  # EC2 instance still allowing IMDSv1
    "IAM_WILDCARD",            # IAM policy with wildcard action/resource
    "PUBLIC_S3",               # S3 bucket with public access not blocked
    "MISSING_VPC_FLOW_LOGS",   # VPC without flow logs
    "PUBLIC_INSTANCE",         # EC2 instance auto-assigning a public IP
    "HARDCODED_SECRET",        # literal password/secret/token in source
]


# ---------------------------------------------------------------------------
# Reusable Terraform fragments.
# ---------------------------------------------------------------------------
_IAM_WILDCARD_POLICY = '''resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
}

resource "aws_iam_role_policy" "app_admin" {
  name = "app-admin-policy"
  role = aws_iam_role.app.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
'''


# ---------------------------------------------------------------------------
# Corpus. id -> {description, severity (TerraVault's primary), expected, tf}.
# `expected` lists the shared-taxonomy categories that are genuinely present.
# ---------------------------------------------------------------------------
CASES: Dict[str, dict] = {
    # ---- positive: one category each -------------------------------------
    "pub_ingress_ssh": {
        "description": "Security group exposes SSH (22) to 0.0.0.0/0",
        "severity": "CRITICAL",
        "expected": ["PUBLIC_INGRESS"],
        "tf": '''resource "aws_security_group" "ssh" {
  name        = "ssh-open"
  description = "SSH open to the world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''',
    },
    "pub_ingress_rdp": {
        "description": "Security group exposes RDP (3389) to 0.0.0.0/0",
        "severity": "CRITICAL",
        "expected": ["PUBLIC_INGRESS"],
        "tf": '''resource "aws_security_group" "rdp" {
  name        = "rdp-open"
  description = "RDP open to the world"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''',
    },
    "pub_ingress_ipv6": {
        "description": "Security group exposes SSH (22) to ::/0 (IPv6 only)",
        "severity": "CRITICAL",
        "expected": ["PUBLIC_INGRESS"],
        "tf": '''resource "aws_security_group" "ssh_v6" {
  name        = "ssh-open-ipv6"
  description = "SSH open to the world over IPv6"

  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
''',
    },
    "wide_port_range": {
        "description": "Security group opens the full 0-65535 range to 0.0.0.0/0",
        "severity": "CRITICAL",
        "expected": ["PUBLIC_INGRESS"],
        "tf": '''resource "aws_security_group" "all_ports" {
  name        = "all-ports-open"
  description = "Every port open to the world"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''',
    },
    "unrestricted_egress": {
        "description": "Security group allows all egress to 0.0.0.0/0; ingress is private",
        "severity": "LOW",
        "expected": ["UNRESTRICTED_EGRESS"],
        "tf": '''resource "aws_security_group" "egress" {
  name        = "egress-open"
  description = "Outbound open to the world"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''',
    },
    "unencrypted_rds": {
        "description": "RDS instance with storage encryption disabled",
        "severity": "HIGH",
        "expected": ["UNENCRYPTED_RDS"],
        "tf": '''resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = false
  publicly_accessible = false
  skip_final_snapshot = true
}

variable "db_password" {
  type      = string
  sensitive = true
}
''',
    },
    "unencrypted_ebs": {
        "description": "EBS volume with encryption disabled",
        "severity": "HIGH",
        "expected": ["UNENCRYPTED_EBS"],
        "tf": '''resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false

  tags = {
    Name = "data-volume"
  }
}
''',
    },
    "public_rds": {
        "description": "RDS instance with a public endpoint (encrypted, so only the public flag fires)",
        "severity": "CRITICAL",
        "expected": ["PUBLIC_RDS"],
        "tf": '''resource "aws_db_instance" "public" {
  allocated_storage   = 20
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = true
  skip_final_snapshot = true
}

variable "db_password" {
  type      = string
  sensitive = true
}
''',
    },
    "imdsv1": {
        "description": "EC2 instance with no metadata_options, so IMDSv1 is allowed",
        "severity": "HIGH",
        "expected": ["IMDSV1"],
        "tf": '''resource "aws_instance" "legacy" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
}
''',
    },
    "iam_wildcard": {
        "description": "IAM role policy granting Action:* on Resource:*",
        "severity": "CRITICAL",
        "expected": ["IAM_WILDCARD"],
        "tf": _IAM_WILDCARD_POLICY,
    },
    "public_s3": {
        "description": "S3 bucket whose public access block disables all four protections",
        "severity": "HIGH",
        "expected": ["PUBLIC_S3"],
        "tf": '''resource "aws_s3_bucket" "data" {
  bucket = "tv-eval-public-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
''',
    },
    "missing_flow_logs": {
        "description": "VPC declared with no aws_flow_log",
        "severity": "MEDIUM",
        "expected": ["MISSING_VPC_FLOW_LOGS"],
        "tf": '''resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "main-vpc"
  }
}
''',
    },
    "public_instance": {
        "description": "EC2 instance that auto-assigns a public IP (IMDSv2 enforced, so only the public-IP flag fires)",
        "severity": "LOW",
        "expected": ["PUBLIC_INSTANCE"],
        "tf": '''resource "aws_instance" "public" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required"
  }
}
''',
    },
    "hardcoded_secret": {
        "description": "Database password written as a string literal (storage encrypted, private)",
        "severity": "CRITICAL",
        "expected": ["HARDCODED_SECRET"],
        "tf": '''resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "SuperSecretP@ssw0rd123"
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = true
}
''',
    },
    # ---- negative: hardened, exercise false-positive resistance ----------
    "secure_full_stack": {
        "description": "Fully hardened multi-resource module; no shared-taxonomy issue present",
        "severity": "NONE",
        "expected": [],
        "tf": '''resource "aws_security_group" "web" {
  name        = "web"
  description = "Web tier, private only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = false
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}

resource "aws_instance" "app" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "tv-eval-secure-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = var.flow_role_arn
  log_destination = aws_cloudwatch_log_group.flow.arn
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/flow"
  retention_in_days = 90
}

resource "aws_cloudtrail" "main" {
  name                       = "trail"
  s3_bucket_name             = aws_s3_bucket.logs.bucket
  is_multi_region_trail      = true
  enable_log_file_validation = true
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "flow_role_arn" {
  type = string
}
''',
    },
    "private_ingress": {
        "description": "Security group with ingress restricted to a private CIDR",
        "severity": "NONE",
        "expected": [],
        "tf": '''resource "aws_security_group" "private" {
  name        = "private"
  description = "Private ingress only"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
''',
    },
    "encrypted_storage": {
        "description": "RDS and EBS both encrypted and private",
        "severity": "NONE",
        "expected": [],
        "tf": '''resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = false
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}

variable "db_password" {
  type      = string
  sensitive = true
}
''',
    },
    "s3_fully_blocked": {
        "description": "S3 bucket with every public access protection enabled",
        "severity": "NONE",
        "expected": [],
        "tf": '''resource "aws_s3_bucket" "data" {
  bucket = "tv-eval-blocked-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
''',
    },
    "imdsv2_enforced": {
        "description": "EC2 instance enforcing IMDSv2 with no public IP",
        "severity": "NONE",
        "expected": [],
        "tf": '''resource "aws_instance" "app" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false

  metadata_options {
    http_tokens = "required"
  }
}
''',
    },
    "parametrized_secret": {
        "description": "Database password sourced from a variable, not a literal",
        "severity": "NONE",
        "expected": [],
        "tf": '''resource "aws_db_instance" "main" {
  allocated_storage   = 20
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = false
}

variable "db_password" {
  type      = string
  sensitive = true
}
''',
    },
    # ---- combo: realistic modules with several issues --------------------
    "combo_web_app": {
        "description": "Web app module: open ingress, unencrypted RDS, public S3, IMDSv1, IAM wildcard",
        "severity": "CRITICAL",
        "expected": [
            "PUBLIC_INGRESS",
            "UNENCRYPTED_RDS",
            "PUBLIC_S3",
            "IMDSV1",
            "IAM_WILDCARD",
        ],
        "tf": '''resource "aws_security_group" "web" {
  name        = "web"
  description = "Web tier"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app" {
  allocated_storage   = 20
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = false
  publicly_accessible = false
  skip_final_snapshot = true
}

resource "aws_instance" "app" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
}

resource "aws_s3_bucket" "assets" {
  bucket = "tv-eval-combo-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

''' + _IAM_WILDCARD_POLICY + '''
variable "db_password" {
  type      = string
  sensitive = true
}
''',
    },
    "combo_data_platform": {
        "description": "Data platform module: public RDS, unencrypted EBS, public instance, open egress",
        "severity": "CRITICAL",
        "expected": [
            "PUBLIC_RDS",
            "UNENCRYPTED_EBS",
            "PUBLIC_INSTANCE",
            "UNRESTRICTED_EGRESS",
        ],
        "tf": '''resource "aws_db_instance" "warehouse" {
  allocated_storage   = 100
  engine              = "postgres"
  engine_version      = "15"
  instance_class      = "db.t3.medium"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = true
  skip_final_snapshot = true
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

resource "aws_instance" "ingest" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.large"
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_security_group" "ingest" {
  name        = "ingest"
  description = "Ingest tier"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_password" {
  type      = string
  sensitive = true
}
''',
    },
}


def build(out_dir: Path) -> None:
    """Materialise cases/<id>/main.tf and ground_truth.yaml under ``out_dir``.

    Each case lives in its own directory so every scanner treats it as an
    isolated Terraform module: pointing a tool at a directory concatenates all
    ``.tf`` files in it the way Terraform itself does, so colliding resource and
    variable names across cases would otherwise break parsing.
    """
    cases_dir = out_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    # Validate every declared category exists in the taxonomy.
    for case_id, spec in CASES.items():
        for cat in spec["expected"]:
            if cat not in TAXONOMY:
                raise ValueError(f"{case_id}: unknown category {cat!r}")

    manifest: Dict[str, object] = {
        "taxonomy": TAXONOMY,
        "notes": (
            "Tool-neutral labelled corpus for the TerraVault evaluation. "
            "MISSING_LOGGING is intentionally outside the shared taxonomy: it is "
            "a whole-configuration heuristic with no per-resource equivalent in "
            "Checkov/tfsec/Terrascan, so any tool's findings that do not map to a "
            "taxonomy category are ignored symmetrically."
        ),
        "cases": {},
    }

    for case_id, spec in CASES.items():
        case_dir = cases_dir / case_id
        case_dir.mkdir(exist_ok=True)
        (case_dir / "main.tf").write_text(spec["tf"], encoding="utf-8")
        manifest["cases"][case_id] = {  # type: ignore[index]
            "dir": f"cases/{case_id}",
            "file": f"cases/{case_id}/main.tf",
            "description": spec["description"],
            "terravault_primary_severity": spec["severity"],
            "expected": spec["expected"],
        }

    gt_path = out_dir / "ground_truth.yaml"
    with gt_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(manifest, handle, sort_keys=False, default_flow_style=False)

    n_pos = sum(1 for s in CASES.values() if s["expected"])
    n_neg = sum(1 for s in CASES.values() if not s["expected"])
    n_labels = sum(len(s["expected"]) for s in CASES.values())
    print(f"Wrote {len(CASES)} cases ({n_pos} positive, {n_neg} negative) "
          f"with {n_labels} category labels to {cases_dir}")
    print(f"Wrote ground truth to {gt_path}")


if __name__ == "__main__":
    build(Path(__file__).resolve().parent)
