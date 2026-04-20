"""Tests for ``RemediationEngine`` and ``TerraformFixer``.

Focus on observable behaviour: given a vulnerable HCL snippet, the engine
returns patched content that no longer triggers the corresponding rule, and
patches carry the metadata the CLI renders.
"""
import hcl2
import pytest

from terrasafe.application.fixer import TerraformFixer
from terrasafe.domain.remediation import RemediationEngine
from terrasafe.domain.security_rules import SecurityRuleEngine
from terrasafe.infrastructure.parser import HCLParser


pytestmark = pytest.mark.unit


@pytest.fixture
def engine():
    return RemediationEngine()


def _parse(content: str) -> dict:
    return hcl2.loads(content)


# ---------------------------------------------------------------------------
# Per-rule fixes
# ---------------------------------------------------------------------------

def test_open_cidr_replaced_with_internal_range(engine):
    hcl = '''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
    result = engine.fix(hcl, _parse(hcl))

    assert '0.0.0.0/0' not in result.patched_content
    assert '10.0.0.0/8' in result.patched_content
    open_patches = [p for p in result.patches if p.rule == "open_security_groups"]
    assert len(open_patches) == 1
    assert open_patches[0].manual_followup is True


def test_unencrypted_rds_storage_flipped_true(engine):
    hcl = '''
resource "aws_db_instance" "db" {
  storage_encrypted = false
}
'''
    result = engine.fix(hcl, _parse(hcl))
    assert 'storage_encrypted = true' in result.patched_content
    assert any(p.rule == "unencrypted_storage" for p in result.patches)


def test_unencrypted_ebs_flipped_true_without_touching_storage_encrypted(engine):
    hcl = '''
resource "aws_ebs_volume" "vol" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false
}
'''
    result = engine.fix(hcl, _parse(hcl))
    assert 'encrypted         = true' in result.patched_content


def test_public_s3_access_block_all_settings_flipped(engine):
    import re as _re

    hcl = '''
resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket                  = "my-bucket"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
'''
    result = engine.fix(hcl, _parse(hcl))

    for setting in (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    ):
        assert _re.search(rf"{setting}\s*=\s*true", result.patched_content)
    s3_patches = [p for p in result.patches if p.rule == "public_s3"]
    assert len(s3_patches) == 4


def test_hardcoded_password_replaced_with_var_and_variable_block_injected(engine):
    hcl = '''
resource "aws_db_instance" "db" {
  password = "hardcoded123"
}
'''
    result = engine.fix(hcl, _parse(hcl))

    assert 'password = var.db_password' in result.patched_content
    assert 'variable "db_password"' in result.patched_content
    assert 'sensitive   = true' in result.patched_content
    assert any(p.rule == "hardcoded_secrets" for p in result.patches)


def test_hardcoded_secret_skips_existing_variable_references(engine):
    hcl = '''
resource "aws_db_instance" "db" {
  password = var.db_password
  api_key  = "${var.api_key}"
}
resource "aws_cloudtrail" "t" {
  name           = "t"
  s3_bucket_name = "b"
}
'''
    result = engine.fix(hcl, _parse(hcl))
    # No secret substitutions triggered
    assert not any(p.rule == "hardcoded_secrets" for p in result.patches)
    # var.db_password reference still present; no injected variable block
    assert 'password = var.db_password' in result.patched_content
    assert 'variable "db_password"' not in result.patched_content


def test_iam_wildcard_action_replaced_in_json_heredoc(engine):
    hcl = '''
resource "aws_iam_role_policy" "admin" {
  name = "admin"
  role = "role-id"
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
    result = engine.fix(hcl, _parse(hcl))

    assert '"Action": "*"' not in result.patched_content
    assert 'REPLACE_ME:specific-action' in result.patched_content
    iam_patches = [p for p in result.patches if p.rule == "iam_wildcards"]
    assert iam_patches and iam_patches[0].manual_followup is True


def test_iam_wildcard_action_replaced_in_hcl_syntax(engine):
    # The HCL-syntax branch matches bare `Action = "*"`, distinct from the
    # quoted JSON form embedded in heredocs.
    content = 'Action = "*"\n'
    result = engine.fix(content, {})

    assert 'Action = "*"' not in result.patched_content
    assert 'REPLACE_ME:specific-action' in result.patched_content
    iam_patches = [p for p in result.patches if p.rule == "iam_wildcards"]
    assert iam_patches and iam_patches[0].manual_followup is True


def test_missing_logging_appends_cloudtrail_stub(engine):
    hcl = '''
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
'''
    result = engine.fix(hcl, _parse(hcl))

    assert 'resource "aws_cloudtrail"' in result.patched_content
    assert any(p.rule == "missing_logging" for p in result.patches)


def test_missing_logging_skipped_when_cloudtrail_exists(engine):
    hcl = '''
resource "aws_s3_bucket" "data" { bucket = "data" }
resource "aws_cloudtrail" "audit" { name = "trail" s3_bucket_name = "b" }
'''
    result = engine.fix(hcl, _parse(hcl))
    assert not any(p.rule == "missing_logging" for p in result.patches)


def test_missing_logging_skipped_when_tf_content_has_no_resources(engine):
    # Parsed HCL with zero resource blocks must never append a CloudTrail stub.
    content = "# just a comment, nothing to audit\n"
    result = engine.fix(content, {})

    assert "aws_cloudtrail" not in result.patched_content
    assert not any(p.rule == "missing_logging" for p in result.patches)


def test_missing_flow_logs_appends_stub_wired_to_first_vpc(engine):
    hcl = '''
resource "aws_vpc" "primary" {
  cidr_block = "10.0.0.0/16"
}
'''
    result = engine.fix(hcl, _parse(hcl))

    assert 'resource "aws_flow_log"' in result.patched_content
    assert 'aws_vpc.primary.id' in result.patched_content
    assert any(p.rule == "missing_flow_logs" for p in result.patches)


def test_missing_flow_logs_reads_vpc_name_from_list_structured_block(engine):
    # Some parser outputs wrap `aws_vpc` values in a list instead of a dict.
    # The engine must still extract the first declared VPC name, and tolerate
    # malformed siblings (non-dict list items, scalar vpc_data) without crashing.
    tf_content = {
        "resource": [
            {"aws_vpc": ["not-a-dict", {"primary": {"cidr_block": "10.0.0.0/16"}}]},
            {"aws_vpc": "scalar-value-ignored"},
        ]
    }
    content = 'resource "aws_vpc" "primary" { cidr_block = "10.0.0.0/16" }\n'
    result = engine.fix(content, tf_content)

    assert "aws_vpc.primary.id" in result.patched_content
    assert any(p.rule == "missing_flow_logs" for p in result.patches)


def test_fix_ignores_non_dict_resource_entries(engine):
    # Defensive: malformed resource lists must not crash _collect_resource_types.
    tf_content = {"resource": [{"aws_s3_bucket": {"data": {}}}, "not-a-dict", 42]}
    content = 'resource "aws_s3_bucket" "data" { bucket = "data" }\n'
    result = engine.fix(content, tf_content)

    # The one valid dict block still drives the CloudTrail stub injection.
    assert 'resource "aws_cloudtrail"' in result.patched_content
    assert any(p.rule == "missing_logging" for p in result.patches)


def test_fix_is_noop_when_content_already_secure(engine):
    hcl = '''
resource "aws_db_instance" "db" {
  storage_encrypted = true
  password          = var.db_password
}
resource "aws_cloudtrail" "t" { name = "t" s3_bucket_name = "b" }
'''
    result = engine.fix(hcl, _parse(hcl))
    assert result.patched_content == hcl
    assert result.patches == []
    assert result.has_changes is False


def test_fix_adds_trailing_newline_before_appending_stub(engine):
    # Input without a trailing newline must still produce cleanly-joined output.
    content = 'resource "aws_s3_bucket" "data" { bucket = "data" }'
    assert not content.endswith("\n")
    tf_content = {"resource": [{"aws_s3_bucket": {"data": {"bucket": "data"}}}]}

    result = engine.fix(content, tf_content)

    assert result.patched_content.startswith(content + "\n")
    assert "\n# Added by terrasafe --fix: audit logging" in result.patched_content


def test_hardcoded_secret_reuses_variable_for_repeated_occurrences(engine):
    # Two resources share the same secret key; only one variable block injected.
    hcl = '''
resource "aws_db_instance" "a" { password = "literal-a" }
resource "aws_db_instance" "b" { password = "literal-b" }
'''
    result = engine.fix(hcl, _parse(hcl))

    assert result.patched_content.count('variable "db_password"') == 1
    assert result.patched_content.count("password = var.db_password") == 2


def test_hardcoded_secret_skips_injection_when_variable_block_already_declared(engine):
    hcl = '''
variable "db_password" {
  type      = string
  sensitive = true
}
resource "aws_db_instance" "a" {
  password = "literal-secret"
}
'''
    result = engine.fix(hcl, _parse(hcl))

    assert result.patched_content.count('variable "db_password"') == 1
    assert "password = var.db_password" in result.patched_content


# ---------------------------------------------------------------------------
# End-to-end via TerraformFixer against the vulnerable fixture
# ---------------------------------------------------------------------------

def test_fixer_patches_vulnerable_fixture_and_output_reparses(tmp_path):
    """The patched content must (a) apply multiple fixes and (b) remain valid HCL."""
    source = tmp_path / "vuln.tf"
    source.write_text('''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "db" {
  password          = "plaintext-secret"
  storage_encrypted = false
}
resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = "b"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
''')
    fixer = TerraformFixer(HCLParser(), RemediationEngine())
    result = fixer.fix_file(str(source))

    assert result["has_changes"] is True
    assert len(result["patches"]) >= 7  # cidr, rds, 4x s3, vpc flow log, logging
    assert result["diff"].startswith("---")
    # Output must still be parseable as HCL
    hcl2.loads(result["patched_content"])


def test_fixer_writes_fixed_file_by_default(tmp_path):
    source = tmp_path / "a.tf"
    source.write_text('resource "aws_db_instance" "db" { storage_encrypted = false }\n')
    fixer = TerraformFixer(HCLParser(), RemediationEngine())
    outcome = fixer.fix_file(str(source))

    info = fixer.write_output(str(source), outcome["patched_content"])

    dest = tmp_path / "a.fixed.tf"
    assert info["written"] == str(dest)
    assert info["backup"] is None
    assert "storage_encrypted = true" in dest.read_text()
    # Original untouched
    assert "storage_encrypted = false" in source.read_text()


def test_fixer_in_place_creates_backup(tmp_path):
    source = tmp_path / "a.tf"
    source.write_text('resource "aws_db_instance" "db" { storage_encrypted = false }\n')
    fixer = TerraformFixer(HCLParser(), RemediationEngine())
    outcome = fixer.fix_file(str(source))

    info = fixer.write_output(
        str(source), outcome["patched_content"], in_place=True, backup=True
    )

    assert info["written"] == str(source)
    backup = tmp_path / "a.tf.bak"
    assert info["backup"] == str(backup)
    assert "storage_encrypted = false" in backup.read_text()
    assert "storage_encrypted = true" in source.read_text()


def test_fixer_in_place_skips_backup_when_disabled(tmp_path):
    source = tmp_path / "a.tf"
    source.write_text('resource "aws_db_instance" "db" { storage_encrypted = false }\n')
    fixer = TerraformFixer(HCLParser(), RemediationEngine())
    outcome = fixer.fix_file(str(source))

    info = fixer.write_output(
        str(source), outcome["patched_content"], in_place=True, backup=False
    )

    assert info["backup"] is None
    assert not (tmp_path / "a.tf.bak").exists()


def test_fixer_writes_to_explicit_output_path(tmp_path):
    source = tmp_path / "a.tf"
    source.write_text('resource "aws_db_instance" "db" { storage_encrypted = false }\n')
    destination = tmp_path / "out" / "patched.tf"
    destination.parent.mkdir()
    fixer = TerraformFixer(HCLParser(), RemediationEngine())
    outcome = fixer.fix_file(str(source))

    info = fixer.write_output(
        str(source), outcome["patched_content"], output_path=str(destination)
    )

    assert info["written"] == str(destination)
    assert info["backup"] is None
    assert "storage_encrypted = true" in destination.read_text()
    assert "storage_encrypted = false" in source.read_text()


def test_fixer_returns_error_for_invalid_hcl(tmp_path):
    source = tmp_path / "bad.tf"
    source.write_text("definitely { not valid HCL")
    fixer = TerraformFixer(HCLParser(), RemediationEngine())

    result = fixer.fix_file(str(source))

    assert result["error_type"] == "TerraformParseError"
    assert result["has_changes"] is False
    assert result["patches"] == []


# ---------------------------------------------------------------------------
# Scanner regression: after fixing, the vulnerable fixture scores lower
# ---------------------------------------------------------------------------

def test_patched_content_drops_rule_score(tmp_path):
    source = tmp_path / "v.tf"
    source.write_text('''
resource "aws_db_instance" "db" {
  password          = "literal-secret"
  storage_encrypted = false
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false
}
''')
    parser = HCLParser()
    rules = SecurityRuleEngine()

    tf_before, raw_before = parser.parse(str(source))
    vulns_before = rules.analyze(tf_before, raw_before)

    result = RemediationEngine().fix(raw_before, tf_before)
    # Write patched content to a new file and re-scan
    patched = tmp_path / "v.fixed.tf"
    patched.write_text(result.patched_content)
    tf_after, raw_after = parser.parse(str(patched))
    vulns_after = rules.analyze(tf_after, raw_after)

    score_before = sum(v.points for v in vulns_before)
    score_after = sum(v.points for v in vulns_after)
    assert score_after < score_before
