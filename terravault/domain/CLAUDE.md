# Domain Layer — Security Rules & Domain Models

## Scope

This layer defines business entities and detection logic. It depends only on `config.settings` (for `severity_overrides`) — never import from `application` or `infrastructure`.

## Files

### `models.py`
- `Severity` enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `Vulnerability` dataclass: `severity`, `points`, `message`, `resource`, `remediation`
- **Naming collision**: `Vulnerability` here conflicts with the ORM model in `infrastructure/models.py`. Repositories import it as `DomainVulnerability` alias.

### `security_rules.py`
- `SecurityRuleEngine` — 11 rule checks, point constants: `CRITICAL=30`, `HIGH=20`, `MEDIUM=10`, `LOW=5`, `INFO=2`
- `analyze(tf_content, raw_content)` aggregates all checks and applies `severity_overrides` from settings — **new rules must be registered here**

## Rule Inventory

| # | Rule | Method | Severity | Notes |
|---|---|---|---|---|
| 1 | Open security groups | `check_open_security_groups()` | CRITICAL/HIGH/MEDIUM | Internet-open over IPv4 (`0.0.0.0/0`) or IPv6 (`::/0`). Severity by port *range*: range covering SSH(22)/RDP(3389) → CRITICAL, HTTP(80/443) → MEDIUM, other → HIGH |
| 2 | Hardcoded secrets | `check_hardcoded_secrets()` | CRITICAL | Regex: password, api_key, secret_key, token; `_is_parametrized()` excludes `${...}` interpolations (anywhere) and `var.`/`local.`/`data.`/`module.`/`each.`/`count.` refs |
| 3 | Unencrypted storage | `check_encryption()` | HIGH | RDS (`storage_encrypted`) + EBS (`encrypted`) |
| 4 | Public S3 | `check_public_s3()` | HIGH/MEDIUM | 4 boolean settings; >=3 disabled → HIGH, >0 → MEDIUM |
| 5 | IAM policies | `check_iam_policies()` | CRITICAL | Wildcard actions + full admin (`*`/`*`) detection |
| 6 | Missing logging | `check_missing_logging()` | HIGH | Flags if infra resources exist but no CloudTrail/CloudWatch |
| 7 | Missing VPC flow logs | `check_missing_vpc_flow_logs()` | MEDIUM | Flags if `aws_vpc` exists but no `aws_flow_log` |
| 8 | Public RDS | `check_public_rds()` | CRITICAL | `aws_db_instance` with `publicly_accessible = true` (truthy via `_truthy()`) |
| 9 | Unrestricted egress | `check_unrestricted_egress()` | LOW | `aws_security_group` `egress` open to `0.0.0.0/0`/`::/0` (reuses `_open_scopes()`) |
| 10 | IMDSv1 allowed | `check_imdsv2_required()` | HIGH | `aws_instance` without `metadata_options { http_tokens = "required" }`; absence also flagged (IMDSv1 is the default) |
| 11 | Public EC2 instance | `check_public_instance()` | LOW | `aws_instance` with `associate_public_ip_address = true` |

### Severity Overrides

`analyze()` checks `get_settings().severity_overrides` dict. Supported keys:
- `missing_logging` — overrides `[HIGH] Missing logging` findings
- `missing_flow_logs` — overrides `[MEDIUM] Missing VPC flow logs` findings

## Conventions

- New rule functions: `def check_<name>(self, tf_content: dict, raw_content: str = "") -> List[Vulnerability]`
- Add call to `analyze()` to include the rule in scoring
- Return `[]` (not `None`) if no vulnerabilities found
- If the new rule needs severity overrides, add its key to `rule_key_map` in `analyze()`
- ML features are **structural** (`application/feature_extraction.py`), extracted from parsed Terraform — independent of rules. A new rule does **not** require a feature change; only add a structural feature if the new risk has a structural signal the model should learn.

## Coverage (100%)
