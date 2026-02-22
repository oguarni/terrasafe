# Domain Layer — Security Rules & Domain Models

## Scope

This layer is **dependency-free** (stdlib only: `re`, `enum`, `dataclasses`). Never import from `application` or `infrastructure`.

## Files

### `models.py`
- `Severity` enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- `Vulnerability` dataclass: `severity`, `points`, `message`, `resource`, `remediation`
- **Naming collision**: `Vulnerability` here conflicts with the ORM model in `infrastructure/models.py`. Repositories import it as `DomainVulnerability` alias.

### `security_rules.py`
- `SecurityRuleEngine` — 5 rule checks, point constants: `CRITICAL=30`, `HIGH=20`, `MEDIUM=10`, `LOW=5`, `INFO=2`
- `analyze(tf_content, raw_content)` aggregates all checks — **new rules must be added here**

## Rule Inventory

| Rule | Method | Notes |
|---|---|---|
| Open security groups | `check_open_security_groups()` | Port-specific severity (22/3389 → CRITICAL, 80/443 → MEDIUM) |
| Hardcoded secrets | `check_hardcoded_secrets()` | Regex patterns; excludes `var.` and `${` interpolations |
| Encryption | `check_encryption()` | RDS (`storage_encrypted`) + EBS (`encrypted`) |
| Public S3 | `check_public_s3()` | 4 boolean settings checked |
| IAM policies | `check_iam_policies()` | Wildcard actions + full admin (`*`/`*`) detection |

## Conventions

- New rule functions: `def check_<name>(self, tf_content: dict, raw_content: str = "") -> List[Vulnerability]`
- Add call to `analyze()` to include the rule in scoring
- Return `[]` (not `None`) if no vulnerabilities found

## Coverage Gaps (untested)

- RDP port branch (3389) in `check_open_security_groups()`
- HTTP/HTTPS port branches (80/443)
- EBS encryption check
- Partial S3 access control paths
