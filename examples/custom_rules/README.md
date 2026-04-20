# Custom Rules

TerraSafe supports organizational security policies via YAML. Point the
scanner at a rule file or directory through either
`--custom-rules PATH` (CLI) or `TERRASAFE_CUSTOM_RULES_PATH` (API).

## Rule file shape

```yaml
version: "1.0"
rules:
  - id: ORG-S3-001
    name: S3 buckets must enable versioning
    description: Required for rollback after accidental deletion.
    severity: HIGH
    resource_type: aws_s3_bucket
    match: all           # any | all (default: all)
    conditions:
      - attribute: versioning.enabled
        operator: equals
        value: true
    remediation: "Enable versioning { enabled = true } on the bucket."
```

Each rule is evaluated against every resource of the matching
`resource_type`. When `match: all`, every condition must hold. When
`match: any`, a single satisfied condition fires the rule.

## Operators

| Operator        | Meaning                                              |
|-----------------|------------------------------------------------------|
| `equals`        | `actual == value`                                    |
| `not_equals`    | `actual != value`                                    |
| `in`            | `actual in value` (value must be a list)             |
| `not_in`        | `actual not in value`                                |
| `contains`      | substring match (str) or membership (list)           |
| `not_contains`  | inverse of `contains`                                |
| `regex`         | `re.search(value, actual)` against string attributes |
| `exists`        | attribute is present                                 |
| `missing`       | attribute is absent                                  |
| `greater_than`  | numeric comparison                                   |
| `less_than`     | numeric comparison                                   |

## Severity and scoring

Severity accepts `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. Points
default to the built-in scale (30/20/10/5/2) but can be overridden per
rule via an explicit `points:` field between 0 and 100.

## CLI usage

```bash
python -m terrasafe.cli --custom-rules examples/custom_rules/ my.tf
```

A directory is scanned for `*.yml` / `*.yaml` files; duplicate rule IDs
across files raise an error before the scan starts.
