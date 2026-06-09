# Application Layer — Scanner Orchestration

## Scope

Use cases and orchestration. Depends on `domain`; may reference `infrastructure` interfaces only via dependency injection.

## Files

### `scanner.py` — `IntelligentSecurityScanner`

Constructor receives `HCLParser`, `SecurityRuleEngine`, `MLPredictor` via DI (no direct instantiation inside).

## Scan Pipeline

```
parse(filepath) → rule analysis ─┐
                                 ├→ weighted combination → final score
parse(filepath) → structural feature extraction → validation → ML prediction ─┘
```

**Score formula**: `final_score = int(0.6 * rule_score + 0.4 * ml_score)`

Constants exported: `RULE_WEIGHT = 0.6`, `ML_WEIGHT = 0.4`

- **Rule score**: `min(100, sum(v.points))` — capped at 100
- **ML score**: 0–100 from `MLPredictor.predict_risk()`

The two branches are **independent**: the rule score comes from the findings,
the ML score from the structural shape of the parsed infrastructure. The ML
input is no longer a re-count of rule findings (which made the old ML circular),
so it can react to risk the fixed rule set does not encode.

## Structural Feature Extraction (8 dimensions)

Lives in `feature_extraction.py` (`StructuralFeatureExtractor`), driven off the
parsed `tf_content` + `raw_content` — **not** the vulnerability list. The scanner
calls `self.feature_extractor.extract(tf_content, raw_content)`.

| Index | Feature | Derived from |
|---|---|---|
| 0 | `resource_count` | number of declared resources |
| 1 | `resource_type_diversity` | distinct resource types |
| 2 | `ingress_rule_count` | security-group `ingress` blocks |
| 3 | `public_exposure_count` | `0.0.0.0/0`/`::/0` ingress + public-IP attributes |
| 4 | `iam_resource_count` | resources whose type starts `aws_iam_` |
| 5 | `encryption_coverage` | encrypted / total encryptable storage (1.0 if none) |
| 6 | `logging_resource_count` | CloudTrail / CloudWatch / flow-log resources |
| 7 | `secret_parametrization` | secrets from vars vs. literals (1.0 if none) |

Empty content: `[0, 0, 0, 0, 0, 1.0, 0, 1.0]` (ratios default secure).

Feature validation clips to `FEATURE_BOUNDS` before ML inference (prevents model
poisoning); the bounds live alongside `FEATURE_NAMES` in `feature_extraction.py`.

## Caching

- Instance-level `dict` caches (NOT `@lru_cache` — was a previous bug, never reintroduce)
- Max 100 entries; key = `(filepath, file_hash, mtime)`
- Always `deepcopy` on cache hit — never return cache references directly
- Hash cache: `_hash_cache` (key = `(filepath, mtime)`)
- Scan cache: `_scan_cache` (key = `(filepath, file_hash, mtime)`)

## Result Structures

**Success**:
```python
{
    "file": str,
    "score": int,
    "rule_based_score": int,
    "ml_score": float,
    "confidence": str,          # HIGH / MEDIUM / LOW
    "vulnerabilities": list,
    "summary": dict,            # {critical: N, high: N, ...}
    "features_analyzed": dict,
    "performance": {
        "scan_time_seconds": float,
        "file_size_kb": float,
        "from_cache": bool,
    },
}
```

**Error** (score == -1):
```python
{"score": -1, "error": str, "error_type": str, "file": str}
```

Error types: `TerraformParseError`, `FileNotFoundError`, `PermissionError`, generic `Exception`

## Anti-patterns

- Never use `@lru_cache` on instance methods
- Never return cache dict values directly without `deepcopy`
- Never instantiate `HCLParser`, `SecurityRuleEngine`, or `MLPredictor` inside scanner methods
- Never derive ML features from the rule findings — extract from parsed Terraform, or the ML signal becomes circular
- Never change the feature vector dimensionality without updating `feature_extraction.py` (`FEATURE_NAMES`/`FEATURE_BOUNDS`/`extract()`), `ml_model.py:_generate_secure_baseline()`, `cli_formatter.py`, and `CLAUDE_ML.md`
