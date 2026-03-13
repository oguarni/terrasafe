# Application Layer — Scanner Orchestration

## Scope

Use cases and orchestration. Depends on `domain`; may reference `infrastructure` interfaces only via dependency injection.

## Files

### `scanner.py` — `IntelligentSecurityScanner`

Constructor receives `HCLParser`, `SecurityRuleEngine`, `MLPredictor` via DI (no direct instantiation inside).

## Scan Pipeline

```
parse(filepath) → rule analysis → feature extraction → feature validation → ML prediction → weighted combination
```

**Score formula**: `final_score = int(0.6 * rule_score + 0.4 * ml_score)`

Constants exported: `RULE_WEIGHT = 0.6`, `ML_WEIGHT = 0.4`

- **Rule score**: `min(100, sum(v.points))` — capped at 100
- **ML score**: 0–100 from `MLPredictor.predict_risk()`

## Feature Extraction (7 dimensions)

Vectorized via `numpy.char.find()` on lowercased vulnerability messages:

| Index | Feature | Pattern match |
|---|---|---|
| 0 | `open_ports` | "open security group" or "exposed to internet" |
| 1 | `hardcoded_secrets` | "hardcoded" or "secret" |
| 2 | `public_access` | "s3 bucket" AND "public" |
| 3 | `unencrypted_storage` | "unencrypted" |
| 4 | `missing_logging` | "missing logging" |
| 5 | `missing_flow_logs` | "missing vpc flow logs" |
| 6 | `total_resources` | count of unique `v.resource` values |

Default (no vulns): `[0, 0, 0, 0, 0, 0, 1]`

Feature validation clips to defined bounds before ML inference (prevents model poisoning):
- Features 0–5: clipped to [0, 100]
- Feature 6 (total_resources): clipped to [0, 10000]

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

## Coverage (93.28%)

Untested lines:
- Line 17: `track_metrics` import fallback
- Line 68: Hash cache eviction path
- Lines 86-90: `_get_file_hash` fallback (hash without caching)
- Line 168: Scan cache eviction path
- Line 232: Feature out-of-bounds warning log

## Anti-patterns

- Never use `@lru_cache` on instance methods
- Never return cache dict values directly without `deepcopy`
- Never instantiate `HCLParser`, `SecurityRuleEngine`, or `MLPredictor` inside scanner methods
- Never change the feature vector dimensionality without updating `_validate_features()` bounds, `_format_features()` names, and `CLAUDE_ML.md`
