# Application Layer — Scanner Orchestration

## Scope

Use cases and orchestration. Depends on `domain`; may reference `infrastructure` interfaces only via dependency injection.

## Files

### `scanner.py` — `IntelligentSecurityScanner`

Constructor receives `HCLParser`, `SecurityRuleEngine`, `MLPredictor` via DI (no direct instantiation inside).

## Scan Pipeline

```
parse(filepath) → rule analysis → feature extraction → ML prediction → weighted combination
```

**Score formula**: `final_score = int(0.6 * rule_score + 0.4 * ml_score)`

Constants exported: `RULE_WEIGHT = 0.6`, `ML_WEIGHT = 0.4`

- **Rule score**: `min(100, sum(v.points))` — capped at 100
- **ML score**: 0–100 from `MLPredictor.predict()`

## Feature Extraction

5-dimension vector extracted via keyword matching on lowercased vulnerability messages:

| Index | Feature | Keyword match |
|---|---|---|
| 0 | `open_ports` | "open port" or "security group" |
| 1 | `hardcoded_secrets` | "secret" or "password" or "credential" |
| 2 | `public_access` | "public" |
| 3 | `unencrypted_storage` | "encrypt" |
| 4 | `total_resources` | count of `tf_content` keys |

Feature validation clips to defined bounds before ML inference (prevents model poisoning).

## Caching

- Instance-level `dict` caches (NOT `@lru_cache` — was a previous bug, never reintroduce)
- Max 100 entries; key = `(filepath, file_hash, mtime)`
- Always `deepcopy` on cache hit — never return cache references directly

## Result Structures

**Success**:
```python
{
    "score": int,
    "rule_based_score": int,
    "ml_score": float,
    "confidence": str,          # HIGH / MEDIUM / LOW
    "vulnerabilities": list,
    "summary": str,
    "features_analyzed": dict,
    "performance": dict,
}
```

**Error**:
```python
{"score": -1, "error": str, "error_type": str, "file": str}
```

## Testing

- `tests/test_security_scanner.py` — 724 lines, 30+ tests
- `mock_filesystem` context manager in that file — reuse for new scanner tests (mocks `Path.exists`, `is_file`, `stat`, `builtins.open` via `ExitStack`)

## Anti-patterns

- Never use `@lru_cache` on instance methods
- Never return cache dict values directly without `deepcopy`
- Never instantiate `HCLParser`, `SecurityRuleEngine`, or `MLPredictor` inside scanner methods
