# Tests — Conventions & Patterns

## Suite Summary

- **319 tests** collected (318 passed, 1 skipped)
- **89% overall coverage** (1536 statements, 169 missed)
- **0 failures**, 0 errors, 82 warnings (deprecation)
- Benchmarks: `test_scan_time_benchmark` (~93us), `test_parser_performance` (~4.2ms)

## Environment Setup (critical ordering)

`conftest.py` sets env vars **before** any terrasafe imports — settings are `lru_cache`d so import order matters:

```python
os.environ["TERRASAFE_API_KEY_HASH"] = "$2b$12$..."  # valid bcrypt hash (>=60 chars)
os.environ["TERRASAFE_ENVIRONMENT"] = "development"
os.environ["TERRASAFE_DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost:5432/test"
os.environ["TERRASAFE_REDIS_URL"] = "redis://localhost:6379"
os.environ["TERRASAFE_LOG_LEVEL"] = "INFO"
```

`from terrasafe.api import app` is wrapped in `try/except` in conftest's `reset_rate_limiter`.

## Fixtures

- `setup_test_environment` — session-scoped, autouse (env vars already set at module level)
- `reset_rate_limiter` — per-test, autouse (clears rate limiter state between tests)

## Markers

Defined in `pytest.ini`: `unit`, `integration`, `api`, `slow`, `security`, `ml`

Only `unit` and `ml` are actively applied. **Apply markers to all new tests.**

```python
@pytest.mark.unit
class TestMyFeature:
    ...

@pytest.mark.ml
class TestMLFeature:
    ...
```

## Test Files & Coverage

| Test File | Tests | Covers |
|---|---|---|
| `test_api.py` | 14 | `api.py` (73.57%) |
| `test_cli_args.py` | 19 | `cli.py` (98.10%) |
| `test_cli_formatter.py` | 21 | `cli_formatter.py` (100%) |
| `test_config_logging.py` | 13 | `config/logging.py` (84.31%) |
| `test_infrastructure_database.py` | 25 | `infrastructure/database.py` (100%) |
| `test_infrastructure_repositories.py` | 25 | `infrastructure/repositories.py` (95.45%) |
| `test_main.py` | 10 | `main.py` (0%), model save errors |
| `test_metrics.py` | 35 | `metrics.py` (96.15%) |
| `test_ml_model.py` | 22 | `infrastructure/ml_model.py` (75.46%) |
| `test_parser.py` | 12 | `infrastructure/parser.py` (89.74%) |
| `test_performance.py` | 13 | Benchmarks, resource usage |
| `test_rate_limiter.py` | 9 | `infrastructure/rate_limiter.py` (97.67%) |
| `test_sarif_formatter.py` | 15 | `sarif_formatter.py` (100%) |
| `test_security.py` | 23 (1 skip) | API security, auth, CORS |
| `test_security_rules_iam.py` | 8 | `domain/security_rules.py` IAM checks |
| `test_security_rules_logging.py` | 12 | Logging + VPC flow log rules |
| `test_security_scanner.py` | 27 | `application/scanner.py` (93.28%) |
| `test_validation.py` | 16 | `infrastructure/validation.py` (100%) |

## Low-Coverage Modules

| Module | Coverage | Gaps |
|---|---|---|
| `main.py` | 0% | Entry point — never executed in tests |
| `config/settings.py` | 72.97% | AWS Secrets Manager resolution, production paths |
| `api.py` | 73.57% | Rate limiting setup, Redis connection, lifespan startup |
| `infrastructure/ml_model.py` | 75.46% | Rollback, incremental updates, drift detection |

## Mocking Patterns

### Scanner / filesystem tests
Use `mock_filesystem` context manager from `test_security_scanner.py`:
```python
with mock_filesystem(content="...") as mock_path:
    result = scanner.scan(mock_path)
```
Mocks: `Path.exists`, `Path.is_file`, `Path.stat`, `builtins.open` via `ExitStack`.

### Async code (database, cache, repositories)
```python
from unittest.mock import AsyncMock
mock_session = AsyncMock(spec=AsyncSession)
```

### Settings — two patterns
```python
# API tests
patch('terrasafe.api.settings', mock_settings)

# Infrastructure tests
patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings)
```

### Real file operations
Use `tmp_path` fixture — resolves to `/tmp`, which is in parser's allowed dirs.

### FastAPI HTTP tests
Use `TestClient` from `starlette.testclient` (`test_api.py`, `test_security.py`).

## Dependencies

Required dev packages: `pytest`, `pytest-cov`, `pytest-mock`, `pytest-asyncio`, `pytest-benchmark`, `psutil`

## Anti-patterns

- Never import terrasafe modules before env vars are set in conftest
- Never use `@lru_cache` in test fixtures (causes state leakage across tests)
- Never mock `builtins.open` without also mocking `Path.exists` and `Path.is_file`
- The `TERRASAFE_API_KEY_HASH` env var must be a valid bcrypt hash (>=60 chars) — short values trigger validation errors
