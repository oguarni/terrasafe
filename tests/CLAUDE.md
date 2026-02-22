# Tests — Conventions & Patterns

## Environment Setup (critical ordering)

`conftest.py` sets env vars **before** any terrasafe imports — settings are `lru_cache`d so import order matters:

```python
os.environ["TERRASAFE_API_KEY_HASH"] = "..."
os.environ["TERRASAFE_ENVIRONMENT"] = "test"
os.environ["TERRASAFE_DATABASE_URL"] = "..."
os.environ["TERRASAFE_REDIS_URL"] = "..."
os.environ["TERRASAFE_LOG_LEVEL"] = "DEBUG"
```

`from terrasafe.api import app` is wrapped in `try/except` in conftest.

## Fixtures

- `setup_test_environment` — session-scoped, autouse
- `reset_rate_limiter` — per-test, autouse

## Markers

Defined: `unit`, `integration`, `api`, `slow`, `security`, `ml`

Only `unit` and `ml` are actively applied. **Apply markers to all new tests.**

```python
@pytest.mark.unit
class TestMyFeature:
    ...

@pytest.mark.ml
class TestMLFeature:
    ...
```

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

## Coverage Gaps

| Gap | Location |
|---|---|
| Silent skip | Integration tests if `test_files/` directory missing |
| Requires extra packages | Performance tests need `pytest-benchmark` + `psutil` |

## Anti-patterns

- Never import terrasafe modules before env vars are set in conftest
- Never use `@lru_cache` in test fixtures (causes state leakage across tests)
- Never mock `builtins.open` without also mocking `Path.exists` and `Path.is_file`
