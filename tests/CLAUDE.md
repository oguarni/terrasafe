# Tests — Conventions & Patterns

## Philosophy

Test behavior at boundaries, not implementation. Prefer fewer high-signal tests over exhaustive coverage. Delete tests that:
- Assert on private methods, internal data structures, or mock call order
- Verify framework behavior (Prometheus wrappers, logging setup, dataclass defaults)
- Mock every dependency then assert the mock was called (tests the mock, not the code)

Keep tests that:
- Cover the product surface: security rule detection, scan pipeline, API contract, CLI exit codes
- Fail when real regressions ship (wrong severity, missed vulnerability, broken auth)
- Use real inputs (real Terraform content, `tmp_path` files, `TestClient`) over deep mocks

## Environment Setup (critical ordering)

`conftest.py` sets env vars **before** any terravault imports — settings are `lru_cache`d so import order matters:

```python
os.environ["TERRAVAULT_API_KEY_HASH"] = "$2b$12$..."  # valid bcrypt hash (>=60 chars)
os.environ["TERRAVAULT_ENVIRONMENT"] = "development"
os.environ["TERRAVAULT_DATABASE_URL"] = "postgresql+asyncpg://test:test@localhost:5432/test"
os.environ["TERRAVAULT_REDIS_URL"] = "redis://localhost:6379"
os.environ["TERRAVAULT_LOG_LEVEL"] = "INFO"
```

## Markers

Defined in `pytest.ini`: `unit`, `integration`, `api`, `slow`, `security`, `ml`. Apply `unit` or `ml` to new tests.

## Mocking Patterns

### Scanner / filesystem tests
Use `mock_filesystem` context manager from `test_security_scanner.py` (patches `Path.exists`, `Path.is_file`, `Path.stat`, `open`).

### Async code
Use `AsyncMock(spec=AsyncSession)` for async infra.

### Settings
```python
patch('terravault.api.settings', mock_settings)                           # API tests
patch('terravault.infrastructure.database.get_settings', return_value=m)  # infra
```

### Real file operations
Use the `tmp_path` fixture — parser allows `/tmp`.

### FastAPI HTTP
Use `TestClient` from `starlette.testclient`.

## Dependencies

`pytest`, `pytest-cov`, `pytest-mock`, `pytest-asyncio`, `pytest-benchmark`, `psutil`.

## Anti-patterns

- Importing terravault modules before env vars are set in conftest
- Using `@lru_cache` in test fixtures (state leakage)
- Mocking `builtins.open` without also mocking `Path.exists` / `Path.is_file`
- `TERRAVAULT_API_KEY_HASH` shorter than a valid bcrypt hash
- Chasing 100% coverage with tests that mock the thing they claim to test
