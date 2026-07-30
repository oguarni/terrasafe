# Infrastructure Layer — External Services & Adapters

## Critical Rule

**Never call `get_settings()` at module level** in any infrastructure module. Always call inside `__init__` or methods. Module-level calls cause import-time failures in tests.

## Files

### `parser.py` — `HCLParser`
- Path traversal protection: only CWD and `/tmp` are allowed
- Custom exceptions: `TerraformParseError`, `PathTraversalError`, `FileSizeLimitError`, `ParseTimeoutError`
- Parse strategy: HCL2 → JSON fallback
- Coverage: 86%
- Tests use `tmp_path` fixture (resolves to `/tmp`, within allowed dirs)

### `database.py` — `DatabaseManager`
- Async SQLAlchemy, singleton via `get_db_manager()`
- `drop_all_tables()` refuses in production environment
- Coverage: 38% — the largest remaining gap in this layer; no tests exercise connect/disconnect, session handling, or health checks
- Tests mock via `patch('terravault.infrastructure.database.get_settings', return_value=mock_settings)`

### `models.py` — ORM Models
- Models: `Scan`, `Vulnerability`, `MLModelVersion`
- `ScanHistory` was removed — it was never used anywhere in the codebase
- Coverage: 100%

### `repositories.py` — `ScanRepository`
- Imports domain `Vulnerability` as `DomainVulnerability` to avoid naming collision with ORM model
- `ScanRepository.create()` accepts both dataclass and dict vulnerabilities despite type hint
- Coverage: 100% (`tests/test_repositories.py`, named `FakeAsyncSession` double — no live DB)

### `cache.py`
- `SecureCache` was removed — it was never integrated into the scan pipeline
- File now contains only a stub comment explaining the removal

### `rate_limiter.py` — `FallbackRateLimiter`
- `cleanup_old_entries()` was removed — superseded by `_cleanup_locked()`
- Periodic cleanup every 100 calls via internal `_cleanup_locked()`
- Coverage: 100% (`tests/test_rate_limiter.py`, frozen-clock fixture for window expiry)

### `validation.py`
- `validate_file_hash()`, `validate_scan_id()`, `sanitize_filename()` — standalone, no internal deps
- Coverage: 94%

### `utils.py`
- `categorize_vulnerability()` — standalone helper, maps vulnerability messages to categories
- Coverage: 92%

### `ml_model.py`
- See `CLAUDE_ML.md` in this directory for full ML system documentation
- Coverage: 80%

## Coverage note

Figures above are per-file **line** rates, measured with branch coverage on
(`branch = True` in `.coveragerc`, enabled 2026-07-26) and read from
`coverage.xml`. Before that, `coverage.xml` reported `branch-rate 0.0` — an
absence of measurement, not a result — so any earlier "100%" claim in this file
reflected line coverage only, or was simply stale.

They are a snapshot, not a gate: the ratchet enforces the repo-wide figure in
`.ratchet.json`, nothing enforces these. Re-read them from `coverage.xml` rather
than trusting them, and correct any that have drifted in the same commit.

## Testing Patterns

- Repositories: use the `FakeAsyncSession` double in `tests/test_repositories.py`; stage a `FakeResult` per `execute()` call in the order the method issues them
- Database: mock `AsyncSession` via `patch('terravault.infrastructure.database.get_settings')` with `_make_mock_settings()` helper
- Parser: use `tmp_path` fixture for real temp files
- No real DB integration tests exist
- ML model: use `tmp_path` for model file operations

## Anti-patterns

- Never call `get_settings()` at module level
- Never bypass path traversal checks in parser
