# Infrastructure Layer — External Services & Adapters

## Critical Rule

**Never call `get_settings()` at module level** in any infrastructure module. Always call inside `__init__` or methods. Module-level calls cause import-time failures in tests.

## Files

### `parser.py` — `HCLParser`
- Path traversal protection: only CWD and `/tmp` are allowed
- Custom exceptions: `TerraformParseError`, `PathTraversalError`, `FileSizeLimitError`, `ParseTimeoutError`
- Parse strategy: HCL2 → JSON fallback
- Coverage: 100%
- Tests use `tmp_path` fixture (resolves to `/tmp`, within allowed dirs)

### `database.py` — `DatabaseManager`
- Async SQLAlchemy, singleton via `get_db_manager()`
- `drop_all_tables()` refuses in production environment
- Coverage: 100%
- Tests mock via `patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings)`

### `models.py` — ORM Models
- Models: `Scan`, `Vulnerability`, `MLModelVersion`
- `ScanHistory` was removed — it was never used anywhere in the codebase
- Coverage: 100%

### `repositories.py` — `ScanRepository`
- Imports domain `Vulnerability` as `DomainVulnerability` to avoid naming collision with ORM model
- `ScanRepository.create()` accepts both dataclass and dict vulnerabilities despite type hint
- Coverage: 100%

### `cache.py`
- `SecureCache` was removed — it was never integrated into the scan pipeline
- File now contains only a stub comment explaining the removal

### `rate_limiter.py` — `FallbackRateLimiter`
- `cleanup_old_entries()` was removed — superseded by `_cleanup_locked()`
- Periodic cleanup every 100 calls via internal `_cleanup_locked()`
- Coverage: 100%

### `validation.py`
- `validate_file_hash()`, `validate_scan_id()`, `sanitize_filename()` — standalone, no internal deps
- Coverage: 100%

### `utils.py`
- `categorize_vulnerability()` — standalone helper, maps vulnerability messages to categories
- Coverage: 100%

### `ml_model.py`
- See `CLAUDE_ML.md` in this directory for full ML system documentation
- Coverage: 100%

## Testing Patterns

- Database: mock `AsyncSession` via `patch('terrasafe.infrastructure.database.get_settings')` with `_make_mock_settings()` helper
- Parser: use `tmp_path` fixture for real temp files
- No real DB integration tests exist
- ML model: use `tmp_path` for model file operations

## Anti-patterns

- Never call `get_settings()` at module level
- Never bypass path traversal checks in parser
