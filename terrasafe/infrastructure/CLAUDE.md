# Infrastructure Layer — External Services & Adapters

## Critical Rule

**Never call `get_settings()` at module level** in any infrastructure module. Always call inside `__init__` or methods. Module-level calls cause import-time failures in tests.

## Files

### `parser.py` — `HCLParser`
- Path traversal protection: only CWD and `/tmp` are allowed
- Custom exceptions: `TerraformParseError`, `PathTraversalError`, `FileSizeLimitError`, `ParseTimeoutError`
- Parse strategy: HCL2 → JSON fallback
- Tests use `tmp_path` fixture (resolves to `/tmp`, within allowed dirs)

### `database.py` — `DatabaseManager`
- Async SQLAlchemy, singleton via `get_db_manager()`
- `drop_all_tables()` refuses in production environment
- Tests mock via `patch('terrasafe.infrastructure.database.get_settings', return_value=mock_settings)`

### `models.py` — ORM Models
- Models: `Scan`, `Vulnerability`, `ScanHistory`, `MLModelVersion`
- `ScanHistory` is defined but **never used** anywhere in the codebase

### `repositories.py`
- Imports domain `Vulnerability` as `DomainVulnerability` to avoid naming collision with ORM model
- `ScanRepository.create()` accepts both dataclass and dict vulnerabilities despite type hint

### `cache.py` — `SecureCache`
- Async Redis with SHA-256 key hashing
- **Completely unused** in the codebase — scanner uses instance dicts; API uses slowapi/FallbackRateLimiter

### `rate_limiter.py` — `FallbackRateLimiter`
- `cleanup_old_entries()` public method exists but is **never called** from any code
- Periodic cleanup every 100 calls via internal `_cleanup_locked()`

### `validation.py`
- `validate_file_hash()`, `validate_scan_id()`, `sanitize_filename()` — standalone, no internal deps

### `utils.py`
- `categorize_vulnerability()` — standalone helper

### `ml_model.py`
- See `CLAUDE_ML.md` in this directory for full ML system documentation

## Testing Patterns

- Database: mock `AsyncSession` via `patch('terrasafe.infrastructure.database.get_settings')` with `_make_mock_settings()` helper
- Parser: use `tmp_path` fixture for real temp files
- No real DB integration tests exist

## Anti-patterns

- Never call `get_settings()` at module level
- Never bypass path traversal checks in parser
- Never instantiate `SecureCache` expecting it to integrate — it is currently dead code
