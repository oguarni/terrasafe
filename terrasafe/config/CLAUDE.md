# Config Layer — Settings & Logging

## Scope

Application-wide configuration and structured logging. Settings are loaded once via `lru_cache` — import order matters (env vars must be set before first `get_settings()` call).

## Files

### `settings.py` — `Settings` (Pydantic BaseSettings)

- All settings prefixed with `TERRASAFE_` env vars (e.g., `TERRASAFE_LOG_LEVEL`)
- `get_settings()` is `@lru_cache`d — singleton pattern, first call wins
- `.env` file loaded automatically via `SettingsConfigDict`

#### Key Settings Groups

| Group | Fields | Notes |
|---|---|---|
| API | `api_host`, `api_port`, `api_key_hash`, `api_cors_origins` | `api_key_hash` validated: min 60 chars (bcrypt), rejects placeholders |
| Database | `database_url`, `database_pool_size` | Optional — app runs without DB |
| Redis | `redis_url`, `redis_max_connections` | Fallback rate limiter if unavailable |
| Cache | `cache_ttl_seconds`, `cache_max_entries` | Instance-level cache, not Redis |
| ML | `model_confidence_threshold`, `model_version`, `model_path`, `severity_overrides` | `model_path` default: `models/isolation_forest.pkl` |
| Security | `max_file_size_mb`, `scan_timeout_seconds`, `rate_limit_requests`, `rate_limit_window_seconds` | |
| Logging | `log_level`, `log_format`, `log_file` | Validated: level ∈ {DEBUG..CRITICAL}, format ∈ {json,text} |
| Environment | `environment`, `debug` | Validated: ∈ {development, staging, production} |

#### Production Features

- `database_url_resolved` property fetches credentials from AWS Secrets Manager (`boto3`) in production when `database_url` is not set
- `is_production()` / `is_development()` helper methods
- `max_file_size_bytes` computed property

#### Coverage (100%)

### `logging.py` — Structured Logging

- `StructuredFormatter` — JSON output with correlation IDs
- `TextFormatter` — human-readable for development
- `setup_logging(log_level, log_format, log_file)` — dictConfig-based setup
- `set_correlation_id()` / `get_correlation_id()` / `clear_correlation_id()` — `ContextVar`-based request tracing
- `LoggerAdapter` — auto-injects correlation ID into log records
- `get_logger_with_context(name)` — returns `LoggerAdapter` with correlation ID injection

#### Coverage (100%)

## Anti-patterns

- Never call `get_settings()` at module level in infrastructure modules — causes import-time failures
- Never use short/placeholder values for `TERRASAFE_API_KEY_HASH` — validator rejects them
- In tests, set env vars **before** importing any terrasafe module (settings are cached on first access)
