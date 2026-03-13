# Entry Points — API, CLI, Formatters, Metrics

## Scope

Top-level application entry points and cross-cutting concerns. These files wire together domain, application, and infrastructure layers.

## Files

### `api.py` — FastAPI REST API

- `load_dotenv()` called before imports (E402 exception — intentional)
- Components initialized at module level as singletons: `parser`, `rule_analyzer`, `model_manager`, `ml_predictor`, `scanner`, `db_manager`
- API key auth: bcrypt-hashed keys via `X-API-Key` header (`hash_api_key()`, `verify_api_key_hash()`)
- Rate limiting: Redis-backed (`slowapi`) with `FallbackRateLimiter` if Redis unavailable
- Lifespan handler: validates `api_key_hash` on startup, connects/disconnects DB

#### Endpoints

| Endpoint | Method | Auth | Rate Limit | Description |
|---|---|---|---|---|
| `/health` | GET | No | No | Service status, DB health, rate limiter status |
| `/scan` | POST | API key | 10/min | Upload and scan `.tf` file; saves results to DB |
| `/metrics` | GET | No | No | Prometheus metrics (requires `prometheus-client`) |
| `/api/docs` | GET | No | No | API usage documentation |
| `/docs` | GET | No | No | Swagger UI (FastAPI default) |
| `/redoc` | GET | No | No | ReDoc (FastAPI default) |

#### Middleware

- `TrustedHostMiddleware` — `["*"]` in dev, `["localhost", "127.0.0.1"]` in prod
- `CORSMiddleware` — origins from `settings.api_cors_origins`
- Correlation ID middleware — reads/generates `X-Correlation-ID` header

#### Coverage (73.57%)

Untested: Redis rate limiter setup (lines 123-152), lifespan startup/shutdown (lines 201-226), `main()` server start

### `cli.py` — Command-Line Interface

- `load_dotenv()` called before imports (E402 exception — intentional)
- `_build_scanner()` wires DI components
- Output formats: `text` (default, single-file), `json` (multi-file CI), `sarif` (multi-file CI)
- Exit codes:
  - Text mode: 0 (pass), 1 (threshold exceeded), 2 (error), 3 (critical >=90)
  - CI mode: 0 (pass), 1 (threshold exceeded), 2 (any error)
- `--threshold N` (default 70), `--no-history` flag
- History: writes `scan_results_{stem}.json` + appends to `scan_history.json` (max 100 entries)

#### Coverage (98.10%)

Untested: lines 66, 72 (history file error paths)

### `cli_formatter.py` — `format_results_for_display()`

- Converts scan result dict to colored terminal output
- Coverage: 100%

### `sarif_formatter.py` — `results_to_sarif()`

- Converts scan results list to SARIF v2.1.0 JSON for CI integration
- Coverage: 100%

### `metrics.py` — Prometheus Metrics

- Graceful degradation: all metrics no-op if `prometheus_client` not installed
- `track_metrics` decorator: wraps sync/async functions, records scan results, errors
- `_record_scan_result()` — records score, duration, confidence, vulnerabilities, cache hits
- Metric families: `terrasafe_scans_total`, `terrasafe_scan_duration_seconds`, `terrasafe_vulnerabilities_detected_total`, etc.
- Coverage: 96.15%

### `main.py` — `uvicorn.run()` entry point

- Just imports `app` from `api.py` and runs uvicorn
- Coverage: 0% (never executed in tests — entry point only)

## Anti-patterns

- Never instantiate scanner components inside request handlers — use module-level singletons
- Never store plaintext API keys — always use bcrypt hashing
- In CI output modes (json/sarif), logging goes to stderr to keep stdout clean
