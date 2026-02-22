# TerraSafe Project Guide

## Overview

TerraSafe is a hybrid Terraform security scanner implementing Clean Architecture with:
- **Architecture**: Clean Architecture layers (domain → application → infrastructure)
- **Security Approach**: 60% rule-based detection + 40% ML anomaly detection
- **Tech Stack**: FastAPI, PostgreSQL, Redis, Isolation Forest ML, Prometheus/Grafana
- **Language**: Python 3.10+

## Quick Start

```bash
# Setup
make install

# Train ML model
make train-model

# Run security scan
make scan FILE=path/to/terraform.tf

# Run tests
make test

# Run with coverage
make coverage
```

## Architecture

### Clean Architecture Layers

```
domain/          → Business entities and rules (security rules, validators)
application/     → Use cases and orchestration (scanner, ML predictor)
infrastructure/  → External services (database, ML models, parsers, API)
```

### Key Patterns

- **Repository Pattern**: All database access through repositories in `infrastructure/repositories.py`
- **Dependency Injection**: Settings and external services injected via FastAPI dependencies
- **Model Versioning**: ML models tracked with metadata, drift detection enabled
- **Input Validation**: All external inputs validated (file hashes, UUIDs, ML features)

## Development

### Running Locally

```bash
# Start dependencies (PostgreSQL, Redis)
docker-compose up -d postgres redis

# Activate virtual environment
source .venv/bin/activate

# Run API server
uvicorn terrasafe.api:app --reload

# CLI usage
python -m terrasafe.cli path/to/file.tf
```

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=terrasafe --cov-report=html

# Run specific test module
pytest tests/test_application_scanner.py -v
```

### Code Quality

```bash
# Linting (flake8) — exclude E402 (dotenv load order) and E501 (marginal line length)
flake8 terrasafe/ --max-line-length=120 --exclude=__pycache__ --ignore=E402,E501,W503,W504

# Type checking
mypy terrasafe/ --ignore-missing-imports

# Security scan (uses .bandit config — skips B101)
bandit -r terrasafe/ --ini .bandit -f screen

# Formatting
black terrasafe/ tests/
```

### Linting Standards

- **Max line length**: 120 characters (flake8 + pylint)
- **E402 exceptions**: `api.py` and `cli.py` call `load_dotenv()` before imports (intentional)
- **Bandit config**: `.bandit` file skips B101 (`assert_used`) project-wide
- **Pre-commit hooks**: Configured in `.pre-commit-config.yaml` (black, isort, flake8, bandit, detect-secrets)

## Security Notes

- **Secrets**: Production credentials via AWS Secrets Manager (see `terrasafe/config/settings.py`)
- **Rate Limiting**: Fallback in-memory rate limiter if Redis unavailable
- **API Keys**: Hashed with bcrypt, no plaintext storage
- **Input Validation**: SHA-256 hashes, UUIDs, ML feature bounds all validated

## Domain Guides

Subdirectory CLAUDE.md files provide focused instructions per architectural layer:

| Layer | File | Topics |
|---|---|---|
| Domain | `terrasafe/domain/CLAUDE.md` | Security rules, severity model, rule inventory, coverage gaps |
| Application | `terrasafe/application/CLAUDE.md` | Scan pipeline, scoring, caching, feature extraction |
| Infrastructure | `terrasafe/infrastructure/CLAUDE.md` | DB, cache, parser, repositories, rate limiter |
| ML System | `terrasafe/infrastructure/CLAUDE_ML.md` | IsolationForest, training, drift detection, model files |
| Tests | `tests/CLAUDE.md` | Fixtures, markers, mocking patterns, coverage gaps |

## Known Issues

All previously documented issues have been resolved:

- `SecureCache` removed from `infrastructure/cache.py` — file replaced with a stub comment
- `FallbackRateLimiter.cleanup_old_entries()` removed — superseded by `_cleanup_locked()`
- `ScanHistory` ORM model removed from `models.py` and `alembic/env.py`
- `settings.model_path` now wired to `ModelManager.__init__` (default: `models/isolation_forest.pkl`)
- `check_iam_policies()` covered by `tests/test_security_rules_iam.py` (7 test cases)
- `config/logging.py` covered by `tests/test_config_logging.py` (9 test cases)
- `Severity.INFO = "INFO"` added to domain enum; `POINTS_INFO = 2` added to `security_rules.py`
- `update_model_with_feedback()` rewrites to combine historical + new data (no more catastrophic forgetting)

## Contributing

1. Create feature branch from `master`
2. Run tests: `make test`
3. Run linting: `make lint`
4. Submit PR with descriptive commit messages
