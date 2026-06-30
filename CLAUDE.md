# TerraVault Project Guide

## Overview

TerraVault is a hybrid Terraform security scanner implementing Clean Architecture with:
- **Architecture**: Clean Architecture layers (domain → application → infrastructure)
- **Security Approach**: 60% rule-based detection (11 rules) + 40% ML anomaly detection (8-dim *structural* feature vector, independent of the rule findings)
- **Tech Stack**: FastAPI, PostgreSQL, Redis, Isolation Forest ML, Prometheus/Grafana
- **Language**: Python 3.10+
- **Health**: focused test suite (72 pytest cases, 74% line coverage on 1,518 SLOC) on security rules, scan pipeline, API contract, and ML predictions; Pylint 10.00/10, 0 Flake8 issues, 0 Bandit findings, 0 Safety advisories, 0 mypy errors

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
terravault/
  domain/          → Business entities and rules (security rules, severity enum)
  application/     → Use cases and orchestration (scanner, feature extraction)
  infrastructure/  → External services (database, ML models, parser, rate limiter)
  config/          → Settings (Pydantic) and structured logging
  api.py           → FastAPI REST API
  cli.py           → Command-line interface (text/json/sarif output)
  metrics.py       → Prometheus metrics and track_metrics decorator
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
uvicorn terravault.api:app --reload

# CLI usage
python -m terravault.cli path/to/file.tf
python -m terravault.cli --output-format json --threshold 50 file1.tf file2.tf
```

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=terravault --cov-report=html

# Run specific test module
pytest tests/test_security_scanner.py -v

# Run by marker
pytest -m unit
pytest -m ml
```

### Code Quality

```bash
# Linting (flake8) — exclude E402 (dotenv load order) and E501 (marginal line length)
flake8 terravault/ --max-line-length=120 --exclude=__pycache__ --ignore=E402,E501,W503,W504

# Type checking
mypy terravault/ --ignore-missing-imports

# Security scan (uses .bandit config — skips B101)
bandit -r terravault/ --ini .bandit -f screen

# Formatting
black terravault/ tests/
```

### Linting Standards

- **Max line length**: 120 characters (flake8 + pylint)
- **E402 exceptions**: `api.py` and `cli.py` call `load_dotenv()` before imports (intentional)
- **Bandit config**: `.bandit` file skips B101 (`assert_used`) project-wide
- **Pre-commit hooks**: Configured in `.pre-commit-config.yaml` (black, isort, flake8, bandit, detect-secrets)

## Security Notes

- **Secrets**: Production credentials via AWS Secrets Manager (see `terravault/config/settings.py`)
- **Rate Limiting**: Fallback in-memory rate limiter if Redis unavailable
- **API Keys**: Hashed with bcrypt, no plaintext storage
- **Input Validation**: SHA-256 hashes, UUIDs, ML feature bounds all validated

## Domain Guides

Subdirectory CLAUDE.md files provide focused instructions per architectural layer:

| Layer | File | Topics |
|---|---|---|
| Entry Points | `terravault/CLAUDE.md` | API, CLI, formatters, metrics, middleware |
| Config | `terravault/config/CLAUDE.md` | Settings (Pydantic), structured logging, correlation IDs |
| Domain | `terravault/domain/CLAUDE.md` | 11 security rules, severity model, rule inventory, severity overrides |
| Application | `terravault/application/CLAUDE.md` | Scan pipeline, scoring, caching, 8-dim structural feature extraction |
| Infrastructure | `terravault/infrastructure/CLAUDE.md` | DB, cache, parser, repositories, rate limiter |
| ML System | `terravault/infrastructure/CLAUDE_ML.md` | IsolationForest, training, drift detection, model files |
| Tests | `tests/CLAUDE.md` | 72 focused tests, fixtures, markers, mocking patterns, per-module coverage |

## Known Issues

All previously documented issues have been resolved:

- `SecureCache` removed from `infrastructure/cache.py` — file replaced with a stub comment
- `FallbackRateLimiter.cleanup_old_entries()` removed — superseded by `_cleanup_locked()`
- `ScanHistory` ORM model removed from `models.py` and `alembic/env.py`
- `settings.model_path` now wired to `ModelManager.__init__` (default: `models/isolation_forest.pkl`)
- `check_iam_policies()` covered by `tests/test_security_rules_iam.py` (8 test cases)
- `config/logging.py` covered by `tests/test_config_logging.py` (13 test cases)
- `Severity.INFO = "INFO"` added to domain enum; `POINTS_INFO = 2` added to `security_rules.py`
- `update_model_with_feedback()` rewrites to combine historical + new data (no more catastrophic forgetting)

## Quality Gate

Pull requests against `master`/`main` run an automated Quality Gate
(`.github/workflows/quality-gate.yml`). The gate enforces, in a single
`scripts/quality_gate.py` invocation:

| Check | Threshold |
|---|---|
| pytest | every test passes |
| ratchet | coverage %, file-length count, and duplicate blocks do not regress vs `.ratchet.json` |
| pylint | score = 10.00 / 10 |
| flake8 | 0 findings |
| bandit | 0 findings at `-ll` |
| mypy | 0 errors |

On failure the gate uploads `gate-report.md` as an artifact and comments
the report on the PR.

### Ratchet (catraca) baseline

`scripts/ratchet.py` enforces a one-way improvement rule on three metrics:

| Metric | Direction | Source |
|---|---|---|
| `coverage_pct` | must not decrease | `coverage.xml` line-rate |
| `files_over_300_sloc` | must not increase | `.py` files in `terravault/` over 300 lines |
| `duplicate_blocks` | must not increase | pylint `R0801` at `--min-similarity-lines=4` |

The baseline lives in `.ratchet.json` (tracked in git). After a merge to
master, the `ratchet-bump` job in `.github/workflows/devsecops.yml` recomputes
the baseline — reusing the `test` job's `coverage.xml` rather than running
pytest again — and pushes a `chore(ratchet): bump baseline` commit **only when
one of the three metrics actually moves**. Runs where coverage, file count, and
duplicate blocks are unchanged leave `.ratchet.json` untouched, so the bot no
longer commits on every push. Developers never edit `.ratchet.json` by hand.

Local usage:

```bash
make ratchet         # check against baseline
make ratchet-show    # baseline vs current side-by-side
make ratchet-update  # rewrite baseline (only for an intentional bump)
```

### Self-correction loop

Add the `auto-fix` label to the PR to opt in to Claude self-correction:

1. The `auto-fix` job downloads `gate-report.md`.
2. It invokes `anthropics/claude-code-action@v1` with the failure report
   and an instruction to apply the minimal change set.
3. Claude commits any fixes as
   `chore(quality-gate): auto-fix attempt N` and pushes to the PR branch.
4. The job re-runs the gate inline and comments the post-fix result.
5. A 3-attempt limit is enforced by counting prior auto-fix commits.

Optional repository secret `AUTO_FIX_PAT` (a fine-grained PAT with
`contents: write` on this repo) makes the post-fix push trigger the
normal Quality Gate workflow on the new SHA. Without it, the inline
re-verification is authoritative for the current run.

### Run it locally

```bash
make quality-gate            # full gate, mirrors CI
python scripts/quality_gate.py
```

## Slash Commands

Project-specific slash commands for common workflows:

| Command | Description |
|---|---|
| `/diagnostic` | Full project health check (tests, coverage, lint, bandit, mypy) |
| `/scan-tf` | Scan Terraform files for security vulnerabilities |
| `/security-audit` | Deep security audit of the TerraVault codebase |
| `/coverage-gaps` | Identify untested code and suggest targeted tests |
| `/rules-inventory` | Audit security rules engine coverage and gaps |
| `/ml-status` | Check ML model health, drift, and configuration |

## Contributing

1. Create feature branch from `master`
2. Run tests: `make test`
3. Run linting: `make lint`
4. Submit PR with descriptive commit messages
