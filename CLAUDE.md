# TerraVault Project Guide

## Overview

TerraVault is a hybrid Terraform security scanner implementing Clean Architecture with:
- **Architecture**: Clean Architecture layers (domain → application → infrastructure)
- **Security Approach**: 60% rule-based detection (11 rules) + 40% ML anomaly detection (8-dim *structural* feature vector, independent of the rule findings)
- **Tech Stack**: FastAPI, PostgreSQL, Redis, Isolation Forest ML, Prometheus/Grafana
- **Language**: Python 3.10+
- **Health**: focused test suite (195 pytest cases, 82.63% line / 73.28% branch coverage) on security rules, scan pipeline, API contract, repositories, rate limiting, ML predictions, and the CI report tooling; Pylint 10.00/10, 0 Flake8 issues, 0 Bandit findings, 0 mypy errors
- **Dependencies**: `pip-audit` clean (0 advisories) across `requirements.txt` and `requirements-dev.txt` — see *Dependency advisories* below for what was fixed and why the pins look the way they do

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
- **Pre-commit hooks**: Configured in `.pre-commit-config.yaml` (black, isort, flake8, mypy, bandit, gitleaks). Secret detection is gitleaks only, matching what the DevSecOps pipeline gates on — a second engine with different findings would fail locally on things CI accepts
- **Type checking**: `mypy.ini` keeps `disallow_untyped_defs = False` globally and switches it on per module. A layer listed there is fully annotated and must stay that way; never relax a section that already passes.

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
| Tests | `tests/CLAUDE.md` | What to test and what to delete, fixtures, markers, mocking patterns |

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

Pull requests against `main` run an automated Quality Gate
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
| `coverage_pct` | must not decrease | `coverage.xml` line-rate (branch coverage is also measured since 2026-07-26, but the ratchet still gates on line-rate) |
| `files_over_300_sloc` | must not increase | `.py` files in `terravault/` over 300 lines |
| `duplicate_blocks` | must not increase | pylint `R0801` at `--min-similarity-lines=4` |

The baseline lives in `.ratchet.json` (tracked in git). After a merge to
main, the `ratchet-bump` job in `.github/workflows/devsecops.yml` recomputes
the baseline — reusing the `test` job's `coverage.xml` rather than running
pytest again — and pushes a `chore(ratchet): bump baseline` commit **only when
one of the three metrics actually moves**. Runs where coverage, file count, and
duplicate blocks are unchanged leave `.ratchet.json` untouched, so the bot no
longer commits on every push. Developers never edit `.ratchet.json` by hand.

`--update` is **monotone**: each metric is clamped to its ratcheted direction,
so a run that measures worse than the baseline logs `ratchet: holding baseline`
and writes nothing. This matters because coverage is not identical across
environments — CI scored 82.63% on the tree a local run scored 82.80% — and
without the clamp the bump job would ratchet the bar *down* to whichever run
happened to measure lowest.

Moving a baseline backwards is therefore deliberate only: `--update --force`
resets it from current metrics, regressions included. Use it when a drop is
intentional (a heavily-tested module was deleted), never to make a red gate
green.

Local usage:

```bash
make ratchet         # check against baseline
make ratchet-show    # baseline vs current side-by-side
make ratchet-update  # move baseline forward (improvements only)

python scripts/ratchet.py --update --force   # deliberate reset, allows a drop
```

### Dependency advisories

The `security-scan` job audits `requirements.txt` and `requirements-dev.txt`
with `pip-audit` (PyPA, PyPI Advisory / OSV database). It replaced
`safety check`, which reported **0 findings on the same requirements set**
that pip-audit found 9 advisories in. Reproduce locally with:

```bash
pip-audit -r requirements.txt -r requirements-dev.txt   # currently: clean
```

All 9 are resolved. Two constraints drove the shape of the fix, and both are
worth knowing before touching these pins again:

**Bump the parent, not the transitive.** Two of the vulnerable packages were
unreachable because a parent capped them:

| Vulnerable | Capped by | Fix |
|---|---|---|
| `starlette` 0.52.1 | `fastapi<=0.132.1` pinned `starlette<1.0.0` | `fastapi==0.133.0` — first release to drop the cap |
| `lxml` 5.4.0 | `cyclonedx-bom==4.2.0` → `cyclonedx-python-lib[validation]` capped `lxml<6` | `cyclonedx-bom==7.3.1` — its lib requires `lxml<7` |

Pinning the transitive under the old cap would have produced a broken
resolve, not a fix. Once the parent admits the safe version, the transitive
*is* pinned explicitly (`starlette==1.3.1`, `lxml==6.1.1`) so the security
floor is reproducible instead of "whatever pip picked that day".

**Vendored code is not in any requirements file, and the runtime image has no
build tooling.** Trivy flagged `setuptools/_vendor/jaraco.context-5.3.0`
(CVE-2026-23949) and `setuptools/_vendor/wheel-0.45.1` (CVE-2026-24049) in the
built image. Neither appears in `requirements.txt`, and no pin there can reach
them — they ship inside the base image's setuptools.

Upgrading the tooling fixed those two and immediately surfaced two more, this
time inside pip's own `_vendor/`: msgpack 1.1.2 (GHSA-6v7p-g79w-8964) and a
setuptools 70.3.0 (CVE-2025-47273). No pin fixes those either. So the
Dockerfile does both: it upgrades pip/setuptools/wheel for the *build*, then
uninstalls all three so the *runtime* image contains none of it. Nothing in
the running container invokes pip, and no runtime dependency imports
`pkg_resources`.

If you ever reintroduce build tooling into the final image, expect its
vendored tree to reappear in the Trivy gate — that is the gate working, not a
false positive.

Crossing `pytest` 7 → 9 (PYSEC-2026-1845) forced the plugin set forward with
it, `pytest-asyncio` 0.21 → 1.4 included. The suite's 30
`@pytest.mark.asyncio` decorators were unaffected — 1.x still honours them in
the strict mode this repo uses.

### DevSecOps report: informational checks

The consolidated report (`scripts/pipeline_report.py`, commented on every PR
by the `pipeline-report` job) accepts `--informational <kind>`. Such an input
is parsed and rendered in full — under an *Informational findings* heading,
with a real `"status"` plus `"informational": true` in
`pipeline-metrics.json` — but is excluded from `overall`.

Three kinds are informational today, and the reason is the same in each case:
they report findings on **every** run by construction, so gating on them
pinned `overall` to `fail` forever and fired `devsecops-auto-fix` on findings
its own prompt calls no-fix zones.

| Kind | Why it always reports |
|---|---|
| `terravault-scan`, `terravault-sarif` | scanned against `test_files/`, a deliberately vulnerable fixture set |
| `trivy-sarif` | `python:3.10-slim` base-image CVEs; enforcement lives in the Security-tab SARIF upload, which this does not touch |

Do not add a kind to this list to make a red pipeline green — that is the one
thing the flag must never be used for. It is for inputs whose findings are
*expected*, not for inputs that are merely inconvenient.

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

### Spec Kit (spec-driven development)

TerraVault is the pilot repository for [github/spec-kit](https://github.com/github/spec-kit)
(CLI `specify`, pinned to v0.16.1). Spec Kit installs the same ten `speckit-*`
skills for both agents — Claude Code reads `.claude/skills/`, Codex CLI reads
`.agents/skills/` — over one shared `.specify/` tree, so a feature specified in
one agent is resumable in the other.

Use it for **multi-step features that need a written contract before code**
(a new security rule family, a framework mapping, an API surface change).
Do not use it for bug fixes, refactors, or single-file edits — the existing
slash commands above and a plain prompt are cheaper and better suited.

| Command | Use it |
|---|---|
| `/speckit-constitution` | Once, to seed `.specify/memory/constitution.md`. It must **reference** this guide and the Quality Gate, not restate them |
| `/speckit-specify` | Start every feature — writes `specs/<nnn>-<slug>/spec.md` |
| `/speckit-clarify` | Only when the spec has open questions; run before `plan` |
| `/speckit-plan` | Technical design against Clean Architecture layers |
| `/speckit-tasks` | Dependency-ordered `tasks.md` |
| `/speckit-analyze` | Consistency check across spec/plan/tasks before implementing |
| `/speckit-implement` | Execute the task list |

Avoid `/speckit-checklist` and `/speckit-converge` (both generate long reports
that crowd out context for little gain on a repo this size), and
`/speckit-taskstoissues` (this repo does not track work as GitHub issues).

Spec Kit does not replace any gate. `/speckit-implement` output is still subject
to `make quality-gate` and the ratchet — treat a green gate, not a completed
`tasks.md`, as done.

```bash
# Refresh skills after a Spec Kit release (never use `init --force`:
# it rewrites files Spec Kit considers managed)
specify integration upgrade claude
specify integration upgrade codex
specify integration status        # read-only health check
```

## Contributing

1. Create feature branch from `main`
2. Run tests: `make test`
3. Run linting: `make lint`
4. Submit PR with descriptive commit messages
