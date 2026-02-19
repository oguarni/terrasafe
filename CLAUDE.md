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

## Security Notes

- **Secrets**: Production credentials via AWS Secrets Manager (see `terrasafe/config/settings.py`)
- **Rate Limiting**: Fallback in-memory rate limiter if Redis unavailable
- **API Keys**: Hashed with bcrypt, no plaintext storage
- **Input Validation**: SHA-256 hashes, UUIDs, ML feature bounds all validated

## Contributing

1. Create feature branch from `master`
2. Run tests: `make test`
3. Run linting: `make lint`
4. Submit PR with descriptive commit messages
