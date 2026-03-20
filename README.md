<div align="center">
  <img src="screenshots/terrasafe_icon.png" alt="TerraSafe Logo" width="200">

  # TerraSafe

  **Hybrid Terraform Security Scanner — Deterministic Rules + ML Anomaly Detection**

  [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
  [![Tests 397 Passed](https://img.shields.io/badge/tests-397%20passed-2ea44f)](tests/)
  [![Coverage 100%](https://img.shields.io/badge/coverage-100%25-2ea44f)](tests/)
  [![SAST Clean](https://img.shields.io/badge/SAST-0%20issues-2ea44f)](https://bandit.readthedocs.io/)
  [![License CC BY-NC-SA 4.0](https://img.shields.io/badge/license-CC%20BY--NC--SA%204.0-lightgrey)](LICENSE)
  [![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)

  <br>

  A security scanner for Terraform Infrastructure as Code that combines **7 deterministic detection rules** with **Isolation Forest anomaly detection** to identify misconfigurations, hardcoded secrets, and infrastructure risks before they reach production.

</div>

---

### Highlights

- **Hybrid Scoring** — 60% rule-based + 40% ML anomaly detection delivers both precision and coverage
- **Sub-second scans** — ~0.027s per file, suitable for CI/CD gating without pipeline slowdown
- **Production-grade API** — FastAPI with bcrypt auth, Redis-backed rate limiting, async I/O, and Prometheus observability
- **Proven quality** — 397 tests, 100% code coverage, zero SAST findings

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [CLI Usage](#cli-usage)
- [REST API](#rest-api)
- [Quality Metrics](#quality-metrics)
- [DevSecOps Pipeline](#devsecops-pipeline)
- [Docker Deployment](#docker-deployment)
- [Monitoring & Observability](#monitoring--observability)
- [Technology Stack](#technology-stack)
- [Screenshots](#screenshots)
- [Academic Context](#academic-context)
- [Limitations & Future Work](#limitations--future-work)
- [References](#references)
- [License](#license)

---

## Features

### Security Scanner
- Pattern matching for **7 vulnerability categories**: open ports, hardcoded secrets, unencrypted storage, public S3 buckets, IAM misconfigurations, missing CloudWatch logging, and missing VPC flow logs
- Severity classification: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`
- Actionable remediation suggestions per finding
- Configurable severity overrides for organizational policy alignment

### Machine Learning Engine
- **Isolation Forest** anomaly detection (unsupervised — no labeled data required)
- 7-dimensional feature vector: open ports, hardcoded secrets, public access, unencrypted storage, missing logging, missing flow logs, resource count
- Model persistence via Joblib with versioning and drift detection
- Confidence scoring based on anomaly distance from learned security baselines

### REST API
- FastAPI with OpenAPI/Swagger docs at `/docs`
- Bcrypt-hashed API key authentication
- Redis-backed caching and rate limiting (with in-memory fallback)
- Async file processing with configurable timeouts
- Prometheus metrics at `/metrics`
- Correlation ID tracing for all requests

### DevSecOps
- GitHub Actions CI/CD with 5-stage pipeline
- SAST (Bandit), dependency scanning (Safety), secret detection (GitLeaks)
- Docker image security scan (Trivy)
- Pre-commit hooks for local development
- SBOM generation (CycloneDX)

---

## Quick Start

### Prerequisites
- Python 3.10+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/oguarni/terrasafe.git
cd terrasafe

# Install everything (creates venv, installs deps)
make install
```

### Run the Demo

```bash
# Scan all three test configurations
make demo

# Or scan a specific file
python -m terrasafe.cli test_files/vulnerable.tf
python -m terrasafe.cli test_files/secure.tf
python -m terrasafe.cli test_files/mixed.tf
```

### Run Tests

```bash
make test          # All tests
make coverage      # With coverage report
make lint          # Code quality (Pylint + Flake8)
make security-scan # Bandit SAST + Safety dependency check
```

> For full API setup with Docker, database, and monitoring, see the **[Quick Start Guide](QUICKSTART.md)**.

---

## Architecture

TerraSafe follows **Clean Architecture** with strict layer separation:

```
terrasafe/
├── domain/            # Business rules, severity levels, vulnerability models
├── application/       # Use cases — IntelligentSecurityScanner orchestrator
├── infrastructure/    # Adapters — HCL parser, ML model, database, cache
├── config/            # Settings (Pydantic), structured logging
├── cli.py             # Command-line interface (text/json/sarif output)
├── api.py             # FastAPI REST server
└── metrics.py         # Prometheus instrumentation
```

### Scan Pipeline

```mermaid
graph TD
    A[Terraform .tf File] --> B[HCL2 Parser]
    B --> C[Feature Extraction Engine]

    C --> D[Rule-based Detection]
    C --> E[ML Feature Vectorization]

    D --> F[Pattern Matching<br>7 vulnerability categories]
    E --> G[Isolation Forest<br>Anomaly Detection]

    F --> H[Risk Score Aggregator<br>0.6 x Rules + 0.4 x ML]
    G --> H

    H --> I[Scan Report<br>Score · Vulnerabilities · Confidence]

    style C fill:#e1f5ff,stroke:#0288d1,stroke-width:2px,color:#01579b
    style H fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#e65100
    style I fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
```

### Scoring System

| Weight | Component | Method |
|--------|-----------|--------|
| **60%** | Rule-based | Deterministic pattern matching — CRITICAL (30pts), HIGH (20pts), MEDIUM (10pts), LOW (5pts), INFO (2pts) |
| **40%** | ML Anomaly | Isolation Forest deviation from learned security baseline |

**Score ranges:** `0-30` Secure · `31-60` Review recommended · `61-100` Critical action required

---

## CLI Usage

```bash
# Scan a Terraform file
python -m terrasafe.cli <path-to-file.tf>

# Scan via Makefile
make scan FILE=test_files/vulnerable.tf

# JSON output for CI integration
python -m terrasafe.cli --output-format json --threshold 50 file1.tf file2.tf

# SARIF output for GitHub Code Scanning
python -m terrasafe.cli --output-format sarif file.tf
```

### Example Output — Vulnerable Configuration

```
TerraSafe - Intelligent Terraform Security Scanner
Using hybrid approach: Rules (60%) + ML Anomaly Detection (40%)

============================================================
TERRAFORM SECURITY SCAN RESULTS
============================================================
File: test_files/vulnerable.tf

HIGH RISK
Final Risk Score: 81/100
  Rule-based Score: 100/100
  ML Anomaly Score: 54.7/100
  Confidence: LOW

Detected Vulnerabilities:
[CRITICAL] Open security group - SSH port 22 exposed to internet
   Resource: web_sg
   Fix: Restrict SSH access to specific IP ranges

[CRITICAL] Hardcoded password detected
   Resource: Database/Instance
   Fix: Use variables or secrets manager for sensitive data

[HIGH] Unencrypted RDS instance
   Resource: main_db
   Fix: Enable storage_encrypted = true

[HIGH] Unencrypted EBS volume
   Resource: data_volume
   Fix: Enable encrypted = true

[HIGH] S3 bucket with public access enabled
   Resource: public_bucket
   Fix: Enable all public access blocks
```

### Example Output — Secure Configuration

```
LOW RISK
Final Risk Score: 18/100
  Rule-based Score: 0/100
  ML Anomaly Score: 46.0/100
  Confidence: LOW

No security issues detected!
  All resources properly configured
  Encryption enabled where required
  Network access properly restricted
```

---

## REST API

### Start the API Server

```bash
# Local development
make api

# Production (Docker)
docker-compose up -d
```

### Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Health check with DB and rate limiter status |
| `POST` | `/scan` | API Key | Scan a Terraform file (rate limited: 10/min) |
| `GET` | `/metrics` | No | Prometheus metrics |
| `GET` | `/docs` | No | OpenAPI/Swagger UI |

### Scan via curl

```bash
curl -X POST \
  -H "X-API-Key: YOUR_API_KEY" \
  -F "file=@terraform.tf" \
  http://localhost:8000/scan
```

### Scan via Python

```python
import requests

response = requests.post(
    "http://localhost:8000/scan",
    headers={"X-API-Key": "YOUR_API_KEY"},
    files={"file": open("terraform.tf", "rb")}
)
print(response.json())
```

### Response Format

```json
{
  "file": "vulnerable.tf",
  "score": 85,
  "rule_based_score": 90,
  "ml_score": 75.5,
  "confidence": "HIGH",
  "vulnerabilities": [
    {
      "severity": "CRITICAL",
      "points": 20,
      "message": "Hardcoded AWS credentials detected",
      "resource": "aws_instance.web",
      "remediation": "Use AWS IAM roles or environment variables"
    }
  ],
  "summary": { "critical": 1, "high": 2, "medium": 0, "low": 0 },
  "performance": { "scan_time_seconds": 0.234, "file_size_kb": 1.5, "from_cache": false }
}
```

> Generate API keys with `python scripts/generate_api_key.py`. See **[QUICKSTART.md](QUICKSTART.md)** for full API setup.

---

## Quality Metrics

> All metrics from the latest full local run — **March 19, 2026**.

| Category | Metric | Result |
|----------|--------|--------|
| **Testing** | Test suite | **397 tests** — 395 passed, 2 skipped |
| **Testing** | Code coverage | **100%** across all 24 modules (1,518 SLOC) |
| **Testing** | Benchmark (scan) | ~27 ms mean per file |
| **Testing** | Benchmark (parser) | 34.68 us mean, 28,837 ops/s |
| **Code Quality** | Pylint score | **9.16 / 10** |
| **Code Quality** | Flake8 | **0 issues** |
| **Code Quality** | Codebase size | ~4,300 lines (application code) |
| **Security** | SAST (Bandit) | **0 issues** — 0 High, 0 Medium, 0 Low |
| **Security** | Dependencies (Safety) | **0 vulnerabilities** |
| **Performance** | Scan time | ~**0.027s** per Terraform file |

---

## DevSecOps Pipeline

GitHub Actions pipeline with 5 stages:

```mermaid
graph LR
    A[Security Scan] --> B[Unit Tests]
    B --> C[Integration Scan]
    B --> D[Docker Build + Trivy]
    C --> E[Deploy Staging]
    D --> E

    style A fill:#ffebee,stroke:#c62828,color:#b71c1c
    style B fill:#e3f2fd,stroke:#1565c0,color:#0d47a1
    style C fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    style D fill:#fff3e0,stroke:#ef6c00,color:#e65100
    style E fill:#f3e5f5,stroke:#7b1fa2,color:#4a148c
```

| Stage | Tool | Purpose |
|-------|------|---------|
| **SAST** | Bandit | Static code analysis for Python security issues |
| **Dependencies** | Safety | Known vulnerability check for all pip packages |
| **Secrets** | GitLeaks | Detect hardcoded secrets and credentials |
| **Container** | Trivy | Docker image vulnerability scanning |
| **Coverage** | Codecov | Test coverage tracking and reporting |

### Local Security Scanning

```bash
make security-scan   # Run all security checks
make security-deps   # Dependency vulnerabilities only
make security-sast   # SAST only
make setup-hooks     # Install pre-commit hooks
```

---

## Docker Deployment

### Quick Run

```bash
# Build and scan
docker build -t terrasafe:latest .
docker run --rm -v /path/to/terraform:/scan:ro terrasafe:latest /scan/main.tf
```

### Full Stack (docker-compose)

```bash
docker-compose up -d
```

| Service | Port | Purpose |
|---------|------|---------|
| **terrasafe-api** | 8000 | FastAPI application |
| **PostgreSQL** | 5432 | Persistent scan storage |
| **Redis** | 6379 | Caching and rate limiting |
| **Prometheus** | 9090 | Metrics collection |
| **Grafana** | 3000 | Dashboards and visualization |

The Docker image runs as a **non-root user** with `--read-only` filesystem and `--security-opt=no-new-privileges` recommended.

---

## Monitoring & Observability

- **Prometheus** scrapes `/metrics` every 10s — scan rates, cache hits, latencies, error rates
- **Grafana** dashboard (`TerraSafe Overview`) with pre-configured panels:
  - Scan rate and cache hit ratio
  - Vulnerability distribution by severity and category
  - P95/P99 scan duration
  - API request latency and error rates
- **Structured JSON logging** with correlation IDs for request tracing
- **Health check** endpoint at `/health` with database connectivity status

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Python 3.10+ | ML ecosystem, clean syntax |
| ML Framework | scikit-learn (Isolation Forest) | Unsupervised anomaly detection |
| Parser | python-hcl2 | Native Terraform HCL2 parsing |
| API Framework | FastAPI + Uvicorn | Async REST API with OpenAPI docs |
| Database | PostgreSQL + SQLAlchemy (async) | Scan history persistence |
| Cache | Redis | LRU caching, rate limiting |
| Auth | bcrypt | API key hashing |
| Monitoring | Prometheus + Grafana | Metrics and dashboards |
| Containers | Docker + Docker Compose | Multi-service deployment |
| CI/CD | GitHub Actions | DevSecOps automation |
| Numerical | NumPy | Feature vector operations |
| Model Persistence | Joblib | Serialized scikit-learn models |

---

## Screenshots

<p align="center">
  <h3>Vulnerability Detection</h3>
  <img src="screenshots/vulnerable_scan.png" alt="Vulnerable Scan Output" width="800">
</p>

<p align="center">
  <h3>Secure Infrastructure Analysis</h3>
  <img src="screenshots/secure_scan.png" alt="Secure Scan Output" width="800">
</p>

<p align="center">
  <h3>ML Model Training</h3>
  <img src="screenshots/ml_training.png" alt="ML Training Output" width="800">
</p>

<p align="center">
  <h3>Grafana Monitoring Dashboard</h3>
  <img src="screenshots/terrasafe_dashboard_full.png" alt="TerraSafe Grafana Dashboard" width="800">
</p>

---

## Academic Context

| | |
|---|---|
| **Course** | Capstone Project I and II |
| **Institution** | Federal University of Technology - Parana (UTFPR) |
| **Program** | B.S. in Software Engineering, 8th Semester |
| **Type** | Technical Report |

### Why Isolation Forest?

Isolation Forest was selected after evaluating alternatives against four criteria: suitability for unlabeled data, efficiency on structured configuration inputs, performance with limited training samples, and output interpretability.

| Criterion | Isolation Forest | Neural Networks | Genetic Algorithms | Decision Trees |
|-----------|:---:|:---:|:---:|:---:|
| Unsupervised (no labels) | Strong | Weak | N/A | Weak |
| Efficient on structured data | Strong | Overkill | Misaligned | Moderate |
| Small-sample performance | Strong | Weak | Moderate | Moderate |
| Explainable output | Strong | Weak | Moderate | Strong |

### Innovation Aspects

1. **Hybrid detection** — Combines deterministic rules with probabilistic ML, producing complementary signals that reduce both false positives and false negatives
2. **Self-improving baseline** — The model refines its security baseline as more configurations are analyzed, with drift detection to flag distributional shifts
3. **Explainable scoring** — Feature vectors and confidence levels provide full transparency into every finding, supporting auditability
4. **CI/CD-ready performance** — Sub-second scanning enables security gating in deployment pipelines without meaningful latency overhead

---

## Limitations & Future Work

### Current Limitations
- Training data based on synthetic security baselines
- No support for Terraform modules or remote state
- Vulnerability descriptions in English only

### Roadmap
- Deep learning models for complex pattern recognition
- Multi-cloud support (Azure, GCP)
- Custom policy definition language
- Terraform module and provider analysis
- Integration with cloud provider security APIs

---

## References

- Gartner (2024). *Cloud Security Failures Report*
- IBM Security (2024). *Cost of a Data Breach Report*
- HashiCorp. *Terraform Security Best Practices*
- Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. In Proceedings of the Eighth IEEE International Conference on Data Mining (ICDM '08)

---

## License

This project is licensed under **CC BY-NC-SA 4.0**. This license covers all current and historical commits. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

  Developed by **Gabriel Felipe Guarnieri** — UTFPR Software Engineering

  [Quick Start Guide](QUICKSTART.md) · [API Documentation](http://localhost:8000/docs) · [Report an Issue](https://github.com/oguarni/terrasafe/issues)

</div>
