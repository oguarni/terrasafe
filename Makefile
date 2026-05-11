# Makefile for TerraSafe - Terraform Security Scanner
.PHONY: help install test run-demo clean docker lint coverage api metrics test-api security-scan security-deps security-sast security-all setup-hooks quality-gate

# Variables
PYTHON := python3
VENV := .venv
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
CLI := PYTHONPATH=. $(VENV)/bin/python -m terrasafe.cli

# Default target
help:
	@echo "TerraSafe - Available commands:"
	@echo "  make install       - Set up virtual environment and install dependencies"
	@echo "  make test          - Run all tests (unit + integration)"
	@echo "  make test-unit     - Run unit tests only"
	@echo "  make test-int      - Run integration tests only"
	@echo "  make coverage      - Generate test coverage report"
	@echo "  make coverage-html - Generate HTML coverage with missing lines"
	@echo "  make lint          - Run code quality checks"
	@echo "  make demo          - Run demo on all test files"
	@echo "  make scan FILE=<path> - Scan specific Terraform file"
	@echo "  make docker        - Build and run in Docker container"
	@echo "  make api           - Start the FastAPI REST API server"
	@echo "  make metrics       - Display Prometheus metrics"
	@echo "  make test-api      - Test API endpoints"
	@echo "  make security-scan - Run security checks (deps + SAST)"
	@echo "  make security-deps - Check for vulnerable dependencies"
	@echo "  make security-sast - Run static security analysis"
	@echo "  make setup-hooks   - Install pre-commit security hooks"
	@echo "  make quality-gate  - Run the full Quality Gate (pytest + coverage + pylint + flake8 + bandit + mypy)"
	@echo "  make clean         - Remove generated files and cache"

# Install dependencies
install:
	@echo "🔧 Setting up environment..."
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip "setuptools>=70.0.0"
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt
	@echo "✅ Installation complete"

# Run all tests
test: install
	@echo "🧪 Running all tests..."
	$(PYTEST) -v

# Run all tests including enhanced
test-all: install
	@echo "🧪 Running all tests with coverage..."
	$(PYTEST) tests/ -v --cov=terrasafe --cov-report=term --cov-report=html

# Run unit tests only
test-unit: install
	@echo "🧪 Running unit tests..."
	$(PYTEST) -v -m unit

# Run integration tests only  
test-int: install
	@echo "🧪 Running integration tests..."
	$(PYTEST) -v -m integration

# Generate coverage report
coverage: install
	@echo "📊 Generating coverage report..."
	$(PYTEST) --cov=terrasafe --cov-report=term --cov-report=html
	@echo "✅ Coverage report saved to htmlcov/index.html"

# Generate HTML coverage report with detailed missing lines
coverage-html: install
	@echo "📊 Generating HTML coverage report..."
	$(PYTEST) --cov=terrasafe --cov-report=html --cov-report=term-missing
	@echo "✅ Report available at htmlcov/index.html"

# Run linting
lint: install
	@echo "🔍 Running code quality checks..."
	$(VENV)/bin/flake8 terrasafe/ --max-line-length=120 --exclude=__pycache__ --ignore=E226,E402,E501,W503,W504
	$(VENV)/bin/pylint terrasafe/ --max-line-length=120 --disable=E1101,E1102 --fail-under=8.5
	@echo "✅ Linting complete"

# Format code
format: install
	@echo "🎨 Formatting code..."
	$(VENV)/bin/black terrasafe/ tests/
	@echo "✅ Code formatted"

# Run demo
demo: install
	@echo "🚀 Running TerraSafe demo..."
	@chmod +x scripts/run_demo.sh
	scripts/run_demo.sh

# Scan specific file
scan: install
	@if [ -z "$(FILE)" ]; then \
		echo "❌ Error: Please specify FILE=<path>"; \
		echo "   Example: make scan FILE=test_files/vulnerable.tf"; \
		exit 1; \
	fi
	@echo "🔍 Scanning $(FILE)..."
	$(CLI) $(FILE)

# Docker build and run
docker:
	@echo "🐳 Building Docker image..."
	docker build -t terrasafe:latest .
	@echo "🚀 Running in Docker..."
	docker run --rm -v $(PWD)/test_files:/app/test_files terrasafe:latest test_files/vulnerable.tf

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf *.pyc
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf .pytest_cache
	rm -rf models/*.pkl
	rm -f scan_results_*.json scan_history.json
	@echo "✅ Cleanup complete"

# Train model
train-model: install
	@echo "🤖 Training ML model..."
	$(VENV)/bin/python -c "from terrasafe.infrastructure.ml_model import ModelManager; from terrasafe.application.scanner import IntelligentSecurityScanner; from terrasafe.infrastructure.parser import HCLParser; from terrasafe.domain.security_rules import SecurityRuleEngine; from terrasafe.infrastructure.ml_model import MLPredictor; parser = HCLParser(); rules = SecurityRuleEngine(); manager = ModelManager(); predictor = MLPredictor(manager); scanner = IntelligentSecurityScanner(parser, rules, predictor); print('Model initialized')"
	@echo "✅ Model trained and saved"

# Run API server
api: install
	@echo "🚀 Starting TerraSafe API..."
	$(VENV)/bin/python -m terrasafe.api

# Display Prometheus metrics
metrics: install
	@echo "📊 Starting with Prometheus metrics..."
	$(VENV)/bin/python -c "from terrasafe.metrics import generate_latest; print(generate_latest().decode())"

# Test API endpoints
test-api: install
	@echo "🧪 Testing API endpoints..."
	@echo "Testing /health endpoint..."
	@curl -X GET http://localhost:8000/health || echo "API not running. Start with 'make api' first."
	@echo "\nTesting /scan endpoint with vulnerable.tf..."
	@curl -X POST -F "file=@test_files/vulnerable.tf" http://localhost:8000/scan || echo "API not running or file not found."

# GitHub Actions local test
test-ci:
	@echo "🔄 Testing GitHub Actions workflow locally..."
	@which act > /dev/null || (echo "Install 'act' first: https://github.com/nektos/act" && exit 1)
	act -j security-scan

# Security targets
security-scan: install
	@echo "🔒 Running security scans..."
	$(MAKE) security-deps
	$(MAKE) security-sast

security-deps: install
	@echo "🔍 Checking for vulnerable dependencies..."
	$(VENV)/bin/pip install safety
	$(VENV)/bin/safety check

security-sast: install
	@echo "🔍 Running SAST with Bandit..."
	$(VENV)/bin/pip install bandit
	$(VENV)/bin/bandit -r terrasafe/ --ini .bandit -f screen

security-all: security-scan
	@echo "🔒 Running comprehensive security audit..."
	@echo "Checking for secrets..."
	@git secrets --scan || echo "Install git-secrets for secret detection"

# Run the Quality Gate locally (mirror of the GitHub Actions check)
quality-gate: install
	@echo "🚦 Running Quality Gate..."
	$(VENV)/bin/python scripts/quality_gate.py

# Pre-commit setup
setup-hooks: install
	@echo "🪝 Setting up pre-commit hooks..."
	$(VENV)/bin/pip install pre-commit
	$(VENV)/bin/pre-commit install
	@echo "✅ Pre-commit hooks installed"

# Generate Software Bill of Materials
sbom: install
	@echo "📦 Generating Software Bill of Materials..."
	$(VENV)/bin/pip install cyclonedx-bom
	$(VENV)/bin/cyclonedx-py requirements -o sbom.json requirements.txt
	@echo "✅ SBOM generated: sbom.json"
