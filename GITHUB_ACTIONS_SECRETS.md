# GitHub Actions Secrets Setup Guide

## Overview
This guide explains how to configure repository secrets for the TerraSafe CI/CD pipeline after refactoring `tests/test_api.py` to use environment variables instead of hardcoded credentials.

## Why This Is Required
GitGuardian detected hardcoded credentials in `tests/test_api.py`. The file has been refactored to load credentials from environment variables:
- `API_USERNAME` - Test username for Terraform configuration examples
- `API_PASSWORD` - Test password for Terraform configuration examples

## Local Development Setup

### 1. Verify .env Configuration
The `.env` file has been updated with test credentials:

```bash
# ============================================================================
# Test API Credentials (for tests/test_api.py)
# ============================================================================
API_USERNAME=admin
API_PASSWORD=CHANGE_ME_IN_PRODUCTION
```

**IMPORTANT**: The `.env` file is already in `.gitignore` (verified) and should NEVER be committed to the repository.

### 2. Running Tests Locally
To run tests locally with the environment variables:

```bash
# Source the .env file to load variables
source .env

# Export the variables
export API_USERNAME API_PASSWORD

# Run the test suite
python3 -m pytest tests/test_api.py -v
```

Or in one command:
```bash
cd /path/to/TerraSafe && source .env && export API_USERNAME API_PASSWORD && python3 -m pytest tests/test_api.py -v
```

## GitHub Actions Setup

### Step 1: Add Repository Secrets

1. Navigate to your GitHub repository
2. Click **Settings** (repository settings, not account settings)
3. In the left sidebar, click **Secrets and variables** → **Actions**
4. Click **New repository secret**

Add the following secrets:

#### Secret 1: API_USERNAME
- **Name**: `API_USERNAME`
- **Value**: `admin` (or your preferred test username)
- Click **Add secret**

#### Secret 2: API_PASSWORD
- **Name**: `API_PASSWORD`
- **Value**: `CHANGE_ME_IN_PRODUCTION` (or your preferred secure test password)
- Click **Add secret**

### Step 2: Update GitHub Actions Workflow

Ensure your workflow file (`.github/workflows/*.yml`) passes these secrets as environment variables to the test runner:

```yaml
name: CI Tests

on:
  push:
    branches: [ master, main, feat ]
  pull_request:
    branches: [ master, main ]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt

    - name: Run API tests
      env:
        API_USERNAME: ${{ secrets.API_USERNAME }}
        API_PASSWORD: ${{ secrets.API_PASSWORD }}
      run: |
        python -m pytest tests/test_api.py -v

    - name: Run all tests
      env:
        API_USERNAME: ${{ secrets.API_USERNAME }}
        API_PASSWORD: ${{ secrets.API_PASSWORD }}
      run: |
        python -m pytest tests/ -v --cov=terrasafe
```

### Step 3: Verify GitGuardian Passes

After pushing your changes:

1. Create a new pull request with the refactored `tests/test_api.py`
2. Wait for the CI/CD pipeline to run
3. Verify that:
   - GitGuardian scan passes (no hardcoded secrets detected)
   - All tests pass with environment variables loaded
   - No authentication or credential errors occur

## Verification Checklist

- [x] `.env` file exists in project root with test credentials
- [x] `.env` is listed in `.gitignore` (verified at lines 26-29)
- [x] `tests/test_api.py` uses `os.environ.get()` for credentials
- [x] No hardcoded `"hardcoded123"` or similar passwords in `tests/test_api.py`
- [x] Local tests pass with environment variables (14/14 tests passed)
- [ ] GitHub repository secrets configured (`API_USERNAME`, `API_PASSWORD`)
- [ ] GitHub Actions workflow updated to pass secrets as env vars
- [ ] GitGuardian scan passes in CI/CD pipeline

## Troubleshooting

### Tests fail with KeyError or None values
**Problem**: Environment variables not loaded

**Solution**:
```bash
# Ensure variables are exported
export API_USERNAME=admin
export API_PASSWORD=CHANGE_ME_IN_PRODUCTION

# Or source the .env file
source .env && export API_USERNAME API_PASSWORD
```

### GitGuardian still detects secrets
**Problem**: Other test files may have hardcoded credentials

**Files to check**:
- `tests/test_security_scanner.py:206` - Contains `"hardcoded123"` in test string (intentional for testing detection)
- `tests/test_performance.py:59` - Contains `"hardcoded-password-123"` in test string (intentional)

**Solution**: These are test fixtures designed to verify vulnerability detection. If GitGuardian flags them:
1. Add GitGuardian ignore comments: `# pragma: allowlist secret`
2. Or create a `.gitguardian.yaml` with exceptions
3. Or refactor these files similarly to use environment variables

### GitHub Actions tests fail
**Problem**: Secrets not configured or not passed to workflow

**Solution**:
1. Verify secrets exist in repository settings
2. Ensure workflow has `env:` block with secret references
3. Check workflow logs for environment variable values (they should show as `***` if configured correctly)

## Security Best Practices

✅ **DO**:
- Use repository secrets for sensitive values
- Keep `.env` in `.gitignore`
- Use different credentials for production vs test environments
- Rotate test credentials periodically
- Use descriptive secret names

❌ **DON'T**:
- Commit `.env` files to the repository
- Use production credentials in tests
- Share secrets in plain text (Slack, email, etc.)
- Hardcode credentials in source code
- Use weak test passwords like "123456" or "password"

## Additional Resources

- [GitHub Actions - Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [GitGuardian - Secret Detection](https://docs.gitguardian.com/)
- [TerraSafe Security Documentation](./CLAUDE.md)

## Summary

The refactoring successfully removed hardcoded credentials from `tests/test_api.py` by:
1. Adding `import os` to the file
2. Replacing `password = "hardcoded123"` with `password = "{os.environ.get('API_PASSWORD', 'placeholder_for_test')}"`
3. Replacing `username = "admin"` with `username = "{os.environ.get('API_USERNAME', 'admin')}"`
4. Converting the Terraform string from byte literal to f-string with `.encode('utf-8')`

All 14 API tests pass successfully with the new environment variable approach.
