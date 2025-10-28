# TerraSafe Testing Guide

Quick reference for running tests and writing new test cases.

---

## Running Tests

### Setup Environment

```bash
# Set required environment variable
export TERRASAFE_API_KEY_HASH='$2b$12$ovvo/sz4S0q6eyRxiWOAR.5FqpU7z26kumiTjVcnPGnWY5Sq0O8ue'
```

### Run All Tests

```bash
cd TerraSafe
python3 -m pytest tests/ -v
```

Expected output: **41 passed**

### Run Specific Test Files

```bash
# API tests only (14 tests)
python3 -m pytest tests/test_api.py -v

# Security scanner tests only (27 tests)
python3 -m pytest tests/test_security_scanner.py -v
```

### Run Specific Test

```bash
# Run a single test by name
python3 -m pytest tests/test_api.py::test_scan_missing_api_key -v

# Run all tests matching a pattern
python3 -m pytest tests/ -k "authentication" -v
```

### Run with Coverage Report

```bash
# Generate HTML coverage report
python3 -m pytest --cov=terrasafe --cov-report=html tests/

# Open report in browser
xdg-open htmlcov/index.html  # Linux
open htmlcov/index.html       # macOS
```

### Useful pytest Options

```bash
# Show print statements
python3 -m pytest tests/ -v -s

# Stop on first failure
python3 -m pytest tests/ -x

# Show slowest 10 tests
python3 -m pytest tests/ --durations=10

# Run in parallel (requires pytest-xdist)
python3 -m pytest tests/ -n 4

# Quiet mode (less verbose)
python3 -m pytest tests/ -q
```

---

## Test Structure Overview

### test_api.py (14 tests)

**Authentication Tests** (3 tests)
- Missing API key → 403
- Invalid API key → 403
- Empty API key → 403

**Scan Functionality Tests** (5 tests)
- Vulnerable file scanning
- Secure file scanning
- Invalid file type rejection
- Empty file rejection
- Response structure validation

**Resource Limit Tests** (2 tests)
- File size limit enforcement → 413
- Scan timeout enforcement → 504

**Infrastructure Tests** (3 tests)
- Health check endpoint
- Metrics endpoint
- API documentation endpoint

**Concurrency Test** (1 test)
- Thread safety verification

### test_security_scanner.py (27 tests)

**Security Rule Engine** (5 tests)
- Open SSH port detection
- Hardcoded password detection
- Unencrypted RDS detection
- Public S3 bucket detection
- False positive prevention

**Scanner Unit Tests** (11 tests)
- Successful scan flow
- Parse error handling
- File not found handling
- Permission error handling
- Unexpected error handling
- Feature extraction
- Vulnerability summarization
- Vulnerability to dict conversion
- Feature formatting
- Complex scan scenario
- File permission error

**Integration Tests** (3 tests)
- Vulnerable file scanning
- Secure file scanning
- Mixed configuration scanning

**Model Manager** (2 tests)
- Model existence check
- Save and load model

**Vulnerability Dataclass** (2 tests)
- Vulnerability creation
- Default remediation

**HCL Parser** (2 tests)
- Non-existent file error
- Existing file parsing

**ML Predictor** (3 tests)
- Risk prediction with features
- Anomaly detection
- Edge case handling

---

## Writing New Tests

### Use the Reusable Filesystem Fixture

When testing scanner methods that access files:

```python
from tests.test_security_scanner import mock_filesystem

def test_my_scanner_feature(self):
    test_file = "test.tf"
    mock_content = b"resource {}"

    # Use the fixture instead of manual mocking
    with mock_filesystem(file_content=mock_content, file_size=2048):
        results = self.scanner.scan(test_file)

    assert results['score'] >= 0
```

### Use Embedded Terraform Content

For API tests, use the embedded constants:

```python
from tests.test_api import VULNERABLE_TF_CONTENT, SECURE_TF_CONTENT

def test_my_api_feature(client, api_headers):
    response = client.post(
        "/scan",
        files={"file": ("test.tf", VULNERABLE_TF_CONTENT, "text/plain")},
        headers=api_headers
    )
    assert response.status_code == 200
```

### Calculate Expected Scores

Don't hardcode scores - calculate them:

```python
from tests.test_security_scanner import calculate_expected_score

def test_score_calculation(self):
    rule_score = 40
    ml_score = 60.5

    results = self.scanner.scan(test_file)

    expected = calculate_expected_score(rule_score, ml_score)
    assert results['score'] == expected
```

### Write Meaningful Assertions

❌ **Bad (too weak):**
```python
assert score >= 0
assert score <= 100
```

✅ **Good (validates behavior):**
```python
# For high-risk files
assert score > 70, "High-risk file should score above 70"

# For comparisons
assert high_risk_score > low_risk_score + 10, \
    "High-risk should score significantly higher than low-risk"
```

---

## Best Practices

### 1. Follow AAA Pattern

```python
def test_feature(self):
    # Arrange - Setup test data
    test_file = "test.tf"
    mock_content = b"..."

    # Act - Execute the code under test
    with mock_filesystem(file_content=mock_content):
        results = self.scanner.scan(test_file)

    # Assert - Verify the results
    assert results['score'] >= 0
    assert 'vulnerabilities' in results
```

### 2. Test One Thing Per Test

❌ **Bad:**
```python
def test_everything(self):
    # Tests auth, parsing, scoring, and error handling
    # Too much in one test!
```

✅ **Good:**
```python
def test_authentication_missing_key(self):
    # Only tests missing API key

def test_authentication_invalid_key(self):
    # Only tests invalid API key
```

### 3. Use Descriptive Test Names

❌ **Bad:**
```python
def test_1(self):
def test_scan(self):
def test_error(self):
```

✅ **Good:**
```python
def test_scan_missing_api_key_returns_403(self):
def test_scan_file_size_limit_exceeded_returns_413(self):
def test_concurrent_requests_handle_race_conditions(self):
```

### 4. Use Fixtures for Common Setup

```python
@pytest.fixture
def vulnerable_terraform_file():
    """Fixture providing vulnerable Terraform content"""
    return b"""
    resource "aws_security_group" "test" {
      ingress {
        from_port = 22
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
    """

def test_with_fixture(vulnerable_terraform_file):
    # Use the fixture
    response = scan(vulnerable_terraform_file)
    assert response['score'] > 50
```

### 5. Mock at the Right Layer

✅ **Good - Mock at boundaries:**
```python
# Mock filesystem operations
with patch('pathlib.Path.stat'):
    ...

# Mock external API calls
with patch('requests.get'):
    ...
```

❌ **Bad - Mock internal logic:**
```python
# Don't mock your own code's internal methods
with patch.object(scanner, '_calculate_score'):
    ...  # You're not testing anything real!
```

---

## Common Testing Scenarios

### Testing Error Handling

```python
def test_error_scenario(self):
    # Arrange - make something fail
    with patch('pathlib.Path.stat', side_effect=PermissionError("Access denied")):
        # Act
        result = self.scanner.scan("test.tf")

        # Assert - verify graceful error handling
        assert result['score'] == -1
        assert 'Permission' in result['error']
```

### Testing Async Code (API tests)

```python
def test_async_operation(client, api_headers):
    # TestClient automatically handles async
    response = client.post("/scan", files=..., headers=api_headers)

    assert response.status_code == 200
```

### Testing Concurrency

```python
from concurrent.futures import ThreadPoolExecutor

def test_thread_safety(client, api_headers):
    def make_request(i):
        return client.post("/scan", files=..., headers=api_headers)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(make_request, i) for i in range(5)]
        results = [f.result() for f in futures]

    # All requests should succeed
    assert all(r.status_code == 200 for r in results)
```

---

## Debugging Failing Tests

### 1. Use pytest's verbose mode

```bash
python3 -m pytest tests/test_api.py::test_name -vv
```

### 2. Print debugging info

```python
def test_feature(self):
    result = scanner.scan("test.tf")

    # Add temporary print for debugging
    print(f"Result: {result}")
    import pprint
    pprint.pprint(result)

    assert result['score'] > 0
```

Run with `-s` flag to see prints:
```bash
python3 -m pytest tests/test_api.py::test_name -v -s
```

### 3. Use pytest's built-in debugger

```bash
# Drop into debugger on failure
python3 -m pytest tests/test_api.py::test_name --pdb

# Drop into debugger on first failure
python3 -m pytest tests/ --pdb -x
```

### 4. Check logs

Tests in TerraSafe generate logs. Check them:
```python
# In test
import logging
logging.basicConfig(level=logging.DEBUG)

# Run test
python3 -m pytest tests/test_api.py -v -s
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov

    - name: Run tests
      env:
        TERRASAFE_API_KEY_HASH: ${{ secrets.TEST_API_KEY_HASH }}
      run: |
        pytest tests/ --cov=terrasafe --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v2
```

---

## Additional Resources

- **pytest Documentation:** https://docs.pytest.org/
- **unittest Documentation:** https://docs.python.org/3/library/unittest.html
- **Mock Documentation:** https://docs.python.org/3/library/unittest.mock.html
- **Test-Driven Development:** https://testdriven.io/

---

## Getting Help

If you encounter issues:

1. Check this guide first
2. Review `TEST_REFACTORING_SUMMARY.md` for patterns
3. Look at existing tests for examples
4. Check pytest output carefully - it's usually very helpful!
5. Use `pytest --collect-only` to see available tests

---

**Remember:** Good tests are:
- ✓ Fast to run
- ✓ Easy to understand
- ✓ Isolated from each other
- ✓ Repeatable
- ✓ Self-validating (clear pass/fail)
- ✓ Timely (written close to the code they test)
