# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please email:
**security@terrasafe.dev** (or your university email)

**Do NOT** create a public GitHub issue for security vulnerabilities.

### What to Include
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response Timeline
- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Release**: Depends on severity (Critical: 1-3 days, High: 1-2 weeks)

## Security Best Practices for Users

### Running TerraSafe Securely

1. **Use Docker** (runs as non-root user):
```bash
docker run --rm -v $(pwd):/scan terrasafe:latest /scan/terraform.tf
```

2. **Verify Integrity** (if distributing):
```bash
sha256sum terrasafe-1.0.0.tar.gz
# Compare with published checksum
```

3. **Limit File Access**:
```bash
# Only give read access to Terraform files
python -m terrasafe.main --read-only /path/to/terraform/
```

### Dependencies

We use:
- `safety` for dependency vulnerability scanning
- `bandit` for SAST (Static Application Security Testing)
- Automated GitHub Dependabot alerts

### Secure Development

Contributors must:
- Run `make security-scan` before committing
- Use pre-commit hooks (`make setup-hooks`)
- Never commit secrets (use `.gitignore`)
- Follow OWASP Top 10 guidelines

## Known Limitations

1. **ML Model**: Trained on synthetic data - may have false positives
2. **Parser**: Relies on `python-hcl2` - report parser bugs upstream
3. **Scope**: Currently supports AWS only (Azure/GCP coming soon)

## Security Scanning Schedule

- **Dependencies**: Weekly (automated via Dependabot)
- **SAST**: Every commit (via pre-commit hooks)
- **Container**: On release (via Trivy)
- **Penetration Testing**: N/A (CLI tool, no network exposure)
