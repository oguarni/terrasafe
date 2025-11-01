# TerraSafe Quick Start Guide

## 🚀 Quick Setup (5 Minutes)

This guide will help you get TerraSafe up and running with database persistence and monitoring.

---

## Prerequisites

- Docker and Docker Compose installed
- Python 3.10+ installed
- ~2GB free disk space

---

## Automated Setup (Recommended)

We've created an automated setup script that handles everything:

```bash
# Run the setup script
./scripts/setup_infrastructure.sh
```

This script will:
1. ✅ Check/generate API key
2. ✅ Start Redis and PostgreSQL
3. ✅ Run database migrations
4. ✅ Start API, Prometheus, and Grafana
5. ✅ Verify all services are healthy

**Jump to [Using TerraSafe](#using-terrasafe) after running the script!**

---

## Manual Setup

If you prefer manual setup, follow these steps:

### Step 1: API Key Setup

**Your API key has already been generated!**

```
Plain API Key:  REDACTED_API_KEY
Hashed Key:     REDACTED_HASH
```

**⚠️ IMPORTANT:** Save the plain API key securely - you'll need it for API requests!

The hashed key is already configured in your `.env` file.

### Step 2: Start Infrastructure Services

```bash
# Start Redis and PostgreSQL
docker-compose up -d redis postgres

# Wait for services to be healthy (about 10 seconds)
docker-compose ps
```

### Step 3: Run Database Migrations

```bash
# Install alembic if not already installed
pip install alembic

# Run migrations
alembic upgrade head

# Verify migration status
alembic current
```

Expected output:
```
20251023_initial_schema (head)
```

### Step 4: Start Application Services

```bash
# Start the API, Prometheus, and Grafana
docker-compose up -d terrasafe-api prometheus grafana

# Check status
docker-compose ps
```

All services should show "Up (healthy)".

### Step 5: Verify Installation

```bash
# Check API health
curl http://localhost:8000/health

# Should return:
# {
#   "status": "healthy",
#   "service": "TerraSafe",
#   "version": "1.0.0",
#   "database": {
#     "connected": true,
#     "healthy": true
#   }
# }
```

---

## Using TerraSafe

### Access the Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **API** | http://localhost:8000 | API Key required |
| **API Docs** | http://localhost:8000/docs | None (dev only) |
| **Metrics** | http://localhost:8000/metrics | None |
| **Prometheus** | http://localhost:9090 | None |
| **Grafana** | http://localhost:3000 | admin/admin |

### Scan a Terraform File

#### Using curl:

```bash
curl -X POST \
  -H "X-API-Key: REDACTED_API_KEY" \
  -F "file=@test_files/vulnerable.tf" \
  http://localhost:8000/scan
```

#### Using Python:

```python
import requests

url = "http://localhost:8000/scan"
headers = {"X-API-Key": "REDACTED_API_KEY"}

with open("terraform.tf", "rb") as f:
    files = {"file": f}
    response = requests.post(url, headers=headers, files=files)

print(response.json())
```

#### Response Example:

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
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "performance": {
    "scan_time_seconds": 0.234,
    "file_size_kb": 1.5,
    "from_cache": false
  }
}
```

---

## Monitoring with Grafana

### Access Grafana

1. Open http://localhost:3000
2. Login with `admin` / `admin`
3. (Optional) Change password when prompted

### View the TerraSafe Dashboard

The **TerraSafe Overview** dashboard is pre-configured and includes:

- **Scan Rate**: Real-time scan requests per second
- **Cache Hit Rate**: Percentage of cached scans
- **Scan Duration**: Average time to scan files
- **Vulnerabilities by Severity**: Distribution of findings
- **Vulnerabilities by Category**: Trend analysis
- **High-Risk Scans**: P95/P99 percentiles
- **API Latency**: Request performance
- **Error Rates**: System health

The dashboard is located at: **Dashboards → TerraSafe Overview**

---

## Database Operations

### Query Recent Scans

```bash
# Access PostgreSQL
docker-compose exec postgres psql -U terrasafe_user -d terrasafe

# Query recent scans
SELECT filename, score, confidence, created_at
FROM scans
ORDER BY created_at DESC
LIMIT 10;

# Get vulnerability statistics
SELECT severity, COUNT(*) as count
FROM vulnerabilities
GROUP BY severity;
```

### Python Database Access

```python
import asyncio
from terrasafe.infrastructure.database import get_db_manager
from terrasafe.infrastructure.repositories import ScanRepository

async def get_recent_scans():
    db = get_db_manager()
    await db.connect()

    async with db.session() as session:
        repo = ScanRepository(session)
        scans = await repo.get_recent_scans(limit=10)

        for scan in scans:
            print(f"{scan.filename}: {scan.score}/100")

    await db.disconnect()

asyncio.run(get_recent_scans())
```

---

## Useful Commands

### Docker Operations

```bash
# View all service logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f terrasafe-api

# Restart a service
docker-compose restart terrasafe-api

# Stop all services
docker-compose down

# Stop and remove volumes (⚠️ deletes data)
docker-compose down -v
```

### Database Migrations

```bash
# Check current migration
alembic current

# View migration history
alembic history

# Create new migration (after model changes)
alembic revision --autogenerate -m "description"

# Rollback one migration
alembic downgrade -1
```

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run security tests
pytest tests/test_security.py -v

# Run performance tests
pytest tests/test_performance.py -v

# Run with coverage
pytest tests/ --cov=terrasafe --cov-report=html
```

---

## Troubleshooting

### API Returns 403 (Forbidden)

**Problem**: Missing or invalid API key

**Solution**:
```bash
# Verify your API key in the request
curl -H "X-API-Key: REDACTED_API_KEY" \
     http://localhost:8000/health
```

### Database Connection Failed

**Problem**: PostgreSQL not running or not healthy

**Solution**:
```bash
# Check PostgreSQL status
docker-compose ps postgres

# View PostgreSQL logs
docker-compose logs postgres

# Restart PostgreSQL
docker-compose restart postgres
```

### Prometheus Not Scraping Metrics

**Problem**: Prometheus can't reach the API

**Solution**:
```bash
# Check Prometheus targets
open http://localhost:9090/targets

# Verify API metrics endpoint
curl http://localhost:8000/metrics
```

### Grafana Dashboard Shows "No Data"

**Problem**: No scans have been performed yet

**Solution**:
```bash
# Perform a test scan
curl -X POST \
  -H "X-API-Key: REDACTED_API_KEY" \
  -F "file=@test_files/vulnerable.tf" \
  http://localhost:8000/scan

# Wait 15-30 seconds for metrics to update
# Refresh Grafana dashboard
```

---

## Next Steps

### Production Deployment

For production deployment, you should:

1. **Change default passwords**:
   - PostgreSQL password in `.env`
   - Grafana admin password
   - Generate a strong API key

2. **Enable HTTPS**:
   - Use a reverse proxy (nginx, traefik)
   - Configure SSL/TLS certificates

3. **Update CORS settings**:
   - Set proper allowed origins in `.env`
   - Restrict to your domain

4. **Configure backups**:
   - Set up automated PostgreSQL backups
   - Configure volume backups

5. **Set up monitoring alerts**:
   - Configure Prometheus Alertmanager
   - Set up notification channels

### Advanced Features

- **ML Model Versioning**: Track and manage model versions
- **Scan History Analysis**: Query historical trends
- **Custom Dashboards**: Create domain-specific visualizations
- **API Integration**: Integrate with CI/CD pipelines

---

## Getting Help

### Check Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f terrasafe-api
docker-compose logs -f postgres
docker-compose logs -f prometheus
```

### Health Checks

```bash
# API health
curl http://localhost:8000/health

# Database health
docker-compose exec postgres pg_isready -U terrasafe_user

# Redis health
docker-compose exec redis redis-cli ping
```

### Documentation

- **API Documentation**: http://localhost:8000/docs (development only)
- **Implementation Summary**: See `IMPLEMENTATION_SUMMARY.md`
- **Architecture Details**: See `PRIORITY_4_5_IMPLEMENTATION.md`

---

## Summary

You now have a fully operational TerraSafe installation with:

✅ **Security**: Bcrypt-hashed API keys, rate limiting, input validation
✅ **Database**: PostgreSQL with async SQLAlchemy
✅ **Caching**: Redis-backed LRU cache
✅ **Monitoring**: Prometheus metrics + Grafana dashboards
✅ **Performance**: Async I/O, vectorized operations
✅ **Production-Ready**: Health checks, logging, error handling

**Happy scanning!** 🛡️
