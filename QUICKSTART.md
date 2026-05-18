# TerraVault Quick Start Guide

Full-stack deployment — API server, PostgreSQL, Redis, Prometheus, Grafana — running locally in under five minutes on a standard developer machine.

For CLI-only usage with no infrastructure dependencies, see the [README Quick Start](README.md#quick-start) instead. Use this guide when you need the API, persistent history, or the Grafana dashboards.

---

## Prerequisites

- Docker and Docker Compose installed
- Python 3.10+ installed
- ~2GB free disk space

---

## Automated Setup (Recommended)

A single script handles API key generation, infrastructure provisioning, migrations, and health verification:

```bash
./scripts/setup_infrastructure.sh
```

The script will:
1. Generate or verify the API key
2. Start Redis and PostgreSQL
3. Run database migrations
4. Start the API, Prometheus, and Grafana
5. Verify every service is healthy before exiting

Proceed to [Using TerraVault](#using-terravault) once the script completes.

---

## Manual Setup

### Step 1: API Key Setup

Generate a new API key:

```bash
python scripts/generate_api_key.py
```

Save the **plain API key** securely — you will need it for all authenticated API requests. The hashed key is stored in your `.env` file automatically.

### Step 2: Start Infrastructure Services

```bash
# Start Redis and PostgreSQL
docker-compose up -d redis postgres

# Wait for services to be healthy (~10 seconds)
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

### Step 4: Start Application Services

```bash
# Start the API, Prometheus, and Grafana
docker-compose up -d terravault-api prometheus grafana

# Check status
docker-compose ps
```

All services should show `Up (healthy)`.

### Step 5: Verify Installation

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "TerraVault",
  "version": "1.0.0",
  "database": {
    "connected": true,
    "healthy": true
  }
}
```

---

## Using TerraVault

### Service Endpoints

| Service | URL | Credentials |
|---------|-----|-------------|
| **API** | http://localhost:8000 | API Key required |
| **API Docs** | http://localhost:8000/docs | None (dev only) |
| **Metrics** | http://localhost:8000/metrics | None |
| **Prometheus** | http://localhost:9090 | None |
| **Grafana** | http://localhost:3000 | admin / admin |

### Scan a Terraform File

#### Using curl:

```bash
curl -X POST \
  -H "X-API-Key: <your-api-key>" \
  -F "file=@test_files/vulnerable.tf" \
  http://localhost:8000/scan
```

#### Using Python:

```python
import requests

API_KEY = "<your-api-key>"

response = requests.post(
    "http://localhost:8000/scan",
    headers={"X-API-Key": API_KEY},
    files={"file": open("test_files/vulnerable.tf", "rb")}
)
print(response.json())
```

See the [README API section](README.md#rest-api) for the full response format.

---

## Monitoring with Grafana

### Access Grafana

1. Open http://localhost:3000
2. Log in with `admin` / `admin`
3. Change the default password when prompted

### TerraVault Overview Dashboard

The pre-configured dashboard is located at **Dashboards > TerraVault Overview** and includes:

- **Scan Rate** — Real-time scan requests per second
- **Cache Hit Rate** — Percentage of cached responses
- **Scan Duration** — Average and percentile scan times
- **Vulnerabilities by Severity** — Distribution of findings
- **Vulnerabilities by Category** — Trend analysis over time
- **High-Risk Scans** — P95/P99 percentiles
- **API Latency** — Request performance
- **Error Rates** — System health indicators

---

## Database Operations

### Query Recent Scans

```bash
# Access PostgreSQL
docker-compose exec postgres psql -U terravault_user -d terravault

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
from terravault.infrastructure.database import get_db_manager
from terravault.infrastructure.repositories import ScanRepository

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
docker-compose logs -f terravault-api

# Restart a service
docker-compose restart terravault-api

# Stop all services
docker-compose down

# Stop and remove volumes (deletes all data)
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
pytest tests/ --cov=terravault --cov-report=html
```

---

## Troubleshooting

### API Returns 403 (Forbidden)

**Cause**: Missing or invalid API key.

**Solution**: Verify the key matches what was generated in Step 1:
```bash
curl -H "X-API-Key: <your-api-key>" http://localhost:8000/health
```

If the key was lost, generate a new one with `python scripts/generate_api_key.py` and update `.env`.

### Database Connection Failed

**Cause**: PostgreSQL not running or not healthy.

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

**Cause**: Prometheus cannot reach the API container.

**Solution**:
```bash
# Check Prometheus targets
open http://localhost:9090/targets

# Verify API metrics endpoint
curl http://localhost:8000/metrics
```

### Grafana Dashboard Shows "No Data"

**Cause**: No scans have been performed yet. Metrics populate after the first scan.

**Solution**:
```bash
# Perform a test scan
curl -X POST \
  -H "X-API-Key: <your-api-key>" \
  -F "file=@test_files/vulnerable.tf" \
  http://localhost:8000/scan

# Wait 15-30 seconds for Prometheus to scrape, then refresh Grafana
```

---

## Production Deployment

For production environments:

1. **Rotate default credentials** — PostgreSQL password, Grafana admin password, and API key
2. **Enable HTTPS** — Use a reverse proxy (nginx, Traefik) with TLS certificates
3. **Restrict CORS** — Set `API_CORS_ORIGINS` in `.env` to your domain
4. **Configure backups** — Automated PostgreSQL and volume backups
5. **Set up alerting** — Configure Prometheus Alertmanager with notification channels

---

## Getting Help

### Health Checks

```bash
# API health
curl http://localhost:8000/health

# Database health
docker-compose exec postgres pg_isready -U terravault_user

# Redis health
docker-compose exec redis redis-cli ping
```

### Documentation

- **API Documentation**: http://localhost:8000/docs (Swagger UI, development only)
- **Project README**: See [README.md](README.md) for architecture and usage details

---

## Next Steps

With the stack running locally, a good progression is:

1. **Scan your own Terraform** — point `/scan` at a representative module from your project and inspect the findings
2. **Wire into CI** — use JSON output in a pipeline step that fails the build above a chosen risk threshold
3. **Tune severity overrides** — align the default severities with your organization's policy (see the domain guide in `terravault/domain/`)
4. **Harden for production** — follow the [Production Deployment](#production-deployment) checklist before exposing the API beyond localhost
