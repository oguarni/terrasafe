# GCP Learning Sandbox — Cloud Run + Cloud SQL

A **second** deployment of TerraVault targeting Google Cloud Platform.
The goal is *not* to replace Oracle Cloud Always Free (see
[DEPLOY_ORACLE.md](DEPLOY_ORACLE.md)) — it is to:

1. Burn the **R$ 1,786 GCP credits expiring 2026-07-22** before they
   evaporate, and
2. Add a *"Deployed on GCP Cloud Run with Cloud SQL"* line to your CV.

Once credits are exhausted, **shut this down** — Oracle stays live as
the permanent portfolio URL.

---

## Architecture

```
Client
  ↓ HTTPS (managed cert on *.run.app)
Cloud Run service (terravault-api)         ← container image from Artifact Registry
  ↓ Unix socket via Cloud SQL Auth Proxy sidecar
Cloud SQL (db-f1-micro PostgreSQL)
  ↑
Secret Manager (TERRAVAULT_API_KEY_HASH, POSTGRES_PASSWORD)
```

Components dropped vs. the docker-compose stack:

- **Redis** — Cloud Run instances are short-lived; rate limiting uses
  the in-memory `FallbackRateLimiter` (already wired in the codebase).
- **Prometheus / Grafana** — Cloud Run auto-exports metrics to Cloud
  Monitoring; if you want dashboards, build them in Cloud Monitoring.

---

## Cost estimate (with credits)

| Service | Configuration | Monthly |
|---|---|---|
| Cloud Run | scale-to-zero, ~1k requests/day | ~$0 (free tier) |
| Cloud SQL | db-f1-micro, 10 GB SSD, no HA | ~$10 |
| Artifact Registry | 1 image, ~500 MB | ~$0 (free tier) |
| Secret Manager | 4 secrets | ~$0 (free tier) |
| Egress | <1 GB/mo | ~$0 |
| **Total** | | **~$10/mo** |

R$ 1,786 ≈ US$ 300 → roughly **6 months** of runway if you launch today
(2026-05-17). Credits expire 2026-07-22 — about **two billing cycles**.

---

## Prerequisites

```bash
# Install gcloud CLI
curl -sSL https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init           # log in, pick or create a project
gcloud auth application-default login

# Set defaults
export PROJECT_ID=$(gcloud config get-value project)
export REGION=southamerica-east1     # São Paulo
gcloud config set run/region $REGION
gcloud config set artifacts/location $REGION
```

Enable APIs:

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  cloudbuild.googleapis.com
```

---

## 1. Create Cloud SQL (Postgres db-f1-micro)

```bash
export DB_INSTANCE=terravault-db
export DB_NAME=terravault
export DB_USER=terravault_user
export DB_PASSWORD=$(openssl rand -base64 32)

gcloud sql instances create $DB_INSTANCE \
  --database-version=POSTGRES_15 \
  --tier=db-f1-micro \
  --region=$REGION \
  --storage-size=10GB \
  --storage-type=SSD \
  --no-backup \
  --authorized-networks=""    # private only — Cloud Run reaches it via socket

gcloud sql databases create $DB_NAME --instance=$DB_INSTANCE
gcloud sql users create $DB_USER --instance=$DB_INSTANCE --password=$DB_PASSWORD

# Note the connection name — looks like project:region:instance
export DB_CONN=$(gcloud sql instances describe $DB_INSTANCE --format='value(connectionName)')
echo $DB_CONN
```

---

## 2. Push secrets to Secret Manager

```bash
# API key + hash (use the repo's generator)
python3 scripts/generate_secrets.py > .env.secrets
source <(grep -E '^(TERRAVAULT_API_KEY|TERRAVAULT_API_KEY_HASH)=' .env.secrets)

echo -n "$TERRAVAULT_API_KEY_HASH" | \
  gcloud secrets create terravault-api-key-hash --data-file=-

echo -n "$DB_PASSWORD" | \
  gcloud secrets create terravault-db-password --data-file=-

# Save the plain API key in your password manager, then:
shred -u .env.secrets
```

---

## 3. Build and push the container image

```bash
# Create Artifact Registry repo
gcloud artifacts repositories create terravault \
  --repository-format=docker \
  --location=$REGION

# Authenticate Docker against AR
gcloud auth configure-docker $REGION-docker.pkg.dev

# Build + push (Cloud Build does both in one step — no local Docker needed)
gcloud builds submit \
  --tag $REGION-docker.pkg.dev/$PROJECT_ID/terravault/api:latest
```

> Cloud Build counts against credits but is generous on the free tier
> (120 build-minutes/day). A TerraVault build is ~2 min.

---

## 4. Deploy to Cloud Run

```bash
gcloud run deploy terravault-api \
  --image=$REGION-docker.pkg.dev/$PROJECT_ID/terravault/api:latest \
  --region=$REGION \
  --platform=managed \
  --allow-unauthenticated \
  --port=8000 \
  --cpu=1 \
  --memory=1Gi \
  --concurrency=20 \
  --min-instances=0 \
  --max-instances=3 \
  --timeout=60 \
  --add-cloudsql-instances=$DB_CONN \
  --set-env-vars="TERRAVAULT_ENVIRONMENT=production,TERRAVAULT_DEBUG=false,TERRAVAULT_LOG_FORMAT=json" \
  --set-env-vars="TERRAVAULT_API_HOST=0.0.0.0,TERRAVAULT_API_PORT=8000" \
  --set-env-vars="TERRAVAULT_REDIS_URL=redis://disabled" \
  --set-env-vars="TERRAVAULT_DATABASE_URL=postgresql+asyncpg://$DB_USER:PLACEHOLDER@/$DB_NAME?host=/cloudsql/$DB_CONN" \
  --set-env-vars='TERRAVAULT_API_CORS_ORIGINS=["*"]' \
  --set-env-vars='TERRAVAULT_API_TRUSTED_HOSTS=["*"]' \
  --set-secrets="TERRAVAULT_API_KEY_HASH=terravault-api-key-hash:latest"
```

> `TERRAVAULT_API_TRUSTED_HOSTS=["*"]` is acceptable here because Cloud
> Run's frontend already validates the host header against your service
> URL. Don't reuse this on a raw VM.

After deploy you get a URL like
`https://terravault-api-xxxxxx-rj.a.run.app`.

The first request will be slow (~5 s cold start while the ML model
loads). Subsequent requests hit the warm instance.

---

## 5. Inject the DB password into the env URL

The `--set-env-vars` flag can't reference Secret Manager values
inline, so re-deploy with the real password substituted:

```bash
DB_PASSWORD=$(gcloud secrets versions access latest --secret=terravault-db-password)
gcloud run services update terravault-api \
  --region=$REGION \
  --update-env-vars="TERRAVAULT_DATABASE_URL=postgresql+asyncpg://$DB_USER:$DB_PASSWORD@/$DB_NAME?host=/cloudsql/$DB_CONN"
unset DB_PASSWORD
```

(Alternative: bind the whole URL as a secret. The above is the simplest
path for a sandbox.)

---

## 6. Run the Alembic migration once

Cloud Run runs the FastAPI app on startup but does not run migrations.
Run them from your laptop against the Cloud SQL instance via the
auth proxy:

```bash
# Install + start the auth proxy in another terminal
curl -o cloud-sql-proxy https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.11.0/cloud-sql-proxy.linux.amd64
chmod +x cloud-sql-proxy
./cloud-sql-proxy $DB_CONN

# In the original terminal:
DB_PASSWORD=$(gcloud secrets versions access latest --secret=terravault-db-password)
DATABASE_URL="postgresql+asyncpg://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME" \
  alembic upgrade head
```

---

## 7. Smoke test

```bash
SERVICE_URL=$(gcloud run services describe terravault-api --region=$REGION --format='value(status.url)')
API_KEY=<from your password manager>

curl -fsS $SERVICE_URL/health | jq .
curl -fsS -X POST -H "X-API-Key: $API_KEY" \
  -F "file=@test_files/vulnerable.tf" \
  $SERVICE_URL/scan | jq .
```

Cloud Monitoring auto-collects request rate, latency, and error rate.
View at: <https://console.cloud.google.com/run/detail/$REGION/terravault-api/metrics>

---

## CI/CD (optional — adds the real CV bullet)

Add `.github/workflows/deploy-gcp.yml` that builds + pushes + deploys
on every push to `master`:

```yaml
name: Deploy to Cloud Run
on:
  push: { branches: [master] }
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: { id-token: write, contents: read }
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
          service_account: ${{ secrets.GCP_DEPLOY_SA }}
      - uses: google-github-actions/setup-gcloud@v2
      - run: |
          gcloud builds submit --tag southamerica-east1-docker.pkg.dev/${{ vars.GCP_PROJECT }}/terravault/api:${{ github.sha }}
          gcloud run deploy terravault-api \
            --image=southamerica-east1-docker.pkg.dev/${{ vars.GCP_PROJECT }}/terravault/api:${{ github.sha }} \
            --region=southamerica-east1
```

This requires a Workload Identity Federation pool — set up via
`gcloud iam workload-identity-pools create-cred-config`.

---

## Cleanup before credits expire

Run this on **2026-07-15** (one week before expiry) to avoid surprises:

```bash
gcloud run services delete terravault-api --region=$REGION --quiet
gcloud sql instances delete $DB_INSTANCE --quiet
gcloud artifacts repositories delete terravault --location=$REGION --quiet
gcloud secrets delete terravault-api-key-hash --quiet
gcloud secrets delete terravault-db-password --quiet
```

The Oracle Cloud deployment remains untouched.
