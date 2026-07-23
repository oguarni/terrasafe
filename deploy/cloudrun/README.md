# TerraVault on Cloud Run (Always Free tier)

Serverless deployment of `terravault-api`. This **replaces** the GCE VM + Docker
Compose + Caddy stack with a single scale-to-zero Cloud Run service:

| VM stack (before) | Cloud Run (after) |
|---|---|
| Caddy: TLS + reverse proxy + static files | Cloud Run native HTTPS on `*.run.app`; the API serves the SPA itself |
| DuckDNS dynamic DNS | Stable `*.run.app` URL |
| PostgreSQL container | None — the API runs stateless (DB is optional and left unset) |
| Redis container | In-memory rate limiting (`TERRAVAULT_REDIS_URL=""`) |
| Prometheus + Grafana | Cloud Run built-in metrics + Cloud Logging |
| Always-on VM (billable) | `--min-instances=0`: zero cost when idle |

The VM path (`docker-compose.yml`, `Caddyfile`) is untouched and still works; the
Cloud Run behavior is opt-in through environment variables.

## Cost

Inside the [Cloud Run Always Free tier](https://cloud.google.com/run/pricing):
2M requests, 360k GB-s, 180k vCPU-s, and 1 GB North-America egress per month.
`us-central1` is chosen so egress falls in the free North-America allotment and to
sit next to the existing `us-central1` GCS buckets. Scale-to-zero means no idle
compute cost. The container image (~250 MB) fits the Artifact Registry 0.5 GB free
tier; Cloud Build fits its 120 build-min/day free tier.

> Cloud Run and Cloud Build require an **active billing account** even to use the
> free tier. Re-link billing before deploying (Step 2 of the remediation confirmed
> there are **no** orphaned billable resources, so re-linking is safe).

## One-time setup

```bash
# 0. Point gcloud at the project and re-link billing (Console → Billing, or CLI).
gcloud config set project terravault

# 1. Enable the required APIs (run is already enabled).
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

# 2. Generate an API key + bcrypt hash. Keep the PLAINTEXT key (clients send it as
#    X-API-Key); only the HASH goes to the server.
python scripts/generate_api_key.py

# 3. Store the HASH in Secret Manager (free tier: 6 versions, 10k accesses/month).
printf '%s' 'PASTE_THE_BCRYPT_HASH_HERE' | \
  gcloud secrets create terravault-api-key-hash --data-file=- --replication-policy=automatic
# Rotate later with:  gcloud secrets versions add terravault-api-key-hash --data-file=-

# 4. Let the Cloud Run runtime service account read the secret.
PROJECT_NUMBER="$(gcloud projects describe terravault --format='value(projectNumber)')"
gcloud secrets add-iam-policy-binding terravault-api-key-hash \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role=roles/secretmanager.secretAccessor
```

## (Optional) Local container test

Requires Docker. Mirrors what Cloud Build validates at deploy time.

```bash
bash deploy/cloudrun/local_container_test.sh
```

## Deploy

```bash
bash deploy/cloudrun/deploy.sh
```

The first `--source` deploy auto-creates a `cloud-run-source-deploy` Artifact
Registry repo (accept the prompt). On success it prints the service URL.

## Post-deploy

```bash
URL="$(gcloud run services describe terravault-api --region=us-central1 --format='value(status.url)')"
curl -fsS "$URL/health"                       # -> {"status":"healthy",...}
open "$URL"                                    # the SPA, served from the same service
open "$URL/docs"                               # Swagger (TERRAVAULT_ENABLE_DOCS=true)
curl -X POST -H "X-API-Key: <PLAINTEXT_KEY>" -F 'file=@sample.tf' "$URL/scan"
```

`TERRAVAULT_API_TRUSTED_HOSTS` is `["*.run.app"]`, which already accepts the default
URL. If you map a custom domain, add it to that array in
[`env.yaml`](./env.yaml) and redeploy.

## What changed in the app (all backward-compatible)

- `terravault/api.py` — `main()` honors `$PORT` (Cloud Run) with a fallback to
  `TERRAVAULT_API_PORT`; rate limiting uses in-memory storage when
  `TERRAVAULT_REDIS_URL` is empty; optional static-frontend mount at `/`.
- `terravault/config/settings.py` — new `serve_frontend` / `frontend_dir` settings.
- `Dockerfile` — bakes the inference model (`models/*.pkl`) and the `frontend/`
  into the image, since Cloud Run has no volume mounts.

## Notes / hardening backlog

- **`/metrics` is public** in single-service mode (Caddy used to gate it by IP).
  It only exposes Prometheus counters; gate it behind the API key or drop
  `prometheus-client` if that matters for your threat model.
- Rate limiting is **per-instance** in-memory. With scale-to-zero and low traffic
  this is usually one instance; under fan-out it is not a global limit.
- If a cold start OOMs while importing scikit-learn, raise `--memory` to `1Gi`
  (still within the free tier at low traffic).
