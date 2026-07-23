#!/usr/bin/env bash
#
# Deploy terravault-api to Google Cloud Run — 100% GCP Always Free tier.
#
# Serverless replacement for the GCE VM + Docker Compose + Caddy stack:
#   - scale-to-zero (--min-instances=0): no idle cost, stays in the free tier
#   - Cloud Run terminates HTTPS on *.run.app  (no Caddy, no DuckDNS, no Let's Encrypt)
#   - no Postgres / Redis / Prometheus / Grafana (the API runs stateless; rate
#     limiting is in-memory; observability is Cloud Run's built-in metrics + logs)
#
# Prerequisites (see README.md for the one-time setup):
#   1. Billing re-linked to the project (Cloud Run/Build require it even for free-tier use).
#   2. APIs enabled: run, cloudbuild, artifactregistry.
#   3. Secret `terravault-api-key-hash` created in Secret Manager.
#
# Run from the REPOSITORY ROOT (the build context and Dockerfile live there):
#   bash deploy/cloudrun/deploy.sh
set -euo pipefail

PROJECT="${PROJECT:-terravault}"
REGION="${REGION:-us-central1}"          # free North-America egress; matches the GCS buckets
SERVICE="${SERVICE:-terravault-api}"
SECRET="${SECRET:-terravault-api-key-hash}"

if [[ ! -f "Dockerfile" ]]; then
  echo "ERROR: run this from the repository root (Dockerfile not found in $(pwd))." >&2
  exit 1
fi

gcloud run deploy "$SERVICE" \
  --project="$PROJECT" \
  --region="$REGION" \
  --source=. \
  --allow-unauthenticated \
  --min-instances=0 \
  --max-instances=3 \
  --cpu=1 \
  --memory=512Mi \
  --concurrency=40 \
  --timeout=60 \
  --port=8080 \
  --env-vars-file=deploy/cloudrun/env.yaml \
  --set-secrets="TERRAVAULT_API_KEY_HASH=${SECRET}:latest"

echo
echo "Deployed. Service URL:"
gcloud run services describe "$SERVICE" --project="$PROJECT" --region="$REGION" \
  --format="value(status.url)"
