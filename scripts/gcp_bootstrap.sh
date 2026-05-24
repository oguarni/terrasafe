#!/usr/bin/env bash
#
# gcp_bootstrap.sh — one-time provisioning of TerraVault's automatic-deploy
# pipeline on Google Cloud, using the gcloud CLI. Idempotent: safe to re-run.
#
# Target architecture (chosen for lowest ops + lowest idle cost):
#   • Cloud Run         — serverless container, autoscale, scale-to-zero, HTTPS.
#   • Cloud SQL         — managed PostgreSQL, reached over the built-in connector.
#   • Secret Manager    — DB URL + API key hash, injected as env vars at deploy.
#   • Artifact Registry — Docker image store.
#   • Cloud Build       — GitHub-triggered build+deploy on every push to master.
#   • Rate limiting     — in-process (memory://); add Memorystore later if needed.
#
# What this script does NOT do automatically (they cost money / touch prod):
#   • Enable billing            — prints the command; opt in with ENABLE_BILLING=1.
#   • Connect the GitHub repo   — one-time Cloud Build GitHub App install (console).
#   • The first deploy          — opt in with INITIAL_DEPLOY=1, or just push to master.
#
# Prereqs: gcloud authenticated as a project Owner/Editor; billing enabled; a
# Python with `bcrypt` available (the repo .venv has it) to hash the API key.
#
# Usage:
#   bash scripts/gcp_bootstrap.sh
#   PROJECT_ID=foo REGION=us-central1 ENABLE_BILLING=1 bash scripts/gcp_bootstrap.sh

set -euo pipefail

# ---- Configuration (override any via environment) ---------------------------
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-terravault-api}"
REPO="${REPO:-terravault}"
SQL_INSTANCE="${SQL_INSTANCE:-terravault-pg}"
SQL_TIER="${SQL_TIER:-db-f1-micro}"
SQL_DB="${SQL_DB:-terravault}"
SQL_USER="${SQL_USER:-terravault_user}"
RUNTIME_SA_ID="${RUNTIME_SA_ID:-terravault-run}"
GITHUB_OWNER="${GITHUB_OWNER:-oguarni}"
GITHUB_REPO="${GITHUB_REPO:-terravault}"
DEPLOY_BRANCH="${DEPLOY_BRANCH:-master}"
TRIGGER_REGION="${TRIGGER_REGION:-global}"
PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"

ENABLE_BILLING="${ENABLE_BILLING:-0}"
INITIAL_DEPLOY="${INITIAL_DEPLOY:-0}"

RUNTIME_SA="${RUNTIME_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

# Secret names
SECRET_DB_PASSWORD="terravault-db-password"
SECRET_DB_URL="terravault-database-url"
SECRET_API_KEY_HASH="terravault-api-key-hash"

log()  { printf '\033[0;32m[bootstrap]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[0;31m[bootstrap] ERROR:\033[0m %s\n' "$1" >&2; exit 1; }

[ -n "$PROJECT_ID" ] || die "No project set. Run 'gcloud config set project <id>' or pass PROJECT_ID=."
log "Project=$PROJECT_ID Region=$REGION Service=$SERVICE"
gcloud config set project "$PROJECT_ID" >/dev/null

# ---- 1. Billing -------------------------------------------------------------
billing_enabled="$(gcloud billing projects describe "$PROJECT_ID" \
  --format='value(billingEnabled)' 2>/dev/null || echo "false")"
if [ "$billing_enabled" != "True" ]; then
  if [ "$ENABLE_BILLING" = "1" ]; then
    acct="$(gcloud billing accounts list --filter='open=true' \
      --format='value(name)' --limit=1 2>/dev/null || true)"
    [ -n "$acct" ] || die "No open billing account found. Create/select one in the console."
    log "Linking billing account ${acct} to ${PROJECT_ID}"
    gcloud billing projects link "$PROJECT_ID" --billing-account="$acct"
  else
    warn "Billing is NOT enabled on ${PROJECT_ID}. Nothing below can be created."
    warn "Enable it (a spending decision) with either:"
    warn "    gcloud billing projects link ${PROJECT_ID} --billing-account=ACCOUNT_ID"
    warn "    # or re-run this script with ENABLE_BILLING=1"
    die "Aborting until billing is enabled."
  fi
fi

# ---- 2. Enable APIs ---------------------------------------------------------
log "Enabling required APIs (idempotent)…"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  iam.googleapis.com

# ---- 3. Artifact Registry ---------------------------------------------------
if gcloud artifacts repositories describe "$REPO" --location="$REGION" >/dev/null 2>&1; then
  log "Artifact Registry repo '$REPO' exists."
else
  log "Creating Artifact Registry repo '$REPO'…"
  gcloud artifacts repositories create "$REPO" \
    --repository-format=docker --location="$REGION" \
    --description="TerraVault container images"
fi

# ---- 4. Cloud SQL (PostgreSQL) ---------------------------------------------
if gcloud sql instances describe "$SQL_INSTANCE" >/dev/null 2>&1; then
  log "Cloud SQL instance '$SQL_INSTANCE' exists."
else
  log "Creating Cloud SQL instance '$SQL_INSTANCE' (POSTGRES_15, $SQL_TIER)… (~5 min)"
  gcloud sql instances create "$SQL_INSTANCE" \
    --database-version=POSTGRES_15 \
    --tier="$SQL_TIER" \
    --region="$REGION" \
    --storage-size=10 --storage-type=SSD \
    --availability-type=zonal \
    --backup --backup-start-time=03:00
fi

INSTANCE_CONNECTION_NAME="$(gcloud sql instances describe "$SQL_INSTANCE" \
  --format='value(connectionName)')"
log "Instance connection name: $INSTANCE_CONNECTION_NAME"

if gcloud sql databases describe "$SQL_DB" --instance="$SQL_INSTANCE" >/dev/null 2>&1; then
  log "Database '$SQL_DB' exists."
else
  log "Creating database '$SQL_DB'…"
  gcloud sql databases create "$SQL_DB" --instance="$SQL_INSTANCE"
fi

# ---- 5. Secrets: DB password + DB URL + API key hash ------------------------
# Helper: ensure a secret exists, then add a new version with the given value.
put_secret() {
  local name="$1" value="$2"
  gcloud secrets describe "$name" >/dev/null 2>&1 || \
    gcloud secrets create "$name" --replication-policy=automatic >/dev/null
  printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- >/dev/null
}

# Reuse the stored password across re-runs so the SQL user keeps matching.
if gcloud secrets describe "$SECRET_DB_PASSWORD" >/dev/null 2>&1; then
  DB_PASSWORD="$(gcloud secrets versions access latest --secret="$SECRET_DB_PASSWORD")"
  log "Reusing existing DB password from Secret Manager."
else
  DB_PASSWORD="$(openssl rand -hex 24)"   # hex => URL-safe, no encoding needed
  put_secret "$SECRET_DB_PASSWORD" "$DB_PASSWORD"
  log "Generated and stored a new DB password."
fi

# Create or align the SQL user's password.
if gcloud sql users list --instance="$SQL_INSTANCE" \
   --format='value(name)' | grep -qx "$SQL_USER"; then
  gcloud sql users set-password "$SQL_USER" --instance="$SQL_INSTANCE" --password="$DB_PASSWORD"
  log "Reset password for existing SQL user '$SQL_USER'."
else
  gcloud sql users create "$SQL_USER" --instance="$SQL_INSTANCE" --password="$DB_PASSWORD"
  log "Created SQL user '$SQL_USER'."
fi

# asyncpg + Cloud SQL unix socket URL (works for both the app and Alembic).
DB_URL="postgresql+asyncpg://${SQL_USER}:${DB_PASSWORD}@/${SQL_DB}?host=/cloudsql/${INSTANCE_CONNECTION_NAME}"
put_secret "$SECRET_DB_URL" "$DB_URL"
log "Stored database URL secret '$SECRET_DB_URL'."

# API key hash: only generate once. Print the plaintext key a single time.
if gcloud secrets describe "$SECRET_API_KEY_HASH" >/dev/null 2>&1; then
  log "API key hash secret already exists — leaving it untouched."
else
  command -v "$PYTHON_BIN" >/dev/null 2>&1 || PYTHON_BIN="python3"
  API_KEY="$(openssl rand -hex 32)"
  API_KEY_HASH="$("$PYTHON_BIN" - "$API_KEY" <<'PY'
import sys, bcrypt
print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())
PY
)" || die "Could not hash API key — ensure '$PYTHON_BIN' has bcrypt installed."
  put_secret "$SECRET_API_KEY_HASH" "$API_KEY_HASH"
  warn "=============================================================="
  warn " API KEY (shown ONCE — save it now, send as X-API-Key header):"
  warn "   ${API_KEY}"
  warn "=============================================================="
fi

# ---- 6. Service accounts + IAM ---------------------------------------------
if gcloud iam service-accounts describe "$RUNTIME_SA" >/dev/null 2>&1; then
  log "Runtime service account exists: $RUNTIME_SA"
else
  log "Creating runtime service account '$RUNTIME_SA_ID'…"
  gcloud iam service-accounts create "$RUNTIME_SA_ID" \
    --display-name="TerraVault Cloud Run runtime"
fi

# Runtime SA: connect to Cloud SQL + read its two secrets (least privilege).
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${RUNTIME_SA}" \
  --role=roles/cloudsql.client --condition=None >/dev/null
for s in "$SECRET_DB_URL" "$SECRET_API_KEY_HASH"; do
  gcloud secrets add-iam-policy-binding "$s" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role=roles/secretmanager.secretAccessor >/dev/null
done
log "Granted runtime SA: cloudsql.client + secret access."

# Cloud Build SA: push images, deploy to Cloud Run, act as the runtime SA.
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
CLOUDBUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${CLOUDBUILD_SA}" \
  --role=roles/run.admin --condition=None >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${CLOUDBUILD_SA}" \
  --role=roles/artifactregistry.writer --condition=None >/dev/null
gcloud iam service-accounts add-iam-policy-binding "$RUNTIME_SA" \
  --member="serviceAccount:${CLOUDBUILD_SA}" \
  --role=roles/iam.serviceAccountUser >/dev/null
log "Granted Cloud Build SA: run.admin + artifactregistry.writer + actAs runtime SA."

# ---- 7. Cloud Build GitHub trigger -----------------------------------------
# Requires the Cloud Build GitHub App to already be installed on the repo.
if gcloud builds triggers describe terravault-deploy \
     --region="$TRIGGER_REGION" >/dev/null 2>&1; then
  log "Cloud Build trigger 'terravault-deploy' exists."
elif gcloud builds triggers create github \
       --name=terravault-deploy \
       --region="$TRIGGER_REGION" \
       --repo-owner="$GITHUB_OWNER" --repo-name="$GITHUB_REPO" \
       --branch-pattern="^${DEPLOY_BRANCH}\$" \
       --build-config=cloudbuild.yaml \
       --substitutions="_REGION=${REGION},_SERVICE=${SERVICE},_REPO=${REPO},_SQL_INSTANCE=${SQL_INSTANCE},_RUNTIME_SA_ID=${RUNTIME_SA_ID}" \
       2>/dev/null; then
  log "Created Cloud Build trigger 'terravault-deploy' on push to '$DEPLOY_BRANCH'."
else
  warn "Could not create the GitHub trigger — the repo is probably not connected yet."
  warn "Connect it once (Cloud Build GitHub App), then re-run this script:"
  warn "    https://console.cloud.google.com/cloud-build/triggers/connect?project=${PROJECT_ID}"
fi

# ---- 8. Optional first deploy ----------------------------------------------
if [ "$INITIAL_DEPLOY" = "1" ]; then
  log "Running the first build+deploy via Cloud Build…"
  gcloud builds submit --config=cloudbuild.yaml \
    --substitutions="_REGION=${REGION},_SERVICE=${SERVICE},_REPO=${REPO},_SQL_INSTANCE=${SQL_INSTANCE},_RUNTIME_SA_ID=${RUNTIME_SA_ID}" \
    .
  URL="$(gcloud run services describe "$SERVICE" --region="$REGION" \
    --format='value(status.url)' 2>/dev/null || true)"
  [ -n "$URL" ] && log "Service URL: $URL  (try: curl $URL/health)"
else
  log "Provisioning complete. Trigger the first deploy with EITHER:"
  log "    git push origin ${DEPLOY_BRANCH}      # if the trigger is connected"
  log "    INITIAL_DEPLOY=1 bash scripts/gcp_bootstrap.sh   # build+deploy now"
fi

log "Done."
