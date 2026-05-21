# Deploy TerraVault to Google Cloud (Compute Engine VM)

Target: a publicly reachable TerraVault deployment on a Google Cloud
**Compute Engine** VM running the full `docker-compose.yml` stack
(API + Postgres + Redis + Prometheus + Grafana + Caddy TLS) behind a
free DuckDNS subdomain with automatic HTTPS via Let's Encrypt.

This mirrors the local stack one-to-one, so everything you see in
`docker compose up` locally — including the web dashboard and the
Grafana/Prometheus monitoring — runs in production unchanged.

---

## What you'll have when you're done

```
https://terravault-<yourname>.duckdns.org/          → Web dashboard (frontend)
https://terravault-<yourname>.duckdns.org/scan.html → Scan upload page
https://terravault-<yourname>.duckdns.org/health    → 200 OK
https://terravault-<yourname>.duckdns.org/docs      → Swagger UI (off in prod by default; see ENABLE_DOCS)
https://terravault-<yourname>.duckdns.org/scan      → API key gated (POST)
http://127.0.0.1:3000  (SSH tunnel only)            → Grafana
http://127.0.0.1:9090  (SSH tunnel only)            → Prometheus
```

Caddy serves the static frontend at `/` and reverse-proxies the
explicit API paths (`/scan`, `/health`, `/docs`, `/redoc`,
`/openapi.json`, `/api/docs`) to the FastAPI container. The frontend
calls the API on the same origin, so no CORS round-trip is needed.

---

## Architecture

```
Client
  ↓ HTTPS :443 (Let's Encrypt cert, auto-renewed by Caddy)
GCE VM (e2-medium, Ubuntu 22.04)
  └─ docker compose stack on a private bridge network:
       Caddy        → TLS termination + static frontend + reverse proxy
       terravault-api (FastAPI)
       postgres     → scan history
       redis        → cache + rate limiting
       prometheus   → metrics scrape (private)
       grafana      → dashboards (private)
```

Only Caddy (80/443) is exposed publicly. Postgres, Redis, Prometheus,
Grafana, and the API direct port are reachable only inside the VM or
through an SSH tunnel.

---

## Cost

GCE has **no perpetual free VM in São Paulo** (`southamerica-east1`).
An `e2-medium` there is ~US$25/mo, comfortably covered by trial/promo
credits. Two ways to keep the bill low:

| Option | Region | Machine | Monthly | Notes |
|---|---|---|---|---|
| São Paulo (low latency) | `southamerica-east1` | `e2-medium` | ~$25 | Best latency from Brazil; pay with credits |
| Always-Free tier | `us-west1` / `us-central1` / `us-east1` | `e2-micro` | ~$0 | 1 free `e2-micro`/mo, but only 1 GB RAM — tight for the full stack, add swap |
| Static external IP | any | — | ~$0 while attached | Charged only when reserved but **un**attached |

This guide uses **`southamerica-east1` + `e2-medium`**. To run on the
free tier instead, swap `--zone`, `--machine-type=e2-micro`, and the
region in every command below, then add the swap file from
[Troubleshooting](#troubleshooting).

---

## Prerequisites

```bash
# Install gcloud CLI
curl -sSL https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init                       # log in, pick or create a project
gcloud auth application-default login

# Set defaults
export PROJECT_ID=$(gcloud config get-value project)
export REGION=southamerica-east1
export ZONE=southamerica-east1-b
gcloud config set compute/region $REGION
gcloud config set compute/zone $ZONE

# Enable the Compute Engine API
gcloud services enable compute.googleapis.com
```

---

## 1. Reserve a static external IP

A static IP means your DuckDNS record never has to chase a changing
address.

```bash
gcloud compute addresses create terravault-ip --region=$REGION
export VM_IP=$(gcloud compute addresses describe terravault-ip \
  --region=$REGION --format='value(address)')
echo $VM_IP
```

---

## 2. Open ingress ports 80 and 443

GCP's default network ships the convenience tags `http-server` and
`https-server`, whose firewall rules already allow TCP 80 and 443. We
attach those tags to the VM in the next step. Caddy also speaks HTTP/3
over **UDP 443**, which the built-in rules do not cover — add it:

```bash
gcloud compute firewall-rules create terravault-https-udp \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=udp:443 \
  --target-tags=https-server \
  --source-ranges=0.0.0.0/0
```

Do **not** open 3000 (Grafana), 9090 (Prometheus), 5432 (Postgres),
6379 (Redis), or 8000 (API direct). Caddy is the only public ingress;
everything else is reached via SSH tunnel.

---

## 3. Provision the VM

```bash
gcloud compute instances create terravault-prod \
  --zone=$ZONE \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=30GB \
  --boot-disk-type=pd-balanced \
  --address=$VM_IP \
  --tags=http-server,https-server

# Wait ~30s for SSH to come up, then connect
gcloud compute ssh terravault-prod --zone=$ZONE
```

`gcloud compute ssh` generates and registers an SSH key for you on
first use — no manual key upload needed.

---

## 4. Register a free DuckDNS subdomain

1. Go to <https://www.duckdns.org/> → log in with GitHub/Google.
2. Create a subdomain: `terravault-<yourname>` (e.g.
   `terravault-guarnieri.duckdns.org`).
3. Set the **current IP** field to your VM's static IP (`echo $VM_IP`
   from step 1) and click **update ip**.
4. Save your **DuckDNS token** (top of page).

Because the IP is reserved/static, you do **not** need the DuckDNS
auto-updater cron. (If you ever delete and recreate the VM with a new
IP, just update the DuckDNS record once.)

---

## 5. Install Docker on the VM

Run these **on the VM** (after `gcloud compute ssh`):

```bash
# Docker engine + compose plugin
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

---

## 6. Clone the repo and prepare secrets

```bash
git clone https://github.com/oguarni/terravault.git
cd terravault

# Generate strong secrets (script ships in the repo)
python3 -m pip install --user bcrypt
python3 scripts/generate_secrets.py > .env.secrets
cat .env.secrets    # copy the values — write API key plaintext into your password manager
```

Build the `.env` file:

```bash
cp .env.example .env
$EDITOR .env
```

Set these exact keys in `.env` (use the values from `.env.secrets`):

```ini
TERRAVAULT_ENVIRONMENT=production
TERRAVAULT_DEBUG=false

TERRAVAULT_API_KEY_HASH=<paste from .env.secrets>
POSTGRES_PASSWORD=<paste from .env.secrets>
GRAFANA_ADMIN_PASSWORD=<paste from .env.secrets>

TERRAVAULT_PUBLIC_DOMAIN=terravault-<yourname>.duckdns.org
TERRAVAULT_API_CORS_ORIGINS=["https://terravault-<yourname>.duckdns.org"]
TERRAVAULT_API_TRUSTED_HOSTS=["terravault-<yourname>.duckdns.org","localhost","127.0.0.1"]

# Interactive docs (/docs, /redoc, /openapi.json) are OFF in production by
# default. Uncomment to publish Swagger UI on your portfolio site:
# TERRAVAULT_ENABLE_DOCS=true
```

Then shred the secrets dump:

```bash
shred -u .env.secrets
```

---

## 7. Initialize the ML model (`models/` ships empty)

The repo ships only `models/.gitkeep`; the first scan needs a model
on disk. The bootstrap script trains and persists one using the
default IsolationForest config:

```bash
python3 -m pip install --user -r requirements.txt
bash scripts/init_models.sh
ls models/   # expect: isolation_forest.pkl, scaler.pkl, training_metadata.json, versions/
```

The API container mounts `./models` read-only, so this step **must**
run on the host before `docker compose up`.

---

## 8. Launch the stack

```bash
docker compose up -d
docker compose ps
docker compose logs -f caddy   # watch Let's Encrypt cert issuance
```

Caddy will provision the TLS cert in ~30 seconds the first time. Look
for `certificate obtained successfully` in the Caddy logs.

The API container's entrypoint runs `alembic upgrade head` on startup, so
the database schema is created automatically — no manual migration step.
Confirm it applied: `docker compose logs terravault-api | grep alembic`
should show `Running upgrade … -> …` then `migrations applied`.

---

## 9. Smoke test from your laptop

```bash
DOMAIN=terravault-<yourname>.duckdns.org
API_KEY=<from your password manager>

# 1. TLS reachable
curl -fsS https://$DOMAIN/health | jq .

# 2. Frontend served at /
curl -fsS https://$DOMAIN/ | head -n 5    # expect <!DOCTYPE html> ... <title>TerraVault | Security Dashboard</title>
xdg-open https://$DOMAIN/                  # browser: dashboard

# 3. Swagger UI — only if you set TERRAVAULT_ENABLE_DOCS=true (off in prod by default)
xdg-open https://$DOMAIN/docs

# 4. Authenticated scan
curl -fsS -X POST \
  -H "X-API-Key: $API_KEY" \
  -F "file=@test_files/vulnerable.tf" \
  https://$DOMAIN/scan | jq .

# 5. Metrics blocked from public
curl -i https://$DOMAIN/metrics    # expect 404
```

---

## 10. Reach Grafana + Prometheus (private, via SSH tunnel)

`gcloud compute ssh` forwards local ports with the standard `ssh -L`
flags after a `--`:

```bash
gcloud compute ssh terravault-prod --zone=$ZONE -- \
  -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090

# then on your laptop:
xdg-open http://127.0.0.1:3000   # Grafana — admin / GRAFANA_ADMIN_PASSWORD
xdg-open http://127.0.0.1:9090   # Prometheus
```

---

## Operations

### Update to a new commit

```bash
gcloud compute ssh terravault-prod --zone=$ZONE
cd terravault
bash scripts/deploy_vm.sh   # ff-only pull, rebuild, health-gate, smoke test
```

`deploy_vm.sh` aborts on a dirty tree or an unhealthy container, so a bad
roll fails loudly instead of silently serving a broken stack. To update
only the API without touching images, the manual path still works:
`git pull && docker compose up -d --build terravault-api`.

### Rotate the API key

```bash
python3 scripts/generate_secrets.py    # only use the API key fields
$EDITOR .env                            # replace TERRAVAULT_API_KEY_HASH
docker compose up -d terravault-api
```

### Backups

The `terravault-postgres-data` volume holds scan history. `scripts/backup_db.sh`
dumps it, rotates local copies, and (optionally) pushes the dump to a Cloud
Storage bucket. `scripts/restore_db.sh` loads one back.

> **VM scope gotcha:** a VM created with the default scopes gets
> `devstorage.read_only`, so uploads fail with a 403 even if IAM allows them.
> Grant the VM's service account write on the bucket **and** upgrade its
> storage scope (the scope change requires a stop/start; the static IP and
> TLS cert survive):
> ```bash
> SA=$(gcloud compute instances describe terravault-prod --zone=$ZONE --format='value(serviceAccounts[0].email)')
> gcloud storage buckets add-iam-policy-binding gs://terravault-backups-$PROJECT_ID \
>   --member="serviceAccount:$SA" --role=roles/storage.objectAdmin
> gcloud compute instances stop terravault-prod --zone=$ZONE
> gcloud compute instances set-service-account terravault-prod --zone=$ZONE \
>   --service-account=$SA --scopes=storage-rw,logging-write,monitoring-write,trace,service-control,service-management,pubsub
> gcloud compute instances start terravault-prod --zone=$ZONE
> ```
> Avoid this on a fresh VM by adding `--scopes=storage-rw,…` to the `instances create` in step 3.

```bash
# one-time bucket (Standard storage is a few cents/GB-mo, or use the 5 GB
# always-free regional bucket in a US region; set a lifecycle to auto-delete
# old dumps and stay within the free quota)
gcloud storage buckets create gs://terravault-backups-$PROJECT_ID --location=$REGION

# manual backup on the VM (from the repo root)
GCS_BUCKET=gs://terravault-backups-$PROJECT_ID bash scripts/backup_db.sh

# restore a specific dump (interactive confirmation; OVERWRITES the DB)
bash scripts/restore_db.sh gs://terravault-backups-$PROJECT_ID/terravault-<timestamp>.sql.gz
```

Automate it with the shipped systemd units (daily at 03:00, with catch-up
if the VM was off). Edit the `User`, `WorkingDirectory`, and `GCS_BUCKET`
placeholders in `deploy/systemd/terravault-backup.service` first:

```bash
sudo cp deploy/systemd/terravault-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now terravault-backup.timer
systemctl list-timers terravault-backup.timer   # confirm next run
journalctl -u terravault-backup.service          # inspect the last run
```

`backup_db.sh` exits non-zero on any failure and, if `HEALTHCHECK_URL` is
set, pings it on success — wire that to a dead-man switch (see Monitoring).

### Monitoring & alerting

Grafana + Prometheus run on the VM, but they go dark if the whole VM does —
so the alert that matters most comes from *outside* the box. Add a free
external monitor; nothing to install on the VM:

1. **Uptime** — point [UptimeRobot](https://uptimerobot.com) or
   [Healthchecks.io](https://healthchecks.io) at
   `https://terravault-<yourname>.duckdns.org/health` (HTTP keyword check for
   `"status":"healthy"`, 1–5 min interval). It pages you on a full outage,
   a lapsed TLS cert, or DuckDNS drift.
2. **Backup dead-man switch** — create a Healthchecks.io check with a daily
   period, then set `HEALTHCHECK_URL=https://hc-ping.com/<uuid>` in
   `deploy/systemd/terravault-backup.service`. `backup_db.sh` pings it only on
   success, so a *missed* ping (failed or skipped backup) alerts you — the
   failure mode a "did it run?" check would miss.

Internal dashboards stay where they are (SSH tunnel, step 10); these external
checks are purely the "is the front door open?" layer.

### Stop the VM to pause billing

```bash
gcloud compute instances stop terravault-prod --zone=$ZONE   # stops compute charges
gcloud compute instances start terravault-prod --zone=$ZONE  # static IP is retained
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Caddy stuck on `obtaining certificate` | Port 80 not reachable | Confirm the VM has the `http-server`/`https-server` tags and DuckDNS points at `$VM_IP` |
| 421 Misdirected Request | `TERRAVAULT_API_TRUSTED_HOSTS` doesn't include your DuckDNS domain | Edit `.env`, `docker compose up -d terravault-api` |
| `bcrypt` errors at startup | `TERRAVAULT_API_KEY_HASH` is the plaintext key, not the hash | Re-run `scripts/generate_secrets.py`, use the `_HASH` value |
| Out of memory on `docker compose up` (e2-micro/small) | Not enough RAM for the full stack | Add swap: `sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo '/swapfile none swap sw 0 0' \| sudo tee -a /etc/fstab` |
| HTTP/3 not negotiating | UDP 443 blocked | Confirm the `terravault-https-udp` firewall rule from step 2 exists |

---

## Teardown

To remove everything and stop all charges:

```bash
gcloud compute instances delete terravault-prod --zone=$ZONE --quiet
gcloud compute addresses delete terravault-ip --region=$REGION --quiet
gcloud compute firewall-rules delete terravault-https-udp --quiet
# optional: gcloud storage rm -r gs://terravault-backups-$PROJECT_ID
```
