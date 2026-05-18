# Deploy TerraVault to Oracle Cloud Always Free

Target: a publicly reachable TerraVault deployment on the Oracle Cloud
**Always Free** tier — 4 ARM Ampere cores, 24 GB RAM, 200 GB block
storage, **no monthly bill**, no expiration.

This guide deploys the full `docker-compose.yml` stack (API + Postgres +
Redis + Prometheus + Grafana + Caddy TLS) behind a free DuckDNS
subdomain with automatic HTTPS via Let's Encrypt.

---

## What you'll have when you're done

```
https://terravault-<yourname>.duckdns.org/health     → 200 OK
https://terravault-<yourname>.duckdns.org/docs       → Swagger UI
https://terravault-<yourname>.duckdns.org/scan       → API key gated
http://<VM_PUBLIC_IP>:3000  (SSH tunnel only)       → Grafana
http://<VM_PUBLIC_IP>:9090  (SSH tunnel only)       → Prometheus
```

---

## 1. Create the Oracle Cloud account

1. Go to <https://signup.oraclecloud.com/> and pick **Brazil East
   (São Paulo)** as your home region — lowest latency from Brazil.
2. The signup requires a credit card for identity verification. Oracle
   does **not** charge it as long as you stay inside Always Free limits.
3. Wait 5–10 minutes after signup for the tenancy to fully provision.

> **Always Free Ampere quota:** total of 4 OCPU + 24 GB RAM, split
> across 1–4 VMs. We'll use one big VM with all 4 OCPU and 24 GB RAM.

---

## 2. Provision the Ampere A1 VM

1. **Menu → Compute → Instances → Create instance**
2. Settings:
   - **Name:** `terravault-prod`
   - **Image:** Canonical Ubuntu 22.04 (ARM)
   - **Shape:** `VM.Standard.A1.Flex` — **4 OCPU, 24 GB memory**
   - **Subnet:** default VCN public subnet, **assign public IPv4**
   - **SSH keys:** paste your `~/.ssh/id_ed25519.pub` (generate one with
     `ssh-keygen -t ed25519` if you don't have it)
   - **Boot volume:** keep default 47 GB (Always Free)
3. Click **Create**. Wait ~2 min for state `RUNNING`. Note the
   **public IP**.

> If you see *"Out of host capacity"*, retry with São Paulo,
> Vinhedo (sa-vinhedo-1), or a US region — Ampere capacity rotates.

---

## 3. Open ingress ports 80 and 443

By default the VCN blocks everything except SSH.

1. **Menu → Networking → Virtual Cloud Networks**
2. Click your VCN → **Public Subnet** → **Default Security List**
3. Add **two** Ingress Rules:

| Source CIDR | Protocol | Dest Port | Description |
|---|---|---|---|
| `0.0.0.0/0` | TCP | `80`  | HTTP — Let's Encrypt challenge |
| `0.0.0.0/0` | TCP | `443` | HTTPS — public API |

Do **not** open 3000 (Grafana), 9090 (Prometheus), 5432 (Postgres),
6379 (Redis), or 8000 (API direct). Caddy is the only public ingress.

Then on the VM (Ubuntu uses `iptables` rules persisted by `netfilter`):

```bash
ssh ubuntu@<VM_PUBLIC_IP>
sudo iptables -I INPUT 6 -p tcp -m state --state NEW -m tcp --dport 80  -j ACCEPT
sudo iptables -I INPUT 6 -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save
```

---

## 4. Register a free DuckDNS subdomain

1. Go to <https://www.duckdns.org/> → log in with GitHub/Google.
2. Create a subdomain: `terravault-<yourname>` (e.g.
   `terravault-guarnieri.duckdns.org`).
3. Set the **current IP** field to your VM's public IP and click
   **update ip**.
4. Save your **DuckDNS token** (top of page) for the next step.

Optionally, install the DuckDNS auto-updater on the VM so the record
follows IP changes (Oracle public IPs are sticky unless you stop/start,
but this is cheap insurance):

```bash
mkdir -p ~/duckdns
cat > ~/duckdns/duck.sh <<'EOF'
#!/bin/bash
echo url="https://www.duckdns.org/update?domains=terravault-YOURNAME&token=YOUR_DUCKDNS_TOKEN&ip=" | curl -k -o ~/duckdns/duck.log -K -
EOF
chmod 700 ~/duckdns/duck.sh
( crontab -l 2>/dev/null; echo "*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1" ) | crontab -
```

---

## 5. Install Docker on the VM

```bash
ssh ubuntu@<VM_PUBLIC_IP>

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
```

Then shred the secrets dump:

```bash
shred -u .env.secrets
```

---

## 7. Train the ML model (if `models/` is empty)

The repo ships pre-trained models in `models/`. If they're missing
(e.g. a clean checkout without LFS), run:

```bash
python3 -m pip install --user -r requirements.txt
python3 -m terravault.infrastructure.ml_model train
```

---

## 8. Launch the stack

```bash
docker compose up -d
docker compose ps
docker compose logs -f caddy   # watch Let's Encrypt cert issuance
```

Caddy will provision the TLS cert in ~30 seconds the first time. Look
for `certificate obtained successfully` in the Caddy logs.

---

## 9. Smoke test from your laptop

```bash
DOMAIN=terravault-<yourname>.duckdns.org
API_KEY=<from your password manager>

# 1. TLS reachable
curl -fsS https://$DOMAIN/health | jq .

# 2. Swagger UI
xdg-open https://$DOMAIN/docs

# 3. Authenticated scan
curl -fsS -X POST \
  -H "X-API-Key: $API_KEY" \
  -F "file=@test_files/vulnerable.tf" \
  https://$DOMAIN/scan | jq .

# 4. Metrics blocked from public
curl -i https://$DOMAIN/metrics    # expect 404
```

---

## 10. Reach Grafana + Prometheus (private, via SSH tunnel)

```bash
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 ubuntu@<VM_PUBLIC_IP>
# then on your laptop:
xdg-open http://127.0.0.1:3000   # Grafana — admin / GRAFANA_ADMIN_PASSWORD
xdg-open http://127.0.0.1:9090   # Prometheus
```

---

## Operations

### Update to a new commit

```bash
ssh ubuntu@<VM_PUBLIC_IP>
cd terravault
git pull
docker compose up -d --build terravault-api
```

### Rotate the API key

```bash
python3 scripts/generate_secrets.py    # only use the API key fields
$EDITOR .env                            # replace TERRAVAULT_API_KEY_HASH
docker compose up -d terravault-api
```

### Backups

The `terravault-postgres-data` volume holds scan history. For a free
backup target, dump it to an OCI Object Storage bucket (also Always
Free up to 20 GB):

```bash
docker compose exec -T postgres pg_dump -U terravault_user terravault \
  | gzip > backup-$(date +%F).sql.gz
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Caddy stuck on `obtaining certificate` | Port 80 not reachable | Recheck the VCN ingress rule and `iptables` |
| 421 Misdirected Request | `TERRAVAULT_API_TRUSTED_HOSTS` doesn't include your DuckDNS domain | Edit `.env`, `docker compose up -d terravault-api` |
| `bcrypt` errors at startup | `TERRAVAULT_API_KEY_HASH` is the plaintext key, not the hash | Re-run `scripts/generate_secrets.py`, use the `_HASH` value |
| Out of memory on `docker compose up` | Ampere VM swap disabled by default | `sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile` |

---

## Cost

| Resource | Always Free? | Notes |
|---|---|---|
| Ampere A1 4 OCPU / 24 GB | Yes | 3,000 OCPU-hours/mo — covers 24/7 |
| 47 GB boot volume | Yes | Always Free up to 200 GB total |
| 10 TB outbound transfer | Yes | More than enough for a portfolio demo |
| Public IPv4 | Yes | 2 free reserved IPs |

**Monthly bill: R$ 0.00** as long as you stay within Always Free shapes.
