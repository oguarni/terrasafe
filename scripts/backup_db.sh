#!/usr/bin/env bash
#
# backup_db.sh — dump the TerraVault Postgres database, rotate local copies,
# and (optionally) push the dump to a Cloud Storage bucket.
#
# Designed to run on the GCE VM from the repo root, driven by a systemd timer
# or cron (see docs/DEPLOY_GCP.md → Backups). Safe to run by hand too.
#
# Configuration (env vars, all optional except where noted):
#   BACKUP_DIR        Local directory for dumps        (default: ./backups)
#   BACKUP_KEEP       Local dumps to retain            (default: 7)
#   GCS_BUCKET        gs:// bucket for off-box copies   (default: unset → skip upload)
#   PG_SERVICE        docker compose service name      (default: postgres)
#   PG_USER           Postgres role                    (default: terravault_user)
#   PG_DB             Database name                    (default: terravault)
#   HEALTHCHECK_URL   Ping this URL on success         (default: unset → skip ping)
#
# Exit codes: 0 success, non-zero on any failure (so the timer/monitor notices).

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
BACKUP_KEEP="${BACKUP_KEEP:-7}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PG_USER="${PG_USER:-terravault_user}"
PG_DB="${PG_DB:-terravault}"

# Resolve the docker compose CLI (v2 plugin preferred, fall back to v1).
if docker compose version >/dev/null 2>&1; then
	COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE=(docker-compose)
else
	echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
	exit 1
fi

timestamp="$(date +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"
outfile="$BACKUP_DIR/terravault-${timestamp}.sql.gz"

echo "[backup] dumping ${PG_DB} from service '${PG_SERVICE}' → ${outfile}"
# -T disables TTY allocation so this works under cron/systemd.
# Stream straight through gzip; a pipefail above guarantees a failed pg_dump
# aborts the script instead of leaving a truncated, valid-looking .gz.
"${COMPOSE[@]}" exec -T "$PG_SERVICE" \
	pg_dump --clean --if-exists -U "$PG_USER" "$PG_DB" \
	| gzip -9 > "$outfile"

# Reject a suspiciously tiny dump (e.g. an empty stream that still gzipped).
size_bytes="$(wc -c < "$outfile")"
if [ "$size_bytes" -lt 1024 ]; then
	echo "error: dump is only ${size_bytes} bytes — treating as failure" >&2
	rm -f "$outfile"
	exit 1
fi
echo "[backup] wrote ${size_bytes} bytes"

# Off-box copy.
if [ -n "${GCS_BUCKET:-}" ]; then
	echo "[backup] uploading to ${GCS_BUCKET}"
	gcloud storage cp "$outfile" "${GCS_BUCKET%/}/$(basename "$outfile")"
fi

# Local rotation — keep the newest $BACKUP_KEEP dumps.
echo "[backup] pruning local dumps, keeping ${BACKUP_KEEP}"
ls -1t "$BACKUP_DIR"/terravault-*.sql.gz 2>/dev/null \
	| tail -n "+$((BACKUP_KEEP + 1))" \
	| xargs -r rm -f

# Tell an external monitor we succeeded (Healthchecks.io-style dead-man switch).
if [ -n "${HEALTHCHECK_URL:-}" ]; then
	curl -fsS -m 10 --retry 3 "$HEALTHCHECK_URL" >/dev/null && echo "[backup] pinged healthcheck"
fi

echo "[backup] done"
