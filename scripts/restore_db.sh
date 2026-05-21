#!/usr/bin/env bash
#
# restore_db.sh — restore a TerraVault Postgres dump produced by backup_db.sh.
#
# Usage:
#   bash scripts/restore_db.sh backups/terravault-20260521T030000Z.sql.gz
#   bash scripts/restore_db.sh gs://my-bucket/terravault-20260521T030000Z.sql.gz
#
# The dump was created with --clean --if-exists, so it drops and recreates
# objects as it loads. This OVERWRITES the current database — confirm first.

set -euo pipefail

SRC="${1:-}"
PG_SERVICE="${PG_SERVICE:-postgres}"
PG_USER="${PG_USER:-terravault_user}"
PG_DB="${PG_DB:-terravault}"

if [ -z "$SRC" ]; then
	echo "usage: $0 <dump.sql.gz | gs://bucket/dump.sql.gz>" >&2
	exit 2
fi

if docker compose version >/dev/null 2>&1; then
	COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE=(docker-compose)
else
	echo "error: docker compose not available" >&2
	exit 1
fi

# Pull a GCS object down to a temp file first so a transfer error fails before
# we touch the database.
cleanup=""
if [[ "$SRC" == gs://* ]]; then
	tmp="$(mktemp --suffix=.sql.gz)"
	cleanup="$tmp"
	echo "[restore] fetching ${SRC}"
	gcloud storage cp "$SRC" "$tmp"
	SRC="$tmp"
fi

echo "[restore] about to OVERWRITE database '${PG_DB}' from ${SRC}"
read -r -p "Type the database name to confirm: " confirm
if [ "$confirm" != "$PG_DB" ]; then
	echo "[restore] aborted"
	[ -n "$cleanup" ] && rm -f "$cleanup"
	exit 1
fi

echo "[restore] loading…"
gunzip -c "$SRC" | "${COMPOSE[@]}" exec -T "$PG_SERVICE" psql -U "$PG_USER" -d "$PG_DB"

[ -n "$cleanup" ] && rm -f "$cleanup"
echo "[restore] done — consider restarting the API: ${COMPOSE[*]} restart terravault-api"
