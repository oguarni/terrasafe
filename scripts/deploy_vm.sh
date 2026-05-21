#!/usr/bin/env bash
#
# deploy_vm.sh — pull the latest commit and roll the docker-compose stack on
# the GCE VM, then gate on container health and a local smoke test.
#
# Run from the repo root ON THE VM:
#   bash scripts/deploy_vm.sh
#
# Idempotent: safe to re-run. Aborts (non-zero) if the working tree is dirty,
# the fast-forward fails, or a container doesn't become healthy.

set -euo pipefail

if docker compose version >/dev/null 2>&1; then
	COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE=(docker-compose)
else
	echo "error: docker compose not available" >&2
	exit 1
fi

# Refuse to clobber uncommitted edits on the VM (e.g. a hand-tweaked Caddyfile).
if [ -n "$(git status --porcelain)" ]; then
	echo "error: working tree is dirty — commit/stash VM-local changes first:" >&2
	git status --short >&2
	exit 1
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
echo "[deploy] on branch '${branch}', fast-forwarding…"
git pull --ff-only

echo "[deploy] pulling pinned images + rebuilding API"
"${COMPOSE[@]}" pull --quiet redis postgres prometheus grafana caddy || true
"${COMPOSE[@]}" up -d --build

# Wait for the API and Caddy to report healthy (compose healthchecks).
echo "[deploy] waiting for containers to become healthy…"
deadline=$(( $(date +%s) + 120 ))
for svc in terravault-api terravault-caddy; do
	while :; do
		status="$(docker inspect -f '{{.State.Health.Status}}' "$svc" 2>/dev/null || echo missing)"
		[ "$status" = "healthy" ] && { echo "[deploy] $svc healthy"; break; }
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "error: $svc not healthy (last status: $status)" >&2
			docker compose ps >&2
			exit 1
		fi
		sleep 3
	done
done

# Local smoke test (public-edge checks like /metrics 404 must be run off-box).
echo "[deploy] smoke test: /health via Caddy"
if ! curl -fsS -m 10 http://localhost/health >/dev/null; then
	echo "error: /health did not return 200 through Caddy" >&2
	exit 1
fi

echo "[deploy] done. Verify the public edge from your laptop:"
echo "    curl -s -o /dev/null -w '%{http_code}\\n' https://\$DOMAIN/metrics   # expect 404"
echo "    curl -s https://\$DOMAIN/health | jq ."
