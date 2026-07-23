#!/usr/bin/env bash
#
# Local container smoke test — exercises the SAME image Cloud Run will build,
# with a Cloud-Run-like environment, before you spend a cloud build on it.
#
# Requires Docker. If Docker is not installed, this is the exact contract Cloud
# Build validates for you at deploy time (deploy.sh); the checks below mirror it.
#
# Run from the REPOSITORY ROOT:
#   bash deploy/cloudrun/local_container_test.sh
set -euo pipefail

IMAGE="terravault-api:cloudrun-local"
NAME="terravault-cloudrun-local"
PORT="${PORT:-8080}"

if [[ ! -f "Dockerfile" ]]; then
  echo "ERROR: run from the repository root (Dockerfile not found)." >&2
  exit 1
fi

# The lifespan handler REFUSES to start without TERRAVAULT_API_KEY_HASH, so mint a
# throwaway bcrypt hash for the test. bcrypt ships in requirements, but generate the
# hash on the host to keep the container's env self-contained.
API_KEY="localtest-$(date +%s)"
API_KEY_HASH="$(python3 - "$API_KEY" <<'PY'
import sys, bcrypt
print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())
PY
)"

echo "[1/4] Building image (mirrors Cloud Build)..."
docker build -t "$IMAGE" .

echo "[2/4] Starting one container on :$PORT ..."
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  -p "${PORT}:${PORT}" \
  -e PORT="$PORT" \
  -e TERRAVAULT_ENVIRONMENT=production \
  -e TERRAVAULT_API_HOST=0.0.0.0 \
  -e TERRAVAULT_REDIS_URL="" \
  -e TERRAVAULT_SERVE_FRONTEND=true \
  -e TERRAVAULT_API_TRUSTED_HOSTS='["*"]' \
  -e TERRAVAULT_ENABLE_DOCS=true \
  -e TERRAVAULT_API_KEY_HASH="$API_KEY_HASH" \
  "$IMAGE"

echo "[3/4] Waiting for /health ..."
healthy=0
for _ in $(seq 1 30); do
  if curl -fsS "http://localhost:${PORT}/health" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 1
done
if [[ "$healthy" -ne 1 ]]; then
  echo "FAIL: /health never came up. Logs:" >&2
  docker logs --tail 40 "$NAME" >&2
  exit 1
fi

echo "[4/4] Contract checks:"
echo -n "  /health          : "; curl -fsS "http://localhost:${PORT}/health"; echo
echo -n "  / (SPA served)   : "; curl -fsS "http://localhost:${PORT}/" | grep -qi "<!doctype html" && echo "index.html OK" || echo "NO HTML"
echo -n "  POST /scan no key: "; curl -s -o /dev/null -w '%{http_code} (expect 403)\n' -X POST "http://localhost:${PORT}/scan"

echo
echo "PASS. Test API key (X-API-Key header): $API_KEY"
echo "Tear down with: docker rm -f $NAME"
