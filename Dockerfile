FROM python:3.10-slim

WORKDIR /app

# System dependencies first (changes rarely, better layer caching)
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Upgrade the build tooling the base image bakes in, before anything uses it.
# python:3.10-slim ships pip 23.0.1 and a setuptools old enough that its
# _vendor/ tree carried jaraco.context 5.3.0 (CVE-2026-23949, path traversal)
# and wheel 0.45.1 (CVE-2026-24049, privilege escalation / arbitrary code).
# Both were flagged by the Trivy gate against the built image, and neither is
# reachable through requirements.txt — they are vendored copies, so the fix is
# the tooling itself. setuptools >= 82 vendors wheel 0.46.3 and stopped
# vendoring jaraco.context altogether, so the vulnerable files are removed
# rather than merely patched.
#
# Floors, not exact pins, deliberately: this is the layer whose whole job is to
# be current on security patches, and pinning it exactly would mean editing the
# Dockerfile for every future build-tool advisory. requirements.txt below stays
# exactly pinned — that is what determines what the application runs.
# Own layer, above the COPY, so it is not rebuilt when requirements.txt changes.
RUN pip install --no-cache-dir --upgrade \
        "pip>=25.0" \
        "setuptools>=82.0.0" \
        "wheel>=0.46.2"

# Python dependencies (cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Then remove the build tooling from the runtime image entirely.
#
# Upgrading it (above) fixed the two vendored CVEs Trivy first reported, and
# immediately surfaced two more: pip 26.2.1 ships its own _vendor/ tree
# carrying msgpack 1.1.2 (GHSA-6v7p-g79w-8964) and a setuptools 70.3.0
# (CVE-2025-47273). Those cannot be fixed by any pin — they are inside pip —
# so version-chasing pip is a treadmill, and suppressing them in the gate
# would be asserting something untrue about the image.
#
# Nothing in the running container invokes pip: the entrypoint applies alembic
# migrations and execs uvicorn, and no runtime dependency imports
# pkg_resources (checked across the installed tree — only pytest does, and
# pytest is not in this image). Build tooling in a production image is
# attack surface with no counterpart in function, so it goes. Order matters:
# pip must uninstall itself last.
RUN pip uninstall -y wheel setuptools && pip uninstall -y pip

# Application code + database migrations (alembic/ and alembic.ini are needed
# so the entrypoint can run `alembic upgrade head` on startup)
COPY terravault/ ./terravault/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY entrypoint.sh ./

# Bake the trained inference model + scaler and the static frontend into the image.
# On the VM/compose path these are shadowed by bind mounts (./models, Caddy's
# ./frontend); on Cloud Run, which has no volume mounts, the baked copies are the
# only source. .dockerignore keeps the bulky retrain-only artifacts (models/versions,
# training_data.npy) and frontend build junk out of the context, so only the small
# *.pkl + metadata and the static assets are copied.
COPY models/ ./models/
COPY frontend/ ./frontend/
RUN chmod +x entrypoint.sh

# Security: run as non-root user
RUN useradd -r -s /bin/false appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Entrypoint applies migrations, then runs the CMD (the API server).
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "-m", "terravault.api"]

