#!/usr/bin/env bash
# Launch the A.3 "atypical-but-valid" ML experiment on GCP.
#
# Why GCP: the experiment needs a large, representative population of real
# Terraform mined from the registry (thousands of modules) plus the ~30k public
# GitHub .tf blobs, each scanned through the full production pipeline. That is
# `make evaluate`-class heavy work the project runs on GCP, not locally (the free
# credits expire 2026-07-22).
#
# What it does: stages the (uncommitted) A.3 harness files to GCS, creates a
# self-terminating VM that clones `master`, overlays the staged files, restores
# the trained ML model + training vectors, mines a registry-wide + GitHub corpus,
# scans every config (rules + IF), runs the atypicality experiment, renders the
# report, uploads everything, and powers itself off. No Docker, no competitors.
#
# Run 1 post-mortem (2026-07-20): a sequential scan blew the 150m cap and
# --instance-termination-action=DELETE vaporised the VM before anything was
# uploaded. Hence: parallel scan, a 5-min heartbeat that streams the log and
# phase status to ${DST}/live/, and STOP on cap so the disk survives for
# post-mortem. The VM stops (not deletes) when done — delete it after collect.
#
# Usage:  scripts/gcp_ml_atypical.sh
# Watch:    gsutil cat gs://terravault-ml-artifacts/runs/<RUN>/live/status.txt
# Collect (after ~40-90 min):
#   gsutil cp -r gs://terravault-ml-artifacts/runs/<RUN>/ .
#   gcloud compute instances delete tv-<RUN> --zone=<ZONE>
set -euo pipefail

PROJECT="${TV_PROJECT:-terravault}"
ZONE="${TV_ZONE:-us-central1-a}"
BUCKET="${TV_BUCKET:-terravault-ml-artifacts}"
MACHINE="${TV_MACHINE:-e2-highcpu-16}"
MODEL_RUN="${TV_MODEL_RUN:-20260707-224841}"          # GCS run holding the model + training_data.npy
GITHUB_CORPUS="${TV_GITHUB_CORPUS:-gs://terravault-ml-artifacts/github_corpus}"
MAX_MODULES="${TV_MAX_MODULES:-1500}"                  # registry-wide breadth (+ ~30k GitHub blobs)
REPO_URL="${TV_REPO_URL:-https://github.com/oguarni/terravault.git}"

RUN="ml-atypical-$(date +%Y%m%d-%H%M%S)"
VM="tv-${RUN}"
REPO_ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

echo ">> staging A.3 harness for run ${RUN}"
tar czf "${STAGE}/a3-src.tgz" -C "${REPO_ROOT}" \
  evaluation/ml_atypicality.py \
  evaluation/report_ml_atypicality.py
gsutil cp "${STAGE}/a3-src.tgz" "gs://${BUCKET}/eval-src/${RUN}.tgz"

# Startup script in a file (not inline) so gcloud does not parse its commas as
# --metadata separators. Quoted heredoc keeps ${var} literal -> resolved on the
# VM via md().
STARTUP="${STAGE}/startup.sh"
cat > "${STARTUP}" <<'STARTUP_EOF'
#!/bin/bash
set -x; exec > >(tee /var/log/tv-a3.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/attributes/$1"; }
RUN=$(md run-id); BUCKET=$(md bucket); MODEL_RUN=$(md model-run)
REPO_URL=$(md repo-url); GITHUB_CORPUS=$(md github-corpus); MAX_MODULES=$(md max-modules)
DST="gs://${BUCKET}/runs/${RUN}"

# Heartbeat: every 5 min stream the log, phase status and any phase outputs to
# ${DST}/live/ so a dead run still leaves a full trail in GCS (run-1 lesson).
STATUS=/tmp/status.txt
mark() { echo "$(date -u +%FT%TZ) phase=$1" >> "${STATUS}"; }
( while sleep 300; do
    gsutil -q cp /var/log/tv-a3.log "${STATUS}" "${DST}/live/" 2>/dev/null
    for f in /tmp/collect.txt /tmp/github.txt /tmp/exp.txt; do
      [ -f "$f" ] && gsutil -q cp "$f" "${DST}/live/" 2>/dev/null
    done
  done ) &
HEARTBEAT_PID=$!
mark boot

apt-get update && apt-get install -y python3-pip python3-venv git make
mark deps-done
git clone "${REPO_URL}" /opt/tv && cd /opt/tv

# Overlay the uncommitted A.3 harness staged for this run.
gsutil cp "gs://${BUCKET}/eval-src/${RUN}.tgz" /tmp/a3-src.tgz
tar xzf /tmp/a3-src.tgz -C /opt/tv

# Restore the trained model + training vectors (models/ is gitignored).
mkdir -p /opt/tv/models
gsutil -m cp -r "gs://${BUCKET}/runs/${MODEL_RUN}/models/*" /opt/tv/models/ || true

python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
mark pip-done

# --- mine a representative real-world corpus -------------------------------
# Registry-wide breadth (the large/complex tail) ...
mark mine-registry
.venv/bin/python scripts/corpus_train.py collect \
  --registry-wide --max-modules "${MAX_MODULES}" --workers 16 \
  --corpus-dir corpus | tee /tmp/collect.txt
# ... plus the ~30k public GitHub .tf blobs (the small/simple mass).
mark github-materialise
mkdir -p corpus/github_shards
gsutil -m cp "${GITHUB_CORPUS}/*" corpus/github_shards/ || true
.venv/bin/python scripts/corpus_train.py github-fetch | tee /tmp/github.txt || true

# --- run the experiment + report ------------------------------------------
# Parallel scan across all vCPUs (parse+rules+ML per file is CPU-bound pure
# Python); skip giant blobs; -u so progress flushes live through the tee pipe.
mark scan
RESULTS=/tmp/a3_results
.venv/bin/python -u -m evaluation.ml_atypicality \
  --corpus-dir corpus --model-dir models \
  --training-data models/training_data.npy --out-dir "${RESULTS}" \
  --workers "$(nproc)" --max-file-kb 256 --max-files 50000 --scan-timeout 20 | tee /tmp/exp.txt
mark report
.venv/bin/python -m evaluation.report_ml_atypicality --results-dir "${RESULTS}" | tee -a /tmp/exp.txt || true

mark upload
kill "${HEARTBEAT_PID}" 2>/dev/null || true
find corpus -name '*.tf' | wc -l > /tmp/corpus_file_count.txt
mark done
gsutil -m cp -r "${RESULTS}"/* /tmp/collect.txt /tmp/github.txt /tmp/exp.txt \
  /tmp/corpus_file_count.txt /var/log/tv-a3.log "${STATUS}" "${DST}/"
poweroff
STARTUP_EOF

echo ">> creating self-stopping VM ${VM} (zone ${ZONE}, ${MACHINE})"
gcloud config set project "${PROJECT}" >/dev/null 2>&1
gcloud compute instances create "${VM}" \
  --zone="${ZONE}" --machine-type="${MACHINE}" \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=60GB --scopes=cloud-platform \
  --max-run-duration=170m --instance-termination-action=STOP \
  --metadata=run-id="${RUN}",bucket="${BUCKET}",model-run="${MODEL_RUN}",repo-url="${REPO_URL}",github-corpus="${GITHUB_CORPUS}",max-modules="${MAX_MODULES}" \
  --metadata-from-file=startup-script="${STARTUP}"

echo ">> launched. run id: ${RUN}"
echo ">> status:   gsutil cat gs://${BUCKET}/runs/${RUN}/live/status.txt"
echo ">> follow:   gcloud compute instances get-serial-port-output ${VM} --zone=${ZONE} | tail"
echo ">> results:  gs://${BUCKET}/runs/${RUN}/   (VM self-stops when done — delete it after collect)"
