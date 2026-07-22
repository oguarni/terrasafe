#!/usr/bin/env bash
# Launch the A.3 follow-up on GCP: anomaly-threshold calibration + second corpus.
#
# Why GCP: same class of work as A.3 — mine tens of thousands of real Terraform
# files and push every one through the full production pipeline (parse + 11 rules
# + Isolation Forest). That is `make evaluate`-class heavy work this project runs
# on GCP, not locally (the free credits expire 2026-07-22).
#
# What it does, in two banked stages:
#   1. Re-mines the A.3 corpus (registry top-1500 + the ~30k public GitHub .tf
#      blobs), scans it, dumps every config's raw anomaly score + Mahalanobis
#      distance + rule verdict to a CSV, sweeps candidate percentile cutoffs, and
#      uploads that result on its own. Any later failure cannot cost this.
#   2. Mines a SECOND corpus from the registry rank window BELOW the first mine
#      (--skip-top-modules), which the harness then makes disjoint by content
#      hash, and repeats the calibration across both corpora.
# The model is only ever LOADED: `contamination=0.1` is trained in, and this run
# calibrates a cutoff on the existing model's score — it never refits it.
#
# Guards this launcher inherits from the A.3 post-mortem (paid for twice): the
# scan runs PARALLEL across all vCPUs, every file gets a SIGALRM budget so a
# pathological blob cannot pin a worker, and a 5-min heartbeat streams the log,
# the phase status and partial artifacts to ${DST}/live/ so a killed run still
# leaves a full trail. --instance-termination-action=STOP, never DELETE: run 1 of
# A.3 was a total loss because DELETE vaporised the VM before the upload.
#
# Usage:  scripts/gcp_ml_calibration.sh
# Watch:    gsutil cat gs://terravault-ml-artifacts/runs/<RUN>/live/status.txt
# Collect (after ~30-60 min):
#   gsutil cp -r gs://terravault-ml-artifacts/runs/<RUN>/ .
#   gcloud compute instances delete tv-<RUN> --zone=<ZONE>
set -euo pipefail

PROJECT="${TV_PROJECT:-terravault}"
ZONE="${TV_ZONE:-us-central1-a}"
BUCKET="${TV_BUCKET:-terravault-ml-artifacts}"
MACHINE="${TV_MACHINE:-e2-highcpu-16}"
MODEL_RUN="${TV_MODEL_RUN:-20260707-224841}"          # GCS run holding model v20260708_015533
GITHUB_CORPUS="${TV_GITHUB_CORPUS:-gs://terravault-ml-artifacts/github_corpus}"
HOME_MODULES="${TV_HOME_MODULES:-1500}"                # A.3's mine, reproduced exactly
SKIP_TOP="${TV_SKIP_TOP:-1500}"                        # second mine starts where the first ended
SECOND_MODULES="${TV_SECOND_MODULES:-6000}"            # registry lists ~11.1k AWS modules total
# Semicolon-separated because gcloud parses commas as --metadata entry separators;
# the VM turns it back into the comma-separated list the harness expects.
PERCENTILES="${TV_PERCENTILES:-90;95;97.5;99;99.5;99.9}"
REPO_URL="${TV_REPO_URL:-https://github.com/oguarni/terravault.git}"

RUN="ml-calib-$(date +%Y%m%d-%H%M%S)"
VM="tv-${RUN}"
REPO_ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

echo ">> staging calibration harness for run ${RUN}"
tar czf "${STAGE}/calib-src.tgz" -C "${REPO_ROOT}" \
  evaluation/ml_atypicality.py \
  evaluation/ml_threshold_calibration.py \
  evaluation/report_ml_calibration.py \
  scripts/corpus_train.py
gsutil cp "${STAGE}/calib-src.tgz" "gs://${BUCKET}/eval-src/${RUN}.tgz"

# Startup script in a file (not inline) so gcloud does not parse its commas as
# --metadata separators. Quoted heredoc keeps ${var} literal -> resolved on the
# VM via md().
STARTUP="${STAGE}/startup.sh"
cat > "${STARTUP}" <<'STARTUP_EOF'
#!/bin/bash
set -x; exec > >(tee /var/log/tv-calib.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/attributes/$1"; }
RUN=$(md run-id); BUCKET=$(md bucket); MODEL_RUN=$(md model-run)
REPO_URL=$(md repo-url); GITHUB_CORPUS=$(md github-corpus)
HOME_MODULES=$(md home-modules); SKIP_TOP=$(md skip-top); SECOND_MODULES=$(md second-modules)
PERCENTILES=$(md percentiles | tr ';' ',')
DST="gs://${BUCKET}/runs/${RUN}"
HOME_RESULTS=/tmp/calib_home
FULL_RESULTS=/tmp/calib_full
BANKED=evaluation/results/ml_atypicality/ml_atypicality_metrics.json

# Heartbeat: every 5 min stream the log, phase status and any phase outputs to
# ${DST}/live/ so a dead run still leaves a full trail in GCS (A.3 run-1 lesson).
STATUS=/tmp/status.txt
mark() { echo "$(date -u +%FT%TZ) phase=$1" >> "${STATUS}"; }
( while sleep 300; do
    gsutil -q cp /var/log/tv-calib.log "${STATUS}" "${DST}/live/" 2>/dev/null
    for f in /tmp/collect_home.txt /tmp/github.txt /tmp/collect_second.txt \
             /tmp/calib_home.txt /tmp/calib_full.txt /tmp/corpus_counts.txt; do
      [ -f "$f" ] && gsutil -q cp "$f" "${DST}/live/" 2>/dev/null
    done
    gsutil -q cp "${HOME_RESULTS}"/*.json "${DST}/live/" 2>/dev/null
  done ) &
HEARTBEAT_PID=$!
mark boot

apt-get update && apt-get install -y python3-pip python3-venv git make
mark deps-done

git clone "${REPO_URL}" /opt/tv && cd /opt/tv

# Overlay the uncommitted calibration harness staged for this run.
gsutil cp "gs://${BUCKET}/eval-src/${RUN}.tgz" /tmp/calib-src.tgz
tar xzf /tmp/calib-src.tgz -C /opt/tv

# Restore the trained model + training vectors (models/ is gitignored). The model
# is the *input* to this run: it is loaded, scored with, and never refitted.
mkdir -p /opt/tv/models
gsutil -m cp -r "gs://${BUCKET}/runs/${MODEL_RUN}/models/*" /opt/tv/models/ || true

python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
mark pip-done

# --- corpus 1: reproduce the A.3 mine exactly ------------------------------
# Registry breadth (the large/complex tail) ...
mark mine-home
.venv/bin/python scripts/corpus_train.py collect \
  --registry-wide --max-modules "${HOME_MODULES}" --workers 16 \
  --corpus-dir corpus_home | tee /tmp/collect_home.txt
# ... plus the ~30k public GitHub .tf blobs (the small/simple mass).
mark github-materialise
mkdir -p corpus_home/github_shards
gsutil -m cp "${GITHUB_CORPUS}/*" corpus_home/github_shards/ || true
.venv/bin/python scripts/corpus_train.py github-fetch \
  --corpus-dir corpus_home --shards-dir corpus_home/github_shards | tee /tmp/github.txt || true

# --- stage 1: calibrate on the A.3 corpus alone and BANK it -----------------
# Uploaded on its own so the primary deliverable (the per-config score artifact
# + the cutoff sweep) survives any failure of the second-corpus mine below.
# --max-files is set well above the ~45k unique files A.3 saw, so it stays
# non-binding here and leaves the second corpus room without truncation bias.
mark calib-home
.venv/bin/python -u -m evaluation.ml_threshold_calibration \
  --corpus "home=corpus_home" --model-dir models \
  --training-data models/training_data.npy --out-dir "${HOME_RESULTS}" \
  --percentiles "${PERCENTILES}" --baseline-metrics "${BANKED}" \
  --workers "$(nproc)" --max-file-kb 256 --max-files 90000 --scan-timeout 20 \
  | tee /tmp/calib_home.txt
cat > "${HOME_RESULTS}/corpus_sources.json" <<JSON
{"home": "Terraform Registry (registry-wide, top ${HOME_MODULES} by downloads) + public GitHub .tf blobs (BigQuery export) — the A.3 mine, re-mined"}
JSON
.venv/bin/python -m evaluation.report_ml_calibration --results-dir "${HOME_RESULTS}" \
  | tee -a /tmp/calib_home.txt || true
mark upload-home
gsutil -m cp -r "${HOME_RESULTS}"/* "${DST}/home/" || true

# --- corpus 2: the registry rank window BELOW the first mine ----------------
# Disjoint by construction at module level (rank window), then proved disjoint at
# file level by content hash inside the harness. Time-boxed so a slow mine cannot
# eat the run's budget: whatever landed on disk is what gets scanned.
mark mine-second
timeout 40m .venv/bin/python scripts/corpus_train.py collect \
  --registry-wide --skip-top-modules "${SKIP_TOP}" --max-modules "${SECOND_MODULES}" \
  --workers 24 --corpus-dir corpus_second | tee /tmp/collect_second.txt || true

{ echo "home_tf_files=$(find corpus_home -name '*.tf' | wc -l)"
  echo "second_tf_files=$(find corpus_second -name '*.tf' 2>/dev/null | wc -l)"; } \
  > /tmp/corpus_counts.txt

# --- stage 2: calibrate across both corpora --------------------------------
# Corpus order matters: 'second' drops every file whose content hash 'home'
# already admitted, which is the disjointness proof recorded in the metrics.
mark calib-full
.venv/bin/python -u -m evaluation.ml_threshold_calibration \
  --corpus "home=corpus_home" --corpus "second=corpus_second" --model-dir models \
  --training-data models/training_data.npy --out-dir "${FULL_RESULTS}" \
  --percentiles "${PERCENTILES}" --baseline-metrics "${BANKED}" \
  --workers "$(nproc)" --max-file-kb 256 --max-files 90000 --scan-timeout 20 \
  | tee /tmp/calib_full.txt
cat > "${FULL_RESULTS}/corpus_sources.json" <<JSON
{"home": "Terraform Registry (registry-wide, top ${HOME_MODULES} by downloads) + public GitHub .tf blobs (BigQuery export) — the A.3 mine, re-mined",
 "second": "Terraform Registry, download-rank window [${SKIP_TOP}+1, ${SKIP_TOP}+${SECOND_MODULES}] — modules the A.3 mine never touched, then filtered by content hash against it"}
JSON
mark report
.venv/bin/python -m evaluation.report_ml_calibration --results-dir "${FULL_RESULTS}" \
  | tee -a /tmp/calib_full.txt || true

mark upload
kill "${HEARTBEAT_PID}" 2>/dev/null || true
mkdir -p /tmp/manifests
cp corpus_home/manifest.json /tmp/manifests/home_manifest.json 2>/dev/null || true
cp corpus_home/github_manifest.json /tmp/manifests/home_github_manifest.json 2>/dev/null || true
cp corpus_second/manifest.json /tmp/manifests/second_manifest.json 2>/dev/null || true
gsutil -m cp /tmp/manifests/* "${DST}/manifests/" || true
mark done
gsutil -m cp -r "${FULL_RESULTS}"/* /tmp/collect_home.txt /tmp/github.txt \
  /tmp/collect_second.txt /tmp/calib_home.txt /tmp/calib_full.txt \
  /tmp/corpus_counts.txt /var/log/tv-calib.log "${STATUS}" "${DST}/"
poweroff
STARTUP_EOF

echo ">> creating self-stopping VM ${VM} (zone ${ZONE}, ${MACHINE})"
gcloud config set project "${PROJECT}" >/dev/null 2>&1
gcloud compute instances create "${VM}" \
  --zone="${ZONE}" --machine-type="${MACHINE}" \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=60GB --scopes=cloud-platform \
  --max-run-duration=170m --instance-termination-action=STOP \
  --metadata=run-id="${RUN}",bucket="${BUCKET}",model-run="${MODEL_RUN}",repo-url="${REPO_URL}",github-corpus="${GITHUB_CORPUS}",home-modules="${HOME_MODULES}",skip-top="${SKIP_TOP}",second-modules="${SECOND_MODULES}",percentiles="${PERCENTILES}" \
  --metadata-from-file=startup-script="${STARTUP}"

echo ">> launched. run id: ${RUN}"
echo ">> status:   gsutil cat gs://${BUCKET}/runs/${RUN}/live/status.txt"
echo ">> follow:   gcloud compute instances get-serial-port-output ${VM} --zone=${ZONE} | tail"
echo ">> stage 1:  gs://${BUCKET}/runs/${RUN}/home/   (banked before the second mine starts)"
echo ">> results:  gs://${BUCKET}/runs/${RUN}/   (VM self-stops when done — delete it after collect)"
