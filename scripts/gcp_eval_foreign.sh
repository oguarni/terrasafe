#!/usr/bin/env bash
# Launch the third-party (KICS) corpus evaluation on GCP.
#
# Why GCP: the head-to-head needs the three competitor Docker images
# (Checkov/tfsec/Terrascan) pulled and run over the whole foreign corpus — that
# is `make evaluate`-class "heavy" work, which the project runs on GCP, not on
# the local machine (and the free credits expire 2026-07-22).
#
# What it does: stages the (uncommitted) evaluation/ harness changes to GCS,
# creates a self-terminating VM that clones `master`, overlays the staged
# harness files, restores the trained ML model, sparse-clones the KICS fixtures
# at a pinned commit, builds the foreign corpus, runs the full 4-tool evaluation
# in target-slice mode, uploads the results, and powers itself off. It never
# commits or pushes.
#
# Usage:  scripts/gcp_eval_foreign.sh
# Collect (from any machine, after ~30-60 min):
#   gsutil ls  gs://terravault-ml-artifacts/runs/ | grep foreign
#   gsutil cp -r gs://terravault-ml-artifacts/runs/<RUN>/ .
set -euo pipefail

PROJECT="${TV_PROJECT:-terravault}"
ZONE="${TV_ZONE:-us-central1-a}"
BUCKET="${TV_BUCKET:-terravault-ml-artifacts}"
MACHINE="${TV_MACHINE:-e2-standard-4}"
MODEL_RUN="${TV_MODEL_RUN:-20260707-224841}"   # GCS run holding the trained model
REPO_URL="${TV_REPO_URL:-https://github.com/oguarni/terravault.git}"
# Pinned KICS commit -> the VM rebuilds the exact corpus validated locally
# (deterministic builder + pinned fixtures = identical 57 cases). Override with
# TV_KICS_SHA to refresh against a newer KICS.
KICS_SHA="${TV_KICS_SHA:-ac94c2cd8411bf9310b64cae8a628ffadd26b8f6}"

RUN="foreign-$(date +%Y%m%d-%H%M%S)"
VM="tv-${RUN}"
REPO_ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

echo ">> staging harness changes for run ${RUN}"
tar czf "${STAGE}/eval-src.tgz" -C "${REPO_ROOT}" \
  evaluation/kics_mapping.py \
  evaluation/dataset/build_foreign_corpus.py \
  evaluation/evaluate.py \
  evaluation/runners.py \
  evaluation/taxonomy.py
gsutil cp "${STAGE}/eval-src.tgz" "gs://${BUCKET}/eval-src/${RUN}.tgz"

# The VM startup script goes in a file (not inline) so gcloud does not try to
# parse the commas inside it as --metadata key=value separators. A quoted
# heredoc keeps every ${var} literal — they are resolved on the VM via md().
STARTUP="${STAGE}/startup.sh"
cat > "${STARTUP}" <<'STARTUP_EOF'
#!/bin/bash
set -x; exec > >(tee /var/log/tv-foreign.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata/computeMetadata/v1/instance/attributes/$1"; }
RUN=$(md run-id); BUCKET=$(md bucket); MODEL_RUN=$(md model-run)
REPO_URL=$(md repo-url); KICS_SHA=$(md kics-sha)
DST="gs://${BUCKET}/runs/${RUN}"

apt-get update && apt-get install -y python3-pip python3-venv git docker.io make
systemctl start docker

git clone "${REPO_URL}" /opt/tv && cd /opt/tv

# Overlay the uncommitted harness changes staged for this run.
gsutil cp "gs://${BUCKET}/eval-src/${RUN}.tgz" /tmp/eval-src.tgz
tar xzf /tmp/eval-src.tgz -C /opt/tv

# Restore the trained ML model (models/ is gitignored) so scans do not error.
mkdir -p /opt/tv/models
gsutil -m cp -r "gs://${BUCKET}/runs/${MODEL_RUN}/models/*" /opt/tv/models/ || true

python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Fetch the KICS Terraform/AWS fixtures at the pinned commit (reproducibility).
mkdir -p /opt/kics && cd /opt/kics
git init -q
git remote add origin https://github.com/Checkmarx/kics.git
git sparse-checkout init --cone
git sparse-checkout set assets/queries/terraform/aws
git -c protocol.version=2 fetch --depth 1 --filter=blob:none origin "${KICS_SHA}"
git checkout -q FETCH_HEAD
cd /opt/tv

FOREIGN=/opt/tv/evaluation/dataset/foreign
python -m evaluation.dataset.build_foreign_corpus \
  --kics-root /opt/kics/assets/queries/terraform/aws --out-dir "${FOREIGN}" \
  | tee /tmp/build.txt

# Full 4-tool head-to-head on the foreign corpus (Docker competitors + native TV).
RESULTS=/tmp/foreign_results
python -m evaluation.evaluate \
  --ground-truth "${FOREIGN}/ground_truth_foreign.yaml" \
  --dataset-root "${FOREIGN}" --results-dir "${RESULTS}" \
  --score-mode target_slice | tee /tmp/eval.txt

echo "{\"kics_sha\": \"${KICS_SHA}\", \"run\": \"${RUN}\"}" > /tmp/corpus_source.json
gsutil -m cp -r "${RESULTS}"/* "${FOREIGN}/ground_truth_foreign.yaml" \
  "${FOREIGN}/build_manifest.json" /tmp/build.txt /tmp/eval.txt \
  /tmp/corpus_source.json /var/log/tv-foreign.log "${DST}/"
poweroff
STARTUP_EOF

echo ">> creating self-terminating VM ${VM} (zone ${ZONE}, ${MACHINE})"
gcloud config set project "${PROJECT}" >/dev/null 2>&1
gcloud compute instances create "${VM}" \
  --zone="${ZONE}" --machine-type="${MACHINE}" \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=50GB --scopes=cloud-platform \
  --max-run-duration=90m --instance-termination-action=DELETE \
  --metadata=run-id="${RUN}",bucket="${BUCKET}",model-run="${MODEL_RUN}",repo-url="${REPO_URL}",kics-sha="${KICS_SHA}" \
  --metadata-from-file=startup-script="${STARTUP}"

echo ">> launched. run id: ${RUN}"
echo ">> follow:   gcloud compute instances get-serial-port-output ${VM} --zone=${ZONE} | tail"
echo ">> results:  gs://${BUCKET}/runs/${RUN}/   (VM self-deletes when done)"
