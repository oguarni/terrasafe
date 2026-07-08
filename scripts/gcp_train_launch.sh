#!/usr/bin/env bash
# gcp_train_launch.sh - launch the corpus-training job on a GCE VM.
# Linux/macOS port of gcp_train_launch.ps1 (see docs/GCP_TRAINING.md).
#
# Fire-and-forget: the moment this script finishes, the job runs entirely on
# Google's infrastructure. The VM powers itself off when the job completes
# (or after --max-hours, whichever comes first), so billing stops on its own.
#
# Usage (from the repo root):
#   scripts/gcp_train_launch.sh                                # curated 400-module run
#   scripts/gcp_train_launch.sh \
#       --machine-type e2-highcpu-32 --modules 12000 --max-hours 12 \
#       --registry-wide --github-corpus gs://terravault-ml-artifacts/github_corpus
set -euo pipefail

MACHINE_TYPE="e2-highcpu-4"
MODULES=400
MAX_HOURS=6
REGISTRY_WIDE=0
GITHUB_CORPUS=""
WORKERS=0
DISK_GB=60

while [[ $# -gt 0 ]]; do
    case "$1" in
        --machine-type)  MACHINE_TYPE="$2"; shift 2 ;;
        --modules)       MODULES="$2"; shift 2 ;;
        --max-hours)     MAX_HOURS="$2"; shift 2 ;;
        --registry-wide) REGISTRY_WIDE=1; shift ;;
        --github-corpus) GITHUB_CORPUS="$2"; shift 2 ;;
        --workers)       WORKERS="$2"; shift 2 ;;
        --disk-gb)       DISK_GB="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/.gcp-train.json"
if [[ -f "$CONFIG" ]]; then
    PROJECT_ID="$(python3 -c "import json; print(json.load(open('$CONFIG'))['projectId'])")"
    ZONE="$(python3 -c "import json; print(json.load(open('$CONFIG'))['zone'])")"
    BUCKET="$(python3 -c "import json; print(json.load(open('$CONFIG'))['bucket'])")"
else
    PROJECT_ID="terravault"
    ZONE="us-central1-a"
    BUCKET="terravault-ml-artifacts"
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
VM_NAME="terravault-train-$RUN_ID"
GCS_RUN="gs://$BUCKET/runs/$RUN_ID"
MAX_MINUTES=$((MAX_HOURS * 60))

COLLECT_FLAGS="--workers $WORKERS"
SOURCE_LABEL="synthetic secure baseline + Terraform Registry corpus"
if [[ "$REGISTRY_WIDE" -eq 1 ]]; then
    COLLECT_FLAGS="$COLLECT_FLAGS --registry-wide"
    SOURCE_LABEL="synthetic secure baseline + registry-wide Terraform Registry corpus"
fi
if [[ -n "$GITHUB_CORPUS" ]]; then
    SOURCE_LABEL="$SOURCE_LABEL + GitHub public dataset corpus"
fi

echo "==> Run id: $RUN_ID  (VM: $VM_NAME, machine: $MACHINE_TYPE, modules: $MODULES)"
echo "    registry-wide: $REGISTRY_WIDE, github corpus: ${GITHUB_CORPUS:-none}"

# --- 1. Package the working tree (tracked + untracked-but-not-ignored files).
echo "==> Packaging source tree"
cd "$REPO_ROOT"
FILE_LIST="$(mktemp)"
SRC_TGZ="$(mktemp --suffix=.tgz)"
trap 'rm -f "$FILE_LIST" "$SRC_TGZ"' EXIT
git -c core.quotepath=off ls-files -co --exclude-standard > "$FILE_LIST"
tar -czf "$SRC_TGZ" --verbatim-files-from -T "$FILE_LIST"
echo "    $(du -h "$SRC_TGZ" | cut -f1) source bundle"

# --- 2. Upload the source bundle.
echo "==> Uploading source to $GCS_RUN/src.tgz"
gcloud storage cp "$SRC_TGZ" "$GCS_RUN/src.tgz" --project "$PROJECT_ID"

# --- 3. Generate the VM startup script.
STARTUP="$(mktemp --suffix=.sh)"
cat > "$STARTUP" <<'TEMPLATE'
#!/bin/bash
set -euo pipefail
# Watchdog + minimal trap FIRST: whatever fails later, billing always stops.
shutdown -P "+__MAXMIN__"
trap poweroff EXIT
export PATH="$PATH:/snap/bin"
DEST="__DEST__"
GITHUB_CORPUS="__GITHUB_CORPUS__"
LOG=/var/log/train.log
touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

# Ubuntu GCE images ship gcloud as a snap, but on FIRST boot snap seeding can
# still be in progress when the startup script runs. Wait for seeding, then
# install only if truly absent.
if ! command -v gcloud >/dev/null 2>&1; then
    snap wait system seed.loaded || true
fi
if ! command -v gcloud >/dev/null 2>&1; then
    snap install google-cloud-cli --classic
fi

status() {
    echo "$(date -u +%FT%TZ) $1" >> /var/log/status.log
    # Secondary, dependency-free channel: guest attributes via the metadata
    # server, readable from outside even if GCS uploads are failing.
    curl -s -X PUT --data "$1" -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/terravault/status" || true
    gcloud storage cp /var/log/status.log "$DEST/STATUS" --quiet || true
}
finish() {
    code=$?
    if [ $code -eq 0 ]; then status "DONE"; else status "FAILED exit=$code (see train.log)"; fi
    gcloud storage cp "$LOG" "$DEST/train.log" --quiet || true
    poweroff
}
trap finish EXIT

status "BOOTSTRAP installing packages"
apt-get update -y
apt-get install -y python3-venv python3-pip

status "BOOTSTRAP fetching source"
mkdir -p /opt/terravault
cd /opt/terravault
gcloud storage cp "$DEST/src.tgz" .
tar xzf src.tgz

status "BOOTSTRAP installing python deps"
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

status "COLLECT downloading __MODULES__ registry modules"
.venv/bin/python scripts/corpus_train.py collect --max-modules __MODULES__ __COLLECT_FLAGS__

if [ -n "$GITHUB_CORPUS" ]; then
    status "GITHUB fetching blob shards"
    mkdir -p corpus/github_shards
    gcloud storage cp "$GITHUB_CORPUS/*" corpus/github_shards/ --quiet
    .venv/bin/python scripts/corpus_train.py github-fetch
fi

status "EXTRACT structural features"
.venv/bin/python scripts/corpus_train.py extract --workers __WORKERS__

status "TRAIN isolation forest"
.venv/bin/python scripts/corpus_train.py train --source-label "__SOURCE_LABEL__"

status "UPLOAD artifacts"
gcloud storage cp -r models "$DEST/models" --quiet
gcloud storage cp corpus/features.npy corpus/features_meta.json "$DEST/corpus/" --quiet
if [ -f corpus/manifest.json ]; then gcloud storage cp corpus/manifest.json "$DEST/corpus/" --quiet; fi
if [ -f corpus/github_manifest.json ]; then gcloud storage cp corpus/github_manifest.json "$DEST/corpus/" --quiet; fi

status "SNAPSHOT archiving corpus"
tar -czf corpus_snapshot.tgz corpus/modules
gcloud storage cp corpus_snapshot.tgz "$DEST/corpus/corpus_snapshot.tgz" --quiet
TEMPLATE
sed -i \
    -e "s|__DEST__|$GCS_RUN|g" \
    -e "s|__MAXMIN__|$MAX_MINUTES|g" \
    -e "s|__MODULES__|$MODULES|g" \
    -e "s|__COLLECT_FLAGS__|$COLLECT_FLAGS|g" \
    -e "s|__GITHUB_CORPUS__|$GITHUB_CORPUS|g" \
    -e "s|__WORKERS__|$WORKERS|g" \
    -e "s|__SOURCE_LABEL__|$SOURCE_LABEL|g" \
    "$STARTUP"

# --- 4. Boot the VM. From here on, nothing depends on this computer.
echo "==> Creating VM $VM_NAME (this is the moment billing starts)"
gcloud compute instances create "$VM_NAME" \
    --project "$PROJECT_ID" \
    --zone "$ZONE" \
    --machine-type "$MACHINE_TYPE" \
    --image-family ubuntu-2404-lts-amd64 \
    --image-project ubuntu-os-cloud \
    --boot-disk-size "${DISK_GB}GB" \
    --boot-disk-type pd-balanced \
    --scopes storage-rw \
    --metadata enable-guest-attributes=TRUE \
    --metadata-from-file startup-script="$STARTUP"

# --- 5. Record the run locally and in the bucket (for any other computer).
RUN_JSON="$(mktemp --suffix=.json)"
python3 - "$RUN_JSON" <<PY
import json, sys, datetime
info = {
    "runId": "$RUN_ID",
    "vmName": "$VM_NAME",
    "zone": "$ZONE",
    "project": "$PROJECT_ID",
    "bucket": "$BUCKET",
    "machine": "$MACHINE_TYPE",
    "modules": $MODULES,
    "registryWide": bool($REGISTRY_WIDE),
    "githubCorpus": "$GITHUB_CORPUS",
    "started": datetime.datetime.now().astimezone().isoformat(),
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(info, handle, indent=2)
config_path = "$CONFIG"
try:
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
except FileNotFoundError:
    config = {"projectId": "$PROJECT_ID", "region": "$ZONE"[:-2], "zone": "$ZONE", "bucket": "$BUCKET"}
config["lastRun"] = info
with open(config_path, "w", encoding="utf-8") as handle:
    json.dump(config, handle, indent=2)
PY
gcloud storage cp "$RUN_JSON" "$GCS_RUN/run.json" --project "$PROJECT_ID"
gcloud storage cp "$RUN_JSON" "gs://$BUCKET/runs/latest.json" --project "$PROJECT_ID"
rm -f "$RUN_JSON" "$STARTUP"

echo ""
echo "Launched. The job now runs entirely on GCP - you can shut this computer down."
echo ""
echo "Monitor from this repo:      scripts/gcp_train_status.sh"
echo "Monitor from ANY computer (Cloud Shell at console.cloud.google.com works too):"
echo "  gcloud storage cat $GCS_RUN/STATUS"
echo "  gcloud compute instances describe $VM_NAME --zone $ZONE --project $PROJECT_ID --format='value(status)'   # TERMINATED = finished"
echo "  gcloud storage cat $GCS_RUN/train.log                     # full log, uploaded when the run ends"
echo ""
echo "When DONE, fetch the trained model:"
echo "  gcloud storage cp -r $GCS_RUN/models ."
echo "And delete the powered-off VM:"
echo "  gcloud compute instances delete $VM_NAME --zone $ZONE --project $PROJECT_ID --quiet"
