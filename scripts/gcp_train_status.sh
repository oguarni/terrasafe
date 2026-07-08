#!/usr/bin/env bash
# gcp_train_status.sh - check on the training run from any machine.
# Linux/macOS port of gcp_train_status.ps1.
#
# Reads .gcp-train.json (written by gcp_train_launch.sh). On a machine without
# that file, pass --bucket (everything else is read from the run records the
# launcher stored in the bucket):
#   scripts/gcp_train_status.sh --bucket terravault-ml-artifacts
#
# Switches:
#   --log     show the tail of the training log (uploaded when the run ends)
#   --serial  show live serial-console output while the VM is still RUNNING
set -uo pipefail

BUCKET=""
SHOW_LOG=0
SHOW_SERIAL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bucket) BUCKET="$2"; shift 2 ;;
        --log)    SHOW_LOG=1; shift ;;
        --serial) SHOW_SERIAL=1; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/.gcp-train.json"
RUN_JSON=""
if [[ -f "$CONFIG" ]]; then
    [[ -z "$BUCKET" ]] && BUCKET="$(python3 -c "import json; print(json.load(open('$CONFIG')).get('bucket',''))")"
    RUN_JSON="$(python3 -c "import json; print(json.dumps(json.load(open('$CONFIG')).get('lastRun') or {}))")"
fi
if [[ -z "$BUCKET" ]]; then
    echo "No .gcp-train.json found and no --bucket given." >&2
    exit 2
fi
if [[ -z "$RUN_JSON" || "$RUN_JSON" == "{}" ]]; then
    echo "==> No local run record; reading gs://$BUCKET/runs/latest.json"
    RUN_JSON="$(gcloud storage cat "gs://$BUCKET/runs/latest.json")" || {
        echo "Could not read gs://$BUCKET/runs/latest.json - has a run been launched?" >&2
        exit 1
    }
fi

RUN_ID="$(echo "$RUN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['runId'])")"
VM_NAME="$(echo "$RUN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['vmName'])")"
ZONE="$(echo "$RUN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['zone'])")"
PROJECT="$(echo "$RUN_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['project'])")"
GCS_RUN="gs://$BUCKET/runs/$RUN_ID"

echo "==> Run $RUN_ID  (VM: $VM_NAME, zone: $ZONE, project: $PROJECT)"

echo "==> VM state:"
STATE="$(gcloud compute instances describe "$VM_NAME" --zone "$ZONE" --project "$PROJECT" --format='value(status)' 2>/dev/null)"
if [[ -z "$STATE" ]]; then
    echo "    VM not found (already deleted?)"
else
    echo "    $STATE   (RUNNING = still working, TERMINATED = job finished and powered off)"
fi

echo "==> Phase history (STATUS file):"
if ! gcloud storage cat "$GCS_RUN/STATUS" 2>/dev/null; then
    echo "    No STATUS in the bucket yet - checking the VM's direct heartbeat..."
    HEARTBEAT="$(gcloud compute instances get-guest-attributes "$VM_NAME" --zone "$ZONE" --project "$PROJECT" \
        --query-path="terravault/status" --format='value(value)' 2>/dev/null)"
    if [[ -n "$HEARTBEAT" ]]; then
        echo "    VM-reported phase: $HEARTBEAT"
    else
        echo "    No heartbeat either - a fresh VM takes ~2 minutes to boot and report."
    fi
fi

echo "==> Artifacts in $GCS_RUN/:"
gcloud storage ls -r "$GCS_RUN/" 2>/dev/null

if [[ "$SHOW_LOG" -eq 1 ]]; then
    echo "==> train.log (last 60 lines):"
    if ! gcloud storage cat "$GCS_RUN/train.log" 2>/dev/null | tail -60; then
        echo "    train.log not uploaded yet (it lands when the run ends). Try --serial."
    fi
fi

if [[ "$SHOW_SERIAL" -eq 1 ]]; then
    echo "==> Serial console (last 40 lines):"
    gcloud compute instances get-serial-port-output "$VM_NAME" --zone "$ZONE" --project "$PROJECT" 2>/dev/null | tail -40
fi

if [[ "$STATE" == "TERMINATED" ]]; then
    echo ""
    echo "Job finished. Fetch the model and clean up:"
    echo "  gcloud storage cp -r $GCS_RUN/models ."
    echo "  gcloud compute instances delete $VM_NAME --zone $ZONE --project $PROJECT --quiet"
fi
