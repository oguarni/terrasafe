# gcp_train_launch.ps1 - launch the corpus-training job on a GCE VM.
#
# Fire-and-forget: the moment this script finishes, the job runs entirely on
# Google's infrastructure. You can shut this computer down immediately.
# The VM powers itself off when the job completes (or after -MaxHours, whichever
# comes first), so a finished run stops billing on its own.
#
# What it does:
#   1. Packages your local working tree (tracked + new files, never .env/ignored)
#   2. Uploads it to the artifacts bucket
#   3. Boots a VM whose startup script runs: collect -> extract -> train -> upload
#   4. Prints the commands to monitor the run from ANY computer
#
# Usage (from the repo root, plain PowerShell - NOT as admin):
#   .\scripts\gcp_train_launch.ps1
#   .\scripts\gcp_train_launch.ps1 -MachineType e2-highcpu-8 -Modules 600

[CmdletBinding()]
param(
    [string]$MachineType = "e2-highcpu-4",
    [int]$Modules = 400,
    [int]$MaxHours = 6
)

$ErrorActionPreference = "Continue"

function Assert-LastExit([string]$What) {
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (exit code $LASTEXITCODE). Fix the error above and re-run."
    }
}

$repoRoot = Split-Path $PSScriptRoot -Parent
$configPath = Join-Path $repoRoot ".gcp-train.json"
if (-not (Test-Path $configPath)) {
    throw "Missing $configPath - run .\scripts\gcp_setup.ps1 first."
}
$config = Get-Content $configPath -Raw | ConvertFrom-Json
$projectId = $config.projectId
$zone = $config.zone
$bucket = $config.bucket

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$vmName = "terravault-train-$runId"
$gcsRun = "gs://$bucket/runs/$runId"

Write-Host "==> Run id: $runId  (VM: $vmName, machine: $MachineType, modules: $Modules)" -ForegroundColor Cyan

# --- 1. Package the working tree (tracked + untracked-but-not-ignored files).
# Built from 'git ls-files', so .env, corpus/, models/ and other ignored
# artifacts are excluded by construction.
Write-Host "==> Packaging source tree" -ForegroundColor Cyan
Push-Location $repoRoot
try {
    $fileList = Join-Path $env:TEMP "terravault-src-files-$runId.txt"
    $srcTgz = Join-Path $env:TEMP "terravault-src-$runId.tgz"
    git ls-files -co --exclude-standard | Set-Content -Encoding Ascii $fileList
    Assert-LastExit "git ls-files"
    tar -czf $srcTgz -T $fileList
    Assert-LastExit "tar"
    $sizeMb = [math]::Round((Get-Item $srcTgz).Length / 1MB, 1)
    Write-Host "    $srcTgz ($sizeMb MB)"

    # --- 2. Upload the source bundle.
    Write-Host "==> Uploading source to $gcsRun/src.tgz" -ForegroundColor Cyan
    gcloud storage cp $srcTgz "$gcsRun/src.tgz" --project $projectId
    Assert-LastExit "gcloud storage cp src.tgz"

    # --- 3. Generate the VM startup script (bash, LF endings, no BOM).
    $maxMinutes = $MaxHours * 60
    $startupTemplate = @'
#!/bin/bash
set -euo pipefail
# Watchdog + minimal trap FIRST: whatever fails later, billing always stops.
shutdown -P "+__MAXMIN__"
trap poweroff EXIT
export PATH="$PATH:/snap/bin"
DEST="__DEST__"
LOG=/var/log/train.log
touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

# Ubuntu GCE images ship gcloud as a snap, but on FIRST boot snap seeding can
# still be in progress when the startup script runs (this race killed run
# 20260707-172425). Wait for seeding, then install only if truly absent.
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
.venv/bin/python scripts/corpus_train.py collect --max-modules __MODULES__

status "EXTRACT structural features"
.venv/bin/python scripts/corpus_train.py extract

status "TRAIN isolation forest"
.venv/bin/python scripts/corpus_train.py train

status "UPLOAD artifacts"
gcloud storage cp -r models "$DEST/models" --quiet
gcloud storage cp corpus/features.npy corpus/features_meta.json corpus/manifest.json "$DEST/corpus/" --quiet
'@
    $startupScript = $startupTemplate.Replace("__DEST__", $gcsRun).Replace("__MAXMIN__", "$maxMinutes").Replace("__MODULES__", "$Modules")
    $startupPath = Join-Path $env:TEMP "terravault-startup-$runId.sh"
    [System.IO.File]::WriteAllText($startupPath, $startupScript.Replace("`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))

    # --- 4. Boot the VM. From here on, nothing depends on this computer.
    Write-Host "==> Creating VM $vmName (this is the moment billing starts)" -ForegroundColor Cyan
    gcloud compute instances create $vmName `
        --project $projectId `
        --zone $zone `
        --machine-type $MachineType `
        --image-family ubuntu-2404-lts-amd64 `
        --image-project ubuntu-os-cloud `
        --boot-disk-size 40GB `
        --boot-disk-type pd-balanced `
        --scopes storage-rw `
        --metadata enable-guest-attributes=TRUE `
        --metadata-from-file startup-script=$startupPath
    Assert-LastExit "gcloud compute instances create"

    # --- 5. Record the run locally and in the bucket (for the second computer).
    $runInfo = [ordered]@{
        runId   = $runId
        vmName  = $vmName
        zone    = $zone
        project = $projectId
        bucket  = $bucket
        machine = $MachineType
        modules = $Modules
        started = (Get-Date -Format "o")
    }
    $runJson = Join-Path $env:TEMP "terravault-run-$runId.json"
    [System.IO.File]::WriteAllText($runJson, ($runInfo | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    gcloud storage cp $runJson "$gcsRun/run.json" --project $projectId
    gcloud storage cp $runJson "gs://$bucket/runs/latest.json" --project $projectId

    $config | Add-Member -NotePropertyName lastRun -NotePropertyValue $runInfo -Force
    [System.IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Launched. The job now runs entirely on GCP - you can shut this computer down." -ForegroundColor Green
Write-Host ""
Write-Host "Monitor from this repo:      .\scripts\gcp_train_status.ps1" -ForegroundColor Yellow
Write-Host "Monitor from ANY computer (Cloud Shell at console.cloud.google.com works too):"
Write-Host "  gcloud storage cat $gcsRun/STATUS"
Write-Host "  gcloud compute instances describe $vmName --zone $zone --project $projectId --format='value(status)'   # TERMINATED = finished"
Write-Host "  gcloud storage cat $gcsRun/train.log                     # full log, uploaded when the run ends"
Write-Host "  gcloud storage ls -r $gcsRun/                            # artifacts"
Write-Host ""
Write-Host "When DONE, fetch the trained model:"
Write-Host "  gcloud storage cp -r $gcsRun/models .    # then place next to the repo's models/"
Write-Host "And delete the powered-off VM (stops the last few cents of disk billing):"
Write-Host "  gcloud compute instances delete $vmName --zone $zone --project $projectId --quiet"
