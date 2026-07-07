# gcp_train_status.ps1 - check on the training run from any machine.
#
# Reads .gcp-train.json (written by gcp_setup.ps1 / gcp_train_launch.ps1).
# On a machine without that file, pass -Bucket (everything else is read from
# the run records the launcher stored in the bucket):
#   .\scripts\gcp_train_status.ps1 -Bucket terravault-ml-artifacts
#
# Switches:
#   -Log     show the tail of the training log (uploaded when the run ends)
#   -Serial  show live serial-console output while the VM is still RUNNING

[CmdletBinding()]
param(
    [string]$Bucket,
    [switch]$Log,
    [switch]$Serial
)

$repoRoot = Split-Path $PSScriptRoot -Parent
$configPath = Join-Path $repoRoot ".gcp-train.json"

$run = $null
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($Bucket)) { $Bucket = $config.bucket }
    if ($config.PSObject.Properties.Name -contains "lastRun") { $run = $config.lastRun }
}
if ([string]::IsNullOrWhiteSpace($Bucket)) {
    throw "No .gcp-train.json found and no -Bucket given. Run gcp_setup.ps1, or pass -Bucket <name>."
}
if ($null -eq $run) {
    Write-Host "==> No local run record; reading gs://$Bucket/runs/latest.json" -ForegroundColor Cyan
    $latest = gcloud storage cat "gs://$Bucket/runs/latest.json"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read gs://$Bucket/runs/latest.json - has a run been launched?"
    }
    $run = ($latest -join "`n") | ConvertFrom-Json
}

$gcsRun = "gs://$Bucket/runs/$($run.runId)"
Write-Host "==> Run $($run.runId)  (VM: $($run.vmName), zone: $($run.zone), project: $($run.project))" -ForegroundColor Cyan

Write-Host "==> VM state:" -ForegroundColor Cyan
$state = gcloud compute instances describe $run.vmName --zone $run.zone --project $run.project --format="value(status)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "    VM not found (already deleted?)"
} else {
    Write-Host "    $state   (RUNNING = still working, TERMINATED = job finished and powered off)"
}

Write-Host "==> Phase history (STATUS file):" -ForegroundColor Cyan
gcloud storage cat "$gcsRun/STATUS"
if ($LASTEXITCODE -ne 0) {
    Write-Host "    No STATUS in the bucket yet - checking the VM's direct heartbeat..."
    $heartbeat = gcloud compute instances get-guest-attributes $run.vmName --zone $run.zone --project $run.project --query-path="terravault/status" --format="value(value)"
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($heartbeat)) {
        Write-Host "    VM-reported phase: $heartbeat"
    } else {
        Write-Host "    No heartbeat either - a fresh VM takes ~2 minutes to boot and report."
    }
}

Write-Host "==> Artifacts in $gcsRun/:" -ForegroundColor Cyan
gcloud storage ls -r "$gcsRun/"

if ($Log) {
    Write-Host "==> train.log (last 60 lines):" -ForegroundColor Cyan
    $logLines = gcloud storage cat "$gcsRun/train.log"
    if ($LASTEXITCODE -eq 0) {
        $logLines | Select-Object -Last 60
    } else {
        Write-Host "    train.log not uploaded yet (it lands when the run ends). Try -Serial for live output."
    }
}

if ($Serial) {
    Write-Host "==> Serial console (last 40 lines):" -ForegroundColor Cyan
    $serialOut = gcloud compute instances get-serial-port-output $run.vmName --zone $run.zone --project $run.project
    if ($LASTEXITCODE -eq 0) {
        $serialOut | Select-Object -Last 40
    }
}

if ($state -eq "TERMINATED") {
    Write-Host ""
    Write-Host "Job finished. Fetch the model and clean up:" -ForegroundColor Green
    Write-Host "  gcloud storage cp -r $gcsRun/models ."
    Write-Host "  gcloud compute instances delete $($run.vmName) --zone $($run.zone) --project $($run.project) --quiet"
}
