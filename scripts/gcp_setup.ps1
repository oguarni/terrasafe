# gcp_setup.ps1 - one-time GCP setup for the corpus-training pipeline.
#
# Idempotent: safe to re-run. No admin rights required.
# What it does:
#   1. Points gcloud at the right project (default: terravault)
#   2. Enables the Compute Engine + Cloud Storage APIs
#   3. Creates the ML artifacts bucket (with object versioning)
#   4. Writes .gcp-train.json so the launch/status scripts know your settings
#
# Usage (from the repo root, plain PowerShell - NOT as admin):
#   .\scripts\gcp_setup.ps1
#   .\scripts\gcp_setup.ps1 -ProjectId terravault -Region us-central1

[CmdletBinding()]
param(
    [string]$ProjectId = "terravault",
    [string]$Region = "us-central1",
    [string]$Zone = "us-central1-a"
)

function Assert-LastExit([string]$What) {
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (exit code $LASTEXITCODE). Fix the error above and re-run."
    }
}

Write-Host "==> Checking gcloud CLI" -ForegroundColor Cyan
$gcloudCmd = Get-Command gcloud -ErrorAction SilentlyContinue
if ($null -eq $gcloudCmd) {
    throw "gcloud CLI not found. Install it with: winget install Google.CloudSDK  (then reopen PowerShell and run 'gcloud auth login')"
}
$account = gcloud config get-value account
Assert-LastExit "gcloud config get-value account"
if ([string]::IsNullOrWhiteSpace($account) -or $account -eq "(unset)") {
    throw "gcloud is not logged in. Run: gcloud auth login"
}
Write-Host "    Logged in as: $account"

Write-Host "==> Setting active project to '$ProjectId'" -ForegroundColor Cyan
gcloud config set project $ProjectId
Assert-LastExit "gcloud config set project"

Write-Host "==> Checking billing is linked (trial credits live on the billing account)" -ForegroundColor Cyan
$billingEnabled = gcloud billing projects describe $ProjectId --format="value(billingEnabled)"
if ($LASTEXITCODE -eq 0 -and $billingEnabled -ne "True") {
    Write-Warning "Project '$ProjectId' has NO billing account linked - VM creation will fail."
    Write-Warning "Link it in the Console: Billing -> Account management -> link project '$ProjectId'."
}

Write-Host "==> Enabling Compute Engine + Cloud Storage APIs (can take ~1 min on first run)" -ForegroundColor Cyan
gcloud services enable compute.googleapis.com storage.googleapis.com --project $ProjectId
Assert-LastExit "gcloud services enable"

$bucketName = "$ProjectId-ml-artifacts"
Write-Host "==> Ensuring bucket gs://$bucketName exists" -ForegroundColor Cyan
$existing = gcloud storage buckets list --project $ProjectId --filter="name=$bucketName" --format="value(name)"
Assert-LastExit "gcloud storage buckets list"
if ([string]::IsNullOrWhiteSpace($existing)) {
    gcloud storage buckets create "gs://$bucketName" --project $ProjectId --location $Region --uniform-bucket-level-access
    if ($LASTEXITCODE -ne 0) {
        # Bucket names are global; fall back to a suffixed name if taken.
        $bucketName = "$ProjectId-ml-artifacts-$(Get-Random -Maximum 99999)"
        Write-Host "    Name taken - retrying as gs://$bucketName"
        gcloud storage buckets create "gs://$bucketName" --project $ProjectId --location $Region --uniform-bucket-level-access
        Assert-LastExit "gcloud storage buckets create"
    }
    gcloud storage buckets update "gs://$bucketName" --versioning
    Assert-LastExit "gcloud storage buckets update --versioning"
    Write-Host "    Created gs://$bucketName (versioning on)"
} else {
    Write-Host "    Already exists"
}

# New GCP projects no longer grant the default compute service account any
# storage access (Google removed the automatic Editor grant), so the training
# VM could not up/download artifacts without this explicit binding.
Write-Host "==> Granting the default compute service account write access on the bucket" -ForegroundColor Cyan
$projectNumber = gcloud projects describe $ProjectId --format="value(projectNumber)"
Assert-LastExit "gcloud projects describe"
$computeSa = "$projectNumber-compute@developer.gserviceaccount.com"
gcloud storage buckets add-iam-policy-binding "gs://$bucketName" --member="serviceAccount:$computeSa" --role=roles/storage.objectAdmin --format="value(name)" | Out-Null
Assert-LastExit "bucket add-iam-policy-binding"
Write-Host "    $computeSa -> roles/storage.objectAdmin on gs://$bucketName"

$repoRoot = Split-Path $PSScriptRoot -Parent
$configPath = Join-Path $repoRoot ".gcp-train.json"
$config = [ordered]@{
    projectId = $ProjectId
    region    = $Region
    zone      = $Zone
    bucket    = $bucketName
}
$json = ($config | ConvertTo-Json)
[System.IO.File]::WriteAllText($configPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "==> Wrote $configPath" -ForegroundColor Cyan

Write-Host "==> Existing VMs in project '$ProjectId':" -ForegroundColor Cyan
gcloud compute instances list --project $ProjectId

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "  Project : $ProjectId"
Write-Host "  Bucket  : gs://$bucketName"
Write-Host "  Zone    : $Zone"
Write-Host ""
Write-Host "Next step:  .\scripts\gcp_train_launch.ps1" -ForegroundColor Yellow
Write-Host "(Note: your previous active gcloud project was changed to '$ProjectId'.)"
