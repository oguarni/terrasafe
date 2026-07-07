# Train the ML model on real Terraform modules (GCP, fully asynchronous)

This runbook launches the corpus-training job — the "future work" from
`terravault/infrastructure/CLAUDE_ML.md`: refit the Isolation Forest on
structural features extracted from **real, well-maintained Terraform modules**
(Terraform Registry: `terraform-aws-modules`, `cloudposse`, `aws-ia`) instead
of only the 300 synthetic baseline vectors.

The job runs **entirely on a GCE VM**: you launch it, shut your computer down,
and check on it later from any other machine. The VM powers itself off when it
finishes (or after a watchdog timeout), so billing stops on its own.

```
your PC ──launch──▶ GCE VM (Ubuntu 24.04)          GCS bucket
                      1. pip install deps            runs/<id>/src.tgz   ◀─ your code
                      2. collect 400 modules         runs/<id>/STATUS    ◀─ live phase log
                      3. extract 8-dim features      runs/<id>/train.log ◀─ full log (at end)
                      4. train IsolationForest       runs/<id>/models/   ◀─ trained model
                      5. upload + poweroff           runs/<id>/corpus/   ◀─ features + manifest
```

None of this needs Administrator rights — plain PowerShell is fine.

---

## 1. One-time setup (~2 min)

```powershell
.\scripts\gcp_setup.ps1
```

Points gcloud at the `terravault` project, enables the Compute + Storage APIs,
creates the `gs://terravault-ml-artifacts` bucket, and writes `.gcp-train.json`
(local, gitignored) for the other scripts. Re-running is harmless.

## 2. Launch (~1 min, then hands-off)

```powershell
.\scripts\gcp_train_launch.ps1                     # defaults: e2-highcpu-4, 400 modules, 6h watchdog
.\scripts\gcp_train_launch.ps1 -Modules 600        # bigger corpus
```

It uploads your **local working tree** (tracked + new files; `.env` and other
gitignored files are excluded by construction) and boots the VM. When the
command returns, **you can turn your computer off** — nothing after that
depends on it.

## 3. Monitor — from this computer or any other

From the repo:

```powershell
.\scripts\gcp_train_status.ps1            # VM state + phase history + artifacts
.\scripts\gcp_train_status.ps1 -Serial    # live output while it runs
.\scripts\gcp_train_status.ps1 -Log       # training log (uploaded when the run ends)
```

**From a different computer** — easiest is Cloud Shell: open
<https://console.cloud.google.com>, click the `>_` icon (top right), and you
have a browser terminal already logged in. Then:

```bash
gcloud config set project terravault
gcloud storage cat gs://terravault-ml-artifacts/runs/latest.json   # names of the current run
gcloud storage cat gs://terravault-ml-artifacts/runs/<RUN_ID>/STATUS
gcloud compute instances list --project terravault                 # TERMINATED = finished
gcloud storage cat gs://terravault-ml-artifacts/runs/<RUN_ID>/train.log
```

(On a machine with gcloud installed, `gcloud auth login` first; or clone the
repo and use `.\scripts\gcp_train_status.ps1 -Bucket terravault-ml-artifacts`.)

The STATUS file is a timestamped phase history; the last line tells you where
the run is: `BOOTSTRAP…` → `COLLECT…` → `EXTRACT…` → `TRAIN…` → `UPLOAD…` →
`DONE` (or `FAILED exit=N`, with the reason in `train.log`).

## 4. Collect the result

```bash
gcloud storage cp -r gs://terravault-ml-artifacts/runs/<RUN_ID>/models .
```

Drop the contents into the repo's `models/` (locally or on the deploy VM) —
`isolation_forest.pkl`, `scaler.pkl`, `training_metadata.json`,
`training_data.npy`, plus the versioned backup under `versions/`. The metadata
records exactly how many baseline + corpus samples the model was fitted on.

Then delete the powered-off VM (a stopped VM still bills a few cents/day for
its disk):

```bash
gcloud compute instances delete <VM_NAME> --zone us-central1-a --project terravault --quiet
```

Old model versions stay in `models/versions/` — `ModelManager.rollback_to_version()`
restores any of them if the new model misbehaves.

## Cost honesty

| Item | Rate | Typical run |
|---|---|---|
| `e2-highcpu-4` VM (us-central1) | ~$0.10/h | well under $1 |
| 40 GB balanced disk | ~$0.004/h | cents |
| Bucket storage | ~$0.02/GB-mo | cents |

The whole pipeline is CPU + network work; GPUs would sit idle and the free
trial doesn't offer them anyway. Scaling that genuinely helps the model =
more **modules** (`-Modules`), not a bigger machine.

**Free-trial quota:** trial accounts are capped at 8 concurrent vCPUs. If
`terravault-prod` (2 vCPUs) is running, `e2-highcpu-4` fits comfortably; a
`-MachineType e2-highcpu-8` launch would exceed the cap — stop the prod VM
first or stay at 4.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `instances create` fails with quota error | Trial vCPU cap — use `e2-highcpu-4`, or stop other VMs |
| `instances create` fails mentioning billing | Project not linked to the billing account — Console → Billing → link `terravault` |
| STATUS stuck on a phase | `.\scripts\gcp_train_status.ps1 -Serial` shows the live console |
| `FAILED exit=N` in STATUS | Read `train.log`; the VM stays (powered off) for post-mortem, delete it when done |
| Nothing in STATUS after 5 min | Check serial output; verify the VM got an external IP (it needs internet for pip/registry) |

## Running the pipeline locally instead

The same script works on any machine, from the repo root:

```bash
python scripts/corpus_train.py all --max-modules 400          # collect + extract + train
python scripts/corpus_train.py train --model-dir models       # retrain from cached corpus
```

`corpus/` is gitignored; models land in `models/` as usual.
