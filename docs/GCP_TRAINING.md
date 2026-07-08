# Train the ML model on real Terraform modules (GCP, fully asynchronous)

This runbook launches the corpus-training job — the "future work" from
`terravault/infrastructure/CLAUDE_ML.md`: refit the Isolation Forest on
structural features extracted from **real Terraform code** instead of only
the 300 synthetic baseline vectors. Two corpus sources are supported:

1. **Terraform Registry modules** — curated namespaces
   (`terraform-aws-modules`, `cloudposse`, `aws-ia`, ~278 AWS modules) or,
   with `--registry-wide`, every AWS-provider module in the registry
   (~11,000 modules).
2. **GitHub public dataset** (optional) — every distinct `.tf` blob in
   BigQuery's `bigquery-public-data.github_repos` snapshot (~30,000 unique
   files after dedup), staged once with `scripts/corpus_github_bq.sh`.

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

None of this needs Administrator rights — plain PowerShell is fine. Every
`.ps1` script has a `.sh` twin for Linux/macOS (`scripts/gcp_train_launch.sh`,
`scripts/gcp_train_status.sh`); the flags map 1:1.

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

Linux equivalent:

```bash
scripts/gcp_train_launch.sh                        # same defaults
```

### Maximum-scale corpus (registry-wide + GitHub)

The curated namespaces top out at ~278 modules. To train on everything
available, stage the GitHub blobs once (≈USD 15–20 of BigQuery scan, then
reusable forever):

```bash
scripts/corpus_github_bq.sh                        # -> gs://<bucket>/github_corpus/
```

then launch with both sources:

```bash
scripts/gcp_train_launch.sh \
    --machine-type e2-highcpu-16 --modules 12000 --max-hours 12 \
    --registry-wide --github-corpus gs://terravault-ml-artifacts/github_corpus
```

(PowerShell: `-RegistryWide -GithubCorpus gs://... -MachineType e2-highcpu-16
-Modules 12000 -MaxHours 12`.) The extractor deduplicates by content hash
across both sources and records a per-source breakdown in
`features_meta.json` and the model's `training_metadata.json`.

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
| `e2-highcpu-16` VM (us-central1) | ~$0.40/h | ~$1 for a max-scale run |
| 60 GB balanced disk | ~$0.006/h | cents |
| Bucket storage | ~$0.02/GB-mo | cents |
| BigQuery GitHub corpus (one-time) | $6.25/TiB scanned | ~$15–20, shards reusable |

The whole pipeline is CPU + network work; GPUs would sit idle. Scaling that
genuinely helps the model = a bigger **corpus** (`--registry-wide`,
`--github-corpus`), not a bigger machine — collection is network-bound and
even a registry-wide extract takes only minutes on 16 cores.

**Quota:** the project's real ceiling is `CPUS_ALL_REGIONS` = **32 vCPUs
globally** (per-region CPUS is 200, so the global cap is the one that bites).
With `terravault-prod` (2 vCPUs) running, the largest launchable machine is
30 vCPUs — `e2-highcpu-16` is the biggest standard highcpu type that fits.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `instances create` fails with quota error | Trial vCPU cap — use `e2-highcpu-4`, or stop other VMs |
| `instances create` fails mentioning billing | Project not linked to the billing account — Console → Billing → link `terravault` |
| STATUS stuck on a phase | `.\scripts\gcp_train_status.ps1 -Serial` shows the live console |
| EXTRACT pinned at ~2 of N cores for 30+ min | pathological corpus files wedging the HCL parser — `corpus_train.py` now skips any file after a 15 s per-file timeout (`TIMEOUT` lines in train.log); if you see this, the VM is running an old source bundle |
| `FAILED exit=N` in STATUS | Read `train.log`; the VM stays (powered off) for post-mortem, delete it when done |
| Nothing in STATUS after 5 min | Check serial output; verify the VM got an external IP (it needs internet for pip/registry) |

## Running the pipeline locally instead

The same script works on any machine, from the repo root:

```bash
python scripts/corpus_train.py all --max-modules 400          # collect + extract + train
python scripts/corpus_train.py collect --registry-wide --max-modules 12000 --workers 16
python scripts/corpus_train.py github-fetch --shards-dir corpus/github_shards
python scripts/corpus_train.py extract --workers 0            # 0 = one per CPU core
python scripts/corpus_train.py train --model-dir models       # retrain from cached corpus
```

`corpus/` is gitignored; models land in `models/` as usual.
