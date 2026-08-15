# Calibration runs — which one is canonical

Two GCP runs were executed on 2026-07-21. They are the **same job**; the second carries one
arithmetic fix. Quote the canonical run.

| Run | GCS run id | Directory | A.3 reconciliation | Status |
| --- | --- | --- | --- | --- |
| 2 | `ml-calib-20260721-215119` | `evaluation/results/ml_calibration/` | **10/10 fields exact** | **canonical — quote this one** |
| 1 | `ml-calib-20260721-213038` | `evaluation/results/ml_calibration_run1_superseded/` | 9/10 fields exact | superseded |

## The only difference

Run 1 computed `selectivity_lift` by dividing rates that had **already been rounded** to 4 decimal
places, which read 50.251 against A.3's banked 50.25 (delta 0.001). Run 1's other nine reconciliation
fields matched exactly, so this was a display artifact, never a scientific disagreement. Run 2 divides
the raw rates and reproduces 50.25 exactly.

Run 1 is kept rather than deleted because it is an **independent replicate on a separately mined
corpus** — the registry moves between minings, so a second run agreeing to the digit is evidence the
pipeline is deterministic, which is the reproducibility bar this project claims elsewhere.

## Do not re-run this to "improve" it

`per_config_scores.csv.gz` and `training_reference_scores.csv.gz` in the canonical directory contain
the raw per-configuration Isolation Forest scores and the training score distribution. **Any future
threshold — percentile, absolute, or banded — is re-derivable offline from those two files with zero
paid compute.** The GCP credits that produced them expired 2026-07-22; re-mining is neither necessary
nor affordable. Re-derive, do not re-run.
