# ML Model System — `ml_model.py`

## Components

- `ModelManager` — persistence, versioning, drift detection, rollback, incremental updates
- `MLPredictor` — inference, feature validation, risk scoring, auto-training

## Model Configuration

- Algorithm: `IsolationForest`
- `contamination=0.1`, `n_estimators=150`, `random_state=42`, `n_jobs=-1`
- Scaler: `StandardScaler`

## Feature Vector (8 dimensions — structural, rule-independent)

The model scores the **structure of the infrastructure**, extracted directly
from the parsed Terraform by `application/feature_extraction.py`
(`StructuralFeatureExtractor`). It is **not** derived from the rule findings, so
the ML signal can flag anomalous configurations the 7 rules do not cover. The
canonical layout lives in `feature_extraction.FEATURE_NAMES` / `FEATURE_BOUNDS`.

| Index | Feature | Bounds | Meaning |
|---|---|---|---|
| 0 | `resource_count` | 0–10000 | total resources declared |
| 1 | `resource_type_diversity` | 0–200 | distinct resource types |
| 2 | `ingress_rule_count` | 0–1000 | inbound security-group rules |
| 3 | `public_exposure_count` | 0–1000 | public CIDR ingress + public-IP attributes |
| 4 | `iam_resource_count` | 0–1000 | `aws_iam_*` resources |
| 5 | `encryption_coverage` | 0.0–1.0 | fraction of encryptable storage encrypted (1.0 if none) |
| 6 | `logging_resource_count` | 0–1000 | CloudTrail / CloudWatch / flow-log resources |
| 7 | `secret_parametrization` | 0.0–1.0 | fraction of secrets from variables, not literals (1.0 if none) |

Feature values are clipped to bounds before inference (in `scanner.py:_validate_features()`).

**Important**: When changing the feature vector, update in sync:
1. `application/feature_extraction.py` — `FEATURE_NAMES`, `FEATURE_BOUNDS`, and `StructuralFeatureExtractor.extract()`
2. `ml_model.py:_generate_secure_baseline()` + `_FEATURE_NAMES` (local mirror — infra must not import application)
3. `scanner.py:_format_features()` (consumes `FEATURE_NAMES`)
4. `cli_formatter.py:_format_features()` — terminal display
5. This document — table above

## Training Data

- `_generate_secure_baseline()` synthesises **300** secure-infrastructure feature
  vectors with `np.random.default_rng(42)` (never legacy `np.random.seed()`).
- Every feature **varies** across the corpus (no constant-zero columns, unlike
  the previous hand-coded patterns), and the values share the exact semantics
  `StructuralFeatureExtractor` produces at inference time — so the fitted
  `StandardScaler` is correctly calibrated (no train/inference scale mismatch).
- `encryption_coverage` and `secret_parametrization` are **centered at 1.0** (the
  secure mode), so a fully-encrypted/parametrized file sits at the centre of the
  manifold and insecure values fall outside it as anomalies.
- **Limitation / future work:** the baseline is synthetic-but-principled. The
  next step is to fit it on structural features extracted from a corpus of real,
  known-secure Terraform modules.

## Risk Scoring

| Prediction | Score range | Logic |
|---|---|---|
| Anomaly (`-1`) | 50–100 | `min(100, max(50, 50 + abs(anomaly_score) * 100))` |
| Normal (`1`) | 0–50 | `max(0, min(50, 50 - anomaly_score * 50))` |

Confidence: `HIGH` if `|score| > 0.3`, `MEDIUM` if `|score| > 0.1`, else `LOW`

Fallback on any error: returns `(50.0, "LOW")`

## Model Files

```
models/
  isolation_forest.pkl      <- path driven by settings.model_path
  scaler.pkl
  training_metadata.json
  training_data.npy         <- full training set for safe incremental updates
  current_version.txt
  versions/<version>/       <- versioned backups (model.pkl, scaler.pkl, metadata.json)
```

## Incremental Updates

`update_model_with_feedback()` loads `training_data.npy`, stacks historical + new data, refits a
fresh `StandardScaler` and `IsolationForest` on the combined set. No catastrophic forgetting.

`_train_baseline_model()` passes `training_data=augmented_data` to `save_model()` so the initial
dataset is persisted immediately after the first training run (`make train-model`).

## Drift Detection

- Warns if model is >30 days old
- Version mismatch warning **skipped** for auto-generated timestamps matching `v\d{8}_\d{6}`

## `save_model()`

Re-raises on failure (tested in `tests/test_main.py`).

## Coverage (100%)

## Anti-patterns

- Never use `np.random.seed()` — use `np.random.default_rng()`
- Never skip feature validation/clipping before calling `predict_risk()`
- Never ignore `save_model()` failures silently
