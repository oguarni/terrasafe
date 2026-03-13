# ML Model System — `ml_model.py`

## Components

- `ModelManager` — persistence, versioning, drift detection, rollback, incremental updates
- `MLPredictor` — inference, feature validation, risk scoring, auto-training

## Model Configuration

- Algorithm: `IsolationForest`
- `contamination=0.1`, `n_estimators=150`, `random_state=42`, `n_jobs=-1`
- Scaler: `StandardScaler`

## Feature Vector (7 dimensions)

| Index | Feature | Bounds |
|---|---|---|
| 0 | `open_ports` | 0–100 |
| 1 | `hardcoded_secrets` | 0–100 |
| 2 | `public_access` | 0–100 |
| 3 | `unencrypted_storage` | 0–100 |
| 4 | `missing_logging` | 0–100 |
| 5 | `missing_flow_logs` | 0–100 |
| 6 | `total_resources` | 0–10000 |

Feature values are clipped to bounds before inference (in `scanner.py:_validate_features()`).

**Important**: When adding new features, update in sync:
1. `scanner.py:_extract_features()` — extraction logic
2. `scanner.py:_validate_features()` — bounds arrays (min_bounds, max_bounds)
3. `scanner.py:_format_features()` — feature_names list
4. `ml_model.py:_train_baseline_model()` — baseline_patterns columns
5. This document — bounds table above

## Training Data

- 18 synthetic "secure" baseline patterns x 3 augmentations + 5 edge cases = 77 samples
- Gaussian noise sigma=0.15 applied during augmentation
- Uses `np.random.default_rng(42)` — never use legacy `np.random.seed()`
- Patterns now include 7 features (added `missing_logging` and `missing_flow_logs` columns, baseline values = 0)

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

## Coverage (75.46%)

Untested lines (major gaps):
- Lines 107-109: `_load_training_data()` error paths
- Lines 170-173, 191-198: Drift detection date parsing and version rollback
- Lines 207-216: `list_versions()` and `rollback_to_version()` implementations
- Lines 231-267: `update_model_with_feedback()` combined data path
- Line 349: `predict_risk()` error fallback

## Anti-patterns

- Never use `np.random.seed()` — use `np.random.default_rng()`
- Never skip feature validation/clipping before calling `predict_risk()`
- Never ignore `save_model()` failures silently
