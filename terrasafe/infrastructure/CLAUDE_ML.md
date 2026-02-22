# ML Model System — `ml_model.py`

## Components

- `ModelManager` — persistence, versioning, drift detection
- `MLPredictor` — inference, feature validation, risk scoring

## Model Configuration

- Algorithm: `IsolationForest`
- `contamination=0.1`, `n_estimators=150`, `random_state=42`, `n_jobs=-1`
- Scaler: `StandardScaler`

## Feature Vector (5 dimensions)

| Index | Feature | Bounds |
|---|---|---|
| 0 | `open_ports` | 0–100 |
| 1 | `hardcoded_secrets` | 0–100 |
| 2 | `public_access` | 0–100 |
| 3 | `unencrypted_storage` | 0–100 |
| 4 | `total_resources` | 0–10000 |

Feature values are clipped to bounds before inference (prevents model poisoning).

## Training Data

- 18 synthetic "secure" baseline patterns × 3 augmentations + 5 edge cases ≈ 77 samples
- Gaussian noise σ=0.15 applied during augmentation
- Uses `np.random.default_rng(42)` — never use legacy `np.random.seed()`

## Risk Scoring

| Prediction | Score range | Logic |
|---|---|---|
| Anomaly (`-1`) | 50–100 | Higher anomaly score → higher risk |
| Normal (`1`) | 0–50 | Lower anomaly score → lower risk |

Confidence: `HIGH` if `|score| > 0.3`, `MEDIUM` if `|score| > 0.1`, else `LOW`

Fallback on any error: returns `(50.0, "LOW")`

## Model Files

```
models/
  isolation_forest.pkl
  scaler.pkl
  training_metadata.json
  versions/<version>/     ← versioned backups
```

## Known Issues

- `settings.model_path` field is **never read** — `ModelManager` hardcodes `models/isolation_forest.pkl`
- `update_model_with_feedback()`: incremental learning exists but has documented catastrophic forgetting risk

## Drift Detection

- Warns if model is >30 days old
- Version mismatch warning **skipped** for auto-generated timestamps matching `v\d{8}_\d{6}`

## `save_model()`

Re-raises on failure (tested in `tests/test_main.py`).

## Testing

- `tests/test_ml_model.py` — 324 lines
- Uses `tmp_path` fixture for model file operations

## Anti-patterns

- Never use `np.random.seed()` — use `np.random.default_rng()`
- Never skip feature validation/clipping before calling `predict()`
- Never ignore `save_model()` failures silently
