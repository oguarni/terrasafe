"""ML Model - Infrastructure layer"""
import re
import numpy as np
import json
import logging
import time
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

from terravault.config.settings import get_settings

logger = logging.getLogger(__name__)

# Pattern matching auto-generated timestamp version strings (e.g. v20240115_143022)
_TIMESTAMP_VERSION_RE = re.compile(r'^v\d{8}_\d{6}$')


class ModelNotTrainedError(Exception):
    """Raised when model operations are attempted on untrained model"""


class ModelManager:
    """Manages ML model persistence, loading, and versioning with rollback support"""

    def __init__(self, model_dir: str = "models", model_filename: Optional[str] = None):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.versions_dir = self.model_dir / "versions"
        self.versions_dir.mkdir(exist_ok=True)
        if model_filename:
            self.model_path = self.model_dir / model_filename
        else:
            self.model_path = self.model_dir / Path(get_settings().model_path).name
        self.scaler_path = self.model_dir / "scaler.pkl"
        self.metadata_path = self.model_dir / "training_metadata.json"
        self.current_version_file = self.model_dir / "current_version.txt"
        self.training_data_path = self.model_dir / "training_data.npy"

    def save_model(self, model: IsolationForest, scaler: StandardScaler, metadata: dict,
                   version: Optional[str] = None, training_data: Optional[np.ndarray] = None):
        """
        Save trained model, scaler, and metadata with versioning support.

        Args:
            model: Trained IsolationForest model
            scaler: Fitted StandardScaler
            metadata: Training metadata dictionary
            version: Optional version string (auto-generated if None)
            training_data: Optional full training dataset to persist for future incremental updates

        Raises:
            Exception: Re-raised if persistence fails, so callers know the save did not succeed
        """
        try:
            # Generate version if not provided
            if version is None:
                version = f"v{time.strftime('%Y%m%d_%H%M%S')}"

            # Add version to metadata
            metadata['version'] = version
            metadata['saved_at'] = time.strftime('%Y-%m-%d %H:%M:%S')

            # Save current model
            joblib.dump(model, self.model_path)
            joblib.dump(scaler, self.scaler_path)
            with open(self.metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)

            # Persist training data if provided (enables safe incremental updates)
            if training_data is not None:
                self._save_training_data(training_data)

            # Save versioned backup for rollback capability
            version_dir = self.versions_dir / version
            version_dir.mkdir(exist_ok=True)
            joblib.dump(model, version_dir / "model.pkl")
            joblib.dump(scaler, version_dir / "scaler.pkl")
            with open(version_dir / "metadata.json", 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)

            # Update current version file
            with open(self.current_version_file, 'w', encoding='utf-8') as f:
                f.write(version)

            logger.info("Model version %s saved to %s", version, self.model_dir)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error saving model: %s", e)
            raise

    def _save_training_data(self, data: np.ndarray) -> None:
        """Persist the full training dataset alongside the model."""
        np.save(self.training_data_path, data)
        logger.debug("Training data saved to %s (%s samples)", self.training_data_path, len(data))

    def _load_training_data(self) -> Optional[np.ndarray]:
        """Load persisted training dataset, or return None if not found."""
        if not self.training_data_path.exists():
            return None
        try:
            data: np.ndarray = np.load(self.training_data_path)
            logger.debug("Training data loaded from %s (%s samples)", self.training_data_path, len(data))
            return data
        except (OSError, ValueError) as e:
            logger.warning("Could not load training data: %s", e)
            return None

    def load_model(self) -> Tuple[IsolationForest, StandardScaler]:
        """Load saved model and scaler, raising an error if not found."""
        if not self.model_path.exists() or not self.scaler_path.exists():
            raise ModelNotTrainedError("Model or scaler file not found.")

        try:
            # Load metadata for validation
            metadata = self._load_metadata()

            # Check model version — skip warning for auto-generated timestamp versions
            saved_version = metadata.get('version')
            configured_version = get_settings().model_version
            if (saved_version
                    and saved_version != configured_version
                    and not _TIMESTAMP_VERSION_RE.match(saved_version)):
                logger.warning(
                    "Model version mismatch: Saved %s != Configured %s",
                    saved_version, configured_version
                )

            # Check for drift
            if self._detect_drift(metadata):
                logger.warning("Model drift detected or model is too old. Retraining recommended.")

            # Load locally trained model and scaler (safe deserialization)
            model = joblib.load(self.model_path)  # nosec B301
            scaler = joblib.load(self.scaler_path)  # nosec B301
            logger.info("Model loaded successfully")
            return model, scaler
        except Exception as e:  # pylint: disable=broad-exception-caught
            raise ModelNotTrainedError(f"Error loading model: {e}") from e

    def _load_metadata(self) -> Dict[str, Any]:
        """Load model metadata."""
        if self.metadata_path.exists():
            with open(self.metadata_path, 'r', encoding='utf-8') as f:
                result: Dict[str, Any] = json.load(f)
                return result
        return {}

    def _detect_drift(self, metadata: dict) -> bool:
        """
        Detect if model has drifted or is outdated.

        Args:
            metadata: Model metadata dictionary

        Returns:
            True if drift detected or model stale, False otherwise
        """
        # Check if model is too old (simple drift heuristic)
        if 'saved_at' in metadata:
            try:
                from datetime import datetime
                saved_at = datetime.strptime(metadata['saved_at'], '%Y-%m-%d %H:%M:%S')
                age_days = (datetime.now() - saved_at).days

                # If model is older than 30 days, consider it drifted/stale
                if age_days > 30:
                    logger.warning("Model is %s days old", age_days)
                    return True
            except (ValueError, TypeError) as e:
                logger.warning("Failed to parse model timestamp: %s", e)

        # Future: Implement statistical drift detection (KL divergence, etc.)
        # comparing stored training_stats with recent inference stats

        return False

    def model_exists(self) -> bool:
        """Check if saved model exists"""
        return self.model_path.exists() and self.scaler_path.exists()

    def get_current_version(self) -> Optional[str]:
        """
        Get the current model version.

        Returns:
            Current version string or None if not available
        """
        try:
            if self.current_version_file.exists():
                with open(self.current_version_file, 'r', encoding='utf-8') as f:
                    return f.read().strip()
            return None
        except OSError as e:
            logger.error("Error reading current version: %s", e)
            return None

    def list_versions(self) -> list[str]:
        """
        List all available model versions.

        Returns:
            List of version strings sorted by creation time (newest first)
        """
        try:
            versions = []
            if self.versions_dir.exists():
                for version_dir in self.versions_dir.iterdir():
                    if version_dir.is_dir() and (version_dir / "model.pkl").exists():
                        versions.append(version_dir.name)
            return sorted(versions, reverse=True)
        except OSError as e:
            logger.error("Error listing versions: %s", e)
            return []

    def rollback_to_version(self, version: str) -> Tuple[IsolationForest, StandardScaler]:
        """
        Rollback to a specific model version.

        Args:
            version: Version string to rollback to

        Returns:
            Tuple of (model, scaler) from the specified version

        Raises:
            ModelNotTrainedError: If version not found
        """
        version_dir = self.versions_dir / version
        version_model_path = version_dir / "model.pkl"
        version_scaler_path = version_dir / "scaler.pkl"
        version_metadata_path = version_dir / "metadata.json"

        if not version_dir.exists() or not version_model_path.exists():
            available_versions = self.list_versions()
            raise ModelNotTrainedError(
                f"Version '{version}' not found. Available versions: {available_versions}"
            )

        try:
            # Load locally trained versioned model and scaler (safe deserialization)
            model = joblib.load(version_model_path)  # nosec B301
            scaler = joblib.load(version_scaler_path)  # nosec B301

            # Load metadata if available
            metadata = {}
            if version_metadata_path.exists():
                with open(version_metadata_path, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)

            # Copy versioned files to current
            joblib.dump(model, self.model_path)
            joblib.dump(scaler, self.scaler_path)
            with open(self.metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)

            # Update current version
            with open(self.current_version_file, 'w', encoding='utf-8') as f:
                f.write(version)

            logger.info("Successfully rolled back to version %s", version)
            return model, scaler

        except Exception as e:  # pylint: disable=broad-exception-caught
            raise ModelNotTrainedError(f"Error rolling back to version {version}: {e}") from e

    def update_model_with_feedback(self, model: IsolationForest, scaler: StandardScaler,
                                   new_data: np.ndarray, metadata: dict):
        """
        Update model by combining historical training data with new feedback data.

        Loads the persisted training dataset, stacks it with new_data, refits a fresh
        StandardScaler and IsolationForest on the combined set, then saves everything.
        This prevents catastrophic forgetting of previously learned patterns.

        If no historical training data is found, logs a warning and fits on new_data only.
        """
        try:
            historical = self._load_training_data()
            if historical is not None:
                combined = np.vstack([historical, new_data])
                logger.info(
                    "Combining %s historical + %s new samples (%s total)",
                    len(historical), len(new_data), len(combined)
                )
            else:
                logger.warning(
                    "No historical training data found at %s — fitting on new_data only. "
                    "Run train-model first to enable full incremental updates.",
                    self.training_data_path
                )
                combined = new_data

            # Fit a fresh scaler on the full combined dataset
            new_scaler = StandardScaler()
            scaled_combined = new_scaler.fit_transform(combined)

            # Refit the model on the full combined dataset
            model.fit(scaled_combined)

            # Update metadata
            metadata['total_samples'] = len(combined)
            metadata['feedback_samples_added'] = len(new_data)

            # Save model, updated scaler, and full training data for future updates
            self.save_model(model, new_scaler, metadata, training_data=combined)
            logger.info("Model updated with %s new samples (%s total)", len(new_data), len(combined))
        except (ValueError, OSError) as e:
            logger.error("Error updating model: %s", e)


class MLPredictor:
    """ML-based anomaly predictor"""

    def __init__(self, model_manager: Optional[ModelManager] = None):
        self.model_manager = model_manager or ModelManager()
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._initialize_ml_model()

    def _initialize_ml_model(self):
        """Load an existing model or train a new one."""
        try:
            self.model, self.scaler = self.model_manager.load_model()
        except ModelNotTrainedError:
            logger.warning("No pre-trained model found. Training a new baseline model.")
            self._train_baseline_model()

    def predict_risk(self, features: np.ndarray) -> Tuple[float, str]:
        """Calculate risk score using the loaded ML model."""
        if self.model is None or self.scaler is None:
            raise ModelNotTrainedError("Model is not initialized.")

        try:
            scaled_features = self.scaler.transform(features)
            prediction = self.model.predict(scaled_features)[0]
            anomaly_score = self.model.decision_function(scaled_features)[0]

            # Enhanced risk score calculation
            if prediction == -1:  # Anomaly detected
                risk_score = min(100, max(50, 50 + abs(anomaly_score) * 100))
            else:  # Normal pattern
                risk_score = max(0, min(50, 50 - anomaly_score * 50))

            # Determine confidence based on distance from decision boundary
            if abs(anomaly_score) > 0.3:
                confidence = "HIGH"
            elif abs(anomaly_score) > 0.1:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"

            logger.debug("ML Score: %.1f, Confidence: %s, Anomaly: %.3f", risk_score, confidence, anomaly_score)
            return risk_score, confidence
        except Exception as e:
            logger.error("ML scoring failed: %s", e)
            raise ModelNotTrainedError(f"ML scoring failed: {type(e).__name__}: {e}") from e

    # Feature layout mirrored from application.feature_extraction.FEATURE_NAMES.
    # Duplicated here so the infrastructure layer does not import the application
    # layer; update both together (see CLAUDE_ML.md sync checklist).
    _FEATURE_NAMES = (
        "resource_count", "resource_type_diversity", "ingress_rule_count",
        "public_exposure_count", "iam_resource_count", "encryption_coverage",
        "logging_resource_count", "secret_parametrization",
    )

    def _generate_secure_baseline(self, n_samples: int = 300) -> np.ndarray:
        """Synthesise a corpus of *secure* infrastructure feature vectors.

        Each row is a plausible well-configured Terraform module: encryption and
        secret hygiene near-complete, audit logging present, minimal public
        exposure. The IsolationForest learns this manifold so that insecure
        configurations (low encryption coverage, public exposure, missing
        logging, hardcoded secrets) fall outside it and score as anomalies —
        independently of the deterministic rule findings.

        Unlike the previous hand-coded vectors, every feature varies across the
        corpus (no constant-zero columns) and the values share the exact
        semantics produced by ``StructuralFeatureExtractor`` at inference time,
        so the fitted ``StandardScaler`` is no longer mis-calibrated.
        """
        rng = np.random.default_rng(42)
        rows = []
        for _ in range(n_samples):
            resource_count = int(rng.integers(3, 40))
            # Small modules are often all-distinct types (ratio ~1.0); larger
            # ones repeat types. Allow the full ratio range so diverse-but-secure
            # configurations stay inside the learned manifold.
            diversity = max(2, min(resource_count,
                                   int(round(resource_count * rng.uniform(0.5, 1.0)))))
            ingress = int(rng.poisson(1.5))
            # Secure modules rarely expose anything publicly (e.g. a lone ALB).
            public_exposure = int(rng.binomial(1, 0.2))
            iam = int(rng.integers(0, max(1, resource_count // 5) + 1))
            # Encryption coverage and secret parametrization are *centered* at
            # 1.0 (the secure mode) with a minority of lower-coverage configs, so
            # a fully-encrypted/fully-parametrized file sits at the centre of the
            # manifold and insecure values fall below it.
            encryption_coverage = 1.0 if rng.random() < 0.75 else float(rng.uniform(0.6, 1.0))
            secret_param = 1.0 if rng.random() < 0.8 else float(rng.uniform(0.6, 1.0))
            # Audit logging is present once there is infrastructure worth logging.
            if resource_count >= 4:
                logging_count = int(rng.integers(1, 4))
            else:
                logging_count = int(rng.integers(0, 2))
            rows.append([
                resource_count, diversity, ingress, public_exposure,
                iam, encryption_coverage, logging_count, secret_param,
            ])
        return np.array(rows, dtype=np.float64)

    def _train_baseline_model(self):
        """Train and save a baseline model on synthetic secure infrastructure."""
        training_data = self._generate_secure_baseline()

        # Train scaler and model on the structural feature space
        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(training_data)

        # Configure Isolation Forest with optimized parameters
        self.model = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies (as per requirements)
            random_state=42,
            n_estimators=150,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1
        )

        self.model.fit(scaled_features)

        # Prepare training metadata
        training_stats = {
            'total_samples': len(training_data),
            'feature_names': list(self._FEATURE_NAMES),
            'feature_ranges': {
                name: {
                    'min': round(float(training_data[:, i].min()), 3),
                    'max': round(float(training_data[:, i].max()), 3),
                }
                for i, name in enumerate(self._FEATURE_NAMES)
            },
            'model_parameters': {
                'contamination': 0.1,
                'n_estimators': 150,
                'random_state': 42
            }
        }

        # Save model with metadata and persist training data for future incremental updates
        self.model_manager.save_model(self.model, self.scaler, training_stats, training_data=training_data)
        logger.info("Baseline ML model trained on %s synthetic secure samples", len(training_data))
