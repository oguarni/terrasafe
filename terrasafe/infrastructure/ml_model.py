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

from terrasafe.config.settings import get_settings

logger = logging.getLogger(__name__)

# Pattern matching auto-generated timestamp version strings (e.g. v20240115_143022)
_TIMESTAMP_VERSION_RE = re.compile(r'^v\d{8}_\d{6}$')


class ModelNotTrainedError(Exception):
    """Raised when model operations are attempted on untrained model"""
    pass


class ModelManager:
    """Manages ML model persistence, loading, and versioning with rollback support"""

    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.versions_dir = self.model_dir / "versions"
        self.versions_dir.mkdir(exist_ok=True)
        self.model_path = self.model_dir / "isolation_forest.pkl"
        self.scaler_path = self.model_dir / "scaler.pkl"
        self.metadata_path = self.model_dir / "training_metadata.json"
        self.current_version_file = self.model_dir / "current_version.txt"

    def save_model(self, model: IsolationForest, scaler: StandardScaler, metadata: dict, version: Optional[str] = None):
        """
        Save trained model, scaler, and metadata with versioning support.

        Args:
            model: Trained IsolationForest model
            scaler: Fitted StandardScaler
            metadata: Training metadata dictionary
            version: Optional version string (auto-generated if None)

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
            with open(self.metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Save versioned backup for rollback capability
            version_dir = self.versions_dir / version
            version_dir.mkdir(exist_ok=True)
            joblib.dump(model, version_dir / "model.pkl")
            joblib.dump(scaler, version_dir / "scaler.pkl")
            with open(version_dir / "metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            # Update current version file
            with open(self.current_version_file, 'w') as f:
                f.write(version)

            logger.info(f"Model version {version} saved to {self.model_dir}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            raise

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
                    f"Model version mismatch: Saved {saved_version} != Configured {configured_version}"
                )

            # Check for drift
            if self._detect_drift(metadata):
                logger.warning("Model drift detected or model is too old. Retraining recommended.")

            model = joblib.load(self.model_path)
            scaler = joblib.load(self.scaler_path)
            logger.info("Model loaded successfully")
            return model, scaler
        except Exception as e:
            raise ModelNotTrainedError(f"Error loading model: {e}") from e

    def _load_metadata(self) -> Dict[str, Any]:
        """Load model metadata."""
        if self.metadata_path.exists():
            with open(self.metadata_path, 'r') as f:
                return json.load(f)
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
                    logger.warning(f"Model is {age_days} days old")
                    return True
            except Exception as e:
                logger.warning(f"Failed to parse model timestamp: {e}")

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
                with open(self.current_version_file, 'r') as f:
                    return f.read().strip()
            return None
        except Exception as e:
            logger.error(f"Error reading current version: {e}")
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
        except Exception as e:
            logger.error(f"Error listing versions: {e}")
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
            # Load versioned model and scaler
            model = joblib.load(version_model_path)
            scaler = joblib.load(version_scaler_path)

            # Load metadata if available
            metadata = {}
            if version_metadata_path.exists():
                with open(version_metadata_path, 'r') as f:
                    metadata = json.load(f)

            # Copy versioned files to current
            joblib.dump(model, self.model_path)
            joblib.dump(scaler, self.scaler_path)
            with open(self.metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Update current version
            with open(self.current_version_file, 'w') as f:
                f.write(version)

            logger.info(f"Successfully rolled back to version {version}")
            return model, scaler

        except Exception as e:
            raise ModelNotTrainedError(f"Error rolling back to version {version}: {e}") from e

    def update_model_with_feedback(self, model: IsolationForest, scaler: StandardScaler,
                                   new_data: np.ndarray, metadata: dict):
        """
        Update model using only the new feedback data.

        NOTE: This is a simplified incremental update that refits exclusively on new_data
        (catastrophic forgetting). It does NOT combine with historical training data.
        For production use, consider more sophisticated continual learning strategies.
        """
        try:
            # Scale new data
            scaled_new_data = scaler.transform(new_data)

            # Load existing training data if metadata exists
            if self.metadata_path.exists():
                with open(self.metadata_path, 'r') as f:
                    old_metadata = json.load(f)
                    old_samples = old_metadata.get('total_samples', 0)
                    new_total = old_samples + len(new_data)
                    metadata['total_samples'] = new_total
                    metadata['feedback_samples_added'] = len(new_data)

            # Retrain model on new data only (simplified approach — catastrophic forgetting applies)
            # In production, consider more sophisticated incremental learning
            logger.warning(
                "update_model_with_feedback refits only on new_data; historical patterns are lost."
            )
            model.fit(scaled_new_data)

            # Save updated model
            self.save_model(model, scaler, metadata)
            logger.info(f"Model updated with {len(new_data)} new samples")
        except Exception as e:
            logger.error(f"Error updating model: {e}")


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

            logger.debug(f"ML Score: {risk_score:.1f}, Confidence: {confidence}, Anomaly: {anomaly_score:.3f}")
            return risk_score, confidence
        except Exception as e:
            logger.error(f"Error in ML scoring: {e}")
            return 50.0, "LOW"  # Return neutral score on error

    def _train_baseline_model(self):
        """Train and save a new baseline model with comprehensive patterns."""
        # Use a local RNG instance to avoid polluting global random state
        rng = np.random.default_rng(42)

        # Enhanced baseline patterns representing secure configurations
        # Features: [open_ports, secrets, public_access, unencrypted, resource_count]
        baseline_patterns = [
            # Fully secure configurations
            [0, 0, 0, 0, 5],   # Small secure microservice
            [0, 0, 0, 0, 10],  # Medium secure application
            [0, 0, 0, 0, 15],  # Large secure infrastructure
            [0, 0, 0, 0, 25],  # Enterprise secure setup
            [0, 0, 0, 0, 3],   # Minimal secure Lambda function

            # Web applications (acceptable public exposure)
            [1, 0, 0, 0, 8],   # Simple web app with HTTP
            [2, 0, 0, 0, 12],  # Web app with HTTP/HTTPS
            [2, 0, 1, 0, 20],  # E-commerce with CDN (public S3)
            [1, 0, 1, 0, 15],  # Static site with S3 hosting
            [2, 0, 2, 0, 30],  # Multi-region web platform

            # Development environments (slightly relaxed)
            [1, 0, 0, 1, 6],   # Dev env with one unencrypted volume
            [2, 0, 0, 1, 10],  # Staging with test data
            [1, 0, 1, 1, 8],   # QA environment
            [0, 0, 0, 2, 12],  # Test cluster with temp storage

            # Microservices architectures
            [3, 0, 0, 0, 40],  # Service mesh with multiple endpoints
            [4, 0, 1, 0, 50],  # Kubernetes cluster with ingress
            [2, 0, 0, 0, 35],  # Docker swarm setup
            [3, 0, 2, 0, 45],  # Multi-service with CDN
        ]

        baseline_features = np.array(baseline_patterns)

        # Advanced augmentation with realistic variations
        augmented_data = baseline_features.copy()

        # Add noise variations for each pattern
        for pattern in baseline_features:
            for _ in range(3):  # Create 3 variations per pattern
                noise = rng.normal(0, 0.15, 5)
                augmented = pattern + noise
                augmented = np.maximum(augmented, 0)  # Ensure non-negative
                # Round discrete features
                augmented = np.round(augmented)
                augmented_data = np.vstack([augmented_data, augmented])

        # Add edge cases representing acceptable boundaries
        edge_cases = np.array([
            [5, 0, 0, 0, 60],  # Large microservices
            [0, 0, 5, 0, 40],  # Content delivery network
            [3, 0, 3, 2, 50],  # Legacy migration
            [0, 0, 0, 3, 25],  # Development cluster
            [6, 0, 2, 0, 70],  # API gateway with multiple services
        ])

        augmented_data = np.vstack([augmented_data, edge_cases])

        # Train scaler and model
        self.scaler = StandardScaler()
        scaled_features = self.scaler.fit_transform(augmented_data)

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
            'total_samples': len(augmented_data),
            'secure_patterns': len(baseline_patterns),
            'augmented_samples': len(augmented_data) - len(baseline_patterns),
            'feature_ranges': {
                'open_ports': {'min': int(augmented_data[:, 0].min()), 'max': int(augmented_data[:, 0].max())},
                'hardcoded_secrets': {'min': int(augmented_data[:, 1].min()), 'max': int(augmented_data[:, 1].max())},
                'public_access': {'min': int(augmented_data[:, 2].min()), 'max': int(augmented_data[:, 2].max())},
                'unencrypted_storage': {'min': int(augmented_data[:, 3].min()), 'max': int(augmented_data[:, 3].max())},
                'total_resources': {'min': int(augmented_data[:, 4].min()), 'max': int(augmented_data[:, 4].max())},
            },
            'model_parameters': {
                'contamination': 0.1,
                'n_estimators': 150,
                'random_state': 42
            }
        }

        # Save model with metadata
        self.model_manager.save_model(self.model, self.scaler, training_stats)
        logger.info(f"Enhanced ML model trained successfully with {len(augmented_data)} samples")
