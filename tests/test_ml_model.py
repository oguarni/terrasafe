"""
Unit tests for ML Model - Infrastructure layer
"""
import pytest
import numpy as np
import json
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from terrasafe.infrastructure.ml_model import (
    ModelManager,
    MLPredictor,
    ModelNotTrainedError
)


@pytest.mark.unit
@pytest.mark.ml
class TestModelManager:
    """Test suite for ModelManager"""

    def test_model_exists_false_initially(self, tmp_path):
        """Test model_exists returns False when no model saved"""
        manager = ModelManager(str(tmp_path / "new_models"))
        assert not manager.model_exists()

    def test_save_and_load_model(self, tmp_path):
        """Test saving and loading model"""
        manager = ModelManager(str(tmp_path / "models"))

        # Create simple model and scaler
        model = IsolationForest(random_state=42)
        scaler = StandardScaler()

        # Fit with dummy data
        dummy_data = np.array([[1, 2, 3, 4, 5], [2, 3, 4, 5, 6]])
        scaler.fit(dummy_data)
        model.fit(scaler.transform(dummy_data))

        # Save
        metadata = {"test": "data", "samples": 2}
        manager.save_model(model, scaler, metadata)

        # Verify saved
        assert manager.model_exists()

        # Load
        loaded_model, loaded_scaler = manager.load_model()
        assert loaded_model is not None
        assert loaded_scaler is not None

    def test_load_model_not_found(self, tmp_path):
        """Test loading model when files don't exist"""
        manager = ModelManager(str(tmp_path / "empty_models"))
        with pytest.raises(ModelNotTrainedError) as exc_info:
            manager.load_model()
        assert "Model or scaler file not found" in str(exc_info.value)

    def test_update_model_with_feedback_existing_metadata(self, tmp_path):
        """Test updating model with feedback combines historical + new data."""
        manager = ModelManager(str(tmp_path / "models"))

        # Create initial model and persist training_data alongside it
        model = IsolationForest(random_state=42, contamination=0.1)
        scaler = StandardScaler()
        initial_data = np.array([[1, 2, 3, 4, 5], [2, 3, 4, 5, 6]])
        scaler.fit(initial_data)
        model.fit(scaler.transform(initial_data))

        initial_metadata = {"total_samples": 2}
        manager.save_model(model, scaler, initial_metadata, training_data=initial_data)

        # Update with new data — should combine 2 historical + 2 new = 4 total
        new_data = np.array([[3, 4, 5, 6, 7], [4, 5, 6, 7, 8]])
        metadata = {"version": "1.2"}
        manager.update_model_with_feedback(model, scaler, new_data, metadata)

        # Verify metadata updated
        with open(manager.metadata_path) as f:
            updated_metadata = json.load(f)
        assert updated_metadata['total_samples'] == 4  # 2 historical + 2 new
        assert updated_metadata['feedback_samples_added'] == 2

    def test_rollback_to_version_success(self, tmp_path):
        """Rollback to a previously saved version succeeds"""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import numpy as np
        manager = ModelManager(str(tmp_path / "models"))
        model = IsolationForest(random_state=42)
        scaler = StandardScaler()
        data = np.array([[1, 2, 3, 4, 5], [2, 3, 4, 5, 6]])
        scaler.fit(data)
        model.fit(scaler.transform(data))
        manager.save_model(model, scaler, {"info": "v1"}, version="v20240101_000000")
        loaded_model, loaded_scaler = manager.rollback_to_version("v20240101_000000")
        assert loaded_model is not None
        assert loaded_scaler is not None
        # Current version file should be updated
        assert manager.get_current_version() == "v20240101_000000"


@pytest.mark.unit
@pytest.mark.ml
class TestMLPredictor:
    """Test suite for MLPredictor"""

    def test_predictor_initialization_with_existing_model(self, tmp_path):
        """Test MLPredictor loads existing model"""
        manager = ModelManager(str(tmp_path / "models"))

        # Create and save model
        model = IsolationForest(random_state=42)
        scaler = StandardScaler()
        dummy_data = np.array([[1, 2, 3, 4, 5], [2, 3, 4, 5, 6]])
        scaler.fit(dummy_data)
        model.fit(scaler.transform(dummy_data))
        manager.save_model(model, scaler, {"samples": 2})

        # Create predictor
        predictor = MLPredictor(manager)
        assert predictor.model is not None
        assert predictor.scaler is not None

    def test_predictor_initialization_trains_baseline(self, tmp_path):
        """Test MLPredictor trains baseline model when none exists"""
        manager = ModelManager(str(tmp_path / "new_models"))
        predictor = MLPredictor(manager)

        # Should have trained a new model
        assert predictor.model is not None
        assert predictor.scaler is not None
        assert manager.model_exists()

    def test_predict_risk_with_features(self, tmp_path):
        """Test predict_risk with valid features"""
        manager = ModelManager(str(tmp_path / "models"))
        predictor = MLPredictor(manager)

        # Test with normal pattern
        features = np.array([[0, 0, 0, 0, 0, 0, 10]])
        risk_score, confidence = predictor.predict_risk(features)

        assert isinstance(risk_score, (int, float))
        assert 0 <= risk_score <= 100
        assert confidence in ["HIGH", "MEDIUM", "LOW"]

    def test_predict_risk_anomaly_detected(self, tmp_path):
        """Test predict_risk when anomaly is detected"""
        manager = ModelManager(str(tmp_path / "models"))
        predictor = MLPredictor(manager)

        # Test with anomalous pattern (many issues)
        features = np.array([[10, 10, 10, 10, 1, 1, 5]])
        risk_score, confidence = predictor.predict_risk(features)

        # Should have high risk score
        assert risk_score >= 50


