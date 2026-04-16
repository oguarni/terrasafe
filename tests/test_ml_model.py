"""Unit tests for the ML model infrastructure layer."""
import json

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from terrasafe.infrastructure.ml_model import (
    MLPredictor,
    ModelManager,
    ModelNotTrainedError,
)


pytestmark = [pytest.mark.unit, pytest.mark.ml]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fit_baseline():
    """Build a trained IsolationForest + StandardScaler pair on trivial data."""
    model = IsolationForest(random_state=42, contamination=0.1)
    scaler = StandardScaler()
    data = np.array([[1, 2, 3, 4, 5], [2, 3, 4, 5, 6]])
    scaler.fit(data)
    model.fit(scaler.transform(data))
    return model, scaler, data


@pytest.fixture
def model_manager(tmp_path):
    return ModelManager(str(tmp_path / "models"))


@pytest.fixture
def predictor(model_manager):
    return MLPredictor(model_manager)


# ---------------------------------------------------------------------------
# ModelManager
# ---------------------------------------------------------------------------

def test_model_exists_is_false_before_first_save(model_manager):
    assert model_manager.model_exists() is False


def test_save_then_load_round_trips_model_and_scaler(model_manager):
    model, scaler, _ = _fit_baseline()

    model_manager.save_model(model, scaler, {"test": "data", "samples": 2})

    assert model_manager.model_exists() is True
    loaded_model, loaded_scaler = model_manager.load_model()
    assert loaded_model is not None
    assert loaded_scaler is not None


def test_load_model_raises_when_artifact_files_are_missing(model_manager):
    with pytest.raises(ModelNotTrainedError, match="Model or scaler file not found"):
        model_manager.load_model()


def test_feedback_update_combines_historical_and_new_samples(model_manager):
    model, scaler, data = _fit_baseline()
    model_manager.save_model(model, scaler, {"total_samples": 2}, training_data=data)

    new_data = np.array([[3, 4, 5, 6, 7], [4, 5, 6, 7, 8]])
    model_manager.update_model_with_feedback(model, scaler, new_data, {"version": "1.2"})

    with open(model_manager.metadata_path) as fh:
        metadata = json.load(fh)
    assert metadata["total_samples"] == 4
    assert metadata["feedback_samples_added"] == 2


def test_rollback_restores_and_marks_previous_version_current(model_manager):
    model, scaler, _ = _fit_baseline()
    model_manager.save_model(model, scaler, {"info": "v1"}, version="v20240101_000000")

    loaded_model, loaded_scaler = model_manager.rollback_to_version("v20240101_000000")

    assert loaded_model is not None
    assert loaded_scaler is not None
    assert model_manager.get_current_version() == "v20240101_000000"


# ---------------------------------------------------------------------------
# MLPredictor
# ---------------------------------------------------------------------------

def test_predictor_trains_baseline_when_no_saved_model_exists(model_manager):
    predictor = MLPredictor(model_manager)

    assert predictor.model is not None
    assert predictor.scaler is not None
    assert model_manager.model_exists() is True


@pytest.mark.parametrize(
    "features, expect_min_score",
    [
        pytest.param(np.array([[0, 0, 0, 0, 0, 0, 10]]), None, id="benign_features_score_in_range"),
        pytest.param(np.array([[10, 10, 10, 10, 1, 1, 5]]), 50, id="anomalous_features_high_score"),
    ],
)
def test_predict_risk_returns_bounded_score_and_confidence(predictor, features, expect_min_score):
    score, confidence = predictor.predict_risk(features)

    assert isinstance(score, (int, float))
    assert 0 <= score <= 100
    assert confidence in {"HIGH", "MEDIUM", "LOW"}
    if expect_min_score is not None:
        assert score >= expect_min_score
