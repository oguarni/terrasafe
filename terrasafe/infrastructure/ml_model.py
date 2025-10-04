"""ML Model - Infrastructure layer"""
import numpy as np
from pathlib import Path
from typing import Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class ModelNotTrainedError(Exception):
    """Raised when model operations are attempted on untrained model"""
    pass

class ModelManager:
    """Manages ML model persistence and loading"""
    # Copy ModelManager class
    pass

class MLPredictor:
    """ML-based anomaly predictor"""
    # Copy MLPredictor class
    pass
