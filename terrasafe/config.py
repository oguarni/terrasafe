"""Configuration management for TerraSafe"""
import yaml
from pathlib import Path
from typing import Dict, Any


class Config:
    """Singleton configuration manager"""
    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._config is None:
            self.load_config()

    def load_config(self, config_path: str = "config.yaml"):
        """Load configuration from YAML file"""
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                self._config = yaml.safe_load(f)
        else:
            # Default configuration
            self._config = {
                'severity_scores': {
                    'critical': 30,
                    'high': 20,
                    'medium': 10,
                    'low': 5
                },
                'ml_model': {
                    'weight': 0.4,
                    'contamination': 0.05,
                    'n_estimators': 150
                },
                'rules': {
                    'weight': 0.6
                },
                'thresholds': {
                    'critical_risk': 90,
                    'high_risk': 70,
                    'medium_risk': 40
                }
            }

    def get(self, key: str, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default
