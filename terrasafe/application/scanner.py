"""Scanner orchestration - Application layer"""
import time
import logging
import numpy as np
from pathlib import Path
from typing import Dict, Any, List

from ..domain.models import Vulnerability, Severity
from ..domain.security_rules import SecurityRuleEngine
from ..infrastructure.parser import HCLParser, TerraformParseError
from ..infrastructure.ml_model import MLPredictor

try:
    from terrasafe.metrics import track_metrics
except ImportError:
    # Metrics module not available (e.g., prometheus_client not installed)
    def track_metrics(func):
        """Fallback decorator when metrics are not available"""
        return func

logger = logging.getLogger(__name__)


class IntelligentSecurityScanner:
    """Orchestrates the scanning process"""

    def __init__(
        self,
        parser: HCLParser,
        rule_analyzer: SecurityRuleEngine,
        ml_predictor: MLPredictor
    ):
        self.parser = parser
        self.rule_analyzer = rule_analyzer
        self.ml_predictor = ml_predictor

    @track_metrics
    def scan(self, filepath: str) -> Dict[str, Any]:
        """Main scanning method with performance metrics and improved error handling."""
        start_time = time.time()
        try:
            tf_content, raw_content = self.parser.parse(filepath)

            vulnerabilities = self.rule_analyzer.analyze(tf_content, raw_content)

            rule_score = min(100, sum(v.points for v in vulnerabilities))

            features = self._extract_features(vulnerabilities)
            ml_score, confidence = self.ml_predictor.predict_risk(features)

            final_score = int(0.6 * rule_score + 0.4 * ml_score)

            scan_duration = round(time.time() - start_time, 3)
            file_size_kb = round(Path(filepath).stat().st_size / 1024, 2)

            return {
                'file': filepath,
                'score': final_score,
                'rule_based_score': rule_score,
                'ml_score': ml_score,
                'confidence': confidence,
                'vulnerabilities': [self._vulnerability_to_dict(v) for v in vulnerabilities],
                'summary': self._summarize_vulns(vulnerabilities),
                'features_analyzed': self._format_features(features),
                'performance': {
                    'scan_time_seconds': scan_duration,
                    'file_size_kb': file_size_kb
                }
            }
        except (TerraformParseError, FileNotFoundError) as e:
            logger.error(f"Failed to scan {filepath}: {e}")
            return {'score': -1, 'error': str(e)}
        except Exception as e:
            logger.error(f"An unexpected error occurred during scan: {e}", exc_info=True)
            return {'score': -1, 'error': f"An unexpected error occurred: {e}"}

    def _extract_features(self, vulnerabilities: List[Vulnerability]) -> np.ndarray:
        """Extract feature vector from vulnerabilities for ML model."""
        # Count unique resources from vulnerabilities, default to 5 if empty
        unique_resources = len(set(v.resource for v in vulnerabilities)) if vulnerabilities else 5

        features = {
            'open_ports': 0,
            'hardcoded_secrets': 0,
            'public_access': 0,
            'unencrypted_storage': 0,
            'total_resources': unique_resources
        }

        for vuln in vulnerabilities:
            msg = vuln.message.lower()
            if 'open security group' in msg or 'exposed to internet' in msg:
                features['open_ports'] += 1
            elif 'hardcoded' in msg or 'secret' in msg:
                features['hardcoded_secrets'] += 1
            elif 's3 bucket' in msg and 'public' in msg:
                features['public_access'] += 1
            elif 'unencrypted' in msg:
                features['unencrypted_storage'] += 1

        return np.array(list(features.values())).reshape(1, -1)

    def _summarize_vulns(self, vulns: List[Vulnerability]) -> Dict[str, int]:
        summary = {s.name.lower(): 0 for s in Severity}
        for v in vulns:
            summary[v.severity.name.lower()] += 1
        return summary

    def _format_features(self, features: np.ndarray) -> Dict[str, int]:
        feature_names = ['open_ports', 'hardcoded_secrets', 'public_access', 'unencrypted_storage', 'total_resources']
        return {name: int(val) for name, val in zip(feature_names, features[0])}

    def _vulnerability_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability dataclass to dictionary for JSON serialization."""
        return {
            'severity': vuln.severity.value,
            'points': vuln.points,
            'message': vuln.message,
            'resource': vuln.resource,
            'remediation': vuln.remediation
        }
