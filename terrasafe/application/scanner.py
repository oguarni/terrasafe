"""Scanner orchestration - Application layer with optimized caching"""
import time
import logging
import numpy as np
from pathlib import Path
import hashlib
from functools import lru_cache
from typing import Dict, Any, List, Tuple

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

# Scoring weights for combining rule-based and ML-based scores
# These are exported for use in tests to avoid hardcoding magic numbers
RULE_WEIGHT = 0.6  # 60% weight for rule-based analysis
ML_WEIGHT = 0.4    # 40% weight for ML-based analysis


class IntelligentSecurityScanner:
    """
    Orchestrates the scanning process with optimized caching and feature extraction.

    Improvements:
    - LRU cache with size limit (max 100 entries)
    - Vectorized feature extraction using numpy
    - Better memory management
    """

    def __init__(
        self,
        parser: HCLParser,
        rule_analyzer: SecurityRuleEngine,
        ml_predictor: MLPredictor,
    ):
        self.parser = parser
        self.rule_analyzer = rule_analyzer
        self.ml_predictor = ml_predictor

    @lru_cache(maxsize=100)
    def _get_file_hash_cached(self, filepath: str, mtime: float) -> str:
        """
        Generate hash of file content for caching.
        LRU cached with mtime as part of key to invalidate on file changes.

        Args:
            filepath: Path to file
            mtime: File modification time (for cache invalidation)

        Returns:
            SHA-256 hash of file content
        """
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _get_file_hash(self, filepath: str) -> str:
        """
        Get file hash using cached method.

        Args:
            filepath: Path to file

        Returns:
            SHA-256 hash of file content
        """
        try:
            mtime = Path(filepath).stat().st_mtime
            return self._get_file_hash_cached(filepath, mtime)
        except Exception as e:
            logger.warning(f"Failed to get file hash for {filepath}: {e}")
            # Fallback to direct hash without caching
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()

    @track_metrics
    @lru_cache(maxsize=100)
    def _scan_cached(self, filepath: str, file_hash: str, mtime: float) -> Tuple[Dict[str, Any], float]:
        """
        Cached scan implementation.
        Uses LRU cache with file hash and mtime to invalidate on changes.

        Args:
            filepath: Path to file
            file_hash: Hash of file content
            mtime: File modification time

        Returns:
            Tuple of (scan_result, scan_time)
        """
        start_time = time.time()

        tf_content, raw_content = self.parser.parse(filepath)

        vulnerabilities = self.rule_analyzer.analyze(tf_content, raw_content)

        rule_score = min(100, sum(v.points for v in vulnerabilities))

        features = self._extract_features(vulnerabilities)
        # Validate features to prevent model poisoning
        validated_features = self._validate_features(features)
        ml_score, confidence = self.ml_predictor.predict_risk(validated_features)

        final_score = int(RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score)

        scan_duration = round(time.time() - start_time, 3)

        result = {
            'file': filepath,
            'score': final_score,
            'rule_based_score': rule_score,
            'ml_score': ml_score,
            'confidence': confidence,
            'vulnerabilities': [self._vulnerability_to_dict(v) for v in vulnerabilities],
            'summary': self._summarize_vulns(vulnerabilities),
            'features_analyzed': self._format_features(validated_features),
        }

        return result, scan_duration

    def scan(self, filepath: str) -> Dict[str, Any]:
        """
        Main scanning method with performance metrics and improved error handling.

        Uses LRU cache to avoid re-scanning unchanged files.
        """
        start_time = time.time()

        try:
            # Get file metadata for cache validation
            file_stat = Path(filepath).stat()
            file_size_kb = round(file_stat.st_size / 1024, 2)
            mtime = file_stat.st_mtime

            # Get file hash for cache key
            file_hash = self._get_file_hash(filepath)

            # Try cached scan
            try:
                result, cached_scan_duration = self._scan_cached(filepath, file_hash, mtime)
                logger.info(f"Scan completed for {filepath} (cached: {cached_scan_duration}s)")

                # Add performance metrics
                result['performance'] = {
                    'scan_time_seconds': cached_scan_duration,
                    'file_size_kb': file_size_kb,
                    'from_cache': True
                }

                return result
            except Exception as cache_error:
                logger.warning(f"Cache error, performing direct scan: {cache_error}")
                # Fall through to direct scan

            # Direct scan without cache
            result, scan_duration = self._scan_cached.__wrapped__(
                self, filepath, file_hash, mtime
            )

            result['performance'] = {
                'scan_time_seconds': scan_duration,
                'file_size_kb': file_size_kb,
                'from_cache': False
            }

            return result
        except TerraformParseError as e:
            logger.error(f"Parse error scanning {filepath}: {e}")
            return {
                'score': -1,
                'error': f"Parse error: {str(e)}",
                'error_type': 'TerraformParseError',
                'file': filepath
            }
        except FileNotFoundError as e:
            logger.error(f"File not found: {filepath}")
            return {
                'score': -1,
                'error': f"File not found: {filepath}. Please verify the file path exists.",
                'error_type': 'FileNotFoundError',
                'file': filepath
            }
        except PermissionError as e:
            logger.error(f"Permission denied accessing {filepath}: {e}")
            return {
                'score': -1,
                'error': f"Permission denied: Cannot access {filepath}. Check file permissions.",
                'error_type': 'PermissionError',
                'file': filepath
            }
        except Exception as e:
            logger.error(f"Unexpected error scanning {filepath}: {type(e).__name__} - {e}", exc_info=True)
            return {
                'score': -1,
                'error': f"Unexpected {type(e).__name__} error during scan: {str(e)}",
                'error_type': type(e).__name__,
                'file': filepath
            }

    def _validate_features(self, features: np.ndarray) -> np.ndarray:
        """
        Validate and sanitize ML features to prevent model poisoning.

        Args:
            features: Feature array to validate

        Returns:
            Validated feature array with values clipped to acceptable bounds
        """
        # Define acceptable bounds for each feature
        # [open_ports, hardcoded_secrets, public_access, unencrypted_storage, total_resources]
        min_bounds = np.array([0, 0, 0, 0, 0], dtype=np.int32)
        max_bounds = np.array([100, 100, 100, 100, 10000], dtype=np.int32)

        # Clip features to acceptable ranges
        validated = np.clip(features, min_bounds, max_bounds)

        # Log if any features were out of bounds
        if not np.array_equal(features, validated):
            logger.warning(
                f"Features out of bounds detected - Original: {features[0]}, "
                f"Validated: {validated[0]}"
            )

        return validated

    def _extract_features(self, vulnerabilities: List[Vulnerability]) -> np.ndarray:
        """
        Extract feature vector from vulnerabilities for ML model.
        Optimized with vectorized operations and efficient pattern matching.

        Args:
            vulnerabilities: List of detected vulnerabilities

        Returns:
            Numpy array of features (shape: 1x5)
        """
        if not vulnerabilities:
            # Return default feature vector for empty vulnerability list
            return np.array([[0, 0, 0, 0, 1]], dtype=np.int32)

        # Count unique resources
        unique_resources = len(set(v.resource for v in vulnerabilities))

        # Vectorized approach: convert all messages to lowercase once
        messages = np.array([v.message.lower() for v in vulnerabilities])

        # Use vectorized string operations for pattern matching
        # This is more efficient than loop-based approach for larger datasets
        open_ports_mask = np.char.find(messages, 'open security group') >= 0
        open_ports_mask |= np.char.find(messages, 'exposed to internet') >= 0

        hardcoded_mask = np.char.find(messages, 'hardcoded') >= 0
        hardcoded_mask |= np.char.find(messages, 'secret') >= 0

        s3_mask = np.char.find(messages, 's3 bucket') >= 0
        public_mask = np.char.find(messages, 'public') >= 0
        public_access_mask = s3_mask & public_mask

        unencrypted_mask = np.char.find(messages, 'unencrypted') >= 0

        # Count matches using numpy sum (faster than Python loops)
        features = np.array([
            np.sum(open_ports_mask),
            np.sum(hardcoded_mask),
            np.sum(public_access_mask),
            np.sum(unencrypted_mask),
            unique_resources
        ], dtype=np.int32).reshape(1, -1)

        return features

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
