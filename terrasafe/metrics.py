"""
Prometheus metrics for TerraSafe.
Provides comprehensive monitoring and observability.
"""

import time
import functools
import asyncio
from typing import Callable, Any
import logging

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Info,
        generate_latest
    )
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False

from terrasafe.infrastructure.utils import categorize_vulnerability

logger = logging.getLogger(__name__)

if METRICS_AVAILABLE:
    # API Request Metrics
    api_requests_total = Counter(
        'terrasafe_api_requests_total',
        'Total number of API requests',
        ['method', 'endpoint', 'status']
    )

    api_request_duration_seconds = Histogram(
        'terrasafe_api_request_duration_seconds',
        'API request duration in seconds',
        ['method', 'endpoint'],
        buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
    )

    # Scan Metrics
    scans_total = Counter(
        'terrasafe_scans_total',
        'Total number of scans performed',
        ['status', 'from_cache']
    )

    scan_duration = Histogram(
        'terrasafe_scan_duration_seconds',
        'Scan duration in seconds',
        ['from_cache'],
        buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0]
    )

    scan_score = Histogram(
        'terrasafe_scan_score',
        'Security score distribution',
        buckets=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    )

    scan_file_size_bytes = Histogram(
        'terrasafe_scan_file_size_bytes',
        'File size distribution in bytes',
        buckets=[1024, 10240, 102400, 1024000, 10240000]
    )

    # Vulnerability Metrics
    vulnerabilities_detected_total = Counter(
        'terrasafe_vulnerabilities_detected_total',
        'Total number of vulnerabilities detected',
        ['severity', 'category']
    )

    vulnerabilities_per_scan = Histogram(
        'terrasafe_vulnerabilities_per_scan',
        'Number of vulnerabilities per scan',
        buckets=[0, 1, 2, 5, 10, 20, 50]
    )

    # ML Model Metrics
    ml_prediction_confidence = Histogram(
        'terrasafe_ml_prediction_confidence',
        'ML model prediction confidence',
        ['confidence_level'],
        buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    )

    ml_score_gauge = Gauge(
        'terrasafe_ml_score',
        'Latest ML model score'
    )

    # Cache Metrics
    cache_hits_total = Counter(
        'terrasafe_cache_hits_total',
        'Total number of cache hits'
    )

    cache_misses_total = Counter(
        'terrasafe_cache_misses_total',
        'Total number of cache misses'
    )

    # Database Metrics
    db_query_duration_seconds = Histogram(
        'terrasafe_db_query_duration_seconds',
        'Database query duration in seconds',
        ['operation'],
        buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
    )

    # Error Metrics
    errors_total = Counter(
        'terrasafe_errors_total',
        'Total number of errors',
        ['error_type', 'component']
    )

    # Legacy metrics for backward compatibility
    scan_counter = scans_total
    vulnerability_counter = vulnerabilities_detected_total
    risk_score_gauge = Gauge('terrasafe_last_risk_score', 'Last calculated risk score')
    ml_confidence_gauge = Gauge('terrasafe_ml_confidence', 'ML model confidence', ['level'])

else:
    logger.warning("Prometheus metrics not available. Install prometheus-client to enable metrics.")


def track_metrics(func: Callable) -> Callable:
    """
    Decorator to track metrics for a function.

    Tracks execution time and errors automatically.

    Args:
        func: Function to track

    Returns:
        Decorated function
    """
    if not METRICS_AVAILABLE:
        return func

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs) -> Any:
        start_time = time.time()

        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time

            # Track scan metrics if result is a scan result
            if isinstance(result, dict) and 'score' in result:
                _record_scan_result(result, duration)
            elif isinstance(result, tuple) and len(result) >= 1 and isinstance(result[0], dict) and 'score' in result[0]:
                _record_scan_result(result[0], duration)

            return result

        except Exception as e:
            errors_total.labels(
                error_type=type(e).__name__,
                component=func.__module__
            ).inc()
            raise

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs) -> Any:
        start_time = time.time()

        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time

            # Track scan metrics if result is a scan result
            if isinstance(result, dict) and 'score' in result:
                _record_scan_result(result, duration)
            elif isinstance(result, tuple) and len(result) >= 1 and isinstance(result[0], dict) and 'score' in result[0]:
                _record_scan_result(result[0], duration)

            return result

        except Exception as e:
            errors_total.labels(
                error_type=type(e).__name__,
                component=func.__module__
            ).inc()
            raise

    # Return appropriate wrapper based on function type
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


def _record_scan_result(result: dict, duration: float) -> None:
    """
    Record scan metrics from result dictionary.

    Args:
        result: Scan result dictionary
        duration: Scan duration
    """
    if not METRICS_AVAILABLE:
        return

    score = result.get('score', -1)
    if score == -1:
        scans_total.labels(status='error', from_cache='false').inc()
        return

    # Record successful scan
    from_cache = result.get('performance', {}).get('from_cache', False)
    scans_total.labels(status='success', from_cache=str(from_cache)).inc()

    # Record duration
    scan_duration.labels(from_cache=str(from_cache)).observe(duration)

    # Record score
    scan_score.observe(score)
    risk_score_gauge.set(score)

    # Record ML score
    ml_score = result.get('ml_score', 0)
    ml_score_gauge.set(ml_score)

    # Record confidence
    confidence = result.get('confidence', 'LOW')
    ml_confidence_gauge.labels(level=confidence).set(1)
    ml_prediction_confidence.labels(confidence_level=confidence).observe(ml_score / 100.0)

    # Record file size if available
    file_size = result.get('performance', {}).get('file_size_kb', 0) * 1024
    if file_size > 0:
        scan_file_size_bytes.observe(file_size)

    # Record vulnerabilities
    vulns = result.get('vulnerabilities', [])
    vulnerabilities_per_scan.observe(len(vulns))

    for vuln in vulns:
        severity = vuln.get('severity', 'UNKNOWN')
        category = categorize_vulnerability(vuln.get('message', ''))
        vulnerabilities_detected_total.labels(severity=severity, category=category).inc()

    # Record cache metrics
    if from_cache:
        cache_hits_total.inc()
    else:
        cache_misses_total.inc()


def record_api_request(method: str, endpoint: str, status: int, duration: float) -> None:
    """Record API request metrics."""
    if not METRICS_AVAILABLE:
        return

    api_requests_total.labels(method=method, endpoint=endpoint, status=str(status)).inc()
    api_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)


def record_db_query(operation: str, duration: float) -> None:
    """Record database query metrics."""
    if not METRICS_AVAILABLE:
        return

    db_query_duration_seconds.labels(operation=operation).observe(duration)
