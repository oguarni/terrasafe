"""Prometheus metrics for TerraSafe"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from functools import wraps
import time

# Define metrics
scan_counter = Counter('terrasafe_scans_total', 'Total number of scans performed')
scan_duration = Histogram('terrasafe_scan_duration_seconds', 'Scan duration in seconds')
vulnerability_counter = Counter('terrasafe_vulnerabilities_total', 'Total vulnerabilities found', ['severity'])
risk_score_gauge = Gauge('terrasafe_last_risk_score', 'Last calculated risk score')
ml_confidence_gauge = Gauge('terrasafe_ml_confidence', 'ML model confidence', ['level'])


def track_metrics(func):
    """Decorator to track scan metrics"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()

        # Execute scan
        results = func(*args, **kwargs)

        # Update metrics
        duration = time.time() - start_time
        scan_counter.inc()
        scan_duration.observe(duration)

        if results.get('score', -1) != -1:
            risk_score_gauge.set(results['score'])

            # Count vulnerabilities by severity
            if 'summary' in results:
                for severity, count in results['summary'].items():
                    vulnerability_counter.labels(severity=severity).inc(count)

            # Track ML confidence
            confidence = results.get('confidence', 'LOW')
            ml_confidence_gauge.labels(level=confidence).set(1)

        return results
    return wrapper
