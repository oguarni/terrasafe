"""
Integration tests for terrasafe.metrics module.

These tests verify the metrics collection functionality including:
- Metric decorators
- Counter increments
- Histogram recordings
- Gauge updates
- Metrics export
- Track metrics decorator for sync and async functions
"""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, patch
import time

# Import the metrics module
from terrasafe import metrics
from terrasafe.infrastructure.utils import categorize_vulnerability


class TestMetricsAvailability:
    """Test suite for metrics availability checks."""

    def test_metrics_available_flag(self):
        """Test that METRICS_AVAILABLE flag exists."""
        assert hasattr(metrics, 'METRICS_AVAILABLE')
        # In tests, prometheus_client should be available
        assert metrics.METRICS_AVAILABLE is True

    def test_metrics_objects_exist_when_available(self):
        """Test that metric objects exist when prometheus_client is available."""
        if metrics.METRICS_AVAILABLE:
            assert hasattr(metrics, 'api_requests_total')
            assert hasattr(metrics, 'scans_total')
            assert hasattr(metrics, 'scan_duration')
            assert hasattr(metrics, 'vulnerabilities_detected_total')
            assert hasattr(metrics, 'cache_hits_total')
            assert hasattr(metrics, 'cache_misses_total')


class TestTrackMetricsDecorator:
    """Test suite for track_metrics decorator."""

    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        """Reset metrics before each test."""
        # Import prometheus registry for cleanup if needed
        yield
        # Cleanup after test

    def test_track_metrics_sync_function_success(self):
        """Test track_metrics decorator with synchronous function."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        @metrics.track_metrics
        def sample_function(x):
            return x * 2

        result = sample_function(5)

        assert result == 10

    def test_track_metrics_sync_function_with_scan_result(self):
        """Test track_metrics decorator recording scan results."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        @metrics.track_metrics
        def scan_function():
            return {
                'score': 75,
                'ml_score': 0.85,
                'confidence': 'HIGH',
                'vulnerabilities': [],
                'performance': {
                    'from_cache': False,
                    'file_size_kb': 10
                }
            }

        # Mock the _record_scan_result function
        with patch.object(metrics, '_record_scan_result') as mock_record:
            result = scan_function()

            assert result['score'] == 75
            # Verify _record_scan_result was called
            mock_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_track_metrics_async_function_success(self):
        """Test track_metrics decorator with asynchronous function."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        @metrics.track_metrics
        async def async_sample_function(x):
            await asyncio.sleep(0.01)
            return x * 3

        result = await async_sample_function(7)

        assert result == 21

    @pytest.mark.asyncio
    async def test_track_metrics_async_function_with_scan_result(self):
        """Test track_metrics decorator recording async scan results."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        @metrics.track_metrics
        async def async_scan_function():
            await asyncio.sleep(0.01)
            return {
                'score': 90,
                'ml_score': 0.95,
                'confidence': 'VERY_HIGH',
                'vulnerabilities': [],
                'performance': {
                    'from_cache': True,
                    'file_size_kb': 5
                }
            }

        with patch.object(metrics, '_record_scan_result') as mock_record:
            result = await async_scan_function()

            assert result['score'] == 90
            mock_record.assert_called_once()

    def test_track_metrics_sync_function_with_error(self):
        """Test track_metrics decorator handling errors in sync functions."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        @metrics.track_metrics
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError) as exc_info:
            failing_function()

        assert "Test error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_track_metrics_async_function_with_error(self):
        """Test track_metrics decorator handling errors in async functions."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        @metrics.track_metrics
        async def async_failing_function():
            await asyncio.sleep(0.01)
            raise RuntimeError("Async test error")

        with pytest.raises(RuntimeError) as exc_info:
            await async_failing_function()

        assert "Async test error" in str(exc_info.value)

    def test_track_metrics_without_prometheus(self):
        """Test track_metrics decorator when prometheus is not available."""
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            @metrics.track_metrics
            def simple_function(x):
                return x + 1

            result = simple_function(5)
            assert result == 6


class TestRecordScanResult:
    """Test suite for _record_scan_result function."""

    def test_record_scan_result_success(self):
        """Test recording a successful scan result."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        scan_result = {
            'score': 85,
            'ml_score': 0.9,
            'confidence': 'HIGH',
            'vulnerabilities': [
                {'severity': 'CRITICAL', 'message': 'Hardcoded secret found'},
                {'severity': 'HIGH', 'message': 'Open security group exposed'}
            ],
            'performance': {
                'from_cache': False,
                'file_size_kb': 20
            },
            'summary': {
                'CRITICAL': 1,
                'HIGH': 1
            }
        }

        # Call the function
        metrics._record_scan_result(scan_result, 2.5)

        # Verify metrics were recorded (implementation-dependent)
        # This test primarily ensures no errors are raised

    def test_record_scan_result_error_status(self):
        """Test recording a scan result with error status."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        scan_result = {
            'score': -1,
            'error': 'Scan failed'
        }

        # Should record error status
        metrics._record_scan_result(scan_result, 1.0)

    def test_record_scan_result_from_cache(self):
        """Test recording a scan result from cache."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        scan_result = {
            'score': 70,
            'ml_score': 0.75,
            'confidence': 'MEDIUM',
            'vulnerabilities': [],
            'performance': {
                'from_cache': True,
                'file_size_kb': 15
            }
        }

        metrics._record_scan_result(scan_result, 0.1)

    def test_record_scan_result_without_prometheus(self):
        """Test _record_scan_result when prometheus is not available."""
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            scan_result = {'score': 80}

            # Should return without error
            result = metrics._record_scan_result(scan_result, 1.0)
            assert result is None


class TestCategorizeVulnerability:
    """Test suite for _categorize_vulnerability function."""

    def test_categorize_hardcoded_secret(self):
        """Test categorizing hardcoded secrets."""
        category = categorize_vulnerability("Hardcoded secret detected in code")
        assert category == 'hardcoded_secret'

        category = categorize_vulnerability("Secret key found in file")
        assert category == 'hardcoded_secret'

    def test_categorize_open_port(self):
        """Test categorizing open ports."""
        category = categorize_vulnerability("Open security group rule exposed to internet")
        assert category == 'open_port'

        category = categorize_vulnerability("Security group exposed to internet")
        assert category == 'open_port'

    def test_categorize_public_access(self):
        """Test categorizing public access issues."""
        category = categorize_vulnerability("S3 bucket is public")
        assert category == 'public_access'

        category = categorize_vulnerability("Public S3 bucket detected")
        assert category == 'public_access'

    def test_categorize_unencrypted_storage(self):
        """Test categorizing unencrypted storage."""
        category = categorize_vulnerability("Unencrypted database storage")
        assert category == 'unencrypted_storage'

    def test_categorize_weak_authentication(self):
        """Test categorizing weak authentication."""
        category = categorize_vulnerability("MFA not enabled")
        assert category == 'weak_authentication'

        category = categorize_vulnerability("Weak authentication method")
        assert category == 'weak_authentication'

    def test_categorize_other(self):
        """Test categorizing unknown vulnerability types."""
        category = categorize_vulnerability("Some random issue")
        assert category == 'other'


class TestRecordApiRequest:
    """Test suite for record_api_request function."""

    def test_record_api_request_success(self):
        """Test recording a successful API request."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        metrics.record_api_request('GET', '/api/scan', 200, 0.5)

        # Verify no errors were raised

    def test_record_api_request_error(self):
        """Test recording a failed API request."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        metrics.record_api_request('POST', '/api/scan', 500, 1.2)

    def test_record_api_request_without_prometheus(self):
        """Test record_api_request when prometheus is not available."""
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            # Should return without error
            result = metrics.record_api_request('GET', '/api/health', 200, 0.1)
            assert result is None


class TestRecordDbQuery:
    """Test suite for record_db_query function."""

    def test_record_db_query_success(self):
        """Test recording a database query."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        metrics.record_db_query('SELECT', 0.05)

        # Verify no errors were raised

    def test_record_db_query_slow(self):
        """Test recording a slow database query."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        metrics.record_db_query('UPDATE', 2.5)

    def test_record_db_query_without_prometheus(self):
        """Test record_db_query when prometheus is not available."""
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            # Should return without error
            result = metrics.record_db_query('INSERT', 0.1)
            assert result is None


class TestLegacyMetrics:
    """Test suite for legacy metric compatibility."""

    def test_legacy_scan_counter_alias(self):
        """Test that legacy scan_counter is an alias for scans_total."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        assert hasattr(metrics, 'scan_counter')
        assert metrics.scan_counter is metrics.scans_total

    def test_legacy_vulnerability_counter_alias(self):
        """Test that legacy vulnerability_counter is an alias."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        assert hasattr(metrics, 'vulnerability_counter')
        assert metrics.vulnerability_counter is metrics.vulnerabilities_detected_total

    def test_legacy_risk_score_gauge_exists(self):
        """Test that legacy risk_score_gauge exists."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        assert hasattr(metrics, 'risk_score_gauge')

    def test_legacy_ml_confidence_gauge_exists(self):
        """Test that legacy ml_confidence_gauge exists."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        assert hasattr(metrics, 'ml_confidence_gauge')


class TestMetricObjects:
    """Test suite for individual metric objects."""

    def test_counter_metrics_exist(self):
        """Test that all counter metrics are defined."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        counters = [
            'api_requests_total',
            'scans_total',
            'vulnerabilities_detected_total',
            'cache_hits_total',
            'cache_misses_total',
            'errors_total'
        ]

        for counter_name in counters:
            assert hasattr(metrics, counter_name)

    def test_histogram_metrics_exist(self):
        """Test that all histogram metrics are defined."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        histograms = [
            'api_request_duration_seconds',
            'scan_duration',
            'scan_score',
            'scan_file_size_bytes',
            'vulnerabilities_per_scan',
            'ml_prediction_confidence',
            'db_query_duration_seconds'
        ]

        for histogram_name in histograms:
            assert hasattr(metrics, histogram_name)

    def test_gauge_metrics_exist(self):
        """Test that all gauge metrics are defined."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        gauges = [
            'ml_score_gauge',
            'risk_score_gauge',
            'ml_confidence_gauge'
        ]

        for gauge_name in gauges:
            assert hasattr(metrics, gauge_name)


class TestMetricsIntegration:
    """Integration tests for metrics module."""

    @pytest.mark.asyncio
    async def test_full_scan_metrics_workflow(self):
        """Test complete metrics workflow for a scan operation."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        @metrics.track_metrics
        async def perform_scan(file_path: str):
            await asyncio.sleep(0.05)
            return {
                'score': 65,
                'ml_score': 0.7,
                'confidence': 'MEDIUM',
                'vulnerabilities': [
                    {'severity': 'HIGH', 'message': 'Hardcoded password'},
                    {'severity': 'MEDIUM', 'message': 'Weak cipher'}
                ],
                'performance': {
                    'from_cache': False,
                    'file_size_kb': 25
                },
                'summary': {
                    'HIGH': 1,
                    'MEDIUM': 1
                }
            }

        result = await perform_scan('test.tf')

        assert result['score'] == 65
        assert len(result['vulnerabilities']) == 2

    def test_multiple_api_requests_tracking(self):
        """Test tracking multiple API requests."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        requests = [
            ('GET', '/api/scan', 200, 0.5),
            ('POST', '/api/scan', 201, 1.2),
            ('GET', '/api/health', 200, 0.1),
            ('GET', '/api/scan/123', 404, 0.3)
        ]

        for method, endpoint, status, duration in requests:
            metrics.record_api_request(method, endpoint, status, duration)

        # Verify no errors were raised

    def test_cache_metrics_tracking(self):
        """Test tracking cache hits and misses."""
        if not metrics.METRICS_AVAILABLE:
            pytest.skip("Prometheus metrics not available")

        # Simulate cache hit
        scan_result_cached = {
            'score': 80,
            'performance': {'from_cache': True}
        }
        metrics._record_scan_result(scan_result_cached, 0.05)

        # Simulate cache miss
        scan_result_fresh = {
            'score': 75,
            'performance': {'from_cache': False}
        }
        metrics._record_scan_result(scan_result_fresh, 1.5)
