"""Tests for terrasafe.metrics — decorator behavior and prometheus guards."""
import asyncio
import pytest
from unittest.mock import patch

from terrasafe import metrics
from terrasafe.infrastructure.utils import categorize_vulnerability


@pytest.mark.unit
class TestTrackMetricsDecorator:
    def test_sync_function_returns_value(self):
        @metrics.track_metrics
        def fn(x):
            return x * 2
        assert fn(5) == 10

    def test_sync_function_propagates_error(self):
        @metrics.track_metrics
        def fn():
            raise ValueError("boom")
        with pytest.raises(ValueError, match="boom"):
            fn()

    @pytest.mark.asyncio
    async def test_async_function_returns_value(self):
        @metrics.track_metrics
        async def fn(x):
            await asyncio.sleep(0)
            return x * 3
        assert await fn(7) == 21

    @pytest.mark.asyncio
    async def test_async_function_propagates_error(self):
        @metrics.track_metrics
        async def fn():
            await asyncio.sleep(0)
            raise RuntimeError("async boom")
        with pytest.raises(RuntimeError, match="async boom"):
            await fn()

    def test_sync_records_scan_result(self):
        @metrics.track_metrics
        def fn():
            return {
                'score': 75, 'ml_score': 0.85, 'confidence': 'HIGH',
                'vulnerabilities': [],
                'performance': {'from_cache': False, 'file_size_kb': 10},
            }
        with patch.object(metrics, '_record_scan_result') as rec:
            fn()
            rec.assert_called_once()

    def test_decorator_noop_when_prometheus_unavailable(self):
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            @metrics.track_metrics
            def fn(x):
                return x + 1
            assert fn(5) == 6


@pytest.mark.unit
class TestRecordScanResult:
    def test_success_result_does_not_raise(self):
        metrics._record_scan_result({
            'score': 85, 'ml_score': 0.9, 'confidence': 'HIGH',
            'vulnerabilities': [{'severity': 'CRITICAL', 'message': 'Hardcoded secret'}],
            'performance': {'from_cache': False, 'file_size_kb': 20},
            'summary': {'CRITICAL': 1},
        }, 2.5)

    def test_error_result_does_not_raise(self):
        metrics._record_scan_result({'score': -1, 'error': 'Scan failed'}, 1.0)

    def test_noop_when_prometheus_unavailable(self):
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            assert metrics._record_scan_result({'score': 80}, 1.0) is None


@pytest.mark.unit
class TestCategorizeVulnerability:
    @pytest.mark.parametrize("message,expected", [
        ("Hardcoded secret detected", 'hardcoded_secret'),
        ("Open security group exposed to internet", 'open_port'),
        ("S3 bucket is public", 'public_access'),
        ("Unencrypted database storage", 'unencrypted_storage'),
        ("MFA not enabled", 'weak_authentication'),
        ("Some random issue", 'other'),
    ])
    def test_categorization(self, message, expected):
        assert categorize_vulnerability(message) == expected


@pytest.mark.unit
class TestRecordHelpers:
    def test_record_api_request_noop_without_prometheus(self):
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            assert metrics.record_api_request('GET', '/api/health', 200, 0.1) is None

    def test_record_db_query_noop_without_prometheus(self):
        with patch.object(metrics, 'METRICS_AVAILABLE', False):
            assert metrics.record_db_query('INSERT', 0.1) is None

    def test_record_api_request_does_not_raise(self):
        metrics.record_api_request('GET', '/api/scan', 200, 0.5)
        metrics.record_api_request('POST', '/api/scan', 500, 1.2)

    def test_record_db_query_does_not_raise(self):
        metrics.record_db_query('SELECT', 0.05)
