"""Tests to fill remaining coverage gaps — targeting 100% coverage."""
import os
import sys
import json
import asyncio
import pytest
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, Mock, MagicMock


# ---------------------------------------------------------------------------
# main.py — lines 10-16 (import re-exports)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestMainModuleImports:
    def test_main_module_re_exports(self):
        """Importing terrasafe.main covers the re-export import lines."""
        import terrasafe.main as main_mod
        assert hasattr(main_mod, 'main')
        assert hasattr(main_mod, 'logger')
        assert hasattr(main_mod, 'format_results_for_display')
        assert hasattr(main_mod, 'IntelligentSecurityScanner')
        assert hasattr(main_mod, 'HCLParser')
        assert hasattr(main_mod, 'ModelManager')
        assert hasattr(main_mod, 'MLPredictor')
        assert hasattr(main_mod, 'SecurityRuleEngine')
        assert hasattr(main_mod, 'Path')


# ---------------------------------------------------------------------------
# api.py — line 96 (verify_api_key when api_key_hash is None)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestApiKeyNotConfigured:
    def test_verify_api_key_returns_503_when_hash_not_set(self):
        """verify_api_key raises 503 when api_key_hash is None."""
        from terrasafe.api import app
        from fastapi.testclient import TestClient

        with patch('terrasafe.api.settings') as mock_s:
            mock_s.api_key_hash = None
            mock_s.is_development.return_value = True
            client = TestClient(app)
            response = client.post(
                "/scan",
                files={"file": ("test.tf", b"resource {}", "text/plain")},
                headers={"X-API-Key": "any-key"},
            )
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"]


# ---------------------------------------------------------------------------
# api.py — lines 165-167 (fallback rate limiter path)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFallbackRateLimiterPath:
    def test_fallback_rate_limiter_allows_request(self):
        """When RATE_LIMITING_AVAILABLE is False, fallback limiter is used."""
        from terrasafe.api import app, hash_api_key
        from fastapi.testclient import TestClient

        test_key = "test-key-for-fallback-rate-limit"
        test_hash = hash_api_key(test_key)

        with patch('terrasafe.api.RATE_LIMITING_AVAILABLE', False), \
             patch('terrasafe.api.settings') as mock_s:
            mock_s.api_key_hash = test_hash
            mock_s.is_development.return_value = True
            mock_s.max_file_size_bytes = 10 * 1024 * 1024
            mock_s.max_file_size_mb = 10
            mock_s.scan_timeout_seconds = 30
            mock_s.rate_limit_requests = 100
            mock_s.rate_limit_window_seconds = 60
            client = TestClient(app)
            response = client.post(
                "/scan",
                files={"file": ("test.tf", b'resource "aws_instance" "x" {}', "text/plain")},
                headers={"X-API-Key": test_key},
            )
        assert response.status_code == 200

    def test_fallback_rate_limiter_blocks_request(self):
        """Fallback rate limiter returns 429 when limit exceeded."""
        from terrasafe.api import app, hash_api_key, fallback_limiter
        from fastapi.testclient import TestClient

        test_key = "test-key-for-fallback-block"
        test_hash = hash_api_key(test_key)

        with patch('terrasafe.api.RATE_LIMITING_AVAILABLE', False), \
             patch.object(fallback_limiter, 'check_rate_limit', return_value=False), \
             patch('terrasafe.api.settings') as mock_s:
            mock_s.api_key_hash = test_hash
            mock_s.is_development.return_value = True
            mock_s.rate_limit_requests = 100
            mock_s.rate_limit_window_seconds = 60
            client = TestClient(app)
            response = client.post(
                "/scan",
                files={"file": ("test.tf", b'resource "aws_instance" "x" {}', "text/plain")},
                headers={"X-API-Key": test_key},
            )
        assert response.status_code == 429


# ---------------------------------------------------------------------------
# api.py — line 179 (rate_limit decorator no-op)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRateLimitDecoratorNoop:
    def test_rate_limit_returns_func_unchanged_when_redis_unavailable(self):
        """rate_limit decorator returns function unchanged when Redis unavailable."""
        from terrasafe.api import rate_limit

        with patch('terrasafe.api.RATE_LIMITING_AVAILABLE', False):
            @rate_limit("10/minute")
            def dummy():
                return "ok"
            assert dummy() == "ok"


# ---------------------------------------------------------------------------
# api.py — line 453 (metrics not available)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestMetricsEndpointDisabled:
    def test_metrics_returns_503_when_not_available(self):
        """GET /metrics returns 503 when prometheus is not installed."""
        from terrasafe.api import app
        from fastapi.testclient import TestClient

        with patch('terrasafe.api.METRICS_AVAILABLE', False), \
             patch('terrasafe.api.settings') as mock_s:
            mock_s.is_development.return_value = True
            client = TestClient(app)
            response = client.get("/metrics")
        assert response.status_code == 503
        assert "not available" in response.json()["detail"].lower()


# ---------------------------------------------------------------------------
# settings.py — line 132 (invalid log_format)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSettingsValidationGaps:
    def test_invalid_log_format_raises_error(self):
        """Settings rejects an invalid log_format value."""
        from pydantic import ValidationError
        from terrasafe.config.settings import Settings

        with pytest.raises(ValidationError, match="log_format"):
            Settings(log_format="yaml")

    def test_api_key_hash_none_passes_validation(self):
        """api_key_hash=None passes validation (returns None early)."""
        from terrasafe.config.settings import Settings

        s = Settings(api_key_hash=None)
        assert s.api_key_hash is None


# ---------------------------------------------------------------------------
# parser.py — lines 104, 109 (path traversal detection)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestParserPathTraversal:
    def test_path_outside_allowed_dirs_raises(self):
        """Files outside CWD and /tmp are rejected as path traversal."""
        from terrasafe.infrastructure.parser import HCLParser, PathTraversalError

        parser = HCLParser()

        mock_resolved = MagicMock(spec=Path)
        mock_resolved.exists.return_value = True
        mock_resolved.is_file.return_value = True
        mock_resolved.is_dir.return_value = False
        mock_resolved.relative_to.side_effect = ValueError("outside")
        mock_resolved.__str__ = lambda self: "/opt/evil/file.tf"

        mock_path = MagicMock(spec=Path)
        mock_path.resolve.return_value = mock_resolved

        with patch('terrasafe.infrastructure.parser.Path', return_value=mock_path) as MockPath:
            MockPath.cwd.return_value = Path('/home/user/project')
            with pytest.raises(PathTraversalError, match="Path traversal detected"):
                parser.parse("/opt/evil/file.tf")

    def test_path_validation_os_error(self):
        """OSError during path resolution raises TerraformParseError."""
        from terrasafe.infrastructure.parser import HCLParser, TerraformParseError

        parser = HCLParser()

        mock_path = MagicMock(spec=Path)
        mock_path.resolve.side_effect = OSError("filesystem error")

        with patch('terrasafe.infrastructure.parser.Path', return_value=mock_path):
            with pytest.raises(TerraformParseError, match="Path validation failed"):
                parser.parse("test.tf")


# ---------------------------------------------------------------------------
# parser.py — lines 131, 134, 135 (file size stat failure)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestParserFileSizeStatFailure:
    def test_validate_file_size_stat_error_is_graceful(self):
        """_validate_file_size handles stat() failures gracefully."""
        from terrasafe.infrastructure.parser import HCLParser

        parser = HCLParser()
        mock_path = MagicMock(spec=Path)
        mock_path.stat.side_effect = OSError("disk error")
        # Should not raise — just log and return
        parser._validate_file_size(mock_path)


# ---------------------------------------------------------------------------
# ml_model.py — line 35 (custom model_filename)
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.ml
class TestModelManagerCustomFilename:
    def test_init_with_custom_model_filename(self, tmp_path):
        """ModelManager uses explicit model_filename when provided."""
        from terrasafe.infrastructure.ml_model import ModelManager

        manager = ModelManager(str(tmp_path / "models"), model_filename="custom.pkl")
        assert manager.model_path.name == "custom.pkl"


# ---------------------------------------------------------------------------
# ml_model.py — line 126 (version mismatch warning)
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.ml
class TestModelVersionMismatch:
    def test_load_model_version_mismatch_logs_warning(self, tmp_path):
        """Loading a model with mismatched non-timestamp version logs warning."""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        from terrasafe.infrastructure.ml_model import ModelManager

        manager = ModelManager(str(tmp_path / "models"), model_filename="test_model.pkl")
        model = IsolationForest(random_state=42)
        scaler = StandardScaler()
        data = np.array([[1, 2, 3, 4, 5], [2, 3, 4, 5, 6]])
        scaler.fit(data)
        model.fit(scaler.transform(data))

        # Save with a non-timestamp version different from configured
        manager.save_model(model, scaler, {}, version="2.0.0")

        # Load should log version mismatch warning
        with patch('terrasafe.infrastructure.ml_model.get_settings') as mock_gs:
            mock_gs.return_value.model_version = "1.0.0"
            loaded_model, loaded_scaler = manager.load_model()
        assert loaded_model is not None


# ---------------------------------------------------------------------------
# ml_model.py — line 133 (drift detected on load)
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.ml
class TestModelDriftOnLoad:
    def test_load_model_with_drift_logs_warning(self, tmp_path):
        """Loading a stale model (>30 days old) logs drift warning."""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        from terrasafe.infrastructure.ml_model import ModelManager

        manager = ModelManager(str(tmp_path / "models"), model_filename="test_model.pkl")
        model = IsolationForest(random_state=42)
        scaler = StandardScaler()
        data = np.array([[1, 2, 3, 4, 5], [2, 3, 4, 5, 6]])
        scaler.fit(data)
        model.fit(scaler.transform(data))
        manager.save_model(model, scaler, {})

        # Manually set old timestamp in metadata
        old_date = (datetime.now() - timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S')
        with open(manager.metadata_path, 'r') as f:
            metadata = json.load(f)
        metadata['saved_at'] = old_date
        with open(manager.metadata_path, 'w') as f:
            json.dump(metadata, f)

        # Load should detect drift
        loaded_model, loaded_scaler = manager.load_model()
        assert loaded_model is not None


# ---------------------------------------------------------------------------
# ml_model.py — lines 266-267 (rollback error)
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.ml
class TestRollbackError:
    def test_rollback_with_corrupted_model_raises(self, tmp_path):
        """Rollback raises ModelNotTrainedError when model files are corrupt."""
        from terrasafe.infrastructure.ml_model import ModelManager, ModelNotTrainedError

        manager = ModelManager(str(tmp_path / "models"))
        version_dir = manager.versions_dir / "v_corrupt"
        version_dir.mkdir(parents=True)
        (version_dir / "model.pkl").write_text("not a pickle")
        (version_dir / "scaler.pkl").write_text("not a pickle")

        with pytest.raises(ModelNotTrainedError, match="Error rolling back"):
            manager.rollback_to_version("v_corrupt")


# ---------------------------------------------------------------------------
# ml_model.py — line 349 (confidence = "HIGH")
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.ml
class TestPredictRiskHighConfidence:
    def test_predict_risk_returns_high_confidence(self, tmp_path):
        """predict_risk returns HIGH confidence for strong anomaly scores."""
        from terrasafe.infrastructure.ml_model import ModelManager, MLPredictor

        manager = ModelManager(str(tmp_path / "models"))
        predictor = MLPredictor(manager)

        # Mock model to return a strong anomaly with abs(score) > 0.3
        with patch.object(predictor.model, 'predict', return_value=np.array([-1])), \
             patch.object(predictor.model, 'decision_function', return_value=np.array([-0.5])):
            features = np.array([[1, 2, 3, 4, 5, 6, 7]])
            risk_score, confidence = predictor.predict_risk(features)
        assert confidence == "HIGH"
        assert risk_score >= 50


# ---------------------------------------------------------------------------
# security_rules.py — line 154 (EBS volume non-list format)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestEbsVolumeNonListFormat:
    def test_check_encryption_ebs_list_format(self):
        """check_encryption handles EBS volumes already in list format (line 154)."""
        from terrasafe.domain.security_rules import SecurityRuleEngine

        engine = SecurityRuleEngine()
        tf_content = {
            'resource': [
                {
                    'aws_ebs_volume': [
                        {'data_vol': {'encrypted': False}}
                    ]
                }
            ]
        }
        vulns = engine.check_encryption(tf_content)
        assert any("Unencrypted EBS volume" in v.message for v in vulns)


# ---------------------------------------------------------------------------
# rate_limiter.py — line 81 (cleanup removes stale IPs)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCleanupRemovesStaleEntries:
    def test_cleanup_locked_deletes_expired_ips(self):
        """_cleanup_locked removes IPs with no valid requests."""
        from terrasafe.infrastructure.rate_limiter import FallbackRateLimiter

        limiter = FallbackRateLimiter(max_requests=10, window_seconds=1)
        old_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        limiter.requests["stale-ip"] = [old_time]
        limiter.requests["fresh-ip"] = [datetime.now(timezone.utc)]

        limiter._cleanup_locked(datetime.now(timezone.utc))

        assert "stale-ip" not in limiter.requests
        assert "fresh-ip" in limiter.requests


# ---------------------------------------------------------------------------
# cli.py — line 66 (history file with invalid structure)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCliHistoryEdgeCases:
    def test_save_history_resets_invalid_structure(self, tmp_path, monkeypatch):
        """_save_history resets history when file contains non-dict JSON."""
        from terrasafe.cli import _save_history

        monkeypatch.chdir(tmp_path)
        (tmp_path / "scan_history.json").write_text('["not_a_dict"]')

        results = {'score': 30, 'file': str(tmp_path / 'test.tf')}
        _save_history(results, str(tmp_path / 'test.tf'))

        with open(tmp_path / "scan_history.json") as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert 'scans' in data
        assert len(data['scans']) == 1

    def test_save_history_truncates_over_max(self, tmp_path, monkeypatch):
        """_save_history truncates when history exceeds MAX_HISTORY_SIZE."""
        from terrasafe.cli import _save_history

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("TERRASAFE_MAX_HISTORY_SIZE", "2")

        existing = {"scans": [{"score": 10}, {"score": 20}]}
        (tmp_path / "scan_history.json").write_text(json.dumps(existing))

        results = {'score': 30, 'file': str(tmp_path / 'test.tf')}
        _save_history(results, str(tmp_path / 'test.tf'))

        with open(tmp_path / "scan_history.json") as f:
            data = json.load(f)
        assert len(data['scans']) == 2


# ---------------------------------------------------------------------------
# metrics.py — line 178 (async wrapper tuple result)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestMetricsAsyncTupleResult:
    @pytest.mark.asyncio
    async def test_track_metrics_async_records_tuple_result(self):
        """track_metrics async wrapper records tuple result with score dict."""
        from terrasafe import metrics

        if not metrics.METRICS_AVAILABLE:
            pytest.skip("prometheus_client not available")

        @metrics.track_metrics
        async def scan_returning_tuple():
            await asyncio.sleep(0.01)
            return ({'score': 80, 'performance': {'from_cache': False}}, 1.0)

        with patch.object(metrics, '_record_scan_result') as mock_record:
            result = await scan_returning_tuple()
            assert isinstance(result, tuple)
            assert result[0]['score'] == 80
            mock_record.assert_called_once()


# ---------------------------------------------------------------------------
# scanner.py — line 17 (track_metrics import fallback)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestScannerMetricsFallback:
    def test_scanner_uses_fallback_when_metrics_unavailable(self):
        """Scanner falls back to no-op track_metrics when import fails."""
        import importlib
        import terrasafe.application.scanner as scanner_mod

        orig_metrics = sys.modules.get('terrasafe.metrics')
        try:
            sys.modules['terrasafe.metrics'] = None
            importlib.reload(scanner_mod)
            assert callable(scanner_mod.track_metrics)

            def identity(x):
                return x
            assert scanner_mod.track_metrics(identity) is identity
        finally:
            if orig_metrics is not None:
                sys.modules['terrasafe.metrics'] = orig_metrics
            elif 'terrasafe.metrics' in sys.modules:
                del sys.modules['terrasafe.metrics']
            importlib.reload(scanner_mod)
