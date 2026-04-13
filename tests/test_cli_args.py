"""Tests for CLI argument parsing, exit codes, and output format purity."""
import json
import os
import sys
import pytest

# env vars must be set before any terrasafe import (conftest handles it)
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan_result(score=50, filepath="test.tf"):
    return {
        "file": filepath,
        "score": score,
        "rule_based_score": score,
        "ml_score": float(score),
        "confidence": "HIGH",
        "vulnerabilities": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "features_analyzed": {
            "open_ports": 0, "hardcoded_secrets": 0,
            "public_access": 0, "unencrypted_storage": 0, "total_resources": 1,
        },
        "performance": {"scan_time_seconds": 0.1, "file_size_kb": 1.0, "from_cache": False},
    }


def _make_error_result(filepath="bad.tf"):
    return {"score": -1, "error": "Parse error", "file": filepath}


def _run_cli(argv, mock_results):
    """
    Invoke cli.main() with patched argv and scanner, capture stdout/stderr
    and the SystemExit code.
    """
    import io
    from terrasafe import cli

    mock_scanner = MagicMock()

    if isinstance(mock_results, list):
        mock_scanner.scan.side_effect = mock_results
    else:
        mock_scanner.scan.return_value = mock_results

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    with patch.object(sys, 'argv', ['terrasafe'] + argv), \
         patch.object(cli, '_build_scanner', return_value=mock_scanner), \
         patch('sys.stdout', stdout_buf), \
         patch('sys.stderr', stderr_buf):
        try:
            cli.main()
            exit_code = 0
        except SystemExit as e:
            exit_code = e.code if e.code is not None else 0

    return stdout_buf.getvalue(), stderr_buf.getvalue(), exit_code


# ---------------------------------------------------------------------------
# Argparse defaults and backward compat
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestArgparseDefaults:
    def test_single_file_no_flags_runs(self, tmp_path):
        tf = tmp_path / "test.tf"
        tf.write_text('resource "aws_s3_bucket" "x" {}')
        result = _make_scan_result(score=40, filepath=str(tf))
        with patch('terrasafe.cli._save_history'):
            stdout, _, code = _run_cli([str(tf)], result)
        # Text mode: human-readable output expected
        assert "TerraSafe" in stdout or "Risk" in stdout

    def test_default_threshold_is_70(self, tmp_path):
        tf = tmp_path / "test.tf"
        tf.write_text("")
        result = _make_scan_result(score=69, filepath=str(tf))
        with patch('terrasafe.cli._save_history'):
            _, _, code = _run_cli([str(tf)], result)
        assert code == 0  # 69 < 70 → pass

    def test_default_threshold_at_boundary(self, tmp_path):
        tf = tmp_path / "test.tf"
        tf.write_text("")
        result = _make_scan_result(score=70, filepath=str(tf))
        with patch('terrasafe.cli._save_history'):
            _, _, code = _run_cli([str(tf)], result)
        assert code == 1  # 70 >= 70 → fail

    def test_critical_score_exit_3(self, tmp_path):
        tf = tmp_path / "test.tf"
        tf.write_text("")
        result = _make_scan_result(score=91, filepath=str(tf))
        with patch('terrasafe.cli._save_history'):
            _, _, code = _run_cli([str(tf)], result)
        assert code == 3

    def test_error_result_exit_2(self, tmp_path):
        tf = tmp_path / "test.tf"
        tf.write_text("")
        err = _make_error_result(filepath=str(tf))
        with patch('terrasafe.cli._save_history'):
            _, _, code = _run_cli([str(tf)], err)
        assert code == 2


# ---------------------------------------------------------------------------
# --output-format json
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestJsonOutput:
    def test_stdout_is_valid_json(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=50, filepath=str(tf))
        stdout, _, _ = _run_cli([str(tf), "--output-format", "json"], [result])
        parsed = json.loads(stdout)
        assert "results" in parsed
        assert "summary" in parsed

    def test_summary_fields(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=50, filepath=str(tf))
        stdout, _, _ = _run_cli([str(tf), "--output-format", "json"], [result])
        summary = json.loads(stdout)["summary"]
        assert summary["total_files"] == 1
        assert "passed" in summary
        assert "failed" in summary
        assert "max_score" in summary
        assert "threshold" in summary

    def test_json_exit_0_below_threshold(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=30, filepath=str(tf))
        _, _, code = _run_cli([str(tf), "--output-format", "json", "--threshold", "70"], [result])
        assert code == 0

    def test_json_exit_1_at_threshold(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=70, filepath=str(tf))
        _, _, code = _run_cli([str(tf), "--output-format", "json", "--threshold", "70"], [result])
        assert code == 1

    def test_json_exit_2_on_error(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        err = _make_error_result(filepath=str(tf))
        _, _, code = _run_cli([str(tf), "--output-format", "json"], [err])
        assert code == 2

    def test_multi_file_aggregated_summary(self, tmp_path):
        tf1 = tmp_path / "a.tf"
        tf2 = tmp_path / "b.tf"
        tf1.write_text("")
        tf2.write_text("")
        r1 = _make_scan_result(score=85, filepath=str(tf1))
        r2 = _make_scan_result(score=30, filepath=str(tf2))
        stdout, _, _ = _run_cli(
            [str(tf1), str(tf2), "--output-format", "json", "--threshold", "70"],
            [r1, r2],
        )
        data = json.loads(stdout)
        assert data["summary"]["total_files"] == 2
        assert data["summary"]["failed"] == 1
        assert data["summary"]["passed"] == 1
        assert data["summary"]["max_score"] == 85

# ---------------------------------------------------------------------------
# --output-format sarif
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestSarifOutput:
    def test_stdout_is_valid_sarif_json(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=50, filepath=str(tf))
        stdout, _, _ = _run_cli([str(tf), "--output-format", "sarif"], [result])
        parsed = json.loads(stdout)
        assert parsed["version"] == "2.1.0"
        assert "runs" in parsed

    def test_sarif_exit_0_below_threshold(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=30, filepath=str(tf))
        _, _, code = _run_cli([str(tf), "--output-format", "sarif", "--threshold", "70"], [result])
        assert code == 0

    def test_sarif_exit_1_above_threshold(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=80, filepath=str(tf))
        _, _, code = _run_cli([str(tf), "--output-format", "sarif", "--threshold", "70"], [result])
        assert code == 1


# ---------------------------------------------------------------------------
# --no-history
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestNoHistory:
    def test_no_history_skips_file_writes(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=30, filepath=str(tf))

        with patch('terrasafe.cli._save_history') as mock_save:
            _run_cli([str(tf), "--no-history"], result)
            mock_save.assert_not_called()

    def test_without_no_history_writes_files(self, tmp_path):
        tf = tmp_path / "a.tf"
        tf.write_text("")
        result = _make_scan_result(score=30, filepath=str(tf))

        with patch('terrasafe.cli._save_history') as mock_save:
            _run_cli([str(tf)], result)
            mock_save.assert_called_once()
