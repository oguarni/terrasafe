"""Tests for CLI argument parsing, exit codes, and output-format purity."""
import json

import pytest


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Exit codes — one parametrized test covers the full score → exit mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "score, expected_exit",
    [
        pytest.param(30, 0, id="low_risk_passes"),
        pytest.param(70, 1, id="threshold_boundary_fails"),
        pytest.param(91, 3, id="critical_risk_exits_3"),
    ],
)
def test_cli_exit_code_matches_scan_score(
    tmp_path, run_cli, scan_result_factory, score, expected_exit
):
    tf = tmp_path / "test.tf"
    tf.write_text("")
    result = scan_result_factory(score=score, filepath=str(tf))

    _, _, exit_code = run_cli([str(tf)], result)

    assert exit_code == expected_exit


def test_cli_exits_2_when_scan_returns_error_result(tmp_path, run_cli, error_result_factory):
    tf = tmp_path / "test.tf"
    tf.write_text("")
    err = error_result_factory(filepath=str(tf))

    _, _, exit_code = run_cli([str(tf)], err)

    assert exit_code == 2


def test_cli_text_output_is_human_readable_by_default(tmp_path, run_cli, scan_result_factory):
    tf = tmp_path / "test.tf"
    tf.write_text('resource "aws_s3_bucket" "x" {}')
    result = scan_result_factory(score=40, filepath=str(tf))

    stdout, _, _ = run_cli([str(tf)], result)

    assert "TerraSafe" in stdout or "Risk" in stdout


# ---------------------------------------------------------------------------
# JSON output mode
# ---------------------------------------------------------------------------

def test_json_output_is_valid_json_with_summary(tmp_path, run_cli, scan_result_factory):
    tf = tmp_path / "a.tf"
    tf.write_text("")
    result = scan_result_factory(score=50, filepath=str(tf))

    stdout, _, _ = run_cli([str(tf), "--output-format", "json"], [result])

    parsed = json.loads(stdout)
    assert "results" in parsed
    assert "summary" in parsed


def test_json_output_aggregates_multi_file_summary(tmp_path, run_cli, scan_result_factory):
    tf1 = tmp_path / "a.tf"
    tf2 = tmp_path / "b.tf"
    tf1.write_text("")
    tf2.write_text("")
    r1 = scan_result_factory(score=85, filepath=str(tf1))
    r2 = scan_result_factory(score=30, filepath=str(tf2))

    stdout, _, _ = run_cli(
        [str(tf1), str(tf2), "--output-format", "json", "--threshold", "70"],
        [r1, r2],
    )

    summary = json.loads(stdout)["summary"]
    assert summary["total_files"] == 2
    assert summary["failed"] == 1
    assert summary["passed"] == 1
    assert summary["max_score"] == 85


# ---------------------------------------------------------------------------
# SARIF output mode
# ---------------------------------------------------------------------------

def test_sarif_output_emits_schema_compliant_payload(tmp_path, run_cli, scan_result_factory):
    tf = tmp_path / "a.tf"
    tf.write_text("")
    result = scan_result_factory(score=50, filepath=str(tf))

    stdout, _, _ = run_cli([str(tf), "--output-format", "sarif"], [result])

    parsed = json.loads(stdout)
    assert parsed["version"] == "2.1.0"
    assert "runs" in parsed


# ---------------------------------------------------------------------------
# --no-history flag
# ---------------------------------------------------------------------------

def test_no_history_flag_skips_persistence_writes(tmp_path, run_cli, scan_result_factory):
    tf = tmp_path / "a.tf"
    tf.write_text("")
    result = scan_result_factory(score=30, filepath=str(tf))

    run_cli([str(tf), "--no-history"], result)

    run_cli.save_spy.assert_not_called()
