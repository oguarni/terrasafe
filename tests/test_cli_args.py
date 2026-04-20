"""Tests for CLI argument parsing, exit codes, and output-format purity."""
import io
import json
import sys
from unittest.mock import patch

import pytest


pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helper for --fix tests: run CLI with the real fixer (no scanner needed)
# ---------------------------------------------------------------------------

def _run_fix_cli(argv):
    from terrasafe import cli

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    with patch.object(sys, 'argv', ['terrasafe'] + argv), \
         patch('sys.stdout', stdout_buf), \
         patch('sys.stderr', stderr_buf):
        try:
            cli.main()
            exit_code = 0
        except SystemExit as exc:
            exit_code = exc.code if exc.code is not None else 0
    return stdout_buf.getvalue(), stderr_buf.getvalue(), exit_code


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


# ---------------------------------------------------------------------------
# --fix flag
# ---------------------------------------------------------------------------

VULN_TF = '''
resource "aws_db_instance" "db" {
  storage_encrypted = false
}
'''


def test_fix_default_writes_fixed_sibling_file_and_leaves_input(tmp_path):
    src = tmp_path / "a.tf"
    src.write_text(VULN_TF)

    stdout, _, exit_code = _run_fix_cli([str(src), "--fix"])

    assert exit_code == 1  # changes applied
    assert "patch(es) applied" in stdout
    fixed = tmp_path / "a.fixed.tf"
    assert fixed.exists()
    assert "storage_encrypted = true" in fixed.read_text()
    assert "storage_encrypted = false" in src.read_text()


def test_fix_dry_run_shows_diff_without_writing(tmp_path):
    src = tmp_path / "a.tf"
    src.write_text(VULN_TF)

    stdout, _, exit_code = _run_fix_cli([str(src), "--fix", "--dry-run"])

    assert exit_code == 1
    assert "dry-run" in stdout
    assert "storage_encrypted = true" in stdout  # diff contents
    assert not (tmp_path / "a.fixed.tf").exists()
    assert "storage_encrypted = false" in src.read_text()


def test_fix_in_place_overwrites_input_with_backup(tmp_path):
    src = tmp_path / "a.tf"
    src.write_text(VULN_TF)

    _, _, exit_code = _run_fix_cli([str(src), "--fix", "--in-place"])

    assert exit_code == 1
    assert "storage_encrypted = true" in src.read_text()
    backup = tmp_path / "a.tf.bak"
    assert backup.exists()
    assert "storage_encrypted = false" in backup.read_text()


def test_fix_returns_zero_when_no_changes_needed(tmp_path):
    src = tmp_path / "ok.tf"
    src.write_text(
        'resource "aws_db_instance" "db" { storage_encrypted = true }\n'
        'resource "aws_cloudtrail" "t" { name = "t" s3_bucket_name = "b" }\n'
    )

    stdout, _, exit_code = _run_fix_cli([str(src), "--fix"])

    assert exit_code == 0
    assert "no remediable issues" in stdout
    assert not (tmp_path / "ok.fixed.tf").exists()


def test_fix_output_rejects_multiple_files(tmp_path):
    a = tmp_path / "a.tf"
    b = tmp_path / "b.tf"
    a.write_text(VULN_TF)
    b.write_text(VULN_TF)

    _, stderr, exit_code = _run_fix_cli(
        [str(a), str(b), "--fix", "--fix-output", str(tmp_path / "out.tf")]
    )

    assert exit_code == 2
    assert "only supports a single file" in stderr


def test_fix_output_writes_to_explicit_path_for_single_file(tmp_path):
    src = tmp_path / "a.tf"
    src.write_text(VULN_TF)
    destination = tmp_path / "patched.tf"

    stdout, _, exit_code = _run_fix_cli(
        [str(src), "--fix", "--fix-output", str(destination)]
    )

    assert exit_code == 1
    assert destination.exists()
    assert "storage_encrypted = true" in destination.read_text()
    # The original file is untouched and no .bak is created for --fix-output.
    assert "storage_encrypted = false" in src.read_text()
    assert not (tmp_path / "a.tf.bak").exists()
    assert str(destination) in stdout


def test_fix_parse_error_surfaces_exit_code_2(tmp_path):
    bad = tmp_path / "bad.tf"
    bad.write_text("definitely { not valid HCL")

    stdout, _, exit_code = _run_fix_cli([str(bad), "--fix"])

    assert exit_code == 2
    assert "❌" in stdout or "error" in stdout.lower()
