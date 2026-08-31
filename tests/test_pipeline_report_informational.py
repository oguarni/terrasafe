"""Tests for the informational tier in ``scripts/pipeline_report.py``.

Exercised at the CLI boundary with real files, because that is the only
surface the workflows use. The behaviour under test is what keeps the
DevSecOps PR comment meaningful: inputs that report findings by construction
(the deliberately vulnerable ``test_files/`` fixtures, base-image CVEs) must
stay visible in the report without pinning ``overall`` to "fail" forever.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "pipeline_report", REPO_ROOT / "scripts" / "pipeline_report.py"
)
assert _SPEC is not None and _SPEC.loader is not None
pipeline_report = importlib.util.module_from_spec(_SPEC)
sys.modules["pipeline_report"] = pipeline_report
_SPEC.loader.exec_module(pipeline_report)


# A scan of test_files/ as the pipeline actually reports it: vulnerable.tf is
# over threshold on purpose, so this input can never come back clean.
FIXTURE_SCAN = {
    "summary": {"total_files": 3, "passed": 2, "failed": 1, "max_score": 84},
    "results": [
        {
            "file": "test_files/vulnerable.tf",
            "score": 84,
            "vulnerabilities": [
                {
                    "severity": "CRITICAL",
                    "rule": "open_security_group",
                    "message": "SSH port 22 exposed to internet (0.0.0.0/0)",
                }
            ],
        }
    ],
}


@pytest.fixture(name="scan_input")
def _scan_input(tmp_path):
    path = tmp_path / "scan_output.json"
    path.write_text(json.dumps(FIXTURE_SCAN), encoding="utf-8")
    return path


def _run(tmp_path, scan_input, *extra):
    """Invoke the CLI and return (exit_code, metrics_dict, markdown_text)."""
    md = tmp_path / "report.md"
    metrics = tmp_path / "metrics.json"
    code = pipeline_report.main(
        [
            "--input", f"terravault-scan={scan_input}",
            "--output-md", str(md),
            "--output-json", str(metrics),
            *extra,
        ]
    )
    return code, json.loads(metrics.read_text(encoding="utf-8")), md.read_text(encoding="utf-8")


@pytest.mark.unit
def test_failing_input_is_blocking_by_default(tmp_path, scan_input):
    _, metrics, markdown = _run(tmp_path, scan_input)

    assert metrics["overall"] == "fail"
    assert metrics["checks"][0]["informational"] is False
    assert "## Failure details" in markdown


@pytest.mark.unit
def test_informational_input_does_not_decide_the_verdict(tmp_path, scan_input):
    _, metrics, markdown = _run(tmp_path, scan_input, "--informational", "terravault-scan")

    assert metrics["overall"] == "pass"
    assert "**Overall:** ✅ PASSED" in markdown
    assert "## Failure details" not in markdown


@pytest.mark.unit
def test_informational_status_stays_truthful(tmp_path, scan_input):
    """"Not gating" must not become "not reported" — the sidecar keeps `fail`."""
    _, metrics, _ = _run(tmp_path, scan_input, "--informational", "terravault-scan")

    check = metrics["checks"][0]
    assert check["status"] == "fail"
    assert check["informational"] is True
    assert check["finding_count"] == 1


@pytest.mark.unit
def test_informational_findings_are_still_rendered(tmp_path, scan_input):
    _, _, markdown = _run(tmp_path, scan_input, "--informational", "terravault-scan")

    assert "## Informational findings" in markdown
    assert "ℹ️ INFO" in markdown
    assert "SSH port 22 exposed to internet (0.0.0.0/0)" in markdown


@pytest.mark.unit
def test_fail_on_issues_ignores_informational_sections(tmp_path, scan_input):
    blocking, _, _ = _run(tmp_path, scan_input, "--fail-on-issues")
    ignored, _, _ = _run(
        tmp_path, scan_input, "--fail-on-issues", "--informational", "terravault-scan"
    )

    assert blocking == 1
    assert ignored == 0


@pytest.mark.unit
def test_unknown_informational_kind_is_rejected(tmp_path, scan_input):
    """A typo must not silently mark nothing informational and gate anyway."""
    with pytest.raises(SystemExit) as excinfo:
        _run(tmp_path, scan_input, "--informational", "trivy")  # real kind is trivy-sarif

    assert excinfo.value.code == 2
