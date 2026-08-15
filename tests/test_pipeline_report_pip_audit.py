"""Tests for the pip-audit parser in ``scripts/pipeline_report.py``.

The fixture is trimmed from a real ``pip-audit -f json`` run against this
repo's requirements files, including the duplicate-advisory quirk that run
exposed: starlette 0.52.1 reports PYSEC-2026-161 twice because pip-audit
matches it through more than one alias.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "pipeline_report_pa", REPO_ROOT / "scripts" / "pipeline_report.py"
)
assert _SPEC is not None and _SPEC.loader is not None
pipeline_report = importlib.util.module_from_spec(_SPEC)
sys.modules["pipeline_report_pa"] = pipeline_report
_SPEC.loader.exec_module(pipeline_report)


AUDIT_WITH_VULNS = {
    "dependencies": [
        {"name": "python-hcl2", "version": "4.3.2", "vulns": []},
        {
            "name": "starlette",
            "version": "0.52.1",
            "vulns": [
                {
                    "id": "PYSEC-2026-161",
                    "fix_versions": ["1.0.1"],
                    "aliases": ["GHSA-86qp-5c8j-p5mr", "CVE-2026-48710"],
                    "description": (
                        "Starlette reconstructs the requested URL based on the HTTP Host "
                        "request header and requested path, but does not perform any "
                        "validation of the Host header value. This allows attackers to "
                        "inject paths into the host part, prepending the actual path."
                    ),
                },
                # Same advisory, matched again through a second alias.
                {
                    "id": "PYSEC-2026-161",
                    "fix_versions": ["1.0.1"],
                    "aliases": ["CVE-2026-48710"],
                    "description": "duplicate record",
                },
                {
                    "id": "PYSEC-2026-249",
                    "fix_versions": [],
                    "aliases": [],
                    "description": "No fix published yet.",
                },
            ],
        },
    ],
    "fixes": [],
}

AUDIT_CLEAN = {
    "dependencies": [
        {"name": "python-hcl2", "version": "4.3.2", "vulns": []},
        {"name": "joblib", "version": "1.4.2", "vulns": []},
    ],
    "fixes": [],
}


def _parse(tmp_path, payload):
    path = tmp_path / "pip-audit-report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return pipeline_report.parse_pip_audit(path)


@pytest.mark.unit
def test_clean_audit_passes(tmp_path):
    section = _parse(tmp_path, AUDIT_CLEAN)

    assert section.status == "pass"
    assert section.findings == []
    assert section.metrics["dependencies_scanned"] == 2
    assert section.metrics["vulnerable_packages"] == []


@pytest.mark.unit
def test_vulnerable_dependency_fails(tmp_path):
    section = _parse(tmp_path, AUDIT_WITH_VULNS)

    assert section.status == "fail"
    assert section.metrics["vulnerable_packages"] == ["starlette"]
    assert section.metrics["dependencies_scanned"] == 2


@pytest.mark.unit
def test_duplicate_advisory_is_collapsed(tmp_path):
    """Counting raw records would overstate how much there is to fix."""
    section = _parse(tmp_path, AUDIT_WITH_VULNS)

    ids = [f["advisory_id"] for f in section.findings]
    assert ids == ["PYSEC-2026-161", "PYSEC-2026-249"]
    assert section.metrics["advisories"] == 2


@pytest.mark.unit
def test_finding_leads_with_the_fix_version(tmp_path):
    section = _parse(tmp_path, AUDIT_WITH_VULNS)
    fixable, unfixable = section.findings

    assert fixable["message"].startswith("fixed in 1.0.1 — ")
    assert fixable["package"] == "starlette==0.52.1"
    assert "CVE-2026-48710" in fixable["aliases"]
    assert unfixable["message"].startswith("no fix available — ")


@pytest.mark.unit
def test_long_description_is_trimmed_for_the_table(tmp_path):
    section = _parse(tmp_path, AUDIT_WITH_VULNS)
    message = section.findings[0]["message"]

    assert message.endswith("…")
    assert "\n" not in message
    assert len(message) < 220


@pytest.mark.unit
def test_kind_is_registered_for_the_cli(tmp_path):
    """The workflow passes --input pip-audit-json=...; it must resolve."""
    assert "pip-audit-json" in pipeline_report.PARSERS
    assert pipeline_report.KIND_LABELS["pip-audit-json"] == "pip-audit (dependency CVEs)"

    path = tmp_path / "a.json"
    path.write_text(json.dumps(AUDIT_WITH_VULNS), encoding="utf-8")
    section = pipeline_report.parse_input("pip-audit-json", path)
    assert section.label == "pip-audit (dependency CVEs)"
    assert section.status == "fail"
