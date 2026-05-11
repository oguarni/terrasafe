#!/usr/bin/env python3
"""Run the TerraSafe Quality Gate.

Single source of truth for CI and local runs. Executes every check and
emits a structured Markdown report at $GATE_REPORT_PATH (default:
``gate-report.md``). Exits 0 if every check passes, 1 otherwise.

Thresholds (must match CLAUDE.md health stats):
  - pytest: every test passes
  - coverage: line-rate >= 74.00 %
  - pylint: score == 10.00 / 10
  - flake8: 0 findings
  - bandit: 0 findings at -ll severity
  - mypy: 0 errors
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = Path(os.environ.get("GATE_REPORT_PATH", REPO_ROOT / "gate-report.md"))

COVERAGE_FLOOR = 74.0
PYLINT_FLOOR = 10.0
DETAIL_TAIL_CHARS = 4000


@dataclass
class CheckResult:
    name: str
    passed: bool
    summary: str
    details: str = ""


def _run(cmd: List[str]) -> Tuple[int, str]:
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _tail(text: str) -> str:
    if len(text) <= DETAIL_TAIL_CHARS:
        return text
    return "... (truncated) ...\n" + text[-DETAIL_TAIL_CHARS:]


def check_pytest() -> CheckResult:
    code, out = _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--cov=terrasafe",
            "--cov-report=xml",
            "--cov-report=term-missing",
        ]
    )
    if code != 0:
        return CheckResult("pytest", False, "Tests failed", _tail(out))
    return CheckResult("pytest", True, "All tests passed")


def check_coverage() -> CheckResult:
    xml_path = REPO_ROOT / "coverage.xml"
    if not xml_path.exists():
        return CheckResult(
            "coverage",
            False,
            "coverage.xml missing — pytest with --cov did not run",
        )
    tree = ET.parse(xml_path)
    rate = float(tree.getroot().attrib.get("line-rate", "0")) * 100
    summary = f"Line coverage {rate:.2f}% (floor {COVERAGE_FLOOR:.2f}%)"
    if rate + 1e-6 < COVERAGE_FLOOR:
        return CheckResult("coverage", False, summary)
    return CheckResult("coverage", True, summary)


def check_pylint() -> CheckResult:
    code, out = _run(
        [
            sys.executable,
            "-m",
            "pylint",
            "terrasafe/",
            "--score=y",
        ]
    )
    match = re.search(r"Your code has been rated at ([-\d\.]+)/10", out)
    if not match:
        return CheckResult(
            "pylint",
            False,
            "Could not parse pylint score",
            _tail(out),
        )
    score = float(match.group(1))
    summary = f"Pylint score {score:.2f}/10 (floor {PYLINT_FLOOR:.2f}/10)"
    if score + 1e-6 < PYLINT_FLOOR:
        return CheckResult("pylint", False, summary, _tail(out))
    if code != 0:
        return CheckResult(
            "pylint",
            False,
            f"{summary} but pylint exited {code}",
            _tail(out),
        )
    return CheckResult("pylint", True, summary)


def check_flake8() -> CheckResult:
    code, out = _run(
        [
            sys.executable,
            "-m",
            "flake8",
            "terrasafe/",
            "--max-line-length=120",
            "--exclude=__pycache__",
            "--ignore=E226,E402,E501,W503,W504",
        ]
    )
    findings = [line for line in out.splitlines() if line.strip()]
    if code != 0 or findings:
        return CheckResult(
            "flake8",
            False,
            f"{len(findings)} finding(s)",
            _tail(out),
        )
    return CheckResult("flake8", True, "0 findings")


def check_bandit() -> CheckResult:
    code, out = _run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            "terrasafe/",
            "--ini",
            ".bandit",
            "-ll",
            "-f",
            "screen",
        ]
    )
    if code != 0:
        return CheckResult(
            "bandit",
            False,
            "Findings detected at -ll severity",
            _tail(out),
        )
    return CheckResult("bandit", True, "0 findings at -ll severity")


def check_mypy() -> CheckResult:
    code, out = _run(
        [
            sys.executable,
            "-m",
            "mypy",
            "terrasafe/",
            "--ignore-missing-imports",
        ]
    )
    if code != 0:
        return CheckResult("mypy", False, "Type errors", _tail(out))
    return CheckResult("mypy", True, "0 errors")


CHECKS: List[Callable[[], CheckResult]] = [
    check_pytest,
    check_coverage,
    check_pylint,
    check_flake8,
    check_bandit,
    check_mypy,
]


def render_report(results: List[CheckResult]) -> str:
    overall_pass = all(r.passed for r in results)
    lines = [
        "# TerraSafe Quality Gate Report",
        "",
        f"**Overall:** {'PASSED ✅' if overall_pass else 'FAILED ❌'}",
        "",
        "| Check | Status | Summary |",
        "| --- | --- | --- |",
    ]
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(f"| {result.name} | {status} | {result.summary} |")
    lines.append("")

    failed = [r for r in results if not r.passed]
    if failed:
        lines.append("## Failure details")
        lines.append("")
        for result in failed:
            lines.append(f"### {result.name} — {result.summary}")
            lines.append("")
            lines.append("```")
            lines.append(result.details or "(no captured output)")
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def main() -> int:
    results: List[CheckResult] = []
    for check in CHECKS:
        marker = check.__name__.replace("check_", "")
        print(f"::group::{marker}", flush=True)
        result = check()
        status = "PASS" if result.passed else "FAIL"
        print(f"[{status}] {result.summary}", flush=True)
        results.append(result)
        print("::endgroup::", flush=True)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(render_report(results), encoding="utf-8")
    print(f"\nReport written to {REPORT_PATH}", flush=True)

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
