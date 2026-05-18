#!/usr/bin/env python3
"""Consolidate CI pipeline outputs into a single AI-readable report.

Parses the raw output of multiple security/quality tools and emits:

  * a Markdown report (``--output-md``)  — human + LLM readable
  * a JSON sidecar  (``--output-json``)  — machine readable metrics

Each input is declared as ``--input <kind>=<path>``. Missing files are
recorded as a "not produced" entry; malformed files are recorded as a
"parse error" entry. The tool never aborts on a single bad input —
the goal is to produce a report even when the pipeline broke
mid-flight.

Supported kinds:

    bandit-json        Bandit ``-f json`` output
    safety-json        Safety ``check --json`` output
    gitleaks-sarif     GitLeaks SARIF output
    pytest-junit       pytest ``--junit-xml`` output
    coverage-xml       coverage.py XML report
    trivy-sarif        Trivy SARIF output
    terravault-scan    TerraVault CLI ``--output-format json`` output
    terravault-sarif   TerraVault CLI ``--output-format sarif`` output
    gate-report-md     Quality Gate Markdown report (embedded verbatim)
    gate-metrics-json  Quality Gate JSON sidecar
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DETAIL_TAIL_CHARS = 4000
DETAIL_MAX_ITEMS = 25


@dataclass
class Section:
    """One parsed input — feeds a row in the status table and a details block."""

    kind: str
    label: str
    status: str
    summary: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_excerpt: str = ""
    error: Optional[str] = None

    @property
    def passed(self) -> bool:
        return self.status == "pass"


def _truncate(text: str, limit: int = DETAIL_TAIL_CHARS) -> str:
    if len(text) <= limit:
        return text
    return "... (truncated) ...\n" + text[-limit:]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_xml(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_bandit(path: Path) -> Section:
    data = _load_json(path)
    results = data.get("results", []) or []
    sev_counts: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    findings: List[Dict[str, Any]] = []
    for item in results:
        sev = (item.get("issue_severity") or "UNKNOWN").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        findings.append(
            {
                "severity": sev,
                "confidence": item.get("issue_confidence"),
                "test_id": item.get("test_id"),
                "test_name": item.get("test_name"),
                "file": item.get("filename"),
                "line": item.get("line_number"),
                "message": item.get("issue_text"),
            }
        )
    total = len(findings)
    high_or_med = sev_counts["HIGH"] + sev_counts["MEDIUM"]
    status = "fail" if high_or_med > 0 else "pass"
    summary = (
        f"{total} finding(s) "
        f"(HIGH={sev_counts['HIGH']}, MEDIUM={sev_counts['MEDIUM']}, LOW={sev_counts['LOW']})"
    )
    return Section(
        kind="bandit-json",
        label="Bandit (SAST)",
        status=status,
        summary=summary,
        metrics={"total": total, "severities": sev_counts},
        findings=findings,
    )


def parse_safety(path: Path) -> Section:
    data = _load_json(path)
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities") or data.get("results") or []
    else:
        vulns = data
    findings: List[Dict[str, Any]] = []
    for v in vulns:
        findings.append(
            {
                "severity": (v.get("severity") or "UNKNOWN").upper(),
                "package": v.get("package_name") or v.get("package"),
                "installed_version": v.get("analyzed_version") or v.get("installed_version"),
                "vulnerable_spec": v.get("vulnerable_spec"),
                "advisory_id": v.get("vulnerability_id") or v.get("advisory_id"),
                "message": v.get("advisory") or v.get("description"),
            }
        )
    total = len(findings)
    status = "fail" if total > 0 else "pass"
    summary = f"{total} known vulnerability(ies) in dependencies"
    return Section(
        kind="safety-json",
        label="Safety (dependency CVEs)",
        status=status,
        summary=summary,
        metrics={"total": total},
        findings=findings,
    )


def _parse_sarif(path: Path, kind: str, label: str) -> Section:
    data = _load_json(path)
    runs = data.get("runs", []) or []
    findings: List[Dict[str, Any]] = []
    sev_counts: Dict[str, int] = {}
    for run in runs:
        tool_rules = {
            r.get("id"): r
            for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])
        }
        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId") or "unknown"
            rule = tool_rules.get(rule_id, {})
            level = (result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning").upper()
            sev_counts[level] = sev_counts.get(level, 0) + 1
            locations = result.get("locations") or []
            file_path = None
            line = None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = (phys.get("artifactLocation") or {}).get("uri")
                line = (phys.get("region") or {}).get("startLine")
            message = (result.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text")
            findings.append(
                {
                    "severity": level,
                    "rule_id": rule_id,
                    "file": file_path,
                    "line": line,
                    "message": message,
                }
            )
    total = len(findings)
    status = "fail" if total > 0 else "pass"
    sev_summary = ", ".join(f"{k}={v}" for k, v in sorted(sev_counts.items()))
    summary = f"{total} finding(s)" + (f" ({sev_summary})" if sev_summary else "")
    return Section(
        kind=kind,
        label=label,
        status=status,
        summary=summary,
        metrics={"total": total, "severities": sev_counts},
        findings=findings,
    )


def parse_gitleaks_sarif(path: Path) -> Section:
    return _parse_sarif(path, "gitleaks-sarif", "GitLeaks (secrets)")


def parse_trivy_sarif(path: Path) -> Section:
    return _parse_sarif(path, "trivy-sarif", "Trivy (container CVEs)")


def parse_terravault_sarif(path: Path) -> Section:
    return _parse_sarif(path, "terravault-sarif", "TerraVault (SARIF)")


def parse_pytest_junit(path: Path) -> Section:
    root = _load_xml(path)
    tests = failures = errors = skipped = 0
    if root.tag == "testsuites":
        suites = list(root.findall("testsuite"))
    else:
        suites = [root]
    failing: List[Dict[str, Any]] = []
    for suite in suites:
        tests += int(suite.attrib.get("tests", 0) or 0)
        failures += int(suite.attrib.get("failures", 0) or 0)
        errors += int(suite.attrib.get("errors", 0) or 0)
        skipped += int(suite.attrib.get("skipped", 0) or 0)
        for case in suite.findall("testcase"):
            err_el = case.find("error")
            fail_el = case.find("failure")
            chosen = err_el if err_el is not None else fail_el
            if chosen is None:
                continue
            failing.append(
                {
                    "severity": "ERROR" if err_el is not None else "FAILURE",
                    "classname": case.attrib.get("classname"),
                    "name": case.attrib.get("name"),
                    "file": case.attrib.get("file"),
                    "line": case.attrib.get("line"),
                    "message": chosen.attrib.get("message"),
                }
            )
    status = "fail" if (failures + errors) > 0 else "pass"
    summary = f"{tests} test(s); failures={failures}, errors={errors}, skipped={skipped}"
    return Section(
        kind="pytest-junit",
        label="pytest",
        status=status,
        summary=summary,
        metrics={
            "total": tests,
            "failures": failures,
            "errors": errors,
            "skipped": skipped,
        },
        findings=failing,
    )


def parse_coverage_xml(path: Path) -> Section:
    root = _load_xml(path)
    rate_str = root.attrib.get("line-rate", "0")
    rate = float(rate_str) * 100
    summary = f"line coverage = {rate:.2f}%"
    return Section(
        kind="coverage-xml",
        label="Coverage",
        status="pass",
        summary=summary,
        metrics={"line_rate_pct": round(rate, 2)},
    )


def parse_terravault_scan(path: Path) -> Section:
    data = _load_json(path)
    summary = data.get("summary", {}) or {}
    results = data.get("results", []) or []
    findings: List[Dict[str, Any]] = []
    for result in results:
        for vuln in result.get("vulnerabilities", []) or []:
            findings.append(
                {
                    "severity": (vuln.get("severity") or "UNKNOWN").upper(),
                    "file": result.get("file"),
                    "score": result.get("score"),
                    "rule": vuln.get("rule") or vuln.get("rule_id"),
                    "message": vuln.get("message"),
                }
            )
    failed = int(summary.get("failed", 0) or 0)
    status = "fail" if failed > 0 else "pass"
    summary_str = (
        f"{summary.get('failed', 0)}/{summary.get('total_files', 0)} file(s) over threshold; "
        f"max_score={summary.get('max_score', 0)}"
    )
    return Section(
        kind="terravault-scan",
        label="TerraVault scan",
        status=status,
        summary=summary_str,
        metrics={
            "total_files": int(summary.get("total_files", 0) or 0),
            "passed": int(summary.get("passed", 0) or 0),
            "failed": failed,
            "max_score": summary.get("max_score", 0),
        },
        findings=findings,
    )


def parse_gate_report_md(path: Path) -> Section:
    text = path.read_text(encoding="utf-8")
    overall_fail = "FAILED" in text.split("\n", 5)[2] if len(text.split("\n", 5)) > 2 else False
    status = "fail" if overall_fail else "pass"
    summary = "Quality Gate failed" if overall_fail else "Quality Gate passed"
    return Section(
        kind="gate-report-md",
        label="Quality Gate (report)",
        status=status,
        summary=summary,
        raw_excerpt=_truncate(text),
    )


def parse_gate_metrics_json(path: Path) -> Section:
    data = _load_json(path)
    checks = data.get("checks", []) or []
    failed = [c for c in checks if c.get("status") != "pass"]
    status = "fail" if failed else "pass"
    summary = (
        f"{len(failed)} check(s) failing: " + ", ".join(c.get("name") for c in failed)
        if failed
        else f"all {len(checks)} check(s) passing"
    )
    return Section(
        kind="gate-metrics-json",
        label="Quality Gate (metrics)",
        status=status,
        summary=summary,
        metrics={"checks": checks, "overall": data.get("overall")},
    )


PARSERS = {
    "bandit-json": parse_bandit,
    "safety-json": parse_safety,
    "gitleaks-sarif": parse_gitleaks_sarif,
    "trivy-sarif": parse_trivy_sarif,
    "terravault-sarif": parse_terravault_sarif,
    "pytest-junit": parse_pytest_junit,
    "coverage-xml": parse_coverage_xml,
    "terravault-scan": parse_terravault_scan,
    "gate-report-md": parse_gate_report_md,
    "gate-metrics-json": parse_gate_metrics_json,
}

KIND_LABELS = {
    "bandit-json": "Bandit (SAST)",
    "safety-json": "Safety (dependency CVEs)",
    "gitleaks-sarif": "GitLeaks (secrets)",
    "trivy-sarif": "Trivy (container CVEs)",
    "terravault-sarif": "TerraVault (SARIF)",
    "pytest-junit": "pytest",
    "coverage-xml": "Coverage",
    "terravault-scan": "TerraVault scan",
    "gate-report-md": "Quality Gate (report)",
    "gate-metrics-json": "Quality Gate (metrics)",
}


def parse_input(kind: str, path: Path) -> Section:
    parser = PARSERS.get(kind)
    label = KIND_LABELS.get(kind, kind)
    if parser is None:
        return Section(
            kind=kind,
            label=label,
            status="error",
            summary=f"unknown input kind: {kind}",
            error=f"no parser registered for kind={kind}",
        )
    if not path.exists():
        return Section(
            kind=kind,
            label=label,
            status="missing",
            summary="input file not produced",
            error=f"file not found: {path}",
        )
    try:
        section = parser(path)
    except Exception as exc:  # pragma: no cover — parser robustness
        return Section(
            kind=kind,
            label=label,
            status="error",
            summary=f"failed to parse: {exc.__class__.__name__}",
            error=str(exc),
            raw_excerpt=_truncate(path.read_text(encoding="utf-8", errors="replace")),
        )
    if not section.label:
        section.label = label
    return section


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

STATUS_BADGE = {
    "pass": "PASS",
    "fail": "FAIL",
    "error": "ERROR",
    "missing": "SKIPPED",
}


def _status_emoji(status: str) -> str:
    return {"pass": "✅", "fail": "❌", "error": "⚠️", "missing": "⏭️"}.get(status, "•")


def render_markdown(sections: List[Section], title: str, context: Dict[str, str]) -> str:
    overall_fail = any(s.status in ("fail", "error") for s in sections)
    badge = "❌ FAILED" if overall_fail else "✅ PASSED"

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Overall:** {badge}")
    lines.append(f"**Generated:** {context.get('generated_at')}")
    if context.get("commit"):
        lines.append(f"**Commit:** `{context['commit']}`")
    if context.get("pr"):
        lines.append(f"**PR:** #{context['pr']}")
    lines.append("")
    lines.append("| Check | Status | Summary |")
    lines.append("| --- | --- | --- |")
    for s in sections:
        badge_text = f"{_status_emoji(s.status)} {STATUS_BADGE.get(s.status, s.status.upper())}"
        lines.append(f"| {s.label} | {badge_text} | {s.summary} |")
    lines.append("")

    failing = [s for s in sections if s.status in ("fail", "error")]
    if failing:
        lines.append("## Failure details")
        lines.append("")
        for s in failing:
            lines.append(f"### {s.label} — {s.summary}")
            lines.append("")
            if s.error:
                lines.append(f"_Error:_ `{s.error}`")
                lines.append("")
            if s.findings:
                shown = s.findings[:DETAIL_MAX_ITEMS]
                lines.append("| Severity | Location | Detail |")
                lines.append("| --- | --- | --- |")
                for f in shown:
                    loc = _format_location(f)
                    detail = _format_detail(f)
                    sev = (f.get("severity") or "").upper() or "—"
                    lines.append(f"| {sev} | {loc} | {detail} |")
                if len(s.findings) > DETAIL_MAX_ITEMS:
                    lines.append("")
                    lines.append(f"_...and {len(s.findings) - DETAIL_MAX_ITEMS} more findings (see JSON sidecar)._")
                lines.append("")
            if s.raw_excerpt:
                lines.append("<details><summary>Raw output (tail)</summary>")
                lines.append("")
                lines.append("```")
                lines.append(s.raw_excerpt)
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

    skipped = [s for s in sections if s.status == "missing"]
    if skipped:
        lines.append("## Inputs not produced")
        lines.append("")
        for s in skipped:
            lines.append(f"- **{s.label}** (`{s.kind}`): {s.error}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_This report was generated by `scripts/pipeline_report.py`. "
                 "The machine-readable sidecar is `pipeline-metrics.json`._")
    return "\n".join(lines)


def _format_location(finding: Dict[str, Any]) -> str:
    file_ = finding.get("file") or finding.get("classname") or finding.get("package") or "—"
    line = finding.get("line")
    if line is not None:
        return f"`{file_}:{line}`"
    return f"`{file_}`"


def _format_detail(finding: Dict[str, Any]) -> str:
    name = finding.get("name") or finding.get("rule_id") or finding.get("test_id") or finding.get("advisory_id") or finding.get("rule")
    msg = (finding.get("message") or "").replace("|", "\\|").replace("\n", " ")
    if name and msg:
        return f"**{name}** — {msg}"
    return name or msg or "—"


def render_metrics(sections: List[Section], context: Dict[str, str]) -> Dict[str, Any]:
    overall_fail = any(s.status in ("fail", "error") for s in sections)
    return {
        "overall": "fail" if overall_fail else "pass",
        "generated_at": context.get("generated_at"),
        "commit": context.get("commit"),
        "pr": context.get("pr"),
        "checks": [
            {
                "kind": s.kind,
                "label": s.label,
                "status": s.status,
                "summary": s.summary,
                "metrics": s.metrics,
                "finding_count": len(s.findings),
                "findings": s.findings[:DETAIL_MAX_ITEMS],
                "error": s.error,
            }
            for s in sections
        ],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_input_spec(spec: str) -> Tuple[str, Path]:
    if "=" not in spec:
        raise argparse.ArgumentTypeError(
            f"--input expects '<kind>=<path>', got '{spec}'"
        )
    kind, _, raw_path = spec.partition("=")
    return kind.strip(), Path(raw_path.strip())


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        type=_parse_input_spec,
        help="<kind>=<path>; repeatable",
    )
    parser.add_argument("--output-md", required=True, type=Path)
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument("--title", default="Pipeline Report")
    parser.add_argument("--commit", default="")
    parser.add_argument("--pr", default="")
    parser.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="Exit non-zero if any section status is fail/error",
    )
    args = parser.parse_args(argv)

    context = {
        "generated_at": _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "commit": args.commit,
        "pr": args.pr,
    }

    sections: List[Section] = []
    for kind, path in args.input:
        sections.append(parse_input(kind, path))

    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text(render_markdown(sections, args.title, context), encoding="utf-8")

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(render_metrics(sections, context), indent=2, default=str),
        encoding="utf-8",
    )

    print(f"Markdown report written to {args.output_md}", flush=True)
    print(f"JSON metrics  written to {args.output_json}", flush=True)

    if args.fail_on_issues and any(s.status in ("fail", "error") for s in sections):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
