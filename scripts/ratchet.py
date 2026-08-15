#!/usr/bin/env python3
"""TerraVault metric ratchet.

Enforces that three code-health metrics on the ``terravault/`` package never
regress relative to the baseline stored in ``.ratchet.json``:

    coverage_pct          : line coverage % from coverage.xml (must be >= baseline)
    files_over_threshold  : count of .py files with more than FILE_SLOC_THRESHOLD
                            lines (must be <= baseline)
    duplicate_blocks      : count of pylint R0801 (duplicate-code) findings at
                            --min-similarity-lines=4 (must be <= baseline)

Modes:
    --check  (default) compare current metrics against the baseline
    --update           move the baseline forward, keeping improvements only
    --show             print baseline vs current side-by-side

``--update`` is monotone: each metric moves in its ratcheted direction or not
at all, so a transient dip (an environment measuring coverage differently from
the one that set the baseline) can never lower the bar for the next PR. Pass
``--force`` alongside ``--update`` for a deliberate reset — the only supported
way to move a baseline backwards.

Exit codes:
    0 — all metrics tied or improved (check), or baseline written (update)
    1 — at least one metric worsened
    2 — internal error (missing coverage.xml, malformed baseline, etc.)

The script always emits a Markdown summary on stdout so the Quality Gate can
capture it as the check's detail text.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / ".ratchet.json"
PACKAGE_DIR = REPO_ROOT / "terravault"
COVERAGE_XML = REPO_ROOT / "coverage.xml"

FILE_SLOC_THRESHOLD = 300
MIN_SIMILARITY_LINES = 4
COVERAGE_TOLERANCE = 1e-6


@dataclass(frozen=True)
class Metrics:
    """A snapshot of the three ratcheted metrics."""

    coverage_pct: float
    files_over_threshold: int
    duplicate_blocks: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "coverage_pct": round(self.coverage_pct, 2),
            "files_over_threshold": self.files_over_threshold,
            "duplicate_blocks": self.duplicate_blocks,
        }


def _measure_coverage() -> float:
    if not COVERAGE_XML.exists():
        raise SystemExit(
            f"ratchet: {COVERAGE_XML.relative_to(REPO_ROOT)} not found. "
            "Run `pytest --cov=terravault --cov-report=xml` first."
        )
    tree = ET.parse(COVERAGE_XML)
    rate = float(tree.getroot().attrib.get("line-rate", "0")) * 100
    return rate


def _measure_files_over_threshold() -> int:
    count = 0
    for path in PACKAGE_DIR.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        with path.open(encoding="utf-8") as handle:
            lines = sum(1 for _ in handle)
        if lines > FILE_SLOC_THRESHOLD:
            count += 1
    return count


def _measure_duplicate_blocks() -> int:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pylint",
            "terravault/",
            "--disable=all",
            "--enable=R0801",
            f"--min-similarity-lines={MIN_SIMILARITY_LINES}",
            "--score=n",
            "--output-format=json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    raw = proc.stdout.strip()
    if not raw:
        return 0
    try:
        findings = json.loads(raw)
    except json.JSONDecodeError as err:
        raise SystemExit(
            f"ratchet: failed to parse pylint JSON output: {err}\n{proc.stderr}"
        ) from err
    return sum(1 for f in findings if f.get("message-id") == "R0801")


def measure() -> Metrics:
    return Metrics(
        coverage_pct=_measure_coverage(),
        files_over_threshold=_measure_files_over_threshold(),
        duplicate_blocks=_measure_duplicate_blocks(),
    )


def load_baseline() -> Optional[Metrics]:
    if not BASELINE_PATH.exists():
        return None
    try:
        data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise SystemExit(f"ratchet: {BASELINE_PATH.name} is not valid JSON: {err}") from err
    return Metrics(
        coverage_pct=float(data["coverage_pct"]),
        files_over_threshold=int(data["files_over_threshold"]),
        duplicate_blocks=int(data["duplicate_blocks"]),
    )


def _git_sha() -> Optional[str]:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def write_baseline(metrics: Metrics) -> None:
    payload: dict[str, Any] = {
        **metrics.to_payload(),
        "thresholds": {
            "file_sloc_threshold": FILE_SLOC_THRESHOLD,
            "min_similarity_lines": MIN_SIMILARITY_LINES,
        },
        "updated_at": date.today().isoformat(),
    }
    sha = os.environ.get("GITHUB_SHA") or _git_sha()
    if sha:
        payload["updated_commit"] = sha
    BASELINE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _coverage_ok(baseline: Metrics, current: Metrics) -> bool:
    baseline_rounded = round(baseline.coverage_pct, 2)
    current_rounded = round(current.coverage_pct, 2)
    return current_rounded + COVERAGE_TOLERANCE >= baseline_rounded


def compare(baseline: Metrics, current: Metrics) -> bool:
    return (
        _coverage_ok(baseline, current)
        and current.files_over_threshold <= baseline.files_over_threshold
        and current.duplicate_blocks <= baseline.duplicate_blocks
    )


def ratchet_forward(baseline: Metrics, current: Metrics) -> Metrics:
    """Merge ``current`` into ``baseline`` keeping only the improvements.

    The bump job runs on every push to main, and coverage is not identical
    across environments (CI measured 82.63% on the same tree a local run
    scored 82.80%). Taking ``current`` wholesale would let a low reading
    become the new bar, so each metric is clamped to its ratcheted direction.

    >>> ratchet_forward(Metrics(82.8, 5, 0), Metrics(82.63, 6, 0))
    Metrics(coverage_pct=82.8, files_over_threshold=5, duplicate_blocks=0)
    """
    return Metrics(
        coverage_pct=max(baseline.coverage_pct, current.coverage_pct),
        files_over_threshold=min(baseline.files_over_threshold, current.files_over_threshold),
        duplicate_blocks=min(baseline.duplicate_blocks, current.duplicate_blocks),
    )


def _held_metrics(baseline: Metrics, current: Metrics) -> list[str]:
    """Name the metrics whose current reading is worse than the baseline."""
    held = []
    if not _coverage_ok(baseline, current):
        held.append(
            f"coverage_pct {round(current.coverage_pct, 2):.2f}% "
            f"< baseline {round(baseline.coverage_pct, 2):.2f}%"
        )
    if current.files_over_threshold > baseline.files_over_threshold:
        held.append(
            f"files_over_{FILE_SLOC_THRESHOLD}_sloc {current.files_over_threshold} "
            f"> baseline {baseline.files_over_threshold}"
        )
    if current.duplicate_blocks > baseline.duplicate_blocks:
        held.append(
            f"duplicate_blocks {current.duplicate_blocks} "
            f"> baseline {baseline.duplicate_blocks}"
        )
    return held


def render_report(baseline: Metrics, current: Metrics, ok: bool) -> str:
    rows = [
        (
            "coverage_pct",
            f"{round(baseline.coverage_pct, 2):.2f}%",
            f"{round(current.coverage_pct, 2):.2f}%",
            "must not decrease",
            _coverage_ok(baseline, current),
        ),
        (
            f"files_over_{FILE_SLOC_THRESHOLD}_sloc",
            str(baseline.files_over_threshold),
            str(current.files_over_threshold),
            "must not increase",
            current.files_over_threshold <= baseline.files_over_threshold,
        ),
        (
            "duplicate_blocks",
            str(baseline.duplicate_blocks),
            str(current.duplicate_blocks),
            "must not increase",
            current.duplicate_blocks <= baseline.duplicate_blocks,
        ),
    ]
    lines = [
        "# Ratchet Report",
        "",
        f"**Overall:** {'PASS' if ok else 'FAIL'}",
        "",
        "| Metric | Baseline | Current | Direction | Result |",
        "| --- | --- | --- | --- | --- |",
    ]
    for label, base, curr, direction, row_ok in rows:
        marker = "PASS" if row_ok else "FAIL"
        lines.append(f"| {label} | {base} | {curr} | {direction} | {marker} |")
    lines.append("")
    return "\n".join(lines)


def cmd_check() -> int:
    baseline = load_baseline()
    if baseline is None:
        print(
            f"ratchet: {BASELINE_PATH.name} not found. "
            "Run `python scripts/ratchet.py --update` to create the initial baseline.",
            file=sys.stderr,
        )
        return 2
    current = measure()
    ok = compare(baseline, current)
    print(render_report(baseline, current, ok))
    return 0 if ok else 1


def cmd_update(force: bool = False) -> int:
    current = measure()
    baseline = load_baseline()
    if baseline is None:
        write_baseline(current)
        print(f"ratchet: initial baseline written to {BASELINE_PATH.relative_to(REPO_ROOT)}")
        print(json.dumps(current.to_payload(), indent=2))
        return 0

    if force:
        target = current
        print("ratchet: --force given — baseline reset from current metrics, regressions included")
    else:
        target = ratchet_forward(baseline, current)
        for held in _held_metrics(baseline, current):
            print(f"ratchet: holding baseline — {held}")

    # Only rewrite when a real metric moved. The baseline file also carries
    # volatile provenance fields (updated_at / updated_commit); rewriting on
    # every run would churn those and make the ratchet bot commit on every
    # push even when coverage/files/dupes are identical. Skip the write when
    # the three ratcheted metrics match the existing baseline.
    if target.to_payload() == baseline.to_payload():
        print(f"ratchet: metrics unchanged — {BASELINE_PATH.name} left intact")
        print(json.dumps(baseline.to_payload(), indent=2))
        return 0
    write_baseline(target)
    print(f"ratchet: baseline written to {BASELINE_PATH.relative_to(REPO_ROOT)}")
    print(json.dumps(target.to_payload(), indent=2))
    return 0


def cmd_show() -> int:
    current = measure()
    baseline = load_baseline()
    if baseline is None:
        print("ratchet: no baseline yet — showing current metrics only")
        print(json.dumps(current.to_payload(), indent=2))
        return 0
    print(render_report(baseline, current, compare(baseline, current)))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TerraVault metric ratchet")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="compare current to baseline (default)")
    group.add_argument("--update", action="store_true", help="move baseline forward (improvements only)")
    group.add_argument("--show", action="store_true", help="show baseline vs current")
    parser.add_argument(
        "--force",
        action="store_true",
        help="with --update, allow the baseline to move backwards (deliberate reset)",
    )
    args = parser.parse_args(argv)

    if args.force and not args.update:
        parser.error("--force is only meaningful together with --update")

    if args.update:
        return cmd_update(force=args.force)
    if args.show:
        return cmd_show()
    return cmd_check()


if __name__ == "__main__":
    sys.exit(main())
