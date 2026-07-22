#!/usr/bin/env python3
"""Re-derive per-target execution counts for a banked fuzzing baseline.

libFuzzer's fork mode calls exit() before ``-print_final_stats`` runs, so
``stat::number_of_executed_units`` never reaches the campaign summary and
``baseline.json`` records ``executed_units: 0`` / ``execs_per_second: 0.0``.
Those zeros mean *absent*, not *measured as zero* — see
``evaluation/results/fuzz_baseline/BASELINE_CORRECTIONS.md`` section 2.

The cumulative counter does survive in the parent's periodic
``#N: cov: ...`` lines, which land in the per-target ``logs/<target>.fuzz.log``
files. Those logs match the global ``logs/`` ignore rule and are therefore never
committed, so this script banks the derived numbers into a small tracked JSON
before the only copy is lost.

Usage:
    fuzzing/rederive_exec_stats.py \
        --baseline evaluation/results/fuzz_baseline/baseline.json \
        --logs-dir evaluation/results/fuzz_baseline/logs \
        --out      evaluation/results/fuzz_baseline/exec_stats.json
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from aggregate_baseline import BASELINE_KIND, VALIDATION_KIND
from triage_crashes import _parse_executed_units

# A fork-mode campaign that truly executed nothing would still emit a #0 line;
# a missing log yields the same 0. Only the log's presence separates the two.
UNMEASURED = "log_missing"
MEASURED = "derived_from_fork_parent_lines"


@dataclass(frozen=True)
class TargetExecStats:
    """Execution throughput for one fuzz target, re-derived from its log."""

    target: str
    kind: str
    status: str
    executed_units: int
    fuzz_wall_seconds: float
    fuzz_cpu_seconds: float
    execs_per_second: float
    execs_per_cpu_second: float


def derive_target_stats(target: dict, logs_dir: Path) -> TargetExecStats:
    """Recover one target's execution count from its per-target fuzz log.

    Returns a record with ``status == UNMEASURED`` when the log is absent, so a
    consumer can never mistake an unrecoverable target for a genuinely idle one.

    >>> derive_target_stats({"target": "nope"}, Path("/nonexistent")).status
    'log_missing'
    """
    name = target["target"]
    kind = target.get("kind", "unknown")
    log = logs_dir / f"{name}.fuzz.log"
    wall = float(target.get("fuzz_wall_seconds") or 0.0)
    cpu = float(target.get("fuzz_cpu_seconds") or 0.0)

    if not log.is_file():
        return TargetExecStats(name, kind, UNMEASURED, 0, wall, cpu, 0.0, 0.0)

    executed = _parse_executed_units(log)
    return TargetExecStats(
        target=name,
        kind=kind,
        status=MEASURED,
        executed_units=executed,
        fuzz_wall_seconds=wall,
        fuzz_cpu_seconds=cpu,
        execs_per_second=round(executed / wall, 1) if wall else 0.0,
        execs_per_cpu_second=round(executed / cpu, 1) if cpu else 0.0,
    )


def _aggregate(rows: list[TargetExecStats]) -> dict:
    """Totals over one kind-partition, counting only targets whose log survived."""
    measured = [r for r in rows if r.status == MEASURED]
    units = sum(r.executed_units for r in measured)
    cpu = sum(r.fuzz_cpu_seconds for r in measured)
    wall = sum(r.fuzz_wall_seconds for r in measured)
    return {
        "targets_total": len(rows),
        "targets_measured": len(measured),
        "targets_unmeasured": len(rows) - len(measured),
        "total_executed_units": units,
        "total_fuzz_wall_seconds": round(wall, 2),
        "total_fuzz_cpu_seconds": round(cpu, 2),
        "mean_execs_per_cpu_second": round(units / cpu, 1) if cpu else 0.0,
    }


def build_report(baseline: dict, logs_dir: Path) -> dict:
    """Assemble the derived-stats document, including a provenance block.

    Headline totals cover the known-bug targets only, matching
    ``aggregate_baseline._summarise``. The synthetic gate-validation targets are
    reported separately: ``gate_heap_overflow`` alone executes an order of
    magnitude more units than any real target, so folding it into the headline
    would inflate the Stage 0 throughput figure roughly 4.6x.
    """
    rows = [derive_target_stats(t, logs_dir) for t in baseline["targets"]]
    known_bug = [r for r in rows if r.kind == BASELINE_KIND]
    validation = [r for r in rows if r.kind == VALIDATION_KIND]

    return {
        "run_id": baseline.get("run_id"),
        "arm": baseline.get("arm"),
        "derivation": {
            "reason": "fork mode exits before -print_final_stats; executed_units "
                      "was absent from baseline.json, not zero",
            "source": "per-target logs/<target>.fuzz.log, parent '#N: cov:' lines",
            "parser": "fuzzing/triage_crashes.py::_parse_executed_units",
            "caveat": "source logs match the global 'logs/' ignore rule and are "
                      "not committed; this file is the durable copy",
            "scope": f"summary covers kind={BASELINE_KIND} only; "
                     f"kind={VALIDATION_KIND} reported under gate_validation",
        },
        "summary": _aggregate(known_bug),
        "gate_validation": _aggregate(validation),
        "targets": [asdict(r) for r in rows],
    }


def format_table(report: dict) -> str:
    """Render the per-target rows as a markdown table for the console."""
    lines = ["| target | kind | executed units | cpu s | execs/s (wall) | execs/s (cpu) |",
             "| --- | --- | ---: | ---: | ---: | ---: |"]
    for row in report["targets"]:
        units = f"{row['executed_units']:,}" if row["status"] == MEASURED else "—"
        kind = "gate" if row["kind"] == VALIDATION_KIND else "known-bug"
        lines.append(
            f"| {row['target']} | {kind} | {units} | {row['fuzz_cpu_seconds']:.0f} | "
            f"{row['execs_per_second']:,.1f} | {row['execs_per_cpu_second']:,.1f} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", type=Path, required=True,
                        help="banked baseline.json to read target metadata from")
    parser.add_argument("--logs-dir", type=Path, required=True,
                        help="directory holding <target>.fuzz.log files")
    parser.add_argument("--out", type=Path, required=True,
                        help="destination for the derived exec_stats.json")
    args = parser.parse_args()

    if not args.baseline.is_file():
        raise SystemExit(f"baseline not found: {args.baseline}")

    baseline = json.loads(args.baseline.read_text("utf-8"))
    report = build_report(baseline, args.logs_dir)
    args.out.write_text(json.dumps(report, indent=2) + "\n", "utf-8")

    print(format_table(report))
    s, g = report["summary"], report["gate_validation"]
    print(f"\nknown-bug targets: {s['targets_measured']}/{s['targets_total']} recovered; "
          f"{s['total_executed_units']:,} executed units; "
          f"{s['mean_execs_per_cpu_second']:,.1f} execs/CPU-second  <-- quote this")
    print(f"gate validation:   {g['targets_measured']}/{g['targets_total']} recovered; "
          f"{g['total_executed_units']:,} executed units (synthetic, never fold in)")
    unmeasured = s["targets_unmeasured"] + g["targets_unmeasured"]
    if unmeasured:
        print(f"WARNING: {unmeasured} target(s) had no log and stay unmeasured")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
