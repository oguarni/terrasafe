#!/usr/bin/env python3
"""Roll the per-target Stage 0 results up into one baseline table.

Written to be run REPEATEDLY while the campaign is still going, not once at the
end: the run is expected to be killed by the VM duration cap or by credit
expiry, so `baseline.json` and `baseline_report.md` must always describe
whatever has completed so far. Targets that have not been fuzzed yet appear with
their build status and nothing else, which is exactly the honest picture.

These are the numbers a later LLM-augmented arm has to beat, so the report
states the campaign parameters (per-target budget, detector set, seeding policy)
alongside them -- a baseline without its conditions is not comparable to
anything.

Usage: aggregate_baseline.py --run-root /opt/fuzz-run --run-id <id>
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

BASELINE_KIND = "known-bug"
VALIDATION_KIND = "gate-validation"


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _collect_rows(run_root: Path) -> list[dict]:
    """One row per target: the fuzz result if it exists, else the build record."""
    status_dir = run_root / "status"
    results_dir = run_root / "results"
    rows: list[dict] = []

    for build_path in sorted(status_dir.glob("*.build.json")):
        build = _load_json(build_path)
        if not build:
            continue
        result = _load_json(results_dir / f"{build.get('target')}.json")
        if result:
            result.setdefault("build_seconds", build.get("build_seconds", 0))
            rows.append(result)
            continue
        build.setdefault("status", "build-failed")
        if build["status"] == "built":
            build["status"] = "fuzz-pending"
        rows.append(build)
    return rows


def _summarise(rows: list[dict]) -> dict:
    """Headline baseline figures, computed over the known-bug targets only."""
    baseline_rows = [r for r in rows if r.get("kind") == BASELINE_KIND]
    fuzzed = [r for r in baseline_rows if r.get("status") == "fuzzed"]
    with_crash = [r for r in fuzzed if r.get("time_to_first_crash_seconds") is not None]
    with_bug = [r for r in fuzzed if r.get("confirmed_unique_bugs", 0) > 0]

    ttfc = sorted(r["time_to_first_crash_seconds"] for r in with_crash)
    validation = [r for r in rows if r.get("kind") == VALIDATION_KIND]

    return {
        "targets_total": len(baseline_rows),
        "targets_built": len([r for r in baseline_rows if r.get("status") in ("built", "fuzzed", "fuzz-pending")]),
        "targets_build_failed": len([r for r in baseline_rows if r.get("status") == "build-failed"]),
        "targets_fuzzed": len(fuzzed),
        "targets_with_any_crash_artifact": len(with_crash),
        "targets_with_confirmed_bug": len(with_bug),
        "confirmed_unique_bugs": sum(r.get("confirmed_unique_bugs", 0) for r in fuzzed),
        "confirmed_memory_safety_bugs": sum(r.get("confirmed_memory_safety_bugs", 0) for r in fuzzed),
        # Reported separately, never folded into the memory-safety count — see
        # NON_MEMORY_SAFETY_CLASSES in triage_crashes.py for why.
        "confirmed_resource_leak_bugs": sum(r.get("confirmed_resource_leak_bugs", 0) for r in fuzzed),
        "unique_signatures": sum(r.get("unique_signatures", 0) for r in fuzzed),
        "crash_artifacts": sum(r.get("crash_artifacts", 0) for r in fuzzed),
        "median_time_to_first_crash_seconds": ttfc[len(ttfc) // 2] if ttfc else None,
        "fastest_time_to_first_crash_seconds": ttfc[0] if ttfc else None,
        "total_edge_coverage": sum(r.get("edge_coverage", 0) for r in fuzzed),
        "total_executed_units": sum(r.get("executed_units", 0) for r in fuzzed),
        "total_cpu_seconds": round(sum(r.get("fuzz_cpu_seconds", 0.0) for r in rows), 1),
        "total_fuzz_wall_seconds": sum(r.get("fuzz_wall_seconds", 0) for r in rows),
        "gate_validation_targets": len(validation),
        "gate_validation_confirmed_bugs": sum(r.get("confirmed_unique_bugs", 0) for r in validation),
    }


def _fmt(value: object) -> str:
    return "-" if value is None else str(value)


def _render_table(rows: list[dict]) -> list[str]:
    header = ("| target | kind | status | build s | budget s | CPU s | execs | edges | "
              "artifacts | unique sig | confirmed | TTFC s |")
    lines = [header, "|" + "---|" * 12]
    for row in rows:
        lines.append(
            f"| `{row.get('target', '?')}` | {row.get('kind', '?')} | {row.get('status', '?')} | "
            f"{_fmt(row.get('build_seconds'))} | {_fmt(row.get('fuzz_budget_seconds'))} | "
            f"{_fmt(row.get('fuzz_cpu_seconds'))} | {_fmt(row.get('executed_units'))} | "
            f"{_fmt(row.get('edge_coverage'))} | {_fmt(row.get('crash_artifacts'))} | "
            f"{_fmt(row.get('unique_signatures'))} | {_fmt(row.get('confirmed_unique_bugs'))} | "
            f"{_fmt(row.get('time_to_first_crash_seconds'))} |"
        )
    return lines


def _render_bugs(rows: list[dict]) -> list[str]:
    lines: list[str] = ["", "## Confirmed bugs (passed the reproducibility gate)", ""]
    any_bug = False
    for row in rows:
        for bug in row.get("bugs", []):
            if not bug.get("confirmed"):
                continue
            any_bug = True
            frames = " <- ".join(bug.get("top_frames", [])) or "(no symbolised frames)"
            lines.append(
                f"- `{row['target']}` `{bug['signature']}` **{bug['bug_class']}** "
                f"({bug['sanitizer']}) at {frames}; first seen "
                f"{_fmt(bug.get('first_seen_seconds'))}s, minimised to "
                f"{_fmt(bug.get('minimized_bytes'))} B from {_fmt(bug.get('artifact_bytes'))} B, "
                f"{bug.get('duplicate_artifacts', 0)} duplicate artifact(s)."
            )
    if not any_bug:
        lines.append("_None yet._ Artifacts that did not pass the gate are listed per target in "
                     "`results/<target>.json` with their `reject_reason`.")
    return lines


def _render_report(run_id: str, rows: list[dict], summary: dict) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"# Track B Stage 0 — plain-fuzzing baseline ({run_id})",
        "",
        f"Generated {generated}. **Partial by design** — this file is rewritten every couple of "
        "minutes while the campaign runs, so it is always readable even if the VM is stopped "
        "mid-run by the duration cap or by credit expiry.",
        "",
        "## What this is",
        "",
        "The **un-augmented arm** of Track B's thesis question. No LLM is involved anywhere in "
        "this run: hand-written libFuzzer harnesses, no synthesised seeds, no dictionaries, no "
        "LLM triage. Every number below is the floor a later LLM-augmented arm has to beat on "
        "bug yield, time-to-reproduce and triage quality.",
        "",
        "A crash is counted only if a sanitizer confirms it, libFuzzer can minimise it, and the "
        "minimised input replays the same stack signature deterministically. Artifacts that fail "
        "any clause are kept and reported, but never counted.",
        "",
        "## Headline",
        "",
    ]
    for key, value in summary.items():
        lines.append(f"- `{key}`: {_fmt(value)}")
    lines += ["", "## Per-target", ""]
    lines += _render_table(rows)
    lines += _render_bugs(rows)
    lines += [
        "",
        "## Reading the gate-validation rows",
        "",
        "`gate_heap_overflow` and `gate_use_after_free` are synthetic targets with a deliberate "
        "planted bug each. They are excluded from every headline figure. Their only job is to "
        "prove, inside this same run, that the crash -> dedup -> minimise -> replay pipeline "
        "fires at all. If they report zero confirmed bugs, a zero on the real targets means the "
        "pipeline is broken, not that the targets are clean.",
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--run-id", default="unknown")
    args = parser.parse_args()

    run_root = Path(args.run_root)
    rows = _collect_rows(run_root)
    summary = _summarise(rows)

    payload = {
        "run_id": args.run_id,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "arm": "plain-fuzzing-baseline (no LLM)",
        "summary": summary,
        "targets": rows,
    }
    (run_root / "baseline.json").write_text(json.dumps(payload, indent=2), "utf-8")
    (run_root / "baseline_report.md").write_text(_render_report(args.run_id, rows, summary), "utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
