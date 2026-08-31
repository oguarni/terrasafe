#!/usr/bin/env python3
"""Reproducibility gate + baseline metrics for one fuzzing target.

Track B's plan makes reproducibility a hard gate, not a reporting nicety:

    "Report a bug only if a sanitizer confirms it *and* a minimized input
     replays it deterministically."   -- Track B plan, Stage 0

This module is that gate, built in from the very first (un-augmented) baseline
run so the LLM arm can never be measured against a softer standard. A libFuzzer
artifact is promoted to a *confirmed unique bug* only when all four hold:

  1. Replaying the artifact under the same sanitizer options reproduces a
     sanitizer diagnostic (not merely a non-zero exit).
  2. The diagnostic carries a recognised bug class and a symbolised stack.
  3. libFuzzer can minimise the input and the minimised input still reproduces.
  4. The minimised input reproduces the SAME stack signature on N independent
     replays -- i.e. the crash is deterministic, not flaky.

Deduplication uses the sanitizer bug class plus the top application stack
frames, with sanitizer/libFuzzer runtime frames stripped. That is the same
signature scheme ClusterFuzz uses, and Stage 2 of the plan will be scored
against it.

Only stdlib -- the VM runs this with the system python3 and no venv, because a
pip install is one more thing that can fail unattended.

Usage (see fuzz_target.sh):
    triage_crashes.py --build-json b.json --binary ./t --artifacts-dir art \\
        --corpus-dir corp --fuzz-log f.log --coverage-log c.log \\
        --cpu-file cpu.txt --start-epoch 1 --end-epoch 2 \\
        --budget-seconds 900 --out result.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

REPLAY_TIMEOUT_SECONDS = 90
MINIMIZE_TIMEOUT_SECONDS = 120
MINIMIZE_BUDGET_SECONDS = 45
DETERMINISM_REPLAYS = 3
SIGNATURE_FRAMES = 4

# Artifact prefixes libFuzzer writes. "slow-unit" is a performance note, not a
# defect, and is deliberately not triaged.
TRIAGED_PREFIXES = ("crash-", "leak-", "timeout-", "oom-")

SANITIZER_ERROR_RE = re.compile(
    r"==\d+==\s*ERROR:\s*(?P<sanitizer>AddressSanitizer|LeakSanitizer|"
    r"UndefinedBehaviorSanitizer|MemorySanitizer|libFuzzer):\s*(?P<detail>[^\n]*)"
)
UBSAN_RUNTIME_RE = re.compile(r"^(?P<loc>\S+?):\d+:\d+:\s*runtime error:\s*(?P<detail>.+)$", re.M)
FRAME_RE = re.compile(r"^\s*#(?P<index>\d+)\s+0x[0-9a-f]+\s+in\s+(?P<func>[^\s(]+)", re.M)
COVERAGE_RE = re.compile(r"cov:\s*(?P<cov>\d+)\s+ft:\s*(?P<ft>\d+)(?:\s+corp:\s*(?P<corp>\d+))?")
EXECUTED_UNITS_RE = re.compile(r"stat::number_of_executed_units:\s*(\d+)")
# Fork mode calls exit() before -print_final_stats is ever reached, so the
# stat:: line never appears for a forked campaign. Its periodic parent line
# carries the same cumulative run counter, which is the only place the number
# survives: "#123456: cov: 900 ft: 1800 corp: 50/1kb exec/s: 4000 ...".
FORK_RUNS_RE = re.compile(r"^#(\d+):\s+cov:", re.M)

# Frames belonging to the instrumentation rather than the target under test.
RUNTIME_FRAME_PREFIXES = (
    "__asan", "__lsan", "__ubsan", "__msan", "__sanitizer", "__interceptor",
    "fuzzer::", "LLVMFuzzer", "ExecuteFilesOnyByOne", "main", "__libc_start",
    "malloc", "calloc", "realloc", "free", "operator new", "operator delete",
)

BUG_CLASS_KEYWORDS = (
    "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
    "heap-use-after-free", "stack-use-after-return", "stack-use-after-scope",
    "use-after-poison", "double-free", "attempting free on address",
    "alloc-dealloc-mismatch", "memory leaks", "SEGV", "deadly signal",
    "out-of-memory", "timeout", "negative-size-param", "dynamic-stack-buffer-overflow",
    "unknown-crash", "runtime error",
)

# Classes that a sanitizer reports but which are NOT memory-safety violations:
# nothing invalid is ever accessed. A leak is a resource-management defect; OOM
# and timeout are budget outcomes. They are still real findings and stay in
# `confirmed_unique_bugs` — they are only excluded from the memory-safety count.
#
# Why this matters (2026-07-21): Stage 0's scope is "memory-safety + crashes",
# and its whole purpose is to be the honest floor a later LLM arm must beat.
# Classifying by *sanitizer* instead of by *bug class* put LeakSanitizer findings
# in the memory-safety bucket, which reported 6 memory-safety bugs on the first
# baseline when only 1 (c-ares CVE-2016-5180, heap-buffer-overflow) qualified —
# a ~6x inflation of the exact denominator the thesis comparison depends on.
NON_MEMORY_SAFETY_CLASSES = frozenset({"memory leaks", "out-of-memory", "timeout"})


@dataclass
class ConfirmedBug:
    """One deduplicated, sanitizer-confirmed, deterministically replayable bug."""

    signature: str
    sanitizer: str
    bug_class: str
    detail: str
    top_frames: list[str]
    artifact: str
    artifact_bytes: int
    minimized_artifact: Optional[str]
    minimized_bytes: Optional[int]
    first_seen_seconds: Optional[int]
    duplicate_artifacts: int
    sanitizer_confirmed: bool
    minimized: bool
    deterministic: bool
    confirmed: bool
    reject_reason: Optional[str] = None


@dataclass
class TargetBaseline:
    """The per-target row of the Stage 0 baseline table."""

    target: str
    kind: str
    source_url: str
    known_bug_reference: str
    status: str
    build_seconds: int
    fuzz_budget_seconds: int
    fuzz_wall_seconds: int
    fuzz_cpu_seconds: float
    executed_units: int
    execs_per_second: float
    edge_coverage: int
    features: int
    corpus_units: int
    corpus_bytes: int
    crash_artifacts: int
    time_to_first_crash_seconds: Optional[int]
    time_to_first_confirmed_bug_seconds: Optional[int]
    unique_signatures: int
    confirmed_unique_bugs: int
    confirmed_memory_safety_bugs: int
    confirmed_resource_leak_bugs: int
    bugs: list[dict] = field(default_factory=list)


def _run(argv: list[str], timeout: int) -> tuple[int, str]:
    """Run a target replay and return (returncode, combined output)."""
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, check=False,
        )
        return proc.returncode, proc.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        captured = exc.output.decode("utf-8", "replace") if exc.output else ""
        return 124, captured + "\n==0==ERROR: libFuzzer: timeout (replay wall-clock)\n"
    except OSError as exc:
        return 127, f"replay failed to start: {exc!r}"


def _classify(detail: str) -> str:
    """Map a sanitizer detail line onto a coarse, stable bug class."""
    lowered = detail.lower()
    for keyword in BUG_CLASS_KEYWORDS:
        if keyword.lower() in lowered:
            return keyword
    return detail.strip().split()[0] if detail.strip() else "unknown"


def _application_frames(output: str) -> list[str]:
    """Top application stack frames, with instrumentation frames stripped."""
    frames: list[str] = []
    for match in FRAME_RE.finditer(output):
        func = match.group("func")
        if any(func.startswith(prefix) for prefix in RUNTIME_FRAME_PREFIXES):
            continue
        if func not in frames:
            frames.append(func)
        if len(frames) >= SIGNATURE_FRAMES:
            break
    return frames


def _parse_report(output: str) -> Optional[tuple[str, str, str, list[str]]]:
    """Extract (sanitizer, bug_class, detail, frames) from a replay, or None."""
    match = SANITIZER_ERROR_RE.search(output)
    if match:
        detail = match.group("detail").strip()
        return match.group("sanitizer"), _classify(detail), detail, _application_frames(output)
    ubsan = UBSAN_RUNTIME_RE.search(output)
    if ubsan:
        detail = f"{ubsan.group('detail').strip()} @ {ubsan.group('loc')}"
        return "UndefinedBehaviorSanitizer", "runtime error", detail, _application_frames(output)
    return None


def _signature(sanitizer: str, bug_class: str, frames: list[str]) -> str:
    """Stable dedup key: sanitizer + bug class + top application frames."""
    payload = "|".join([sanitizer, bug_class, *frames])
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def _minimize(binary: str, artifact: Path, out_path: Path) -> bool:
    """Ask libFuzzer to shrink a crashing input; True if a smaller one survives."""
    argv = [
        binary, "-minimize_crash=1", "-runs=200000",
        f"-max_total_time={MINIMIZE_BUDGET_SECONDS}",
        f"-exact_artifact_path={out_path}",
        f"-artifact_prefix={out_path.parent}/", str(artifact),
    ]
    _run(argv, MINIMIZE_TIMEOUT_SECONDS)
    return out_path.exists() and out_path.stat().st_size > 0


def _replay_signature(binary: str, unit: Path) -> Optional[str]:
    """Replay one input and return its signature, or None if it did not crash."""
    _, output = _run([binary, str(unit)], REPLAY_TIMEOUT_SECONDS)
    report = _parse_report(output)
    if report is None:
        return None
    sanitizer, bug_class, _, frames = report
    return _signature(sanitizer, bug_class, frames)


def _is_deterministic(binary: str, unit: Path, expected: str) -> bool:
    """The gate's determinism clause: same signature on every independent replay."""
    return all(_replay_signature(binary, unit) == expected for _ in range(DETERMINISM_REPLAYS))


def _collect_artifacts(artifacts_dir: Path) -> list[Path]:
    if not artifacts_dir.is_dir():
        return []
    found = [
        path for path in artifacts_dir.iterdir()
        if path.is_file() and path.name.startswith(TRIAGED_PREFIXES)
    ]
    return sorted(found, key=lambda p: p.stat().st_mtime)


def _highest_coverage(text: str) -> tuple[int, int, int]:
    best = (0, 0, 0)
    for match in COVERAGE_RE.finditer(text):
        cov = int(match.group("cov"))
        if cov >= best[0]:
            best = (cov, int(match.group("ft")), int(match.group("corp") or 0))
    return best


def _parse_coverage(coverage_log: Path, fuzz_log: Path) -> tuple[int, int, int]:
    """Edge coverage from the dedicated corpus replay, or the campaign log.

    The zero-mutation replay is the authoritative number. It can be missing when
    the replay itself was killed by its timeout, so the campaign log's own high
    water mark is the fallback rather than silently reporting zero coverage.
    """
    if coverage_log.is_file():
        best = _highest_coverage(coverage_log.read_text("utf-8", "replace"))
        if best[0] > 0:
            return best
    if fuzz_log.is_file():
        return _highest_coverage(fuzz_log.read_text("utf-8", "replace"))
    return 0, 0, 0


def _parse_executed_units(fuzz_log: Path) -> int:
    if not fuzz_log.is_file():
        return 0
    text = fuzz_log.read_text("utf-8", "replace")
    counters = [int(v) for v in EXECUTED_UNITS_RE.findall(text)]
    counters += [int(v) for v in FORK_RUNS_RE.findall(text)]
    return max(counters, default=0)


def _parse_cpu_seconds(cpu_file: Path) -> float:
    """GNU time '%U %S %e' output; includes reaped children, i.e. fork workers."""
    if not cpu_file.is_file():
        return 0.0
    for line in reversed(cpu_file.read_text("utf-8", "replace").splitlines()):
        parts = line.split()
        if len(parts) >= 2:
            try:
                return round(float(parts[0]) + float(parts[1]), 2)
            except ValueError:
                continue
    return 0.0


def _corpus_stats(corpus_dir: Path) -> tuple[int, int]:
    if not corpus_dir.is_dir():
        return 0, 0
    units = [p for p in corpus_dir.iterdir() if p.is_file()]
    return len(units), sum(p.stat().st_size for p in units)


def _triage(binary: str, artifacts: list[Path], start_epoch: int) -> list[ConfirmedBug]:
    """Dedup by stack signature, then apply the minimise + determinism gate."""
    representatives: dict[str, ConfirmedBug] = {}

    for artifact in artifacts:
        _, output = _run([binary, str(artifact)], REPLAY_TIMEOUT_SECONDS)
        report = _parse_report(output)
        seen_at = int(artifact.stat().st_mtime) - start_epoch
        if report is None:
            # Not sanitizer-confirmed on replay -> the gate rejects it outright.
            signature = _signature("none", "not-reproducible", [artifact.name])
            representatives.setdefault(signature, ConfirmedBug(
                signature=signature, sanitizer="none", bug_class="not-reproducible",
                detail="artifact did not produce a sanitizer report on replay",
                top_frames=[], artifact=str(artifact),
                artifact_bytes=artifact.stat().st_size, minimized_artifact=None,
                minimized_bytes=None, first_seen_seconds=max(seen_at, 0),
                duplicate_artifacts=0, sanitizer_confirmed=False, minimized=False,
                deterministic=False, confirmed=False,
                reject_reason="no sanitizer report on replay",
            )).duplicate_artifacts += 1
            continue

        sanitizer, bug_class, detail, frames = report
        signature = _signature(sanitizer, bug_class, frames)
        if signature in representatives:
            representatives[signature].duplicate_artifacts += 1
            continue

        representatives[signature] = ConfirmedBug(
            signature=signature, sanitizer=sanitizer, bug_class=bug_class,
            detail=detail[:400], top_frames=frames, artifact=str(artifact),
            artifact_bytes=artifact.stat().st_size, minimized_artifact=None,
            minimized_bytes=None, first_seen_seconds=max(seen_at, 0),
            duplicate_artifacts=0, sanitizer_confirmed=True, minimized=False,
            deterministic=False, confirmed=False,
        )

    for bug in representatives.values():
        if not bug.sanitizer_confirmed:
            continue
        artifact = Path(bug.artifact)
        minimized = artifact.parent / f"min-{artifact.name}"
        if _minimize(binary, artifact, minimized):
            bug.minimized = True
            bug.minimized_artifact = str(minimized)
            bug.minimized_bytes = minimized.stat().st_size
            unit_to_check = minimized
        else:
            bug.reject_reason = "minimisation produced no reproducing input"
            unit_to_check = artifact

        bug.deterministic = _is_deterministic(binary, unit_to_check, bug.signature)
        bug.confirmed = bug.sanitizer_confirmed and bug.minimized and bug.deterministic
        if not bug.confirmed and bug.reject_reason is None:
            bug.reject_reason = "minimised input did not replay deterministically"

    return sorted(representatives.values(), key=lambda b: (b.first_seen_seconds or 0))


def _build_row(args: argparse.Namespace, bugs: list[ConfirmedBug],
               artifacts: list[Path], build: dict) -> TargetBaseline:
    cov, features, _ = _parse_coverage(Path(args.coverage_log), Path(args.fuzz_log))
    corpus_units, corpus_bytes = _corpus_stats(Path(args.corpus_dir))
    executed = _parse_executed_units(Path(args.fuzz_log))
    wall = max(args.end_epoch - args.start_epoch, 0)
    confirmed = [b for b in bugs if b.confirmed]
    memory_safety = [b for b in confirmed
                     if b.sanitizer in ("AddressSanitizer", "LeakSanitizer", "MemorySanitizer")
                     and b.bug_class not in NON_MEMORY_SAFETY_CLASSES]
    resource_leaks = [b for b in confirmed if b.bug_class in NON_MEMORY_SAFETY_CLASSES]
    first_crash = min((int(p.stat().st_mtime) - args.start_epoch for p in artifacts), default=None)
    first_confirmed = min((b.first_seen_seconds for b in confirmed
                           if b.first_seen_seconds is not None), default=None)

    return TargetBaseline(
        target=build["target"], kind=build["kind"], source_url=build["source_url"],
        known_bug_reference=build["known_bug_reference"], status="fuzzed",
        build_seconds=build.get("build_seconds", 0),
        fuzz_budget_seconds=args.budget_seconds, fuzz_wall_seconds=wall,
        fuzz_cpu_seconds=_parse_cpu_seconds(Path(args.cpu_file)),
        executed_units=executed,
        execs_per_second=round(executed / wall, 1) if wall else 0.0,
        edge_coverage=cov, features=features,
        corpus_units=corpus_units, corpus_bytes=corpus_bytes,
        crash_artifacts=len(artifacts),
        time_to_first_crash_seconds=max(first_crash, 0) if first_crash is not None else None,
        time_to_first_confirmed_bug_seconds=first_confirmed,
        unique_signatures=len(bugs), confirmed_unique_bugs=len(confirmed),
        confirmed_memory_safety_bugs=len(memory_safety),
        confirmed_resource_leak_bugs=len(resource_leaks),
        bugs=[asdict(b) for b in bugs],
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-json", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--artifacts-dir", required=True)
    parser.add_argument("--corpus-dir", required=True)
    parser.add_argument("--fuzz-log", required=True)
    parser.add_argument("--coverage-log", required=True)
    parser.add_argument("--cpu-file", required=True)
    parser.add_argument("--start-epoch", type=int, required=True)
    parser.add_argument("--end-epoch", type=int, required=True)
    parser.add_argument("--budget-seconds", type=int, required=True)
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    build = json.loads(Path(args.build_json).read_text("utf-8"))

    os.environ.setdefault("ASAN_OPTIONS", "detect_leaks=1:symbolize=1:print_stacktrace=1")
    os.environ.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")

    artifacts = _collect_artifacts(Path(args.artifacts_dir))
    bugs = _triage(args.binary, artifacts, args.start_epoch)
    row = _build_row(args, bugs, artifacts, build)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(asdict(row), indent=2), "utf-8")
    print(f"{row.target}: artifacts={row.crash_artifacts} unique={row.unique_signatures} "
          f"confirmed={row.confirmed_unique_bugs} cov={row.edge_coverage} "
          f"ttfc={row.time_to_first_crash_seconds}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
