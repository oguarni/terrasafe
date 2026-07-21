"""Scanner runners for the TerraVault evaluation harness.

Each runner executes one scanner over a single isolated case directory and
returns the findings normalised to a common shape plus the wall-clock time it
took. Category mapping is *not* done here — that lives in ``taxonomy.py`` so the
raw rule ids stay inspectable and the mapping can be audited independently.

Competitor tools run from their official Docker images. They are launched with
``--user 0`` because this repository is created under a restrictive umask
(directories ``drwxrwx---``); the Terrascan image runs as a non-root user that
would otherwise be unable to read the bind-mounted corpus and would silently
parse zero resources. Running as root inside a throwaway ``--rm`` container that
only reads a read-only mount keeps this safe.

TerraVault runs in-process (it is the tool under test, and there is no point
paying container overhead for it).
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

EVAL_DIR = Path(__file__).resolve().parent
RAW_DIR = EVAL_DIR / "results" / "raw"

# Pinned-by-tag competitor images. Exact resolved versions/digests are recorded
# in the run metadata so the comparison stays reproducible.
CHECKOV_IMAGE = "bridgecrew/checkov:latest"
TFSEC_IMAGE = "aquasec/tfsec:latest"
TERRASCAN_IMAGE = "tenable/terrascan:latest"

DOCKER_TIMEOUT = 180


@dataclass
class Finding:
    """One raw finding from a scanner, before category mapping."""

    rule_id: str
    severity: str = ""
    resource: str = ""


@dataclass
class RunResult:
    """Outcome of running one scanner over one case."""

    tool: str
    case_id: str
    findings: List[Finding] = field(default_factory=list)
    duration_s: float = 0.0
    from_cache: bool = False
    error: Optional[str] = None

    @property
    def rule_ids(self) -> List[str]:
        return [f.rule_id for f in self.findings]


# ---------------------------------------------------------------------------
# Docker plumbing
# ---------------------------------------------------------------------------
def _raw_path(tool: str, case_id: str, results_dir: Optional[Path] = None) -> Path:
    base = (results_dir / "raw") if results_dir else RAW_DIR
    return base / tool / f"{case_id}.json"


def _docker_cmd(image: str, mount: Path, dst: str, tool_args: List[str]) -> List[str]:
    return [
        "docker", "run", "--rm", "--user", "0",
        "-v", f"{mount}:{dst}:ro",
        image, *tool_args,
    ]


def _run_docker(image: str, mount: Path, dst: str, tool_args: List[str]) -> tuple[str, float]:
    """Run a scanner container; return (stdout, wall_clock_seconds).

    Non-zero exit is expected (scanners exit non-zero when they find issues), so
    the return code is ignored and only stdout is parsed.
    """
    cmd = _docker_cmd(image, mount, dst, tool_args)
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=DOCKER_TIMEOUT)
    duration = time.perf_counter() - start
    return proc.stdout, duration


def _load_or_run(
    tool: str, case_id: str, mount: Path, dst: str, tool_args: List[str],
    image: str, use_cache: bool, results_dir: Optional[Path] = None,
) -> tuple[dict, float, bool]:
    """Return (parsed_json, duration, from_cache) for one tool/case."""
    raw_path = _raw_path(tool, case_id, results_dir)
    if use_cache and raw_path.exists():
        try:
            return json.loads(raw_path.read_text(encoding="utf-8")), 0.0, True
        except json.JSONDecodeError:
            pass  # fall through to a fresh run

    stdout, duration = _run_docker(image, mount, dst, tool_args)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(stdout, encoding="utf-8")
    try:
        return json.loads(stdout), duration, False
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{tool}: could not parse JSON for {case_id}: {exc}") from exc


# ---------------------------------------------------------------------------
# Per-tool parsers (raw JSON -> findings)
# ---------------------------------------------------------------------------
def _parse_checkov(data) -> List[Finding]:
    blocks = data if isinstance(data, list) else [data]
    findings: List[Finding] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        failed = (block.get("results") or {}).get("failed_checks") or []
        for chk in failed:
            findings.append(Finding(
                rule_id=chk.get("check_id", ""),
                severity=(chk.get("severity") or "").upper(),
                resource=chk.get("resource", ""),
            ))
    return findings


def _parse_tfsec(data) -> List[Finding]:
    findings: List[Finding] = []
    for res in (data.get("results") or []):
        findings.append(Finding(
            rule_id=res.get("long_id", "") or res.get("rule_id", ""),
            severity=(res.get("severity") or "").upper(),
            resource=res.get("resource", ""),
        ))
    return findings


def _parse_terrascan(data) -> List[Finding]:
    violations = (data.get("results") or {}).get("violations") or []
    findings: List[Finding] = []
    for vio in violations:
        findings.append(Finding(
            rule_id=vio.get("rule_id", ""),
            severity=(vio.get("severity") or "").upper(),
            resource=vio.get("resource_name", ""),
        ))
    return findings


# ---------------------------------------------------------------------------
# Public runners
# ---------------------------------------------------------------------------
def run_checkov(case_dir: Path, case_id: str, use_cache: bool = False,
                results_dir: Optional[Path] = None) -> RunResult:
    try:
        data, dur, cached = _load_or_run(
            "checkov", case_id, case_dir, "/tf",
            ["-d", "/tf", "--framework", "terraform,secrets",
             "-o", "json", "--compact", "--quiet"],
            CHECKOV_IMAGE, use_cache, results_dir,
        )
        return RunResult("checkov", case_id, _parse_checkov(data), dur, cached)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return RunResult("checkov", case_id, error=str(exc))


def run_tfsec(case_dir: Path, case_id: str, use_cache: bool = False,
              results_dir: Optional[Path] = None) -> RunResult:
    try:
        data, dur, cached = _load_or_run(
            "tfsec", case_id, case_dir, "/src",
            ["/src", "-f", "json", "--no-color"],
            TFSEC_IMAGE, use_cache, results_dir,
        )
        return RunResult("tfsec", case_id, _parse_tfsec(data), dur, cached)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return RunResult("tfsec", case_id, error=str(exc))


def run_terrascan(case_dir: Path, case_id: str, use_cache: bool = False,
                  results_dir: Optional[Path] = None) -> RunResult:
    try:
        data, dur, cached = _load_or_run(
            "terrascan", case_id, case_dir, "/iac",
            ["scan", "-i", "terraform", "-t", "aws", "-d", "/iac", "-o", "json"],
            TERRASCAN_IMAGE, use_cache, results_dir,
        )
        return RunResult("terrascan", case_id, _parse_terrascan(data), dur, cached)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return RunResult("terrascan", case_id, error=str(exc))


COMPETITOR_RUNNERS = {
    "checkov": run_checkov,
    "tfsec": run_tfsec,
    "terrascan": run_terrascan,
}


def docker_image_versions() -> Dict[str, str]:
    """Resolve image digests for the run metadata (reproducibility record)."""
    out: Dict[str, str] = {}
    for name, image in (("checkov", CHECKOV_IMAGE), ("tfsec", TFSEC_IMAGE),
                        ("terrascan", TERRASCAN_IMAGE)):
        try:
            proc = subprocess.run(
                ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
                capture_output=True, text=True, check=False, timeout=30,
            )
            out[name] = proc.stdout.strip() or image
        except subprocess.TimeoutExpired:
            out[name] = image
    return out


if __name__ == "__main__":
    # Discovery mode: run every competitor over every case, cache raw output,
    # and print the harvested rule ids so the taxonomy maps can be built/audited.
    import yaml

    gt = yaml.safe_load((EVAL_DIR / "dataset" / "ground_truth.yaml").read_text())
    harvest: Dict[str, Dict[str, list]] = {t: {} for t in COMPETITOR_RUNNERS}
    for cid, spec in gt["cases"].items():
        case_dir = (EVAL_DIR / "dataset" / spec["dir"]).resolve()
        for tool, runner in COMPETITOR_RUNNERS.items():
            res = runner(case_dir, cid, use_cache=False)
            if res.error:
                print(f"  !! {tool}/{cid}: {res.error}")
                continue
            for fid in sorted(set(res.rule_ids)):
                harvest[tool].setdefault(fid, []).append(cid)
            print(f"  {tool:9s}/{cid:20s} {len(res.findings):2d} findings "
                  f"({res.duration_s:.1f}s)")

    print("\n===== HARVESTED RULE IDS =====")
    for tool, ids in harvest.items():
        print(f"\n--- {tool} ({len(ids)} distinct ids) ---")
        for fid, cases in sorted(ids.items()):
            print(f"  {fid:48s} {','.join(cases)}")
