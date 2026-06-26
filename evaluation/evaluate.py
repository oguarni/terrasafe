#!/usr/bin/env python3
"""Orchestrate the TerraVault vs Checkov/tfsec/Terrascan comparison.

Pipeline:

1. Load the labelled corpus (``dataset/ground_truth.yaml``).
2. Scan every case with TerraVault in-process (capturing the hybrid rule/ML
   score breakdown) and with each competitor via Docker (``runners.py``).
3. Project every tool's findings onto the shared taxonomy (``taxonomy.py``) and
   audit that every observed competitor rule id is either mapped or knowingly
   ignored — nothing is dropped silently.
4. Compute detection metrics (``metrics.py``) and the hybrid-scoring analysis.
5. Write ``results/detections.json`` and ``results/metrics.json``; the report
   renderer turns the latter into Markdown/CSV/LaTeX.

Run from the repo root:  ``python -m evaluation.evaluate``  (add ``--use-cache``
to re-score from cached raw scanner output without re-invoking Docker).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Set

import yaml

from evaluation import runners, taxonomy
from evaluation.metrics import compute_tool_metrics

from terravault.infrastructure.parser import HCLParser
from terravault.domain.security_rules import SecurityRuleEngine
from terravault.infrastructure.ml_model import ModelManager, MLPredictor
from terravault.application.scanner import IntelligentSecurityScanner
from terravault.config.settings import get_settings

EVAL_DIR = Path(__file__).resolve().parent
DATASET = EVAL_DIR / "dataset"
RESULTS = EVAL_DIR / "results"


# ---------------------------------------------------------------------------
# TerraVault (native, in-process)
# ---------------------------------------------------------------------------
def _build_scanner() -> IntelligentSecurityScanner:
    return IntelligentSecurityScanner(
        HCLParser(), SecurityRuleEngine(), MLPredictor(ModelManager()),
    )


def run_terravault(scanner: IntelligentSecurityScanner, case_file: Path):
    """Scan one case; return (taxonomy categories, hybrid score breakdown)."""
    result = scanner.scan(str(case_file))
    if result.get("score", -1) == -1:
        return set(), {"error": result.get("error")}
    cats: Set[str] = set()
    for vuln in result.get("vulnerabilities", []):
        cat = taxonomy.terravault_category(vuln["message"])
        if cat:
            cats.add(cat)
    breakdown = {
        "rule_score": result["rule_based_score"],
        "ml_score": round(float(result["ml_score"]), 2),
        "final_score": result["score"],
        "confidence": result["confidence"],
        "n_vulns": len(result.get("vulnerabilities", [])),
        "scan_time_s": result.get("performance", {}).get("scan_time_seconds", 0.0),
    }
    return cats, breakdown


# ---------------------------------------------------------------------------
# Tool version metadata (reproducibility record)
# ---------------------------------------------------------------------------
def _competitor_versions() -> Dict[str, str]:
    probes = {
        "checkov": (runners.CHECKOV_IMAGE, ["--version"]),
        "tfsec": (runners.TFSEC_IMAGE, ["--version"]),
        "terrascan": (runners.TERRASCAN_IMAGE, ["version"]),
    }
    out: Dict[str, str] = {}
    for tool, (image, args) in probes.items():
        try:
            proc = subprocess.run(
                ["docker", "run", "--rm", "--user", "0", image, *args],
                capture_output=True, text=True, check=False, timeout=60,
            )
            line = (proc.stdout.strip().splitlines() or [""])[-1].strip()
            # Terrascan prints "version: v1.19.9"; checkov/tfsec print the bare version.
            out[tool] = line.split(":", 1)[-1].strip() if line.lower().startswith("version:") else line
        except subprocess.TimeoutExpired:
            out[tool] = "unknown"
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="TerraVault evaluation harness")
    ap.add_argument("--use-cache", action="store_true",
                    help="re-score from cached raw scanner output (no Docker re-run)")
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    gt = yaml.safe_load((DATASET / "ground_truth.yaml").read_text(encoding="utf-8"))
    tax: List[str] = gt["taxonomy"]
    cases = gt["cases"]

    ground_truth: Dict[str, Set[str]] = {cid: set(s["expected"]) for cid, s in cases.items()}
    negative_cases: Set[str] = {cid for cid, s in cases.items() if not s["expected"]}

    scanner = _build_scanner()

    per_case: Dict[str, dict] = {}
    hybrid: Dict[str, dict] = {}
    detections: Dict[str, Dict[str, Set[str]]] = {t: {} for t in ["terravault", *runners.COMPETITOR_RUNNERS]}
    raw_counts: Dict[str, int] = {t: 0 for t in runners.COMPETITOR_RUNNERS}
    durations: Dict[str, float] = {t: 0.0 for t in runners.COMPETITOR_RUNNERS}
    tv_scan_time = 0.0
    observed_ids: Dict[str, Set[str]] = {t: set() for t in runners.COMPETITOR_RUNNERS}

    for cid, spec in cases.items():
        case_dir = (DATASET / spec["dir"]).resolve()
        case_file = (DATASET / spec["file"]).resolve()

        tv_cats, breakdown = run_terravault(scanner, case_file)
        detections["terravault"][cid] = tv_cats
        breakdown["expected_n"] = len(spec["expected"])
        breakdown["is_negative"] = cid in negative_cases
        hybrid[cid] = breakdown
        tv_scan_time += float(breakdown.get("scan_time_s", 0.0) or 0.0)

        case_entry = {"expected": spec["expected"], "detections": {"terravault": sorted(tv_cats)}}

        for tool, runner in runners.COMPETITOR_RUNNERS.items():
            res = runner(case_dir, cid, use_cache=args.use_cache)
            if res.error:
                print(f"!! {tool}/{cid}: {res.error}")
                detections[tool][cid] = set()
                case_entry["detections"][tool] = []
                continue
            observed_ids[tool].update(res.rule_ids)
            cats = taxonomy.map_rule_ids(tool, res.rule_ids)
            detections[tool][cid] = cats
            raw_counts[tool] += len(res.findings)
            durations[tool] += res.duration_s
            case_entry["detections"][tool] = sorted(cats)

        per_case[cid] = case_entry

    # ---- audit: every observed competitor id mapped or knowingly ignored ----
    audit: Dict[str, List[str]] = {}
    for tool, ids in observed_ids.items():
        unmapped = sorted(i for i in ids if not taxonomy._single(tool, i))
        audit[tool] = unmapped

    # ---- metrics ----
    tool_metrics = {}
    for tool in ["terravault", *runners.COMPETITOR_RUNNERS]:
        tm = compute_tool_metrics(
            tool, tax, ground_truth, detections[tool], negative_cases,
            total_raw_findings=raw_counts.get(tool, sum(len(v) for v in detections[tool].values())),
            total_duration_s=durations.get(tool, tv_scan_time if tool == "terravault" else 0.0),
        )
        tool_metrics[tool] = tm.to_dict()

    # ---- hybrid-scoring analysis ----
    pos = [h for h in hybrid.values() if not h["is_negative"] and "error" not in h]
    neg = [h for h in hybrid.values() if h["is_negative"] and "error" not in h]

    def _mean(xs):
        return round(sum(xs) / len(xs), 2) if xs else 0.0

    hybrid_summary = {
        "positive_cases": len(pos),
        "negative_cases": len(neg),
        "mean_final_positive": _mean([h["final_score"] for h in pos]),
        "mean_final_negative": _mean([h["final_score"] for h in neg]),
        "mean_rule_positive": _mean([h["rule_score"] for h in pos]),
        "mean_rule_negative": _mean([h["rule_score"] for h in neg]),
        "mean_ml_positive": _mean([h["ml_score"] for h in pos]),
        "mean_ml_negative": _mean([h["ml_score"] for h in neg]),
    }

    versions = _competitor_versions()
    digests = runners.docker_image_versions()
    settings = get_settings()

    out = {
        "run_meta": {
            "generated_at": _dt.datetime.now().replace(microsecond=0).isoformat(),
            "corpus": {
                "n_cases": len(cases),
                "n_positive": len(cases) - len(negative_cases),
                "n_negative": len(negative_cases),
                "n_labels": sum(len(s["expected"]) for s in cases.values()),
            },
            "taxonomy": tax,
            "tools": {
                "terravault": {"version": settings.model_version, "native": True,
                               "approach": "rules (60%) + Isolation Forest ML (40%)"},
                "checkov": {"version": versions.get("checkov"), "image": digests.get("checkov")},
                "tfsec": {"version": versions.get("tfsec"), "image": digests.get("tfsec")},
                "terrascan": {"version": versions.get("terrascan"), "image": digests.get("terrascan")},
            },
            "mapping_audit_unmapped_ids": audit,
        },
        "tools": tool_metrics,
        "per_case": per_case,
        "terravault_hybrid": hybrid,
        "hybrid_summary": hybrid_summary,
    }

    (RESULTS / "metrics.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {RESULTS / 'metrics.json'}")

    # human-readable summary to stdout
    print("\n=== headline (shared-taxonomy detection) ===")
    print(f"{'tool':12s} {'P':>6s} {'R':>6s} {'F1':>6s} {'cats':>5s} {'FP-neg':>7s} {'raw':>5s} {'time(s)':>8s}")
    for tool in ["terravault", "checkov", "tfsec", "terrascan"]:
        m = tool_metrics[tool]
        print(f"{tool:12s} {m['micro_precision']:6.3f} {m['micro_recall']:6.3f} "
              f"{m['micro_f1']:6.3f} {m['categories_covered']:5d} {m['fp_on_negative']:7d} "
              f"{m['total_raw_findings']:5d} {m['total_duration_s']:8.2f}")

    print("\n=== mapping audit (unmapped competitor ids = ignored) ===")
    for tool, ids in audit.items():
        print(f"  {tool}: {len(ids)} unmapped -> {ids}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
