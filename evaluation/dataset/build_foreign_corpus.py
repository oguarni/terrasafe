#!/usr/bin/env python3
"""Build the third-party (KICS) labelled corpus for the evaluation harness.

Reads the KICS Terraform/AWS query fixtures, applies the audited mapping in
``evaluation.kics_mapping``, and emits a corpus in the *exact* schema the home
harness already consumes (``taxonomy`` + ``cases: {id: {dir, file, expected}}``)
so ``evaluate.py`` scores it with the same runners/metrics — nothing is rebuilt.

Each KICS ``test/positive*.tf`` becomes a positive case (``expected = [target]``)
and each ``test/negative*.tf`` a negative case (``expected = []``). Every case
also carries a ``target`` category (for target-slice scoring) plus provenance
metadata (KICS query id, resource types, whether the fixture is within
TerraVault's rule scope).

Curation policy (symmetric across all four tools, so no tool is advantaged):

* Only ``*.tf`` files are imported; ``positive_expected_result.json`` etc. skip.
* A fixture with **no** ``resource`` block (external-module-only or
  variables-only) is dropped — no static scanner can analyse it, so keeping it
  would just add uniform false negatives.
* ``in_tv_scope`` is recorded, not used to drop anything: it marks whether the
  fixture declares a resource type TerraVault's rule for that category inspects,
  so the report can separate genuine detection quality from resource-coverage
  gaps.

Usage::

    python -m evaluation.dataset.build_foreign_corpus \
        --kics-root /path/to/kics/assets/queries/terraform/aws \
        --out-dir   evaluation/dataset/foreign

The output directory is self-contained: point ``evaluate.py`` at it with
``--dataset-root <out-dir> --ground-truth <out-dir>/ground_truth_foreign.yaml``.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from evaluation import kics_mapping
from evaluation.taxonomy import TAXONOMY

# Matches a top-level HCL resource declaration: `resource "aws_s3_bucket" "x" {`.
_RESOURCE_RE = re.compile(r'(?m)^\s*resource\s+"([A-Za-z0-9_]+)"\s+"')
# KICS test files are named positive*.tf / negative*.tf; anything else is skipped.
_LABEL_RE = re.compile(r"^(positive|negative)\w*\.tf$")


@dataclass
class BuildStats:
    """Audit trail for one corpus build (written to build_manifest.json)."""

    imported: int = 0
    positives: int = 0
    negatives: int = 0
    in_scope: int = 0
    out_of_scope: int = 0
    dropped_no_resource: List[str] = field(default_factory=list)
    per_category: Dict[str, int] = field(default_factory=dict)


def _resource_types(tf_text: str) -> List[str]:
    """Return the distinct AWS resource types declared in a .tf fixture."""
    return sorted({m.group(1) for m in _RESOURCE_RE.finditer(tf_text)})


def _label_of(filename: str) -> Optional[str]:
    """'positive' | 'negative' from a KICS fixture filename, else None."""
    m = _LABEL_RE.match(filename)
    return m.group(1) if m else None


def _query_metadata(query_dir: Path) -> Dict[str, str]:
    """Best-effort read of KICS metadata.json (id / queryName / severity)."""
    meta_path = query_dir / "metadata.json"
    if not meta_path.exists():
        return {}
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {
        "id": raw.get("id", ""),
        "queryName": raw.get("queryName", ""),
        "severity": raw.get("severity", ""),
    }


def build(kics_root: Path, out_dir: Path) -> BuildStats:
    """Materialise the foreign corpus under ``out_dir`` and return audit stats."""
    cases_root = out_dir / "cases"
    if cases_root.exists():
        shutil.rmtree(cases_root)
    cases_root.mkdir(parents=True, exist_ok=True)

    stats = BuildStats()
    cases: Dict[str, dict] = {}

    for query in kics_mapping.INCLUDED:
        query_dir = kics_root / query.directory
        test_dir = query_dir / "test"
        if not test_dir.is_dir():
            raise FileNotFoundError(
                f"KICS query fixtures not found: {test_dir}. Is --kics-root the "
                "'assets/queries/terraform/aws' directory of a KICS checkout?"
            )
        meta = _query_metadata(query_dir)

        for tf_file in sorted(test_dir.glob("*.tf")):
            label = _label_of(tf_file.name)
            if label is None:
                continue
            tf_text = tf_file.read_text(encoding="utf-8")
            resources = _resource_types(tf_text)
            case_id = f"{query.directory}__{tf_file.stem}"

            if not resources:
                stats.dropped_no_resource.append(case_id)
                continue

            in_scope = any(r in query.tv_scope for r in resources)
            case_dir = cases_root / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tf_file, case_dir / "main.tf")

            cases[case_id] = {
                "dir": f"cases/{case_id}",
                "file": f"cases/{case_id}/main.tf",
                "description": f"{meta.get('queryName', query.directory)} "
                               f"[{label}] ({tf_file.name})",
                "target": query.category,
                "expected": [query.category] if label == "positive" else [],
                "label": label,
                "resource_types": resources,
                "in_tv_scope": in_scope,
                "kics_query": query.directory,
                "kics_id": meta.get("id", ""),
                "kics_severity": meta.get("severity", ""),
            }

            stats.imported += 1
            stats.positives += label == "positive"
            stats.negatives += label == "negative"
            stats.in_scope += in_scope
            stats.out_of_scope += not in_scope
            stats.per_category[query.category] = \
                stats.per_category.get(query.category, 0) + 1

    manifest = {
        "source": "KICS (Checkmarx) terraform/aws query fixtures",
        "provenance": "Labels authored by KICS maintainers; imported unchanged. "
                      "KICS is not one of the compared tools, so the fixtures are "
                      "foreign to TerraVault, Checkov, tfsec and Terrascan alike.",
        "taxonomy": TAXONOMY,
        "categories_present": sorted(stats.per_category),
        "excluded_queries": kics_mapping.EXCLUDED,
        "stats": {
            "imported": stats.imported,
            "positives": stats.positives,
            "negatives": stats.negatives,
            "in_tv_scope": stats.in_scope,
            "out_of_tv_scope": stats.out_of_scope,
            "dropped_no_resource": stats.dropped_no_resource,
            "per_category": stats.per_category,
        },
    }

    gt = {
        "taxonomy": TAXONOMY,
        "notes": "Third-party corpus from KICS query fixtures (harness "
                 "extension A.2). Scored in target-slice mode: each fixture is "
                 "judged only for the concept KICS labels it with, because the "
                 "corpus does not carry complete multi-label ground truth. "
                 "`in_tv_scope` marks fixtures whose resource type TerraVault's "
                 "rule inspects; out-of-scope misses are coverage gaps by design.",
        "cases": cases,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ground_truth_foreign.yaml").write_text(
        yaml.safe_dump(gt, sort_keys=False, allow_unicode=True), encoding="utf-8")
    (out_dir / "build_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the KICS third-party corpus")
    ap.add_argument("--kics-root", required=True, type=Path,
                    help="path to <kics>/assets/queries/terraform/aws")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="output corpus directory (self-contained)")
    args = ap.parse_args()

    stats = build(args.kics_root.resolve(), args.out_dir.resolve())
    print(f"Imported {stats.imported} cases "
          f"({stats.positives} positive / {stats.negatives} negative) "
          f"into {args.out_dir}")
    print(f"  in TerraVault scope: {stats.in_scope} | "
          f"out of scope (coverage gap): {stats.out_of_scope}")
    print(f"  per category: {stats.per_category}")
    if stats.dropped_no_resource:
        print(f"  dropped {len(stats.dropped_no_resource)} module/var-only "
              f"fixtures (no resource block)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
