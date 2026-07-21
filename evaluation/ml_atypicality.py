#!/usr/bin/env python3
"""A.3 experiment — does the Isolation Forest flag *atypical-but-valid* configs?

The manuscript's honest ablation shows the ML component *compresses* the rules'
separation on the home corpus: every case there isolates a category the rules
already cover, so the anomaly detector never gets to contribute an independent
signal. This experiment builds the missing test. It asks the single open
question of the hybrid design:

    On real configurations the rules find nothing wrong with (rule-clean), does
    the Isolation Forest *selectively* flag the ones that are structurally
    atypical — or does it fire at random / on everything?

Design (kept non-circular on purpose):

* **Population.** Real ``.tf`` files (mined from the Terraform Registry / public
  GitHub — code the author did not write), deduplicated by content hash, each
  declaring at least one resource. We keep the **rule-clean** subset: files
  where the 11 rules report nothing. That is the only population where the ML
  can add anything the rules cannot.
* **Atypicality axis (independent of the ML).** Each config's 8-dim *structural*
  feature vector is scored by its Mahalanobis distance to the training feature
  distribution (Ledoit-Wolf-shrunk covariance). This is a Gaussian-distance
  measure, computed from the training data, *not* the Isolation Forest's tree
  isolation — so ``atypical`` is defined without reference to the model's own
  verdict.
* **Model signal.** The production model's ``decision_function`` gives a
  continuous anomaly score; ``predict == -1`` (equivalently the scanner's
  ``ml_score >= 50``) is the operational *flag*.

The decisive quantities are not "does correlation exist" (the IF and Mahalanobis
both measure distance-from-training, so *some* correlation is expected by
construction) but **selectivity**: the flag rate on the typical half vs. the
atypical decile, their **lift**, and whether the flagged rule-clean configs are
interpretably unusual (the top-N characterisation). Those separate a usable
orthogonal review signal from noise, and the verdict is left to the data.

Usage::

    python -m evaluation.ml_atypicality --corpus-dir corpus/modules \
        --model-dir models --out-dir evaluation/results/ml_atypicality
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
from dataclasses import dataclass, field
from multiprocessing import Pool
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.covariance import LedoitWolf
from sklearn.metrics import roc_auc_score
from scipy.stats import spearmanr

# Production code paths — reused verbatim so the experiment measures the shipped
# scanner, not a re-implementation.
from terravault.application.feature_extraction import FEATURE_NAMES
from terravault.application.scanner import IntelligentSecurityScanner
from terravault.domain.security_rules import SecurityRuleEngine
from terravault.infrastructure.ml_model import ModelManager, MLPredictor
from terravault.infrastructure.parser import HCLParser

_ATYPICAL_QUANTILE = 0.90   # top decile of the atypicality axis == "atypical"
_TYPICAL_QUANTILE = 0.50    # bottom half == "typical"
_TOP_N = 15                 # most-anomalous rule-clean configs to characterise


@dataclass
class ConfigRecord:
    """One scanned real configuration and everything the experiment needs of it."""

    path: str
    rule_clean: bool
    n_rule_findings: int
    features: List[float]           # 8-dim structural vector, FEATURE_NAMES order
    ml_score: float                 # scanner risk score (>= 50 => IF-flagged)
    confidence: str


@dataclass
class ScanStats:
    """Audit trail for the corpus pass (written into the metrics file)."""

    seen: int = 0
    deduped: int = 0
    oversize: int = 0
    no_resource: int = 0
    scan_errors: int = 0
    kept: int = 0
    per_error: Dict[str, int] = field(default_factory=dict)


def build_scanner(model_dir: str) -> IntelligentSecurityScanner:
    """Wire the production scanner (same DI as ``terravault.cli._build_scanner``)."""
    model_manager = ModelManager(model_dir=model_dir)
    return IntelligentSecurityScanner(
        HCLParser(), SecurityRuleEngine(), MLPredictor(model_manager))


def _vector(features_analyzed: Dict[str, float]) -> List[float]:
    """Project the scanner's ``features_analyzed`` dict onto FEATURE_NAMES order."""
    return [float(features_analyzed[name]) for name in FEATURE_NAMES]


def iter_tf_files(root: Path) -> List[Path]:
    """All ``.tf`` files under ``root`` (recursive), sorted for determinism."""
    return sorted(p for p in root.rglob("*.tf") if p.is_file())


def _dedup_and_filter(root: Path, max_file_kb: Optional[int], max_files: Optional[int],
                      stats: ScanStats) -> List[str]:
    """Parent-side fast pass: the unique, size-bounded file list (updates stats).

    Hashing is I/O-bound and cheap; doing it once here keeps the expensive
    parse+rules+ML scan free of duplicate and pathological-size work — which is
    what lets the scan below parallelise cleanly.
    """
    seen_hashes: set[str] = set()
    unique: List[str] = []
    limit = max_file_kb * 1024 if max_file_kb else None
    for path in iter_tf_files(root):
        if max_files is not None and len(unique) >= max_files:
            break
        stats.seen += 1
        try:
            data = path.read_bytes()
        except OSError:
            stats.scan_errors += 1
            continue
        if limit is not None and len(data) > limit:
            stats.oversize += 1
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen_hashes:
            stats.deduped += 1
            continue
        seen_hashes.add(digest)
        unique.append(str(path))
    return unique


# One scanner per worker process, built once in the initialiser (model load is
# not cheap); scanning is CPU-bound pure-Python HCL parsing, so process-level
# parallelism scales near-linearly with cores.
_WORKER_SCANNER: Optional[IntelligentSecurityScanner] = None
_WORKER_TIMEOUT: int = 0
_HAS_ALARM = hasattr(signal, "SIGALRM")


class _ScanTimeout(BaseException):
    """Raised via SIGALRM to abandon a file whose scan blows the time budget.

    Subclasses BaseException (not Exception) so it propagates past the parser's
    and scanner's broad ``except Exception`` handlers straight to the worker —
    a real-world corpus always has a few pathological files whose HCL parse
    backtracks for minutes and would otherwise pin a worker (mirrors the guard
    in ``scripts/corpus_train.py``).
    """


def _alarm_handler(signum: int, frame: object) -> None:  # pragma: no cover - signal path
    raise _ScanTimeout()


def _worker_init(model_dir: str, timeout_s: int = 0) -> None:
    global _WORKER_SCANNER, _WORKER_TIMEOUT  # pylint: disable=global-statement
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    _WORKER_SCANNER = build_scanner(model_dir)
    _WORKER_TIMEOUT = timeout_s if _HAS_ALARM else 0
    if _WORKER_TIMEOUT:
        signal.signal(signal.SIGALRM, _alarm_handler)


def _worker_scan(path_str: str) -> Tuple[str, object]:
    """Scan one file; return a tagged outcome the parent tallies cheaply."""
    assert _WORKER_SCANNER is not None
    if _WORKER_TIMEOUT:
        signal.alarm(_WORKER_TIMEOUT)
    try:
        result = _WORKER_SCANNER.scan(path_str)
    except _ScanTimeout:
        return ("error", "ScanTimeout")
    finally:
        if _WORKER_TIMEOUT:
            signal.alarm(0)
    if result.get("score", -1) == -1:
        return ("error", result.get("error_type", "Unknown"))
    vec = _vector(result["features_analyzed"])
    if vec[0] < 1:  # resource_count == 0 -> no resource block
        return ("no_resource", None)
    vulns = result.get("vulnerabilities", [])
    return ("ok", ConfigRecord(
        path=path_str, rule_clean=len(vulns) == 0, n_rule_findings=len(vulns),
        features=vec, ml_score=float(result["ml_score"]),
        confidence=str(result.get("confidence", "")),
    ))


def _tally(outcome: Tuple[str, object], stats: ScanStats,
           records: List[ConfigRecord]) -> None:
    tag, payload = outcome
    if tag == "ok":
        records.append(payload)  # type: ignore[arg-type]
        stats.kept += 1
    elif tag == "no_resource":
        stats.no_resource += 1
    else:
        etype = str(payload)
        stats.scan_errors += 1
        stats.per_error[etype] = stats.per_error.get(etype, 0) + 1


def scan_corpus(root: Path, model_dir: str, workers: int = 0,
                max_files: Optional[int] = None, max_file_kb: Optional[int] = None,
                timeout_s: int = 20) -> Tuple[List[ConfigRecord], ScanStats]:
    """Scan every unique ``.tf`` under ``root``; return records + an audit trail.

    Deduplicates by content hash and drops oversize / parser-rejected /
    no-resource files (the extractor emits the all-default secure vector for the
    last, uninformative for an atypicality study). ``workers > 1`` parallelises
    the scan across processes; ``max_files`` caps the unique files scanned
    (bounds runtime); ``max_file_kb`` skips pathological giant blobs; each file's
    scan is abandoned after ``timeout_s`` seconds so a poison file cannot pin a
    worker (reported as a ``ScanTimeout`` error).
    """
    stats = ScanStats()
    unique = _dedup_and_filter(root, max_file_kb, max_files, stats)
    records: List[ConfigRecord] = []

    def _progress() -> None:
        done = stats.kept + stats.no_resource + stats.scan_errors
        if done and done % 4000 == 0:
            print(f"  scanned {done}/{len(unique)} unique ({stats.kept} kept)",
                  file=sys.stderr)

    if workers and workers > 1:
        with Pool(workers, initializer=_worker_init,
                  initargs=(model_dir, timeout_s)) as pool:
            for outcome in pool.imap_unordered(_worker_scan, unique, chunksize=8):
                _tally(outcome, stats, records)
                _progress()
    else:
        _worker_init(model_dir, timeout_s)
        for path_str in unique:
            _tally(_worker_scan(path_str), stats, records)
            _progress()
    return records, stats


def mahalanobis_atypicality(feats: np.ndarray, training: np.ndarray) -> np.ndarray:
    """Mahalanobis distance of each config to the training distribution.

    Ledoit-Wolf shrinkage keeps the covariance well-conditioned despite the
    heavily skewed count features. Returns the (non-squared) distance so the
    scale is interpretable; monotone in the squared distance either way.
    """
    lw = LedoitWolf().fit(training)
    return np.sqrt(np.clip(lw.mahalanobis(feats), 0.0, None))


def isolation_forest_signal(feats: np.ndarray, model_dir: str) -> Tuple[np.ndarray, np.ndarray]:
    """Return (continuous anomaly score, boolean flagged) from the shipped model.

    ``anomaly`` is ``-decision_function`` so that *higher = more anomalous*;
    ``flagged`` is ``predict == -1`` — identical to the scanner's ``ml_score >= 50``
    rule, recomputed in batch for the continuous score.
    """
    model, scaler = ModelManager(model_dir=model_dir).load_model()
    scaled = scaler.transform(feats)
    anomaly = -model.decision_function(scaled)
    flagged = model.predict(scaled) == -1
    return anomaly, flagged


def _rate(mask: np.ndarray) -> Tuple[int, int, float]:
    """(count_true, total, fraction) for a boolean mask; 0.0 fraction if empty."""
    n = int(mask.size)
    t = int(mask.sum())
    return t, n, (t / n if n else 0.0)


def _bin_flag_rates(maha: np.ndarray, flagged: np.ndarray) -> List[dict]:
    """Flag rate within Mahalanobis bands <p50, p50-p90, p90-p99, >=p99."""
    edges = [np.percentile(maha, p) for p in (50, 90, 99)]
    bands = [
        ("<p50 (typical)", maha < edges[0]),
        ("p50-p90", (maha >= edges[0]) & (maha < edges[1])),
        ("p90-p99", (maha >= edges[1]) & (maha < edges[2])),
        (">=p99 (extreme)", maha >= edges[2]),
    ]
    out = []
    for label, mask in bands:
        t, n, r = _rate(flagged[mask])
        out.append({"band": label, "flagged": t, "n": n, "flag_rate": round(r, 4)})
    return out


def _training_overlap_mask(feats: np.ndarray, training: np.ndarray) -> np.ndarray:
    """True where a config's feature vector exactly matches a training vector.

    Configs from modules the model trained on reproduce their exact 8-dim
    vector; excluding them yields a held-out subset (a cheap, honest proxy for
    generalisation without a second expensive corpus mine).
    """
    train_set = {tuple(np.round(row, 6)) for row in training}
    return np.array([tuple(np.round(row, 6)) in train_set for row in feats], dtype=bool)


def _analyze_subpop(maha: np.ndarray, anomaly: np.ndarray, flagged: np.ndarray,
                    records: List[ConfigRecord]) -> Optional[dict]:
    """Full selectivity/orthogonality analysis for one rule-clean subpopulation.

    ``records`` is aligned with the arrays (already filtered to the subpop).
    Returns None if the subpopulation is too small to stratify.
    """
    n = int(maha.size)
    if n < 10:
        return None
    ct, _, crate = _rate(flagged)

    atypical = maha >= np.percentile(maha, _ATYPICAL_QUANTILE * 100)
    typical = maha < np.percentile(maha, _TYPICAL_QUANTILE * 100)
    at, an, arate = _rate(flagged[atypical])
    tt, tn, trate = _rate(flagged[typical])
    lift = (arate / trate) if trate > 0 else None

    auc = (roc_auc_score(atypical.astype(int), anomaly)
           if 0 < atypical.sum() < atypical.size else None)
    rho, pval = spearmanr(anomaly, maha)
    flag_share_atypical = (float((flagged & atypical).sum() / flagged.sum())
                           if flagged.sum() else None)

    order = np.argsort(-maha)[:_TOP_N]
    top = [{
        "path": records[i].path,
        "mahalanobis": round(float(maha[i]), 3),
        "if_anomaly": round(float(anomaly[i]), 4),
        "flagged": bool(flagged[i]),
        "features": dict(zip(FEATURE_NAMES, [round(x, 3) for x in records[i].features])),
    } for i in order]

    return {
        "n": n,
        "overall_flag_rate": round(crate, 4),
        "flagged": ct,
        "atypical_decile": {"flagged": at, "n": an, "flag_rate": round(arate, 4)},
        "typical_half": {"flagged": tt, "n": tn, "flag_rate": round(trate, 4)},
        "selectivity_lift": (round(lift, 3) if lift is not None else None),
        "ranking_auc": (round(float(auc), 4) if auc is not None else None),
        "spearman_rho": round(float(rho), 4),
        "spearman_p": float(f"{pval:.3e}"),
        "flag_share_in_atypical_tail": (round(flag_share_atypical, 4)
                                        if flag_share_atypical is not None else None),
        "flag_bands": _bin_flag_rates(maha, flagged),
        "top_atypical": top,
    }


def compute_metrics(records: List[ConfigRecord], training: np.ndarray,
                    model_dir: str, stats: ScanStats) -> dict:
    """Assemble the full metrics dict from the scanned records."""
    feats = np.array([r.features for r in records], dtype=np.float64)
    maha = mahalanobis_atypicality(feats, training)
    anomaly, flagged = isolation_forest_signal(feats, model_dir)
    clean = np.array([r.rule_clean for r in records], dtype=bool)
    overlap = _training_overlap_mask(feats, training)

    result: dict = {
        "population": {
            "kept": stats.kept, "seen": stats.seen, "deduped": stats.deduped,
            "oversize": stats.oversize,
            "no_resource": stats.no_resource, "scan_errors": stats.scan_errors,
            "scan_error_types": stats.per_error,
            "rule_clean": int(clean.sum()), "rule_flagged": int((~clean).sum()),
            "train_vector_overlap": int(overlap.sum()),
            "rule_clean_held_out": int((clean & ~overlap).sum()),
        },
        "feature_names": list(FEATURE_NAMES),
    }

    clean_records = [r for r, keep in zip(records, clean) if keep]
    # Headline: full rule-clean population (rules silent -> only ML can speak).
    full = _analyze_subpop(maha[clean], anomaly[clean], flagged[clean], clean_records)
    if full is None:
        result["error"] = "too few rule-clean configs to stratify (<10)"
        return result
    result["rule_clean_analysis"] = full

    # Held-out: rule-clean configs whose exact vector the model did not train on.
    ho = clean & ~overlap
    ho_records = [r for r, keep in zip(records, ho) if keep]
    held = _analyze_subpop(maha[ho], anomaly[ho], flagged[ho], ho_records)
    if held is not None:
        result["rule_clean_held_out_analysis"] = held

    # Orthogonality check: IF flag rate where the RULES already fire.
    if (~clean).any():
        rt, rn, rr = _rate(flagged[~clean])
        result["rule_flagged_analysis"] = {
            "n": rn, "flagged": rt, "flag_rate": round(rr, 4)}
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="A.3 atypical-but-valid ML experiment")
    ap.add_argument("--corpus-dir", required=True, type=Path,
                    help="directory of real .tf files (searched recursively)")
    ap.add_argument("--model-dir", default="models",
                    help="model dir (isolation_forest.pkl + scaler.pkl)")
    ap.add_argument("--training-data", default="models/training_data.npy", type=Path,
                    help="training feature matrix for the Mahalanobis reference")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="where ml_atypicality_metrics.json is written")
    ap.add_argument("--workers", type=int, default=0,
                    help="parallel scan processes (0/1 = single-process)")
    ap.add_argument("--max-files", type=int, default=None,
                    help="cap on unique files scanned (bounds runtime)")
    ap.add_argument("--max-file-kb", type=int, default=256,
                    help="skip .tf files larger than this many KB (giant blobs)")
    ap.add_argument("--scan-timeout", type=int, default=20,
                    help="per-file scan budget in seconds (poison-file guard)")
    args = ap.parse_args()

    training = np.load(args.training_data)
    records, stats = scan_corpus(args.corpus_dir.resolve(), args.model_dir,
                                 workers=args.workers, max_files=args.max_files,
                                 max_file_kb=args.max_file_kb, timeout_s=args.scan_timeout)
    if not records:
        print("No scannable configs found under --corpus-dir", file=sys.stderr)
        return 1

    metrics = compute_metrics(records, training, args.model_dir, stats)
    metrics["run_meta"] = {
        "corpus_dir": str(args.corpus_dir),
        "model_dir": str(args.model_dir),
        "model_version": ModelManager(model_dir=args.model_dir).get_current_version(),
        "training_vectors": int(training.shape[0]),
        "atypical_quantile": _ATYPICAL_QUANTILE,
        "typical_quantile": _TYPICAL_QUANTILE,
        "workers": args.workers,
        "max_files": args.max_files,
        "max_file_kb": args.max_file_kb,
        "scan_timeout_s": args.scan_timeout,
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / "ml_atypicality_metrics.json"
    out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    rca = metrics.get("rule_clean_analysis", {})
    print(f"kept {stats.kept} configs | rule-clean {metrics['population']['rule_clean']}")
    if rca:
        print(f"rule-clean flag rate {rca['overall_flag_rate']:.1%} | "
              f"atypical decile {rca['atypical_decile']['flag_rate']:.1%} vs "
              f"typical half {rca['typical_half']['flag_rate']:.1%} "
              f"(lift {rca['selectivity_lift']}) | AUC {rca['ranking_auc']}")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
