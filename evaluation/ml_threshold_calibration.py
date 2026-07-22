#!/usr/bin/env python3
"""A.3 follow-up — calibrate the anomaly cutoff and re-test it on a second corpus.

A.3 settled the hybrid design's open question: where the 11 rules are silent, the
Isolation Forest's *ranking* is real, orthogonal and selective. It left two
problems open, and this harness attacks both.

**(A) Threshold calibration.** ``contamination=0.1`` is baked into the trained
model, yet ``predict == -1`` fires on 37,5% of the rule-clean population. The
ranking is sound (AUC 0,9151), so the fix is a *percentile cutoff on the raw
anomaly score*, not the trained-in boolean. Two things follow:

* every scanned config's raw score, Mahalanobis distance and rule verdict are
  dumped to ``per_config_scores.csv.gz`` (plus the model's own training-score
  distribution to ``training_reference_scores.csv.gz``), so **any** cutoff can be
  re-derived offline, forever, without re-running the compute; and
* a sweep evaluates candidate cutoffs taken from percentiles of the *training*
  score distribution — an absolute, model-intrinsic operating point that ships as
  a constant instead of being refitted per corpus.

**(B) Second-corpus external check.** Does the 2,0% typical-half flag rate hold
outside the mine A.3 used? Corpora are scanned in order and every corpus after
the first drops files whose content hash an earlier corpus already contributed,
so disjointness is *proved by hash*, not asserted (``excluded_shared`` plus the
residual-intersection check in the metrics file).

Honest limits carried forward from A.3 — they still bind here: (a) the model
trained on essentially all public Terraform, so this remains an
**in-distribution** study and a second corpus is a *disjoint sample*, not a
held-out distribution (``train_vector_overlap`` quantifies it per corpus);
(b) the Mahalanobis<->IF correlation is partly circular by construction, so the
load-bearing evidence is orthogonality and selectivity, not rho; (c) atypicality
here is pure resource-graph shape, so *structurally unusual is not evidence of
vulnerability* — the signal prioritises human review and must never be an
automatic gate. None of this touches the manuscript's ablation (rules alone
separate by 33,3 pts, hybrid 21,4, ML alone 3,2): on the home corpus the ML still
compresses the rules' separation.

Usage::

    python -m evaluation.ml_threshold_calibration \
        --corpus home=corpus_home --corpus second=corpus_second \
        --model-dir models --training-data models/training_data.npy \
        --out-dir evaluation/results/ml_calibration --workers 16
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

import numpy as np
from scipy.stats import spearmanr
from sklearn.metrics import roc_auc_score

from evaluation.ml_atypicality import (
    ATYPICAL_QUANTILE,
    TYPICAL_QUANTILE,
    ConfigRecord,
    ScanStats,
    count_rate,
    flag_rate_bands,
    mahalanobis_atypicality,
    scan_corpus_indexed,
    training_overlap_mask,
)
from terravault.application.feature_extraction import FEATURE_NAMES
from terravault.infrastructure.ml_model import ModelManager

# Cutoff candidates, as percentiles of the score distribution the model was
# fitted on. p90 is (by construction of sklearn's ``offset_``) the trained-in
# contamination=0.1 point, so the sweep brackets today's behaviour on both sides.
_DEFAULT_PERCENTILES: Tuple[float, ...] = (90.0, 95.0, 97.5, 99.0, 99.5, 99.9)

_MIN_SUBPOP = 10   # below this a stratified rate is noise, not a measurement

_CSV_COLUMNS: Tuple[str, ...] = (
    "corpus", "path", "sha256", "rule_clean", "n_rule_findings", "ml_score",
    "confidence", "if_score_samples", "if_decision_function", "if_anomaly",
    "if_predict_flag", "mahalanobis", "train_vector_match", *FEATURE_NAMES,
)


@dataclass(frozen=True)
class OperatingPoint:
    """A candidate cutoff on the anomaly score plus how it was derived.

    ``predict_native`` marks the shipped ``predict == -1`` verdict, which is
    evaluated through the model itself rather than by comparing against 0.0 so
    the status-quo row of the sweep is exactly what production does today.
    """

    name: str
    anomaly_cutoff: float
    source: str
    predict_native: bool = False


@dataclass
class ScoredCorpus:
    """One scanned corpus with every per-config quantity the sweep needs."""

    label: str
    root: Path
    records: List[ConfigRecord]
    stats: ScanStats
    digest_by_path: Dict[str, str]
    features: np.ndarray          # (n, 8) in FEATURE_NAMES order
    mahalanobis: np.ndarray       # distance to the training distribution
    score_samples: np.ndarray     # raw IF score (higher = more normal)
    decision: np.ndarray          # score_samples - offset_  (< 0 => predict -1)
    anomaly: np.ndarray           # -decision (higher = more anomalous)
    predict_flag: np.ndarray      # the trained-in contamination=0.1 verdict
    rule_clean: np.ndarray
    train_overlap: np.ndarray

    def digests(self) -> Set[str]:
        """Every unique content hash this corpus admitted to the scan."""
        return set(self.digest_by_path.values())


def parse_corpus_spec(spec: str) -> Tuple[str, Path]:
    """Parse a ``LABEL=PATH`` ``--corpus`` argument."""
    label, sep, raw = spec.partition("=")
    if not sep or not label.strip() or not raw.strip():
        raise argparse.ArgumentTypeError(
            f"--corpus expects LABEL=PATH (e.g. home=corpus_home), got {spec!r}")
    return label.strip(), Path(raw.strip())


def parse_percentiles(raw: str) -> List[float]:
    """Parse the comma-separated cutoff percentiles, validating the range."""
    values = [float(part) for part in raw.split(",") if part.strip()]
    for value in values:
        if not 0.0 < value < 100.0:
            raise argparse.ArgumentTypeError(
                f"--percentiles expects values in (0, 100), got {value}")
    return values


def model_scores(feats: np.ndarray, model: object, scaler: object) -> Tuple[
        np.ndarray, np.ndarray, np.ndarray]:
    """``(score_samples, decision_function, predict == -1)`` for a feature matrix.

    ``score_samples`` is kept alongside ``decision_function`` because it is the
    quantity independent of ``offset_``: re-deriving a cutoff offline stays valid
    even if the contamination the model was fitted with is later changed.
    """
    scaled = scaler.transform(feats)                    # type: ignore[attr-defined]
    return (model.score_samples(scaled),                # type: ignore[attr-defined]
            model.decision_function(scaled),            # type: ignore[attr-defined]
            model.predict(scaled) == -1)                # type: ignore[attr-defined]


def scan_and_score(label: str, root: Path, model_dir: str, model: object, scaler: object,
                   training: np.ndarray, exclude_digests: Set[str],
                   workers: int, max_files: Optional[int], max_file_kb: Optional[int],
                   scan_timeout: int) -> Optional[ScoredCorpus]:
    """Scan one corpus and attach every per-config quantity; None if it is empty.

    Returning None (rather than raising) keeps a run that lost one corpus — a
    mine that timed out, say — from destroying the results of the others.
    """
    if not root.exists():
        print(f"[{label}] corpus dir {root} does not exist — skipped", file=sys.stderr)
        return None
    scan = scan_corpus_indexed(root, model_dir, workers=workers, max_files=max_files,
                               max_file_kb=max_file_kb, timeout_s=scan_timeout,
                               exclude_digests=exclude_digests or None)
    if not scan.records:
        print(f"[{label}] no scannable configs under {root} — skipped", file=sys.stderr)
        return None
    feats = np.array([r.features for r in scan.records], dtype=np.float64)
    score_samples, decision, predict_flag = model_scores(feats, model, scaler)
    return ScoredCorpus(
        label=label, root=root, records=scan.records, stats=scan.stats,
        digest_by_path=scan.digest_by_path, features=feats,
        mahalanobis=mahalanobis_atypicality(feats, training),
        score_samples=score_samples, decision=decision, anomaly=-decision,
        predict_flag=predict_flag,
        rule_clean=np.array([r.rule_clean for r in scan.records], dtype=bool),
        train_overlap=training_overlap_mask(feats, training),
    )


def reference_operating_points(training_anomaly: np.ndarray,
                               percentiles: Sequence[float]) -> List[OperatingPoint]:
    """The status-quo cutoff plus one cutoff per percentile of training scores.

    Deriving the cutoff from the distribution the model was *fitted* on makes it
    an absolute, shippable constant: reproducing it needs the model only, no
    evaluation corpus, and it transfers unchanged to any config the scanner sees.
    """
    points = [OperatingPoint("contamination=0.1 (predict == -1)", 0.0,
                             "trained-in", predict_native=True)]
    for percentile in percentiles:
        points.append(OperatingPoint(
            f"train p{percentile:g}",
            float(np.percentile(training_anomaly, percentile)),
            "training-score percentile"))
    return points


def flags_for(point: OperatingPoint, corpus: ScoredCorpus) -> np.ndarray:
    """Boolean flag vector this operating point produces on a corpus."""
    if point.predict_native:
        return corpus.predict_flag
    return corpus.anomaly >= point.anomaly_cutoff


def _rate_block(mask: np.ndarray) -> dict:
    """``{n, flagged, flag_rate}`` for a boolean flag vector (rate rounded for JSON)."""
    flagged, n, rate = count_rate(mask)
    return {"n": n, "flagged": flagged, "flag_rate": round(rate, 4)}


def _raw_rate(mask: np.ndarray) -> float:
    """Unrounded flag rate — ratios must divide these, never the rounded ones.

    A.3 divides raw rates and rounds the quotient; dividing the 4-decimal rates
    instead shifts ``selectivity_lift`` by ~0.001 and would make the automated
    reconciliation against the banked result report a mismatch that is pure
    rounding. The ratios below therefore reproduce A.3's arithmetic exactly.
    """
    return count_rate(mask)[2]


def _ratio(numerator: float, denominator: float) -> Optional[float]:
    """Ratio, or None when the denominator is zero (reported honestly, not as inf)."""
    return round(numerator / denominator, 3) if denominator > 0 else None


def operating_point_metrics(point: OperatingPoint, corpus: ScoredCorpus) -> dict:
    """Flag rates, selectivity and the band table for one cutoff on one corpus."""
    flags = flags_for(point, corpus)
    clean = corpus.rule_clean
    maha_clean, flags_clean = corpus.mahalanobis[clean], flags[clean]

    block: dict = {
        "operating_point": point.name,
        "cutoff_source": point.source,
        "anomaly_cutoff": round(point.anomaly_cutoff, 6),
        "all": _rate_block(flags),
        "rule_clean": _rate_block(flags_clean),
        "rule_flagged": _rate_block(flags[~clean]),
    }
    block["orthogonality_ratio"] = _ratio(_raw_rate(flags_clean), _raw_rate(flags[~clean]))
    if maha_clean.size < _MIN_SUBPOP:
        return block

    atypical = maha_clean >= np.percentile(maha_clean, ATYPICAL_QUANTILE * 100)
    typical = maha_clean < np.percentile(maha_clean, TYPICAL_QUANTILE * 100)
    block["atypical_decile"] = _rate_block(flags_clean[atypical])
    block["typical_half"] = _rate_block(flags_clean[typical])
    block["selectivity_lift"] = _ratio(_raw_rate(flags_clean[atypical]),
                                       _raw_rate(flags_clean[typical]))
    flagged_total = float(flags_clean.sum())
    block["flag_share_in_atypical_tail"] = (
        round(float((flags_clean & atypical).sum()) / flagged_total, 4)
        if flagged_total else None)
    block["flag_bands"] = flag_rate_bands(maha_clean, flags_clean)
    return block


def ranking_quality(corpus: ScoredCorpus) -> dict:
    """Threshold-independent discrimination of the score on the rule-clean subpop.

    Identical protocol to A.3, so the numbers are directly comparable: AUC of the
    continuous score ranking the atypical decile against the rest, plus Spearman
    rho against the Mahalanobis axis.
    """
    clean = corpus.rule_clean
    maha, anomaly = corpus.mahalanobis[clean], corpus.anomaly[clean]
    if maha.size < _MIN_SUBPOP:
        return {"n": int(maha.size), "note": "subpopulation too small to stratify"}
    atypical = maha >= np.percentile(maha, ATYPICAL_QUANTILE * 100)
    auc = (roc_auc_score(atypical.astype(int), anomaly)
           if 0 < atypical.sum() < atypical.size else None)
    rho, pval = spearmanr(anomaly, maha)
    return {
        "n": int(maha.size),
        "ranking_auc": (round(float(auc), 4) if auc is not None else None),
        "spearman_rho": round(float(rho), 4),
        "spearman_p": float(f"{pval:.3e}"),
    }


def population_block(corpus: ScoredCorpus) -> dict:
    """Audit trail + the atypicality-axis band edges actually used for a corpus."""
    stats = corpus.stats
    clean = corpus.rule_clean
    maha_clean = corpus.mahalanobis[clean]
    edges = ({f"p{p:g}": round(float(np.percentile(maha_clean, p)), 3)
              for p in (50, 90, 99)} if maha_clean.size >= _MIN_SUBPOP else {})
    return {
        "label": corpus.label,
        "root": str(corpus.root),
        "kept": stats.kept, "seen": stats.seen, "deduped": stats.deduped,
        "excluded_shared_with_earlier_corpus": stats.excluded_shared,
        "oversize": stats.oversize, "no_resource": stats.no_resource,
        "scan_errors": stats.scan_errors, "scan_error_types": stats.per_error,
        "unique_hashes_admitted": len(corpus.digests()),
        "rule_clean": int(clean.sum()), "rule_flagged": int((~clean).sum()),
        "train_vector_overlap": int(corpus.train_overlap.sum()),
        "rule_clean_train_vector_overlap": int((clean & corpus.train_overlap).sum()),
        "atypicality_band_edges": edges,
    }


def disjointness_proof(corpora: List[ScoredCorpus]) -> dict:
    """Hash-level evidence that the corpora after the first are genuinely new.

    The exclusion happens during the scan, so ``residual_hash_overlap`` must be
    0; it is recomputed here anyway because a disjointness claim that is only
    asserted by construction is not evidence.
    """
    pairs = []
    for index, corpus in enumerate(corpora[1:], start=1):
        earlier: Set[str] = set()
        for previous in corpora[:index]:
            earlier |= previous.digests()
        admitted = corpus.digests()
        total_offered = len(admitted) + corpus.stats.excluded_shared
        pairs.append({
            "corpus": corpus.label,
            "compared_against": [c.label for c in corpora[:index]],
            "files_dropped_as_already_seen": corpus.stats.excluded_shared,
            "unique_files_admitted": len(admitted),
            "shared_fraction_of_offered": (
                round(corpus.stats.excluded_shared / total_offered, 4)
                if total_offered else None),
            "residual_hash_overlap": len(admitted & earlier),
        })
    return {
        "method": ("sha256 of file content; corpora are scanned in the order given "
                   "and each drops content an earlier corpus already admitted"),
        "pairs": pairs,
    }


def _banked_a3_values(banked: dict) -> Dict[str, float]:
    """Pull the A.3 headline numbers out of the committed metrics file."""
    analysis = banked["rule_clean_analysis"]
    population = banked["population"]
    return {
        "kept": population["kept"],
        "rule_clean": population["rule_clean"],
        "rule_flagged": population["rule_flagged"],
        "rule_clean_flag_rate": analysis["overall_flag_rate"],
        "atypical_decile_flag_rate": analysis["atypical_decile"]["flag_rate"],
        "typical_half_flag_rate": analysis["typical_half"]["flag_rate"],
        "selectivity_lift": analysis["selectivity_lift"],
        "ranking_auc": analysis["ranking_auc"],
        "spearman_rho": analysis["spearman_rho"],
        "rule_flagged_flag_rate": banked["rule_flagged_analysis"]["flag_rate"],
    }


def _reconciliation_field(banked_value: object, this_value: object) -> dict:
    """One comparison row: the two values, whether they match, and the drift."""
    field = {"banked_a3": banked_value, "this_run": this_value,
             "match": banked_value == this_value}
    if isinstance(banked_value, (int, float)) and isinstance(this_value, (int, float)):
        field["delta"] = round(float(this_value) - float(banked_value), 4)
    return field


def reconcile_with_a3(banked: dict, corpus: ScoredCorpus, status_quo: dict,
                      ranking: dict) -> dict:
    """Compare this run's status-quo numbers against the banked A.3 result.

    A.3 measured exactly the ``predict == -1`` operating point on the home
    corpus, so a re-mine of the same sources must reproduce it. Any drift is
    reported rather than smoothed over — the registry moves, and the honest
    thing is to show by how much.
    """
    this_run = {
        "kept": corpus.stats.kept,
        "rule_clean": int(corpus.rule_clean.sum()),
        "rule_flagged": int((~corpus.rule_clean).sum()),
        "rule_clean_flag_rate": status_quo["rule_clean"]["flag_rate"],
        "atypical_decile_flag_rate": status_quo.get("atypical_decile", {}).get("flag_rate"),
        "typical_half_flag_rate": status_quo.get("typical_half", {}).get("flag_rate"),
        "selectivity_lift": status_quo.get("selectivity_lift"),
        "ranking_auc": ranking.get("ranking_auc"),
        "spearman_rho": ranking.get("spearman_rho"),
        "rule_flagged_flag_rate": status_quo["rule_flagged"]["flag_rate"],
    }
    baseline = _banked_a3_values(banked)
    fields = {name: _reconciliation_field(baseline[name], this_run.get(name))
              for name in baseline}
    return {
        "corpus": corpus.label,
        "operating_point": status_quo["operating_point"],
        "all_match": all(entry["match"] for entry in fields.values()),
        "fields": fields,
    }


def write_per_config_scores(out_path: Path, corpora: List[ScoredCorpus]) -> int:
    """Dump one row per scanned config — the artifact this whole run exists for.

    With this file on disk any cutoff (percentile, absolute, per-band, or a
    future rule) is re-derivable offline, forever, without re-running the corpus
    mine and scan on paid compute.
    """
    rows = 0
    with gzip.open(out_path, "wt", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(_CSV_COLUMNS)
        for corpus in corpora:
            for index, record in enumerate(corpus.records):
                writer.writerow([
                    corpus.label, record.path,
                    corpus.digest_by_path.get(record.path, ""),
                    int(record.rule_clean), record.n_rule_findings,
                    f"{record.ml_score:.6g}", record.confidence,
                    f"{corpus.score_samples[index]:.9g}",
                    f"{corpus.decision[index]:.9g}",
                    f"{corpus.anomaly[index]:.9g}",
                    int(corpus.predict_flag[index]),
                    f"{corpus.mahalanobis[index]:.6g}",
                    int(corpus.train_overlap[index]),
                    *(f"{value:.6g}" for value in record.features),
                ])
                rows += 1
    return rows


def write_training_reference_scores(out_path: Path, score_samples: np.ndarray,
                                    anomaly: np.ndarray) -> int:
    """Dump the model's own training-score distribution (the cutoff reference).

    Without it a percentile cutoff could not be recomputed offline — the CSV of
    config scores alone would force the reference back onto the evaluation
    corpus, which is exactly the self-referential calibration this run avoids.
    """
    with gzip.open(out_path, "wt", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["if_score_samples", "if_anomaly"])
        for raw, anom in zip(score_samples, anomaly):
            writer.writerow([f"{raw:.9g}", f"{anom:.9g}"])
    return int(score_samples.size)


def build_metrics(corpora: List[ScoredCorpus], points: List[OperatingPoint],
                  training: np.ndarray, banked: Optional[dict]) -> dict:
    """Assemble the full metrics document from the scored corpora."""
    sweep = {corpus.label: [operating_point_metrics(point, corpus) for point in points]
             for corpus in corpora}
    metrics: dict = {
        "feature_names": list(FEATURE_NAMES),
        "corpora": [population_block(corpus) for corpus in corpora],
        "disjointness": disjointness_proof(corpora),
        "reference_cutoffs": [
            {"operating_point": point.name, "anomaly_cutoff": round(point.anomaly_cutoff, 6),
             "source": point.source} for point in points],
        "training_reference": {"vectors": int(training.shape[0])},
        "ranking_quality": {corpus.label: ranking_quality(corpus) for corpus in corpora},
        "threshold_sweep": sweep,
    }
    if banked and corpora:
        home = corpora[0]
        metrics["a3_reconciliation"] = reconcile_with_a3(
            banked, home, sweep[home.label][0], metrics["ranking_quality"][home.label])
    return metrics


def _print_summary(metrics: dict, corpora: List[ScoredCorpus]) -> None:
    """One line per corpus per operating point — the run's live sanity check."""
    for corpus in corpora:
        for block in metrics["threshold_sweep"][corpus.label]:
            typical = block.get("typical_half", {}).get("flag_rate")
            atypical = block.get("atypical_decile", {}).get("flag_rate")
            print(f"[{corpus.label}] {block['operating_point']:<32} "
                  f"cutoff {block['anomaly_cutoff']:+.4f} | "
                  f"rule-clean {block['rule_clean']['flag_rate']:.1%} | "
                  f"rule-flagged {block['rule_flagged']['flag_rate']:.1%} | "
                  f"typical {typical if typical is None else f'{typical:.1%}'} | "
                  f"atypical {atypical if atypical is None else f'{atypical:.1%}'} | "
                  f"lift {block.get('selectivity_lift')}")


def main() -> int:
    ap = argparse.ArgumentParser(description="A.3 follow-up: threshold calibration "
                                             "+ second-corpus check")
    ap.add_argument("--corpus", action="append", required=True, type=parse_corpus_spec,
                    metavar="LABEL=PATH",
                    help="corpus to scan; repeatable and ORDER MATTERS — every corpus "
                         "drops content hashes an earlier one already admitted")
    ap.add_argument("--model-dir", default="models",
                    help="model dir (isolation_forest.pkl + scaler.pkl); never refitted")
    ap.add_argument("--training-data", default="models/training_data.npy", type=Path,
                    help="training feature matrix: Mahalanobis + cutoff reference")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="where metrics and the per-config CSV artifacts are written")
    ap.add_argument("--percentiles", default=",".join(f"{p:g}" for p in _DEFAULT_PERCENTILES),
                    type=parse_percentiles,
                    help="cutoff percentiles of the training score distribution")
    ap.add_argument("--baseline-metrics", type=Path, default=None,
                    help="banked A.3 ml_atypicality_metrics.json to reconcile against")
    ap.add_argument("--workers", type=int, default=0,
                    help="parallel scan processes (0/1 = single-process)")
    ap.add_argument("--max-files", type=int, default=None,
                    help="cap on unique files scanned per corpus (bounds runtime)")
    ap.add_argument("--max-file-kb", type=int, default=256,
                    help="skip .tf files larger than this many KB (giant blobs)")
    ap.add_argument("--scan-timeout", type=int, default=20,
                    help="per-file scan budget in seconds (poison-file guard)")
    args = ap.parse_args()

    training = np.load(args.training_data)
    model, scaler = ModelManager(model_dir=args.model_dir).load_model()
    train_raw, train_decision, _ = model_scores(training, model, scaler)
    train_anomaly = -train_decision
    points = reference_operating_points(train_anomaly, args.percentiles)

    corpora: List[ScoredCorpus] = []
    seen_digests: Set[str] = set()
    for label, root in args.corpus:
        print(f"== scanning corpus '{label}' at {root}", flush=True)
        corpus = scan_and_score(label, root.resolve(), args.model_dir, model, scaler,
                                training, seen_digests, args.workers, args.max_files,
                                args.max_file_kb, args.scan_timeout)
        if corpus is None:
            continue
        seen_digests |= corpus.digests()
        corpora.append(corpus)
        print(f"   kept {corpus.stats.kept} configs "
              f"({int(corpus.rule_clean.sum())} rule-clean, "
              f"{corpus.stats.excluded_shared} dropped as already seen)", flush=True)
    if not corpora:
        print("No scannable configs in any corpus", file=sys.stderr)
        return 1

    banked = (json.loads(args.baseline_metrics.read_text(encoding="utf-8"))
              if args.baseline_metrics and args.baseline_metrics.exists() else None)
    metrics = build_metrics(corpora, points, training, banked)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    scores_csv = args.out_dir / "per_config_scores.csv.gz"
    reference_csv = args.out_dir / "training_reference_scores.csv.gz"
    metrics["artifacts"] = {
        "per_config_scores": scores_csv.name,
        "per_config_rows": write_per_config_scores(scores_csv, corpora),
        "training_reference_scores": reference_csv.name,
        "training_reference_rows": write_training_reference_scores(
            reference_csv, train_raw, train_anomaly),
    }
    metrics["run_meta"] = {
        "model_dir": str(args.model_dir),
        "model_version": ModelManager(model_dir=args.model_dir).get_current_version(),
        "model_retrained": False,
        "training_vectors": int(training.shape[0]),
        "corpora": [f"{label}={root}" for label, root in args.corpus],
        "percentiles": args.percentiles,
        "atypical_quantile": ATYPICAL_QUANTILE,
        "typical_quantile": TYPICAL_QUANTILE,
        "workers": args.workers,
        "max_files": args.max_files,
        "max_file_kb": args.max_file_kb,
        "scan_timeout_s": args.scan_timeout,
    }

    out = args.out_dir / "ml_calibration_metrics.json"
    out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _print_summary(metrics, corpora)
    reconciliation = metrics.get("a3_reconciliation")
    if reconciliation:
        print(f"A.3 reconciliation on '{reconciliation['corpus']}': "
              f"all_match={reconciliation['all_match']}")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
