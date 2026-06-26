"""Detection-quality metrics for the TerraVault evaluation.

Everything is computed at the (case, category) granularity: each case is
labelled with the set of taxonomy categories it genuinely contains, and each
tool is reduced to the set of taxonomy categories it reported per case. From the
confusion counts we derive precision, recall and F1 per category and aggregated
(micro and macro) per tool.

Convention: a category a tool never reports (tp == fp == 0) yields precision 0,
which — since every category appears in at least one positive case — drives its
F1 to 0. That is the correct penalty for "this tool does not cover this
category", and keeps macro averages comparable across tools.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


@dataclass
class CategoryMetrics:
    category: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return _safe_div(2 * p * r, p + r)

    @property
    def support(self) -> int:
        """Number of cases that genuinely contain this category."""
        return self.tp + self.fn

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "support": self.support,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class ToolMetrics:
    tool: str
    per_category: Dict[str, CategoryMetrics]
    # false positives raised on the negative (hardened) cases, by category
    fp_on_negative: int = 0
    total_raw_findings: int = 0
    total_duration_s: float = 0.0

    @property
    def tp(self) -> int:
        return sum(c.tp for c in self.per_category.values())

    @property
    def fp(self) -> int:
        return sum(c.fp for c in self.per_category.values())

    @property
    def fn(self) -> int:
        return sum(c.fn for c in self.per_category.values())

    @property
    def micro_precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def micro_recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def micro_f1(self) -> float:
        p, r = self.micro_precision, self.micro_recall
        return _safe_div(2 * p * r, p + r)

    @property
    def macro_f1(self) -> float:
        cats = list(self.per_category.values())
        return _safe_div(sum(c.f1 for c in cats), len(cats))

    @property
    def categories_covered(self) -> int:
        """Distinct taxonomy categories the tool detected at least once correctly."""
        return sum(1 for c in self.per_category.values() if c.tp > 0)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "micro_precision": round(self.micro_precision, 4),
            "micro_recall": round(self.micro_recall, 4),
            "micro_f1": round(self.micro_f1, 4),
            "macro_f1": round(self.macro_f1, 4),
            "categories_covered": self.categories_covered,
            "fp_on_negative": self.fp_on_negative,
            "total_raw_findings": self.total_raw_findings,
            "total_duration_s": round(self.total_duration_s, 3),
            "per_category": {k: v.to_dict() for k, v in self.per_category.items()},
        }


def compute_tool_metrics(
    tool: str,
    taxonomy: List[str],
    ground_truth: Dict[str, Set[str]],
    detections: Dict[str, Set[str]],
    negative_cases: Set[str],
    total_raw_findings: int = 0,
    total_duration_s: float = 0.0,
) -> ToolMetrics:
    """Build per-category and aggregate metrics for one tool.

    ``ground_truth`` and ``detections`` map case_id -> set of taxonomy
    categories (detections already restricted to the shared taxonomy).
    """
    per_cat = {c: CategoryMetrics(c) for c in taxonomy}
    fp_on_negative = 0

    for case_id, expected in ground_truth.items():
        detected = detections.get(case_id, set())
        for cat in taxonomy:
            in_exp = cat in expected
            in_det = cat in detected
            if in_exp and in_det:
                per_cat[cat].tp += 1
            elif in_det and not in_exp:
                per_cat[cat].fp += 1
                if case_id in negative_cases:
                    fp_on_negative += 1
            elif in_exp and not in_det:
                per_cat[cat].fn += 1

    return ToolMetrics(
        tool=tool,
        per_category=per_cat,
        fp_on_negative=fp_on_negative,
        total_raw_findings=total_raw_findings,
        total_duration_s=total_duration_s,
    )
