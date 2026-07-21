# TerraVault Evaluation Harness

Reproducible benchmark that measures TerraVault's detection quality on a
labelled Terraform corpus and compares it head-to-head with three established
IaC scanners — **Checkov**, **tfsec** and **Terrascan** — run from their
official Docker images.

It produces the evidence for the *Avaliação / Testes* chapter of the technical
report: per-category and aggregate precision / recall / F1, false-positive
resistance, scan time, and an analysis of TerraVault's hybrid rule+ML score.

## Layout

```
evaluation/
  dataset/
    build_corpus.py     # single source of truth: Terraform + ground-truth labels
    cases/<id>/main.tf   # generated isolated modules (one scenario each)
    ground_truth.yaml    # generated manifest: case -> expected categories
  taxonomy.py            # tool-neutral categories + per-tool rule-id mappings
  runners.py             # run each scanner over one case (Docker / in-process)
  metrics.py             # confusion counts -> precision / recall / F1
  evaluate.py            # orchestrator -> results/metrics.json + detections
  report.py              # metrics.json -> report.md + CSV + LaTeX tables
  results/
    raw/<tool>/<case>.json   # preserved raw scanner output (auditable)
    metrics.json             # machine-readable results
    report.md                # the evaluation chapter (PT-BR)
    tables/*.csv, *.tex      # appendix tables + pgfplots chart
```

## Reproduce

```bash
make evaluate          # build corpus, run all tools, compute metrics, render report
make evaluate-report   # re-render report.md from cached metrics.json only
```

Requirements: the project virtualenv (`make install`), a trained ML model
(`make train-model`), and Docker (to pull/run the competitor images).

## Methodology and fairness

The comparison is only meaningful if it is fair to every tool. The design
choices below are deliberate and are restated in `results/report.md`.

1. **Isolated modules.** Each case is its own directory so every scanner treats
   it as a self-contained Terraform module. Pointing a tool at a directory
   concatenates its `.tf` files the way Terraform does; colliding resource and
   variable names across cases would otherwise break parsing.

2. **Shared, tool-neutral taxonomy.** Every tool's native finding ids are
   projected onto 11 security *concepts* (see `taxonomy.py`). A tool gets credit
   for a category on a case iff it reports *any* rule that maps to that category.
   Because each positive case isolates a single category, this projection is
   unambiguous.

3. **Symmetric out-of-taxonomy filtering.** Findings that do not map to a shared
   category are ignored for **all** tools — this includes the hundreds of extra
   rules Checkov/tfsec/Terrascan carry *and* TerraVault's whole-configuration
   `MISSING_LOGGING` heuristic, which has no per-resource equivalent. Counting it
   would bias the result toward TerraVault. The "raw findings" column reports
   total pre-projection findings so the breadth difference stays visible.

4. **Audited rule mapping.** The per-tool maps were built by harvesting the rule
   ids each scanner emits on the corpus (`python -m evaluation.runners`) and
   assigning each to the category of the case(s) it fires on, confirmed against
   the rule name/description. `evaluate.py` records every observed-but-unmapped
   id in `metrics.json` (`run_meta.mapping_audit_unmapped_ids`) so nothing is
   dropped silently.

5. **Container user.** Competitor containers run with `--user 0`. This repository
   is created under a restrictive umask (`drwxrwx---`); the Terrascan image runs
   as a non-root user that otherwise cannot read the bind-mounted corpus and
   silently parses **zero** resources — which would falsely read as "Terrascan
   detects nothing."

6. **Checkov secrets framework.** Checkov runs `--framework terraform,secrets`
   so its secret detection is explicitly part of the comparison.

7. **Timing caveat.** Competitor times include Docker container startup
   (roughly constant per run); TerraVault runs natively in-process. The timing
   table is indicative, not an isolated-engine benchmark.

## Third-party corpus (external validity)

The home corpus is written by the same author as the rules and the labels, so a
perfect score is compatible with "teaching to the test". The **KICS third-party
corpus** attacks that construct-validity threat with fixtures and labels we did
not author.

- **Source:** the per-query `test/positive*.tf` / `negative*.tf` fixtures of
  [KICS](https://github.com/Checkmarx/kics) (Checkmarx). KICS is *not* one of the
  four compared tools, so its fixtures are foreign to TerraVault, Checkov, tfsec
  and Terrascan alike (no tool is evaluated on its own suite).
- **Mapping:** `kics_mapping.py` projects each KICS query onto the shared
  taxonomy and records `tv_scope` (the resource types TerraVault's rule
  inspects) plus an audited `EXCLUDED` list of near-miss queries with reasons.
- **Builder:** `dataset/build_foreign_corpus.py` imports the fixtures, drops
  module-only files (unparseable by any static tool), and emits
  `ground_truth_foreign.yaml` with a `target` per case.
- **Scoring:** run `evaluate.py` with `--score-mode target_slice` — each fixture
  is judged only for the concept KICS labels it with (the corpus lacks complete
  multi-label ground truth). `report_foreign.py` splits recall into fixtures
  *within* TerraVault's resource scope (a fair head-to-head) versus *sibling*
  resources it never covers (a coverage-breadth gap, not a detection failure).

```bash
# Local, TerraVault only (no Docker):
make evaluate-foreign KICS_ROOT=<kics>/assets/queries/terraform/aws FOREIGN_ARGS=--terravault-only
# Full 4-tool comparison (heavy — Docker): run on GCP
scripts/gcp_eval_foreign.sh
```

## Threats to validity

- The home corpus is **synthetic-but-controlled**: curated to isolate categories
  with clean labels, which is a correctness validation rather than a field study.
  The KICS third-party corpus above is the external-validity complement; a
  full real-world-module field study remains future work.
- Results are tied to the **pinned tool versions** recorded in
  `results/metrics.json` (`run_meta.tools`). Rule ids and coverage change across
  releases; re-run `make evaluate` to refresh.
