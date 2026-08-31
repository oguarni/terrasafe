# Evidence map — `sbc_paper_draft.md`

Every quantitative claim in the draft, mapped to the artefact it came from, so the paper can be re-verified mechanically. All paths are relative to the repository root.

**A claim without a source row is a bug.** Rows marked *derived* are arithmetic over sourced values and the arithmetic is shown.

Cross-check document for the headline set: `docs/PLANO_LONGO_futuro.md`, section "Ground truth as of 2026-07-21" (lines 13–43). Where that block and a metrics file disagree, the metrics file wins and the discrepancy is noted below.

---

## 1. Architecture (Section 3 of the draft)

| Claim | Value | Source | Key / location |
|---|---|---|---|
| Rule count | 11 | `terravault/domain/CLAUDE.md` | "Rule Inventory" table (11 rows); `terravault/domain/security_rules.py` |
| Severity point constants | CRITICAL 30, HIGH 20, MEDIUM 10, LOW 5, INFO 2 | `terravault/domain/CLAUDE.md` | `security_rules.py` section |
| Rule-by-rule detection surface (table in 3.2) | see table | `terravault/domain/CLAUDE.md` | "Rule Inventory" table |
| `MISSING_LOGGING` excluded symmetrically | qualitative | `evaluation/README.md` | "Methodology and fairness", item 3 |
| Feature count / names | 8: `resource_count`, `resource_type_diversity`, `ingress_rule_count`, `public_exposure_count`, `iam_resource_count`, `encryption_coverage`, `logging_resource_count`, `secret_parametrization` | `evaluation/results/ml_atypicality/ml_atypicality_metrics.json` | `feature_names` (also `terravault/application/CLAUDE.md`, `terravault/infrastructure/CLAUDE_ML.md`) |
| Ratio features default to 1.0 when denominator empty | qualitative | `terravault/application/CLAUDE.md` | "Structural Feature Extraction (8 dimensions)" |
| Score formula `0.6 * rule + 0.4 * ml` | 0.6 / 0.4 | `terravault/application/scanner.py` | line 132 (`final_score = int(self.rule_weight * rule_score + self.ml_weight * ml_score)`) |
| Weights are operator-configurable and validated to sum to 1.0 | defaults 0.6 / 0.4; env `TERRAVAULT_RULE_WEIGHT` / `TERRAVAULT_ML_WEIGHT` | `terravault/config/settings.py` | lines 79–91 (`rule_weight`, `ml_weight` defaults), lines 198–203 (`validate_score_weights`); `terravault/application/scanner.py` lines 31–33, 51–60 |
| Flag definition (`predict == -1`, i.e. `ml_score >= 50`) | — | `evaluation/ml_atypicality.py` | module docstring, "Model signal"; `terravault/infrastructure/CLAUDE_ML.md` "Risk Scoring" |
| Model version | `v20260708_015533` | `models/versions/v20260708_015533/metadata.json` | `version`; also `ml_atypicality_metrics.json` → `run_meta.model_version` |
| Isolation Forest hyperparameters | `contamination=0.1`, `n_estimators=150`, `random_state=42` | `models/versions/v20260708_015533/metadata.json` | `model_parameters` (also `terravault/infrastructure/CLAUDE_ML.md`) |
| Total training vectors | 35,594 | `models/versions/v20260708_015533/metadata.json` | `total_samples` (also `ml_atypicality_metrics.json` → `run_meta.training_vectors`) |
| Real-corpus vectors | 35,294 | same | `corpus_vectors` / `feedback_samples_added` |
| Terraform Registry vectors | 21,746 | same | `corpus_by_source.registry.kept` |
| GitHub vectors | 13,548 | same | `corpus_by_source.github.kept` |
| Synthetic baseline vectors retained | 300 | *derived*: 35,594 − 35,294 = 300 | corroborated by `terravault/infrastructure/CLAUDE_ML.md` ("`_generate_secure_baseline()` synthesises **300** secure-infrastructure feature vectors") |
| Registry + GitHub sum to the corpus total | 21,746 + 13,548 = 35,294 | *derived* | consistency check on the row above |
| Modules / blobs crawled | 10,639 registry modules; 30,303 GitHub blobs | `models/versions/v20260708_015533/metadata.json` | `corpus_modules`, `github_blobs` |
| Test suite | 137 tests, 0 failures | `gate-metrics.json` (`checks[0].metrics.summary_line` = "137 passed, "); `pytest-junit.xml` (`tests="137"`, `failures="0"`) | measured 2026-07-21 |
| Line coverage | 76.8% | `.ratchet.json` → `coverage_pct`; `gate-metrics.json` → ratchet check `coverage_pct.current` | one-way ratchet baseline |
| Pylint / Flake8 / Bandit / mypy | 10.00/10, 0, 0, 0 | `gate-metrics.json` | `checks[]` entries `pylint`, `flake8`, `bandit`, `mypy` |

> **Note (stale README):** `README.md` still advertises "72 tests / 74% coverage" and describes the ML training corpus as "synthetic-but-principled". Both statements predate model `v20260708_015533` and the current test suite. The draft uses the metrics files, not the README. The README should be updated separately.

---

## 2. Home corpus benchmark (Section 5.1)

Primary source: `evaluation/results/metrics.json` (generated 2026-07-07T23:24:54), rendered as `evaluation/results/report.md`.

| Claim | Value | Source | Key |
|---|---|---|---|
| Corpus size | 22 cases, 16 positive, 6 negative, 23 labels | `evaluation/results/metrics.json` | `run_meta.corpus.{n_cases,n_positive,n_negative,n_labels}` |
| Shared taxonomy size | 11 categories | same | `run_meta.taxonomy` (11 entries) |
| TerraVault P/R/F1 | 100.0 / 100.0 / 100.0 | same | `tools.terravault.{micro_precision,micro_recall,micro_f1}` = 1.0 / 1.0 / 1.0 |
| Checkov P/R/F1 | 100.0 / 95.7 / 97.8 | same | `tools.checkov.*` = 1.0 / 0.9565 / 0.9778 |
| tfsec P/R/F1 | 100.0 / 87.0 / 93.0 | same | `tools.tfsec.*` = 1.0 / 0.8696 / 0.9302 |
| Terrascan P/R/F1 | 100.0 / 47.8 / 64.7 | same | `tools.terrascan.*` = 1.0 / 0.4783 / 0.6471 |
| Raw findings | 23 / 187 / 107 / 63 | same | `tools.*.total_raw_findings` |
| Categories covered | 11 / 10 / 9 / 5 (of 11) | same | `tools.*.categories_covered` |
| False positives on hardened cases | 0 for all four tools | same | `tools.*.fp_on_negative`; `evaluation/results/report.md` §2.3 |
| Labels recovered | TerraVault 23/23; Checkov 22/23; tfsec 20/23; Terrascan 11/23 | same | `tools.*.tp` and `tools.*.fn` |
| Checkov's single miss is the hardcoded secret | — | same | `tools.checkov.per_category.HARDCODED_SECRET.fn` = 1; `evaluation/results/report.md` §2.2 row "Segredo hardcoded" |
| Total scan time | TV 1.27 s, Checkov 230.49 s, tfsec 58.71 s, Terrascan 217.72 s | same | `tools.*.total_duration_s` (1.274 / 230.491 / 58.71 / 217.718); `evaluation/results/tables/timing.csv` |
| Per-case scan time | 0.058 / 10.477 / 2.669 / 9.896 s | `evaluation/results/tables/timing.csv` | column "Por caso (s)" |
| Tool versions (home run) | TerraVault 1.0.0 (native); Checkov 3.3.0; tfsec v1.28.14; Terrascan v1.19.9 | `evaluation/results/metrics.json` | `run_meta.tools.*` (includes image digests) |
| Overview table values | identical to the table above | `evaluation/results/tables/overview.csv` | rendered CSV, cross-check |
| Fairness controls (taxonomy projection, symmetric filtering, audited mapping, `--user 0`, `--framework terraform,secrets`, timing caveat) | qualitative | `evaluation/README.md` | "Methodology and fairness" items 1–7; `evaluation/results/report.md` §1 |
| Unmapped-identifier audit exists | 28 Checkov / 15 tfsec / 12 Terrascan ids recorded | `evaluation/results/metrics.json` | `run_meta.mapping_audit_unmapped_ids` (counts *derived* from list lengths; the draft only claims the audit exists) |

---

## 3. Foreign corpus (Section 5.2)

Primary source: `evaluation/results/foreign/metrics.json` (generated 2026-07-16T03:59:03, `score_mode: target_slice`), rendered as `evaluation/results/foreign/report_foreign.md`.

| Claim | Value | Source | Key |
|---|---|---|---|
| Corpus size | 57 fixtures, 32 positive, 25 negative | `evaluation/results/foreign/metrics.json` | `run_meta.corpus.{n_cases,n_positive,n_negative}` |
| In-scope / out-of-scope fixtures | 38 / 19 | same | `run_meta.corpus.{n_in_tv_scope,n_out_of_tv_scope}` |
| Labels | 32 | same | `run_meta.corpus.n_labels` |
| Fixtures are KICS, imported unchanged, labels by KICS maintainers | qualitative | `evaluation/results/foreign/build_manifest.json` | `source`, `provenance` |
| KICS is not one of the compared tools | qualitative | same | `provenance`; `evaluation/README.md` "Third-party corpus" |
| KICS pinned commit | `ac94c2cd8411bf9310b64cae8a628ffadd26b8f6` | `evaluation/results/foreign/corpus_source.json` | `kics_sha`; default also in `scripts/gcp_eval_foreign.sh` (`KICS_SHA`) |
| GCS run id | `foreign-20260716-004135` | `evaluation/results/foreign/corpus_source.json` | `run` |
| TerraVault P/R/F1 | 70.4 / 59.4 / 64.4 | `evaluation/results/foreign/metrics.json` | `tools.terravault.*` = 0.7037 / 0.5938 / 0.6441 |
| TerraVault TP/FP/FN | 19 / 8 / 13 | same | `tools.terravault.{tp,fp,fn}` |
| Checkov P/R/F1 | 69.4 / 78.1 / 73.5 | same | `tools.checkov.*` = 0.6944 / 0.7812 / 0.7353 |
| tfsec P/R/F1 | 74.1 / 62.5 / 67.8 | same | `tools.tfsec.*` = 0.7407 / 0.625 / 0.678 |
| Terrascan P/R/F1 | 100.0 / 18.8 / 31.6 | same | `tools.terrascan.*` = 1.0 / 0.1875 / 0.3158 |
| False positives on negatives | TV 8, Checkov 11, tfsec 7, Terrascan 0 | same | `tools.*.fp_on_negative`; `evaluation/results/foreign/report_foreign.md` §5 |
| Categories covered | 6 / 6 / 6 / 2 (of 11) | same | `tools.*.categories_covered` |
| Recall inside TerraVault's rule scope | TV 19/23 (83%); Checkov 22/23 (96%); tfsec 18/23 (78%); Terrascan 6/23 (26%) | `evaluation/results/foreign/tables/foreign_scope_split.csv` | rows; narrative in `report_foreign.md` §3 |
| Recall outside that scope | TV 0/9 (0%); Checkov 3/9 (33%); tfsec 2/9 (22%); Terrascan 0/9 (0%) | same | same |
| Of TerraVault's 8 FPs, 7 are S3 and 1 is IMDSv1 | 7 / 1 | `evaluation/results/foreign/metrics.json` | `tools.terravault.per_category.PUBLIC_S3.fp` = 7; `...IMDSV1.fp` = 1 |
| Cause of the S3 FPs (holistic public-access check stricter than a single-flag label) | qualitative | `evaluation/results/foreign/report_foreign.md` | §5 closing note; `evaluation/kics_mapping.py` rationale for `s3_bucket_allows_public_acl` |
| Cause of the IMDSv1 FP (`http_endpoint = "disabled"` without `http_tokens = "required"`) | qualitative | same | §5 closing note; `evaluation/kics_mapping.py` rationale for `instance_uses_metadata_service_IMDSv1` |
| Named coverage gaps: RDS clusters, non-role IAM, standalone SG rules, account-level S3 | qualitative | `evaluation/results/foreign/report_foreign.md` §3; `evaluation/kics_mapping.py` | `aws_rds_cluster` vs `aws_db_instance`; `aws_iam_policy`/`aws_iam_user_policy` vs `aws_iam_role_policy`; `aws_security_group_rule`/`aws_vpc_security_group_ingress_rule` vs inline `ingress`; `aws_s3_account_public_access_block` vs bucket-level |
| Module-only fixtures dropped | 21 | `evaluation/results/foreign/build_manifest.json` | *derived*: `stats.dropped_no_resource` list length = 21 |
| Near-miss KICS queries excluded, with reasons | 6 | same | *derived*: `excluded_queries` has 6 keys, each with a reason string |
| Categories present in the foreign corpus | 8 of 11 | same | *derived*: `categories_present` list length = 8 |
| 15 of the 32 positives are S3 | 15 | `evaluation/results/foreign/metrics.json` | `tools.terravault.per_category.PUBLIC_S3.support` = 15 |
| Foreign run used Checkov 3.3.8 (home run used 3.3.0) | 3.3.8 vs 3.3.0 | `evaluation/results/foreign/metrics.json` → `run_meta.tools.checkov.version`; `evaluation/results/metrics.json` → `run_meta.tools.checkov.version` | different image digests in each file; tfsec/Terrascan versions match across runs |
| Target-slice scoring rationale | qualitative | `evaluation/results/foreign/metrics.json` | `run_meta.corpus_source`; `evaluation/README.md` "Scoring" |
| `tv_scope` semantics (in-scope iff the fixture declares a resource type the rule inspects) | qualitative | `evaluation/kics_mapping.py` | module docstring and `KicsQuery.tv_scope` |

---

## 4. Ablation (Section 5.3)

| Claim | Value | Source | Key |
|---|---|---|---|
| Mean rule score, vulnerable / hardened (home) | 50.0 / 16.67 | `evaluation/results/metrics.json` | `hybrid_summary.mean_rule_positive`, `mean_rule_negative` |
| Mean anomaly score, vulnerable / hardened (home) | 48.68 / 45.48 | same | `hybrid_summary.mean_ml_positive`, `mean_ml_negative` |
| Mean final score, vulnerable / hardened (home) | 49.12 / 27.67 | same | `hybrid_summary.mean_final_positive`, `mean_final_negative` |
| Rule separation 33.3 pts | 33.33 | *derived*: 50.0 − 16.67 | reported as 33.3 (matches `docs/PLANO_LONGO_futuro.md` line 22) |
| ML separation 3.2 pts | 3.20 | *derived*: 48.68 − 45.48 | reported as 3.2 |
| Hybrid separation 21.4 pts | 21.45 | *derived*: 49.12 − 27.67 | reported as 21.4, matching `evaluation/results/report.md` §2.5 ("separação média de 21.4 pontos") |
| Case counts behind the means | 16 vulnerable, 6 hardened | `evaluation/results/metrics.json` | `hybrid_summary.{positive_cases,negative_cases}` |
| Per-case hybrid detail exists | — | `evaluation/results/metrics.json` → `terravault_hybrid`; `evaluation/results/tables/hybrid_scores.csv` | one row per case |
| Foreign-corpus hybrid means | final 40.0 / 36.2; rule 37.03 / 31.2; ML 45.76 / 44.98 | `evaluation/results/foreign/metrics.json` | `hybrid_summary.*` |
| Foreign separations 3.8 / 5.8 / 0.8 | 3.8, 5.83, 0.78 | *derived*: 40.0−36.2; 37.03−31.2; 45.76−44.98 | — |

---

## 5. Atypicality experiment (Section 5.4)

Primary source: `evaluation/results/ml_atypicality/ml_atypicality_metrics.json`, rendered as `report_ml_atypicality.md`; provenance in `run_source.json`.

| Claim | Value | Source | Key |
|---|---|---|---|
| Files scanned | 49,673 | `ml_atypicality_metrics.json` | `population.seen` |
| Hash duplicates removed | 4,624 | same | `population.deduped` |
| Oversized blobs removed | 34 | same | `population.oversize` |
| Files with no `resource` block removed | 25,118 | same | `population.no_resource` |
| Scan errors removed | 1,856 (1,852 `TerraformParseError`, 2 `AttributeError`, 2 `ScanTimeout`) | same | `population.scan_errors`, `population.scan_error_types` |
| Configurations kept | 18,041 | same | `population.kept` |
| Rule-clean subpopulation | 437 | same | `population.rule_clean`; `rule_clean_analysis.n` |
| Rule-flagged subpopulation | 17,604 | same | `population.rule_flagged`; `rule_flagged_analysis.n` |
| Rule-clean share of the population | 2.4% | *derived*: 437 / 18,041 = 0.0242 | — |
| Configurations reproducing a training vector | 18,013 of 18,041 | same | `population.train_vector_overlap` |
| Genuinely held-out rule-clean configurations | 2 | same | `population.rule_clean_held_out` |
| Band: below p50 | 201 configs, 4 flagged, 2.0% | same | `rule_clean_analysis.flag_bands[0]` (`flag_rate` 0.0199) |
| Band: p50–p90 | 189 configs, 113 flagged, 59.8% | same | `flag_bands[1]` (0.5979) |
| Band: p90–p99 | 42 configs, 42 flagged, 100.0% | same | `flag_bands[2]` (1.0) |
| Band: at or above p99 | 5 configs, 5 flagged, 100.0% | same | `flag_bands[3]` (1.0) |
| Bands partition the subpopulation | 201+189+42+5 = 437 | *derived* | consistency check |
| Atypical decile | 47 configs, 47 flagged, 100% | same | `rule_clean_analysis.atypical_decile` |
| Typical half | 201 configs, 4 flagged, 1.99% | same | `rule_clean_analysis.typical_half` |
| Selectivity lift | 50.25x | same | `rule_clean_analysis.selectivity_lift` |
| Ranking AUC | 0.9151 | same | `rule_clean_analysis.ranking_auc` |
| Spearman rho / p | 0.7478 / 2.081e-79 | same | `rule_clean_analysis.spearman_rho`, `spearman_p` (draft rounds p to 2.1e-79, as does the rendered report) |
| Overall rule-clean flag rate | 37.5% (164 of 437) | same | `rule_clean_analysis.overall_flag_rate` = 0.3753, `flagged` = 164 |
| Rule-flagged flag rate | 8.9% (1,571 of 17,604) | same | `rule_flagged_analysis.{flag_rate,flagged,n}` (0.0892) |
| "Fires four times less on rule-flagged" | 37.5 / 8.9 = 4.2x | *derived* | — |
| Largest top-atypical module | 142 resources, 14 types (`marbot-io__marbot-monitoring-basic/main.tf`) | same | `rule_clean_analysis.top_atypical[0].features` |
| Most diverse top-atypical module | 30 resources, 28 types (`clouddrove__vpc/main.tf`) | same | `top_atypical[13].features` |
| No top-atypical config has encryption coverage < 1.0 | 15/15 have `encryption_coverage` = 1.0 | *derived* over `top_atypical[*].features.encryption_coverage` | corroborated by `report_ml_atypicality.md` §5 note |
| Only one top-atypical config has any public exposure | 1 of 15 (`public_exposure_count` = 2) | *derived* over `top_atypical[*].features.public_exposure_count` | `top_atypical[14]`; corroborated by `report_ml_atypicality.md` §5 |
| 6 of the 15 are repetitive (many resources of 1–2 types) | 6 | `report_ml_atypicality.md` | §5 note ("6 das 15 declaram muitos recursos de 1–2 tipos") |
| Atypicality axis definition (Mahalanobis to the training distribution, Ledoit–Wolf shrunk covariance, independent of the IF) | qualitative | `evaluation/ml_atypicality.py` | module docstring, "Atypicality axis"; `report_ml_atypicality.md` §2 |
| Band cut points | p90 atypical, p50 typical | `ml_atypicality_metrics.json` → `run_meta.{atypical_quantile,typical_quantile}`; `evaluation/ml_atypicality.py` → `_ATYPICAL_QUANTILE`, `_TYPICAL_QUANTILE` | 0.90 / 0.50 |
| Top-N characterisation size | 15 | `evaluation/ml_atypicality.py` | `_TOP_N` |
| Run parameters | 8 workers, max 50,000 files, 256 KB cap, 20 s per-file timeout | `ml_atypicality_metrics.json` | `run_meta.{workers,max_files,max_file_kb,scan_timeout_s}` |
| Model used | `v20260708_015533`, 35,594 training vectors | same | `run_meta.{model_version,training_vectors}` |

---

## 6. Reproducibility (Section 4.5)

| Claim | Value | Source | Key |
|---|---|---|---|
| Banked A.3 run id | `ml-atypical-20260721-011109` | `evaluation/results/ml_atypicality/run_source.json` | `gcs_run` |
| Machine and wall clock | `e2-standard-8`, ~450 s | same | `machine`, `wall_clock_s_approx` |
| Corpus mined for the A.3 run | 49,674 `.tf` files; Terraform Registry (registry-wide, 1500 modules) + public GitHub `.tf` blobs (BigQuery export) | same | `corpus_tf_files_mined`, `sources` |
| Independent replicate run id | `ml-atypical-20260721-012015` | same | `independent_reproduction.gcs_run` |
| Replicate hardware | `e2-highcpu-16`, 16 workers (vs 8) | same | `independent_reproduction.machine` |
| Replicate result identical on every headline metric | kept 18,041; rule-clean 437; lift 50.25; AUC 0.9151; rho 0.7478; typical half 0.0199; rule-flagged 0.0892 | same | `independent_reproduction.result` |
| "Separately mined corpus" for the replicate | qualitative | `docs/PLANO_LONGO_futuro.md` | line 37 ("16 vs 8 workers, separately mined corpus"); `run_source.json` records the hardware difference but not the re-mine |
| Launchers are committed | `scripts/gcp_eval_foreign.sh`, `scripts/gcp_ml_atypical.sh` | repository | read-only for this task; both scripts document the GCS layout and collection commands |
| Raw competitor output preserved | per tool, per case | `evaluation/results/raw/<tool>/<case>.json` | e.g. `evaluation/results/raw/tfsec/public_s3.json` |

> **Recorded discrepancy (must stay disclosed).** `run_source.json` reports `corpus_tf_files_mined: 49674` while the pipeline recorded `population.seen: 49673` in `ml_atypicality_metrics.json`. The draft uses 49,673 (the pipeline's own count). The one-file difference is unexplained and should be either explained or footnoted before submission — `TODO(verify)`.

---

## 7. Institutional / submission claims (used in `SUBMISSION_NOTES.md`, and in the authorship note of the draft)

| Claim | Source | Key |
|---|---|---|
| A Qualis-rated conference or journal paper convalidates TCC 2 | `docs/IN_COENS_DV_7_2023.md` | Art. 33, §2º, incisos I–II |
| The student should preferentially be the first author; otherwise a letter from the first author is required | same | Art. 34 caput and §1º |
| Grade by Qualis stratum: 10 for A1–A4; 9 for B1–B2; 8 for B3–B4 | same | Art. 34 §3º |
| UTFPR faculty participation in the publication is optional | same | Art. 34 §2º |
| Convalidation requires a request to DERAC with the publication and its Qualis attached | same | Art. 36 and §1º |
| Only work produced after enrolment counts | same | Art. 33 §3º |
| Six months of first-author rights after approval | same | Art. 37 caput and §1º–2º |
| TCC-as-article follows the SBC model (10–15 pages for the final product) | same | Art. 17 §1º–2º (applies to the TCC deliverable itself, not to the convalidating publication) |
| Defence date 2026-07-03 | `docs/ESTADO_TCC2_2026-07-10.md` | "Contexto" section |
| Advisor: Prof. Newton Carlos Will (banca president); co-advisor: Prof. Marlon (surname not recorded on disk) | same | "Contexto" and "Folha de Aprovação" sections |

---

## 8. Claims deliberately **not** sourced (flagged in the draft)

These appear in the draft only inside `TODO(cite)` / `TODO(...)` markers and must be resolved before submission. None of them is asserted as fact in the current text.

| Draft location | Missing evidence |
|---|---|
| §1, Terraform adoption / IaC prevalence | external citation |
| §1 and §2, "unfavourable ablations are under-reported" | external citation or rewrite as scoped observation |
| §2, IaC security-smell and IaC defect literature | external citations |
| §2, prior comparative evaluations of IaC scanners | external citations |
| §2, false-positive burden in SAST | external citation |
| §2 and §4.4, Ledoit–Wolf shrinkage estimator | external citation |
| §2, prior anomaly detection over IaC / cloud configuration | external citation, or an explicit statement that a documented search found none |
| §2, canonical citable references for Checkov / tfsec / Terrascan / KICS | project references (repository, technical report or tool paper) |
| References, Liu et al. (2008) page range and SBC formatting | verification |
| Title block, co-authors and Prof. Marlon's surname | author decision plus a record on disk |
| §6.5, confidence intervals for separations and band flag rates | computation from the committed metrics files |
| §7, artefact-availability statement (repository URL, commit SHA) | fill in at submission time |
| README-inherited "Gartner (2024)" and "IBM Security (2024)" references | **do not reuse without verifying the primary source**; the first appears misattributed |
