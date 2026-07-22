# When Does the Machine Learning Half Earn Its Place? An Ablation-Driven Evaluation of a Hybrid Terraform Security Scanner

**Gabriel Felipe Guarnieri**<sup>1</sup>

<sup>1</sup> Universidade Tecnológica Federal do Paraná (UTFPR), Campus Dois Vizinhos — Bacharelado em Engenharia de Software

`TODO(authorship)`: confirm the final author list before submission. Art. 34 of IN COENS-DV/UTFPR nº 7/2023 states the student should *preferentially* be the first author for the paper to convalidate TCC 2; Art. 37 reserves first-author rights to the student for six months after approval (defence: 2026-07-03). Advisor Prof. Newton Carlos Will and co-advisor Prof. Marlon (`TODO(name)`: full surname) are the natural co-authors — their inclusion is a decision for the author, not an editorial default.

`TODO(format)`: this draft is written in Markdown for review. Before submission it must be typeset in the official SBC article template (`sbc-template` / `sbc-latex`), which fixes the title block, abstract/resumo order, section numbering and reference style.

---

## Abstract

Hybrid security scanners that pair deterministic rules with machine learning are common in Infrastructure as Code, but the contribution of the learned component is rarely isolated and even more rarely reported when it is unfavourable. We evaluate TerraVault, an open-source Terraform static analyser combining 11 rules (60% of the risk score) with an Isolation Forest over an 8-dimensional structural feature vector (40%). On a controlled 22-module corpus it reaches 100/100/100 precision/recall/F1 under a shared 11-category taxonomy, against 100/95.7/97.8 (Checkov), 100/87.0/93.0 (tfsec) and 100/47.8/64.7 (Terrascan). On 57 third-party KICS fixtures — KICS is not among the compared tools, so no scanner plays at home — it falls to 70.4/59.4/64.4, and the decomposition is the result: 83% recall (19/23) inside its declared resource scope versus 0/9 outside it, which localises the gap in coverage breadth rather than detection quality. An ablation then shows the learned component *compressing* the rules' separation on the controlled corpus, from 33.3 points to 21.4 (anomaly score alone: 3.2). That is not reversed by our final measurement but bounded by it: among 18,041 real configurations, in the 437 the rules report nothing about, the flag rate rises monotonically along an independent Mahalanobis atypicality axis (2.0% to 100%, lift 50.25x, AUC 0.9151), and the model fires on 37.5% of rule-clean versus 8.9% of rule-flagged configurations. The learned half does not sharpen the rules where they already speak; it adds an orthogonal review signal where they are silent — subject to the limit that structural atypicality is graph shape, not evidence of vulnerability.

**Keywords:** Infrastructure as Code, Terraform, static application security testing, anomaly detection, empirical evaluation, DevSecOps.

## Resumo

Analisadores híbridos que combinam regras determinísticas com aprendizado de máquina são comuns em Infraestrutura como Código, mas a contribuição do componente aprendido raramente é isolada e mais raramente ainda é relatada quando é desfavorável. Avaliamos o TerraVault, analisador estático de Terraform de código aberto que combina 11 regras (60% do escore de risco) com um Isolation Forest sobre um vetor estrutural de 8 dimensões (40%). Em um corpus controlado de 22 módulos, ele atinge 100/100/100 de precisão/revocação/F1 sobre uma taxonomia compartilhada de 11 categorias, contra 100/95,7/97,8 (Checkov), 100/87,0/93,0 (tfsec) e 100/47,8/64,7 (Terrascan). Em 57 *fixtures* de terceiros do KICS — que não está entre as ferramentas comparadas, de modo que nenhuma joga em casa — cai para 70,4/59,4/64,4, e o resultado é a decomposição: 83% de revocação (19/23) dentro do escopo de recursos que declara cobrir e 0/9 fora dele, o que localiza a lacuna em amplitude de cobertura e não em qualidade de detecção. Uma ablação mostra então o componente aprendido *comprimindo* a separação das regras no corpus controlado, de 33,3 para 21,4 pontos (escore de anomalia isolado: 3,2). Isso não é revertido pela medição final, mas delimitado por ela: entre 18.041 configurações reais, nas 437 em que as regras nada reportam, a taxa de sinalização cresce monotonicamente ao longo de um eixo independente de atipicidade de Mahalanobis (2,0% a 100%, *lift* de 50,25x, AUC 0,9151), e o modelo dispara em 37,5% das configurações *rule-clean* contra 8,9% das *rule-flagged*. A metade aprendida não afia as regras onde estas já falam; acrescenta um sinal de revisão ortogonal onde elas se calam — sujeito ao limite de que atipicidade estrutural é forma de grafo, não evidência de vulnerabilidade.

---

## 1. Introduction

Infrastructure as Code (IaC) moved provisioning into version control, and with it moved a class of defects that used to live in consoles and runbooks: a security group open to `0.0.0.0/0`, an unencrypted database, a bucket whose public-access blocks are half configured. Terraform is the most widely adopted IaC tool for multi-cloud provisioning `TODO(cite)`, and a family of static analysers has grown around it — Checkov, tfsec, Terrascan and KICS among them — each shipping hundreds of deterministic policies.

A recurring design proposal in this space is the *hybrid* scanner: deterministic rules for the known catalogue plus a learned component intended to generalise beyond it. The proposal is attractive and cheap to state. It is much harder to substantiate, because substantiating it requires an ablation that can come out unfavourable, and unfavourable ablations are under-reported `TODO(cite)`.

This paper reports such an ablation, honestly, together with the two measurements that bound it. Our subject is TerraVault, an open-source Terraform SAST tool built as an undergraduate capstone project: 11 deterministic rules contribute 60% of a 0–100 risk score and an Isolation Forest over an 8-dimensional *structural* feature vector contributes the remaining 40%, with the weights configurable by the operator. TerraVault is positioned strictly as a static analysis / IaC / DevSecOps tool that runs in a pull-request pipeline; it does not consume runtime telemetry and is not a SIEM or SOC product.

We make four contributions.

**C1. A head-to-head benchmark under a shared taxonomy.** On a controlled corpus of 22 isolated Terraform modules (16 vulnerable, 6 hardened) carrying 23 labels, projected onto 11 tool-neutral security concepts, TerraVault attains 100/100/100 precision/recall/F1 against 100/95.7/97.8 (Checkov), 100/87.0/93.0 (tfsec) and 100/47.8/64.7 (Terrascan), with zero false positives for every tool on the hardened cases.

**C2. An external-validity bound measured, not merely disclosed.** A perfect score on a corpus whose fixtures, rules and labels share one author is compatible with both "the tool is good" and "the author tested exactly what he built". We bound that construct-validity threat with 57 fixtures imported unchanged from KICS (Checkmarx), labelled by the KICS maintainers and foreign to all four compared tools. TerraVault scores 70.4/59.4/64.4 there, and the decomposition is the finding: 19/23 (83%) recall inside the resource scope its rules declare, 0/9 outside it.

**C3. An ablation unfavourable to the learned component, plus the population where that component nevertheless earns its place.** On the controlled corpus the rule score alone separates vulnerable from hardened cases by 33.3 points, the hybrid score by 21.4, the anomaly score alone by 3.2: the learned half compresses the rules' separation. We then ask the question the ablation cannot answer — what happens where the rules say nothing? Among 18,041 real Terraform configurations mined from the Terraform Registry and public GitHub, the 437 the rules report nothing about are flagged selectively along an independent atypicality axis (2.0% of the typical half, 100% of the atypical decile; lift 50.25x; ranking AUC 0.9151), and the model fires on 37.5% of rule-clean versus only 8.9% of rule-flagged configurations. Both statements hold simultaneously; Section 5.5 states why neither refutes the other.

**C4. Reproducibility as an artefact, not a claim.** Competitor scanners run from official Docker images pinned by digest, every raw scanner output is committed, and the atypicality experiment was re-executed on different hardware with a different worker count and a separately mined corpus — every headline metric identical to the last reported digit.

## 2. Related Work

**Production IaC scanners.** The tools we compare against are the established open-source analysers for Terraform: Checkov (Bridgecrew/Prisma Cloud), a Python policy engine; tfsec (Aqua Security), a Go rule engine; and Terrascan (Tenable), a policy-as-code engine over OPA/Rego. Our third-party corpus is built from the query fixtures of KICS (Checkmarx). All four are cited in this paper as software artefacts at pinned versions (Section 4) rather than as publications; `TODO(cite)`: add the canonical citable reference for each project (repository, technical report or tool paper) in the SBC reference format.

**Empirical studies of IaC defects and security smells.** There is an established line of empirical work on defects and security smells in IaC scripts and on the effectiveness of IaC static analysers. `TODO(cite)`: cite the specific studies before submission — at minimum a security-smell catalogue for IaC scripts, one comparative evaluation of IaC scanners, and one study of false-positive burden in static analysis. The positioning claim that depends on them ("comparative evaluations report aggregate precision/recall but rarely ablate hybrid components, and rarely evaluate on a corpus authored by neither the tool's author nor a competitor") must be supported or softened to a statement about the tools we examined.

**Anomaly detection over configuration.** The learned component is an Isolation Forest [Liu et al. 2008], selected for four properties that matter here: it is unsupervised (labelled Terraform misconfiguration datasets are scarce), efficient on low-dimensional structured input, usable with modest sample counts, and its per-sample score is directly reportable. Our atypicality axis uses the Mahalanobis distance to the training distribution with a Ledoit–Wolf shrunk covariance estimate `TODO(cite)`: add the Ledoit–Wolf reference and verify the bibliographic details. `TODO(cite)`: add related work applying anomaly detection to configuration or cloud-posture data, if it exists in the IaC setting; if it does not, say so explicitly rather than implying novelty by omission.

**Positioning.** What we did not find in the literature we have read so far is an evaluation of a hybrid IaC scanner that (i) ablates the learned component and reports the unfavourable direction, and (ii) separates a coverage-breadth deficit from a detection-quality deficit using a third-party labelled corpus. This paper is that evaluation. `TODO(cite)`: this negative claim about the literature must be backed by a documented search (venues, query strings, date) or downgraded to "to the best of our knowledge" with the search described in the methodology.

## 3. TerraVault: Architecture

### 3.1 Pipeline

TerraVault parses a `.tf` file with an HCL2 parser and then runs two independent branches over the parsed representation:

1. **Rule branch.** A deterministic engine of 11 checks emits typed findings (severity, message, resource, remediation). Points per finding are CRITICAL 30, HIGH 20, MEDIUM 10, LOW 5, INFO 2; the rule score is the sum capped at 100.
2. **Structural branch.** A feature extractor produces an 8-dimensional vector directly from the parsed configuration — *not* from the rule findings — which is clipped to validated bounds, scaled, and scored by an Isolation Forest. The model's decision function is mapped to a 0–100 anomaly score, with `predict == -1` (equivalently `ml_score >= 50`) as the operational flag.

The final risk score is the convex combination `0.6 * rule_score + 0.4 * ml_score`. The weights are operator-configurable through `TERRAVAULT_RULE_WEIGHT` / `TERRAVAULT_ML_WEIGHT` (or per-scanner constructor arguments) and are validated to sum to 1.0.

The independence of the two branches is deliberate and is a precondition for the experiments in Section 4.4: if the feature vector were derived from the rule findings, the anomaly score would be a re-encoding of the rule score and the question "does the ML add anything where the rules are silent?" would be vacuous.

### 3.2 Rule catalogue (11 rules)

| # | Rule | Severity | Detection surface |
|---|---|---|---|
| 1 | Open security groups | CRITICAL/HIGH/MEDIUM | inline `ingress` on `aws_security_group` open to `0.0.0.0/0` or `::/0`; severity by port range (SSH/RDP → CRITICAL, HTTP/HTTPS → MEDIUM, other → HIGH) |
| 2 | Hardcoded secrets | CRITICAL | literal `password` / `api_key` / `secret_key` / `token`; interpolations and `var.`/`local.`/`data.`/`module.` references excluded |
| 3 | Unencrypted storage | HIGH | `aws_db_instance.storage_encrypted`, `aws_ebs_volume.encrypted` |
| 4 | Public S3 | HIGH/MEDIUM | `aws_s3_bucket_public_access_block`: 3+ protections disabled → HIGH, any disabled → MEDIUM |
| 5 | IAM wildcard policy | CRITICAL | `aws_iam_role_policy` documents with wildcard action / full admin |
| 6 | Missing logging | HIGH | infrastructure declared without CloudTrail/CloudWatch |
| 7 | Missing VPC flow logs | MEDIUM | `aws_vpc` without `aws_flow_log` |
| 8 | Public RDS | CRITICAL | `aws_db_instance.publicly_accessible = true` |
| 9 | Unrestricted egress | LOW | `egress` open to `0.0.0.0/0` / `::/0` |
| 10 | IMDSv1 allowed | HIGH | `aws_instance` without `metadata_options.http_tokens = "required"` |
| 11 | Public EC2 instance | LOW | `aws_instance.associate_public_ip_address = true` |

Rule 6 (`MISSING_LOGGING`) is a whole-configuration heuristic with no per-resource equivalent in the compared scanners; it is excluded symmetrically from all measured comparisons (Section 4.1).

### 3.3 Structural features (8 dimensions)

`resource_count`, `resource_type_diversity`, `ingress_rule_count`, `public_exposure_count`, `iam_resource_count`, `encryption_coverage`, `logging_resource_count`, `secret_parametrization`. The two ratio features default to 1.0 (the secure mode) when the denominator is empty, so a configuration with nothing to encrypt is not penalised. Values are clipped to declared bounds before inference, which also serves as a guard against feature-space poisoning.

### 3.4 Model

The deployed model is version `v20260708_015533`: an Isolation Forest (`contamination=0.1`, `n_estimators=150`, `random_state=42`) over a `StandardScaler`, fitted on **35,594 feature vectors**. Of these, 35,294 are extracted from real Terraform — 21,746 from a registry-wide crawl of the Terraform Registry and 13,548 from distinct `.tf` blobs of the public GitHub dataset, deduplicated by content hash — and 300 are the synthetic secure baseline retained from the initial bootstrap. We state that composition explicitly because an earlier version of the tool was trained on synthetic data only, and the distinction matters for how the results below should be read.

### 3.5 Engineering quality

The implementation follows a Clean Architecture layering (domain / application / infrastructure) and is gated in CI by a single quality gate: 137 passing tests, 76.8% line coverage held by a one-way ratchet, Pylint 10.00/10, 0 Flake8 findings, 0 Bandit findings at `-ll`, 0 mypy errors (measured 2026-07-21). We report these because the experiments in Section 4.4 execute the *shipped* scanner rather than a re-implementation, so its correctness is part of the evidence chain.

## 4. Evaluation Methodology

### 4.1 Home corpus (controlled)

The controlled corpus contains 22 self-contained Terraform modules — 16 vulnerable and 6 hardened — carrying 23 vulnerability labels. Each vulnerable case isolates a single category with every other attribute hardened, so a finding for that category is unambiguous; the hardened cases (parametrised secret, encrypted storage, fully blocked S3, IMDSv2 enforced, private ingress, secure full stack) probe false-positive resistance.

Four fairness decisions govern the comparison:

- **Shared, tool-neutral taxonomy.** Every tool's native finding identifiers are projected onto 11 security *concepts*. A tool earns a category on a case if it reports any rule mapping to that category.
- **Symmetric out-of-taxonomy filtering.** Findings outside the shared taxonomy are discarded for *all* tools — the hundreds of extra policies Checkov, tfsec and Terrascan carry, and TerraVault's own `MISSING_LOGGING` heuristic, which would otherwise bias the comparison in TerraVault's favour. The "raw findings" column preserves the breadth difference.
- **Audited mapping.** Per-tool maps were built from the identifiers each scanner actually emits on the corpus; every observed-but-unmapped identifier is recorded in the metrics file, so nothing is dropped silently.
- **Execution parity.** All scanners analyse the same files in pure static mode, with no `terraform init` and no credentials. Competitor containers run as `--user 0` because the corpus directory is created under a restrictive umask; without this, Terrascan's non-root image silently parses zero resources.

Metrics are micro-averaged precision, recall and F1 at (case, category) granularity. Tool versions and image digests are pinned and recorded (Section 5.1).

### 4.2 Foreign corpus (external validity)

The foreign corpus consists of 57 fixtures (32 positive, 25 negative) imported unchanged from the per-query `positive*.tf` / `negative*.tf` test fixtures of KICS, pinned at commit `ac94c2cd8411bf9310b64cae8a628ffadd26b8f6`. Three properties make it a real external-validity probe:

1. **The labels are third-party.** They were authored by the KICS maintainers, not by us.
2. **No tool plays at home.** KICS is not one of the four compared scanners, so its fixtures are equally foreign to TerraVault, Checkov, tfsec and Terrascan.
3. **Scope is recorded per fixture.** Each imported query records `tv_scope`: the exact AWS resource types TerraVault's corresponding rule inspects. A fixture is *in scope* if it declares one of those types. This is what allows a missed detection on `aws_rds_cluster` (a resource TerraVault's encryption rule does not target) to be reported as a coverage gap rather than a detection failure.

Because the corpus does not carry complete multi-label ground truth, scoring runs in **target-slice mode**: each fixture is judged only for the concept KICS labels it with. 21 fixtures that contain no `resource` block (module-only files, unparseable by any static analyser) were dropped for all tools. Six near-miss KICS queries were excluded with recorded reasons — concept mismatch (flow logs: KICS requires reference integrity to the VPC, TerraVault checks presence), detection-surface mismatch (secrets in `user_data` and Lambda environment blocks, outside TerraVault's regex surface), redundancy (a second `aws_rds_cluster` query that would double-count the same sibling-resource gap), and two S3 sub-concepts with ambiguous ground truth. The exclusion list and its reasons are committed with the harness.

### 4.3 Ablation of the hybrid score

The ablation compares three quantities on the home corpus: the mean rule score, the mean anomaly score and the mean final score, each computed over the 16 vulnerable and the 6 hardened cases. The figure of merit is the *separation* — the difference of the means between vulnerable and hardened. A component that discriminates well produces a large separation; a component that discriminates poorly and carries 40% of the weight necessarily pulls the combination toward its own, smaller separation.

### 4.4 Atypicality experiment (where the rules are silent)

The ablation measures the learned component on a corpus built to exercise the rules. To ask whether it contributes anything *outside* the rule catalogue, we need a population where the rules say nothing.

- **Population.** 49,673 `.tf` files were scanned from a corpus mined from the Terraform Registry (registry-wide) and public GitHub `.tf` blobs. After removing 4,624 hash duplicates, 34 oversized blobs, 25,118 files declaring no `resource` block and 1,856 files that failed to scan (1,852 HCL parse errors, 2 attribute errors, 2 per-file timeouts), **18,041 configurations** remain. Each is scanned by the production pipeline — rules and ML in the same pass. The **rule-clean** subpopulation, where all 11 rules report nothing, contains **437 configurations** (2.4% of the population); the remaining 17,604 are rule-flagged.
- **Atypicality axis, independent of the model.** Each configuration's 8-dimensional structural vector is scored by its Mahalanobis distance to the *training* feature distribution, using a Ledoit–Wolf shrunk covariance. This is a Gaussian distance computed from the training data, not the Isolation Forest's tree isolation, so "atypical" is defined without consulting the model's own verdict.
- **Measurements.** Within the rule-clean subpopulation we report the flag rate per atypicality band (below the median; p50–p90; p90–p99; at or above p99), the lift between the atypical decile and the typical half, the ranking AUC of the continuous anomaly score against the atypical-decile label, the Spearman correlation between the two axes, and the flag rate on rule-clean versus rule-flagged configurations. We additionally characterise the 15 most atypical rule-clean configurations by their raw feature values, because a selectivity number without a qualitative reading cannot distinguish "useful signal" from "systematic artefact".

### 4.5 Reproducibility

The heavy runs execute on Google Compute Engine through committed launcher scripts, and every artefact is retained: raw per-tool scanner output for the benchmark, the metrics JSON for all three experiments, and the GCS run identifiers (`foreign-20260716-004135`, `ml-atypical-20260721-011109`). The atypicality experiment was then re-run as a full independent replicate on different hardware — `e2-highcpu-16` with 16 worker processes instead of `e2-standard-8` with 8, over a separately mined corpus (run `ml-atypical-20260721-012015`). Every headline metric was identical to the digit: 18,041 kept, 437 rule-clean, lift 50.25, AUC 0.9151, rho 0.7478, typical-half rate 0.0199, rule-flagged rate 0.0892. The experiment is deterministic under re-mining and re-parallelisation, which is the reproducibility bar this project claims elsewhere.

## 5. Results

### 5.1 Home corpus: detection benchmark

Tools: TerraVault 1.0.0 (native, in-process); Checkov 3.3.0, tfsec v1.28.14 and Terrascan v1.19.9, each from its official Docker image pinned by digest.

| Tool | Precision | Recall | F1 | Categories | FP (hardened) | Raw findings |
|---|---|---|---|---|---|---|
| TerraVault | 100.0% | 100.0% | 100.0% | 11/11 | 0 | 23 |
| Checkov | 100.0% | 95.7% | 97.8% | 10/11 | 0 | 187 |
| tfsec | 100.0% | 87.0% | 93.0% | 9/11 | 0 | 107 |
| Terrascan | 100.0% | 47.8% | 64.7% | 5/11 | 0 | 63 |

TerraVault recovers all 23 labels; Checkov misses one (the hardcoded secret), tfsec three, Terrascan twelve. No tool produces a false positive on the six hardened cases. The result must be read with its construct: the corpus exercises exactly the 11 categories TerraVault implements, and the raw-findings column shows the breadth the competitors carry outside that taxonomy — 187 findings for Checkov against 23 for TerraVault. That is focus versus breadth, and it is what Section 5.2 measures on foreign ground.

Scan time is reported for completeness, not as an engine benchmark: TerraVault runs natively (1.27 s total, 0.058 s per case) while the competitors pay Docker startup per invocation (Checkov 230.49 s, tfsec 58.71 s, Terrascan 217.72 s in total).

### 5.2 Foreign corpus: the external-validity bound

| Tool | Precision | Recall | F1 | Categories | FP (negatives) |
|---|---|---|---|---|---|
| TerraVault | 70.4% | 59.4% | 64.4% | 6/11 | 8 |
| Checkov | 69.4% | 78.1% | 73.5% | 6/11 | 11 |
| tfsec | 74.1% | 62.5% | 67.8% | 6/11 | 7 |
| Terrascan | 100.0% | 18.8% | 31.6% | 2/11 | 0 |

The aggregate drop from 100/100/100 to 70.4/59.4/64.4 is the honest measure of external validity, and it is not evenly distributed. The decomposition by scope is the result:

| Tool | Recall inside TerraVault's rule scope | Recall outside it |
|---|---|---|
| TerraVault | 19/23 (83%) | 0/9 (0%) |
| Checkov | 22/23 (96%) | 3/9 (33%) |
| tfsec | 18/23 (78%) | 2/9 (22%) |
| Terrascan | 6/23 (26%) | 0/9 (0%) |

Inside the resource scope its rules declare, on fixtures written by someone else, TerraVault recovers 83% — generalisation within its stated scope, with Checkov ahead at 96% and tfsec behind at 78%. Outside that scope it recovers nothing, and the gaps are nameable: RDS **clusters** (`aws_rds_cluster`, where the encryption rule targets `aws_db_instance`), **non-role IAM** policy documents (`aws_iam_policy` / `aws_iam_user_policy` with a list-shaped `Action` plus `Resource: "*"`, where the rule inspects `aws_iam_role_policy` for a literal wildcard action), **standalone security-group rules** (`aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, where the rule reads inline `ingress` blocks) and **account-level S3 public-access blocks** (`aws_s3_account_public_access_block`, where the rule reads the bucket-level resource). Each is a coverage-breadth deficit with a bounded implementation cost, not a failure of detection logic.

TerraVault's 8 false positives on the negatives have two causes. Seven are S3 cases where KICS labels a bucket safe for *one* public-access flag while others remain disabled; TerraVault's check is holistic (any protection disabled implies risk) and is therefore stricter than the label. One is an IMDSv1 case where `http_endpoint = "disabled"` mitigates the metadata service without `http_tokens = "required"` — a real limitation of the current rule, which observes only `http_tokens`. For calibration, Checkov produced 11 false positives on the same negatives and tfsec 7.

### 5.3 The ablation: the learned component compresses the rules' separation

| Component | Mean, vulnerable cases | Mean, hardened cases | Separation |
|---|---|---|---|
| Rule score alone | 50.0 | 16.7 | **33.3** |
| Anomaly score alone | 48.7 | 45.5 | **3.2** |
| Hybrid final score (0.6/0.4) | 49.1 | 27.7 | **21.4** |

This is the paper's central negative result and we state it without softening: on the controlled corpus the deterministic rules separate vulnerable from hardened configurations by 33.3 points, the Isolation Forest by 3.2, and mixing the two at 60/40 yields 21.4 — worse than the rules alone. A component carrying 40% of the weight and discriminating by 3.2 points can only pull the combination toward its own value. Anyone deploying the hybrid score as a threshold gate on configurations of this shape would be better served by the rule score alone.

The mechanism is visible in the corpus design rather than in the model. Each vulnerable case isolates one category with all other attributes hardened, so the vulnerable and hardened cases are structurally near-identical: a handful of resources, similar type diversity, similar IAM and logging counts. The 8-dimensional vector barely moves between them (48.7 versus 45.5), because what changed is a boolean attribute inside one resource, not the shape of the configuration. The anomaly detector is not failing at its own task; it is being asked a question its input cannot answer.

The same pattern, more severely, appears on the foreign corpus, where the fixtures are even more tightly matched (positives and negatives frequently differ by a single attribute): mean final score 40.0 on positives versus 36.2 on negatives (3.8 points), from rule means of 37.0 versus 31.2 (5.8 points) and anomaly means of 45.8 versus 45.0 (0.8 points). On fixture-shaped inputs, the structural signal is close to flat.

### 5.4 Where the anomaly signal does earn its place

The ablation measures the learned component on inputs designed to exercise the rules. The complementary question is what it does where the rules are silent. In the rule-clean subpopulation (437 of 18,041 real configurations), banded by the independent Mahalanobis atypicality axis:

| Atypicality band (Mahalanobis) | Configs | IF-flagged | Flag rate |
|---|---|---|---|
| below p50 (typical half) | 201 | 4 | 2.0% |
| p50–p90 | 189 | 113 | 59.8% |
| p90–p99 | 42 | 42 | 100.0% |
| at or above p99 (extreme) | 5 | 5 | 100.0% |

The flag rate is strictly monotone in atypicality. The atypical decile (47 configurations at or above p90) is flagged at 100.0% against 2.0% for the typical half — a lift of **50.25x**. The continuous anomaly score ranks the atypical decile above the rest with **AUC 0.9151**, and the Spearman correlation between the two axes is **rho = 0.7478** (p = 2.1e-79). Every one of these flags is a configuration the 11 rules passed.

Orthogonality runs in the other direction as well, which is the harder test:

| Population | Configs | IF-flagged | Flag rate |
|---|---|---|---|
| Rule-clean (rules silent) | 437 | 164 | 37.5% |
| Rule-flagged (rules fire) | 17,604 | 1,571 | 8.9% |

If the learned component were a re-encoding of the rules, it would fire *more* on the configurations the rules flag. It fires four times *less*. The violations the rules catch tend to be structurally ordinary — one misconfigured resource in an otherwise unremarkable file — while the large, diverse modules the rules approve are what look anomalous. The two signals are, empirically, orthogonal; this is the premise of the hybrid design, here observed directly rather than assumed.

What the flagged configurations actually are matters as much as the rates. Among the 15 most atypical rule-clean configurations, the atypicality is **pure resource-graph shape**: very large or very diverse modules (up to 142 resources; up to 28 distinct resource types in a 30-resource module) and highly repetitive ones (6 of the 15 declare many resources of only 1–2 types). Not one of them has encryption coverage below 1.0, and only one declares any public exposure at all. This strengthens the orthogonality claim — the model is plainly not reproducing a rule finding by another route — and it imposes the limit stated in Section 6.3: **structurally unusual is not evidence of vulnerability**.

### 5.5 Reconciling the two results

Two statements in this paper point in opposite directions and both are true. They are not in conflict because they are answers to different questions over different populations, and we ask readers to carry them together:

1. **On the controlled corpus, the learned component compresses the rules' separation** (33.3 → 21.4 points). Where the rules already speak, the anomaly score adds noise to the risk ranking, not sharpness. Nothing in Section 5.4 reverses this, and the 60/40 default weighting is not vindicated by it.
2. **In the rule-clean population, the anomaly signal is real, orthogonal and selective** (2.0% → 100% along an independent axis; lift 50.25x; AUC 0.9151; fires on 37.5% of rule-clean versus 8.9% of rule-flagged configurations). Nothing in Section 5.3 refutes this, because the controlled corpus contains no rule-clean-but-structurally-unusual configurations to measure it on.

The operational reading follows directly. The rule findings are what a CI gate should act on. The anomaly score is a **prioritisation signal for human review** over configurations that pass the rules: useful, orthogonal, and — per Section 6.3 — never sufficient on its own to assert risk. A deployment that blocks a merge because the Isolation Forest fired would be misusing this result.

## 6. Threats to Validity

### 6.1 Construct validity

The home corpus, its labels and TerraVault's rules share one author, so its perfect score is compatible with "teaching to the test". This threat is the reason the foreign corpus exists, and it is now **bounded by data rather than merely disclosed**: on third-party fixtures the same tool scores 70.4/59.4/64.4, with the loss localised to out-of-scope resources (0/9) rather than to in-scope detection (19/23). The residual construct threat is that the in-scope/out-of-scope split is itself our classification: `tv_scope` is derived from the resource types each rule inspects, which is a property of our code, not of KICS. We publish the mapping and its per-query rationale so the split can be audited.

### 6.2 Internal validity

*Scoring mode.* The foreign corpus is scored in target-slice mode — each fixture is judged only for the concept KICS labels it with — because it lacks complete multi-label ground truth. A tool that reports an unrelated true issue on a fixture is neither credited nor penalised for it.

*Taxonomy projection.* Native finding identifiers are projected onto 11 concepts. Unmapped identifiers are recorded rather than dropped silently, but the projection is a judgement and a different analyst could map a borderline rule differently.

*Version skew between runs.* The home benchmark ran Checkov 3.3.0 and the foreign benchmark Checkov 3.3.8 (different image digests). tfsec and Terrascan versions are identical across both runs. Checkov's two numbers are therefore not from the same build, and cross-corpus comparisons of Checkov specifically should be read with that caveat.

*Timing.* Competitor timings include Docker container startup, roughly constant per invocation; TerraVault runs in-process. The timing table is indicative, not an isolated-engine benchmark.

*Corpus attrition in the atypicality study.* 1,856 files (1,852 of them HCL parse failures) were excluded from the 18,041-configuration population. If unparseable files are systematically unusual, their exclusion biases the atypicality distribution in an unmeasured direction.

### 6.3 Limits of the atypicality result

Three limits (a–c) travel with the claim and must not be separated from it; (d) is a disclosure about the operating point.

**(a) This is an in-distribution study.** The model was trained on essentially all public Terraform available to us (registry-wide plus the public GitHub `.tf` blobs), and 18,013 of the 18,041 scanned configurations reproduce a training vector exactly. Only 2 rule-clean configurations are genuinely held out. There is therefore no meaningful held-out real corpus to be had at this scale, and the question we answer is *selectivity and orthogonality within the population the model was calibrated for* — not generalisation to unseen distributions.

**(b) The Mahalanobis–Isolation Forest correlation is partly circular by construction.** Both quantities measure distance from the training distribution, so some correlation is expected regardless of whether the model is useful. This is why rho = 0.7478 is *not* the load-bearing evidence. The load-bearing evidence is (i) orthogonality to the rules — the model fires on 37.5% of rule-clean versus 8.9% of rule-flagged configurations, a relation no shared-distance artefact predicts — and (ii) selectivity, the 2.0% floor on the typical half, which shows the production threshold is not simply firing on everything.

**(c) Structural atypicality is not evidence of vulnerability.** In this sample the atypicality is pure resource-graph shape: no top-atypical configuration had encryption coverage below 1.0 or (with one exception) any public exposure. The signal therefore prioritises human review; it must never be used as an automatic gate, and no claim in this paper should be read as "the Isolation Forest finds vulnerabilities the rules miss". It finds *configurations that are unusual*, some of which may deserve a look.

**(d) The operating threshold is uncalibrated.** `contamination=0.1` is trained into the model, yet 37.5% of the rule-clean population trips the resulting flag. Since the *ranking* is sound (AUC 0.9151), the appropriate fix is a percentile cutoff on the continuous anomaly score rather than the raw `predict == -1` decision. That calibration is in flight and is not part of the results reported here.

### 6.4 External validity

TerraVault covers AWS only, 11 categories, single files without module or remote-state resolution; the results say nothing about Azure, GCP or module-composed configurations. The foreign corpus is small (57 fixtures, 32 positives) and exercises only 8 of the 11 taxonomy categories, so per-category figures rest on very few cases — 15 of the 32 positives are S3. Both corpora are fixture sets rather than a field study of production repositories; the atypicality study is the closest thing to a field measurement here, and it measures *structure*, not *incidents*. The benchmark is tied to the pinned tool versions: rule coverage in Checkov, tfsec and Terrascan changes across releases.

### 6.5 Statistical validity

The atypicality bands are small at the tail (42 configurations in p90–p99 and 5 at or above p99), so the 100% flag rates in those bands are point estimates over few samples and should not be read as guarantees. The ablation separations are differences of means over 16 vulnerable and 6 hardened cases; no confidence intervals are reported and, at those sample sizes, none would be narrow. `TODO(stats)`: consider adding bootstrap confidence intervals for the ablation separations and Wilson intervals for the band flag rates before submission — both are cheap to compute from the committed metrics files and would materially strengthen Section 5.

## 7. Conclusion and Future Work

We evaluated a hybrid rule + anomaly-detection Terraform scanner along three axes and reported what each one actually showed. Under a shared 11-category taxonomy the tool reaches 100/100/100 on a controlled corpus against 97.8, 93.0 and 64.7 F1 for Checkov, tfsec and Terrascan. On 57 third-party KICS fixtures it scores 64.4 F1, with the loss localised: 83% recall inside the resource scope its rules declare, 0% outside it — a coverage-breadth deficit with four named gaps rather than a detection-quality deficit. And the learned half, which a hybrid design is usually assumed to strengthen, *compresses* the rules' separation on the controlled corpus (33.3 → 21.4 points), while proving orthogonal and selective where the rules are silent (lift 50.25x, AUC 0.9151, 37.5% versus 8.9%).

The practical lesson generalises past this tool: a learned component in a hybrid security analyser should be evaluated on the population where it is supposed to contribute, and weighted according to what it contributes there — not blended into a single score by default and assumed to help. Here, the honest configuration is: rules gate, anomaly ranks.

Four items follow from the results. **(i) Threshold calibration.** Replace `predict == -1` with a percentile cutoff on the continuous score and re-measure the selectivity curve; the ranking quality (AUC 0.9151) says the information is present and only the operating point is wrong. **(ii) A second, independently mined corpus** to test whether the 2.0% typical-half rate holds outside this mine. **(iii) Close the four named coverage gaps** — RDS clusters, non-role IAM policy documents, standalone security-group rules, account-level S3 blocks — and re-run the foreign benchmark, which now doubles as a regression test for coverage breadth. **(iv) Weighting as a first-class decision**: expose per-population weights, since the evidence supports a rule-dominant gating score plus a separate anomaly-ranked review queue rather than one blended number.

`TODO(artifact)`: add an artefact-availability statement with the public repository URL and the commit SHA that reproduces every number in this paper, plus the licence (AGPL-3.0 with a commercial option).

## References

Grounded references — verified against project artefacts:

- Liu, F. T., Ting, K. M., and Zhou, Z.-H. (2008). *Isolation Forest*. In Proceedings of the Eighth IEEE International Conference on Data Mining (ICDM '08). `TODO(cite)`: confirm page range and publisher formatting for the SBC style.
- Checkov, version 3.3.0 (home benchmark) and 3.3.8 (foreign benchmark), Bridgecrew/Prisma Cloud. Official Docker images pinned by digest in the committed metrics files. `TODO(cite)`: add the citable project reference.
- tfsec, version v1.28.14, Aqua Security. Image pinned by digest. `TODO(cite)`: add the citable project reference.
- Terrascan, version v1.19.9, Tenable. Image pinned by digest. `TODO(cite)`: add the citable project reference.
- KICS (Checkmarx), fixtures at commit `ac94c2cd8411bf9310b64cae8a628ffadd26b8f6`. `TODO(cite)`: add the citable project reference.
- Instrução Normativa COENS-DV/UTFPR nº 7, de 17 de novembro de 2023 (cited only in the submission notes, not required in the paper itself).

Required but not yet grounded — **must be added and verified before submission**:

- `TODO(cite)`: Terraform adoption / IaC prevalence claim in Section 1.
- `TODO(cite)`: empirical work on IaC security smells and IaC defect studies (Section 2).
- `TODO(cite)`: at least one prior comparative evaluation of IaC static analysers (Section 2), to position C1 honestly.
- `TODO(cite)`: literature on false-positive burden in static application security testing (Section 2 and Section 5.2).
- `TODO(cite)`: Ledoit, O. and Wolf, M. — shrinkage covariance estimation (Section 4.4).
- `TODO(cite)`: any prior application of anomaly detection to IaC or cloud configuration; if none is found, state the search that was performed.
- `TODO(cite)`: the under-reporting of unfavourable ablations (Section 1) — either cite it or rewrite the sentence as a scoped observation.

**Note on the project README's existing references.** The repository's README currently cites "Gartner (2024). Cloud Security Failures Report" and "IBM Security (2024). Cost of a Data Breach Report". Neither was verifiable from the repository, and the first appears to be a paraphrase of a widely repeated claim rather than a real report title. Do **not** carry either into the paper without checking the primary source; a fabricated or misattributed reference in a submission is a worse failure than an unsourced sentence.
