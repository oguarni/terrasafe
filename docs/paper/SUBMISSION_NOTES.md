# Submission notes — TerraVault SBC paper

Companion to `sbc_paper_draft.md` and `EVIDENCE_MAP.md`. Everything here is a decision aid, not a decision: items that require verification against a live call for papers or the current Qualis list are marked `TODO(verify)` rather than asserted.

---

## 1. What the institutional rules actually imply

Source: `docs/IN_COENS_DV_7_2023.md` (Instrução Normativa COENS-DV/UTFPR nº 7, de 17 de novembro de 2023). Article references below are to that text.

### 1.1 Convalidation (Art. 33–34, 36) — probably no longer the relevant lever

- **Art. 33** allows TCC 1 and TCC 2 to be *convalidated* by (I) a paper in a conference with Qualis in Computer Science, (II) a journal with Qualis in Computer Science, or (III) intellectual property (software registration or patent filing). §1º: if TCC 1 is already concluded, only TCC 2 is convalidated. §3º: only work produced after enrolment counts.
- **Art. 34** requires the student to be *preferentially* the first author; if not, a letter from the first author describing the student's contribution must be attached (§1º). §2º makes UTFPR faculty participation optional. §3º fixes the grade by Qualis stratum: **10** for A1–A4, **9** for B1–B2, **8** for B3–B4 — evaluated at the moment of the request.
- **Art. 36** requires a formal request to DERAC with the publication and its Qualis attached (plus the first-author letter when applicable).

**Practical reading.** TCC 2 was defended on 2026-07-03 and the final version was submitted. Convalidation is a mechanism for *replacing* the TCC deliverable, so once TCC 2 is approved there is nothing left to convalidate. Do not plan the paper around Art. 33–34 unless the component is still open for some reason — `TODO(verify)` the current academic status with DERAC/PRATCC before relying on either reading. What Art. 34 §3º still tells you is how the institution ranks venues, which is a reasonable proxy for where the effort is best spent: A-stratum venues are worth materially more than B ones.

### 1.2 Art. 37 — the clock that does matter

> "Reserva-se ao acadêmico o direito à publicação de artigos e relatórios, oriundos de TCC, e na qualidade de primeiro autor, até um limite de 6 (seis) meses da data de sua aprovação." (§1º: after that window, the advisor may write them up and set the author order at his discretion, without omitting the student. §2º: if the TCC is part of a larger project, the advisor defines the author order.)

- Approval date: **2026-07-03**. The six-month first-author window therefore closes on or about **2027-01-03** — `TODO(verify)` whether "aprovação" is counted from the defence date or from the homologation of the final version; the earlier date is the safe assumption.
- Consequence: submitting as first author before that date is a right, not a negotiation. After it, author order becomes the advisor's call.
- This does not remove the courtesy and practical value of co-authoring with the advisor and co-advisor — it removes the ambiguity about who decides.

### 1.3 Format rules that do *not* apply here

Art. 12 and Art. 17 (SBC model; 4–6 pages for the TCC 1 proposal, 10–15 pages for a TCC 2 delivered *as an article*) govern the TCC deliverable itself, not an external publication. The page budget for this paper comes from the target venue's call for papers, not from the IN.

---

## 2. Venue candidates

Ranked by fit. **No Qualis stratum is asserted below** — the Qualis list changes and none of it is verifiable from this repository. `TODO(verify)`: check each venue's current Qualis stratum in Computer Science (Sucupira / the CAPES list in force) and its CFP for page limit, language policy, review model (double-blind or not), and deadline, before choosing.

### 2.1 SBSeg — Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (recommended)

- **Why it fits:** it is the SBC venue for information and computer systems security. The paper is a security-tool evaluation whose central claim (when a learned component earns its place in a hybrid detector) is a security-methodology argument. The audience knows SAST, false-positive economics and the "another 100% table" failure mode, which is exactly the audience this paper is written against.
- **Fit for the honest ablation:** a negative-direction ablation with a bounded external-validity study is a better story for a security-methodology audience than for a general software-engineering one.
- **Watch for:** `TODO(verify)` whether the main track (Trilha Principal) page budget matches the current 6–10 page draft, whether there is a shorter track (short papers / tool demos / workshops such as WTICG for undergraduate work) that would fit better, and the language policy.

### 2.2 SBES — Simpósio Brasileiro de Engenharia de Software (part of CBSoft)

- **Why it fits:** the paper is, structurally, an empirical software-engineering study — a tool evaluation with a controlled corpus, a third-party corpus, an ablation and a threats-to-validity section. SBES also has tracks aimed at shorter contributions and at tools; `TODO(verify)` the exact track names, page limits and whether the CBSoft Tools session is a separate submission.
- **Watch for:** an SE audience will scrutinise experimental design more than security semantics — the missing confidence intervals (Section 6.5 of the draft) and the small foreign corpus (n = 57) are the likely review targets. If SBES is chosen, add the statistics before submitting.

### 2.3 VEM — Workshop de Visualização, Evolução e Manutenção de Software (CBSoft)

- **Why it might fit:** a workshop is a lower-risk first submission and a good place to get feedback on the ablation framing.
- **Serious caveat:** workshops frequently have **no Qualis stratum of their own**, which would make the publication worth nothing under the Art. 34 §3º scale and useless for any convalidation argument. `TODO(verify)` before treating VEM as a real option.

### 2.4 Others worth checking

- **SBRC** (Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos) — has a security-relevant scope and is generally well regarded; the IaC/cloud-configuration angle is a plausible fit. `TODO(verify)` scope match.
- **SBSI** (Simpósio Brasileiro de Sistemas de Informação) — broader information-systems scope; weaker fit for a detection-quality argument.
- **International venues** — outside the SBC scope this task targets, but note that the same evidence would support a short paper at an international SE or security workshop. If that is ever the plan, writing in English now is what makes it cheap (Section 3).

### 2.5 Recommendation

**Target SBSeg first.** It is the closest audience match, it is a full symposium rather than a workshop (so a Qualis stratum is likely to exist — still `TODO(verify)`), and the paper's contribution is a security-evaluation methodology argument. Keep SBES as the fallback if the SBSeg cycle does not fit the calendar, and budget the extra statistical work if that fallback is taken.

---

## 3. Language: PT-BR or English?

**Recommendation: write and submit in English, keeping the Portuguese `Resumo` that the SBC template requires anyway.** The draft is already in English.

Reasons, in order of weight:

1. **Nothing in the institutional rules forces Portuguese.** IN 7/2023 requires the SBC *model* for the TCC deliverable (Art. 12, Art. 17) and says nothing about the language of a convalidating or derived publication (Art. 33–34, Art. 37).
2. **SBC main tracks accept English.** `TODO(verify)` per venue CFP, but English submissions are routine at SBSeg and SBES; the SBC template ships with both `Abstract` and `Resumo` precisely because either language is acceptable.
3. **Reach and reuse.** The artefact is public, the code, CLI, README and rule messages are already in English, and the natural next step — an extended version for an international workshop — costs almost nothing if the text starts in English and a full rewrite if it starts in Portuguese.
4. **The competing argument is weaker than it looks.** The existing evaluation reports (`evaluation/results/report.md`, `report_foreign.md`, `report_ml_atypicality.md`) and the TCC monograph are in Portuguese, so a PT-BR paper looks cheaper. It is not: the paper's prose is new either way — what carries over is tables and numbers, which are language-neutral.

**When to switch to PT-BR:** if the chosen track's CFP requires or strongly prefers Portuguese (some regional events and undergraduate tracks such as WTICG do), or if the advisor prefers it for the banca-adjacent audience. In that case translate the draft in full with correct diacritics; do not ship a half-translated paper, and keep the English abstract.

---

## 4. What is still missing before submission

Ordered by "will block acceptance" first.

### 4.1 Blocking

1. **Related work with real citations.** Section 2 of the draft is a scaffold with explicit `TODO(cite)` markers. A submission cannot go out with them. Minimum viable set: (a) one IaC security-smell / IaC defect study, (b) one prior comparative evaluation of IaC scanners, (c) one reference per compared tool, (d) Liu et al. (2008) verified, (e) Ledoit–Wolf verified, (f) something on false-positive burden in SAST. Every one of them must be read before being cited. A fabricated or misattributed reference is the single worst failure mode here.
2. **Positioning claim must be sourced or softened.** The draft asserts that the literature rarely ablates hybrid components and rarely evaluates on a corpus authored by neither the tool author nor a competitor. Either back it with a documented search (venues, query strings, date range — and describe the search in the methodology) or downgrade it to "to the best of our knowledge".
3. **Author list.** Decide co-authors; get Prof. Marlon's full name (not recorded anywhere on disk); confirm with advisor and co-advisor before submission. Art. 37 gives the first-author right until roughly 2027-01-03; that is a right to exercise, and doing it with the advisors informed is the sane path.
4. **Typeset in the official SBC template.** The Markdown draft is for review only. Reflow into `sbc-template` (LaTeX), which fixes title block, abstract/resumo, section numbering and reference style. Recheck the page budget against the CFP after typesetting — tables expand.
5. **Verify venue mechanics.** Qualis stratum, deadline, page limit, language, review model, and whether prior deposit of the TCC monograph in the institutional repository (RIUT) must be disclosed as prior publication. `TODO(verify)`.

### 4.2 Strongly recommended (reviewers will ask)

6. **Statistics.** Bootstrap confidence intervals for the three ablation separations (33.3 / 3.2 / 21.4) and Wilson intervals for the band flag rates — the p90–p99 and >= p99 bands have 42 and 5 samples, and a bare "100.0%" invites a rejection comment. Both are computable from the committed metrics files with no new compute.
7. **Version skew.** The home benchmark ran Checkov 3.3.0 and the foreign benchmark Checkov 3.3.8. Either re-run the home benchmark on 3.3.8 (Docker; `make evaluate`) so both tables describe one build, or keep the disclosure in Section 6.2 and make sure no sentence compares Checkov's two numbers directly. Note the compute constraint: the free GCP credits expire 2026-07-22, so a re-run is local-or-paid from then on.
8. **Figures.** The paper currently has none. Two would carry their weight: (a) the scan-pipeline diagram (rules branch / structural branch / weighted combination), and (b) flag rate versus atypicality band — a four-bar chart straight out of `rule_clean_analysis.flag_bands`. `evaluation/results/tables/headline.tex` already contains a pgfplots table for the benchmark and can seed a third.
9. **Explain the corpus-count discrepancy.** `run_source.json` says 49,674 files mined; `ml_atypicality_metrics.json` says 49,673 seen. One file. Either explain it or footnote it — a reviewer who checks the artefact will find it.
10. **Artefact availability statement.** Public repository URL, the commit SHA that reproduces every number, and the licence (AGPL-3.0 with a commercial option). Check the venue's artefact-evaluation policy, if any.
11. **Third-party corpus licensing.** The foreign corpus is derived from KICS test fixtures at a pinned commit. Before redistributing the built corpus (as opposed to the builder script plus the pinned SHA), confirm KICS's licence permits it and attribute accordingly. `TODO(verify)`. The safe default is to ship the builder and the SHA, not the fixtures.

### 4.3 Housekeeping that protects the paper's credibility

12. **Fix the stale README.** `README.md` still claims 72 tests / 74% coverage and describes the ML training corpus as "synthetic-but-principled". The paper says 137 tests / 76.8% and 35,594 vectors of which 35,294 are real. A reviewer who opens the repository will see the contradiction. Update the README in the same window as the submission.
13. **Do not carry the README's unverified references into the paper.** "Gartner (2024). Cloud Security Failures Report" and "IBM Security (2024). Cost of a Data Breach Report" are currently listed there; the first looks misattributed. Verify against the primary source or drop them.
14. **Threshold calibration is in flight — keep it out of the results.** `contamination=0.1` is uncalibrated (37.5% of the rule-clean population trips it) and the percentile-cutoff fix is not finished. The draft discloses this in Section 6.3(d) and lists it as future work in Section 7. Do not report partial calibration numbers; if the calibration lands before submission, it becomes a new result with its own evidence row, not a patch to an existing sentence.
15. **Positioning discipline.** TerraVault is a SAST / IaC / DevSecOps tool. It must never be described as SIEM or SOC software, in the paper, the abstract, the talk or the artefact page.
16. **Keep the two ablation statements together.** Section 5.5 of the draft exists to prevent a reader (or a reviewer, or a future press-release writer) from quoting "the ML compresses the rules' separation" or "lift 50.25x" in isolation. If the paper is cut for space, that section is not the one to cut.

---

## 5. Draft status

| Item | State |
|---|---|
| Sections 1, 3, 4, 5, 6, 7 | complete and fully sourced (see `EVIDENCE_MAP.md`) |
| Section 2 (Related Work) | scaffold only — every citation is a `TODO(cite)` |
| References | grounded artefacts listed; academic references pending |
| Figures | none yet |
| Statistics (CIs) | none yet |
| Template | Markdown; SBC LaTeX pending |
| Language | English, with PT-BR `Resumo` |
| Length | ~5,900 words of body text (abstract through Section 7) plus 8 tables — roughly **10 pages** in the SBC template, i.e. the top of the 6–10 page target. Re-measure after typesetting. |
| Abstract / Resumo length | ~260 words each; the SBC template expects roughly 10 lines. **Trim both** when typesetting — cut the tool-by-tool comparison figures first, keep the three-result structure. |
| If the venue's page limit is tighter | Cut, in this order: Section 3.5 (engineering quality), the timing paragraph in 5.1, the per-rule table in 3.2 (summarise in prose), the foreign-corpus paragraph in 5.3. **Do not cut Section 5.5** — it is what keeps the two ablation statements from being quoted against each other. |
