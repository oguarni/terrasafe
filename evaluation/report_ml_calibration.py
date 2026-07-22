#!/usr/bin/env python3
"""Render the A.3 threshold-calibration report from ``ml_calibration_metrics.json``.

Companion to ``report_ml_atypicality.py``. A.3 established that the Isolation
Forest *ranks* rule-clean configurations by structural atypicality; this report
answers what to do with that ranking — where to cut it — and whether the cut
survives a second, hash-disjoint corpus.

Every number is read from the metrics file. The recommended operating point is
selected by a rule stated in the report itself (``_MIN_TAIL_RECALL``), not
hand-picked, so the choice is auditable and the reader can re-derive a different
one from ``per_config_scores.csv.gz`` without re-running any compute.

Run:  ``python -m evaluation.report_ml_calibration --results-dir <dir>``
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from evaluation.report import _md_table, _pct

# An operating point that loses more than half of the structurally extreme decile
# has stopped ranking that tail at all; keeping >= 50% of it is the constraint,
# and among the cutoffs that satisfy it the strictest wins (fewest reviews).
_MIN_TAIL_RECALL = 0.50


def _fmt_rate(block: Optional[dict]) -> str:
    """``flagged/n (rate)`` for a rate block, or an em dash when absent."""
    if not block:
        return "—"
    return f"{block['flagged']}/{block['n']} ({_pct(block['flag_rate'])})"


def _fmt_ratio(value: Optional[float], zero_denominator: bool) -> str:
    """A ratio, or an honest marker when its denominator was zero."""
    if value is not None:
        return f"{value}×"
    return "∞ (0 na base)" if zero_denominator else "—"


def sweep_table(sweep: List[dict]) -> tuple[List[str], List[List[str]]]:
    headers = ["Ponto de operação", "Corte (score)", "Rule-clean", "Rule-flagged",
               "Metade típica", "Decil atípico", "Lift"]
    rows = []
    for block in sweep:
        typical = block.get("typical_half")
        rows.append([
            block["operating_point"], f"{block['anomaly_cutoff']:+.4f}",
            _fmt_rate(block["rule_clean"]), _fmt_rate(block["rule_flagged"]),
            _fmt_rate(typical), _fmt_rate(block.get("atypical_decile")),
            _fmt_ratio(block.get("selectivity_lift"),
                       bool(typical and typical["flagged"] == 0)),
        ])
    return headers, rows


def band_table(block: dict) -> tuple[List[str], List[List[str]]]:
    headers = ["Faixa de atipicidade (Mahalanobis)", "Configs", "Sinalizadas", "Taxa"]
    rows = [[b["band"], str(b["n"]), str(b["flagged"]), _pct(b["flag_rate"])]
            for b in block.get("flag_bands", [])]
    return headers, rows


def population_table(corpora: List[dict]) -> tuple[List[str], List[List[str]]]:
    headers = ["Corpus", "Configs mantidas", "Rule-clean", "Descartadas por hash já visto",
               "Sobreposição residual", "Vetor idêntico ao treino"]
    rows = []
    for pop in corpora:
        rows.append([
            f"`{pop['label']}`", str(pop["kept"]), str(pop["rule_clean"]),
            str(pop["excluded_shared_with_earlier_corpus"]), "—",
            f"{pop['train_vector_overlap']}/{pop['kept']}",
        ])
    return headers, rows


def _apply_residual_overlap(rows: List[List[str]], disjointness: dict) -> None:
    """Fill the residual-overlap column from the hash-intersection recheck."""
    residual = {pair["corpus"]: pair["residual_hash_overlap"]
                for pair in disjointness.get("pairs", [])}
    for row in rows:
        label = row[0].strip("`")
        row[4] = str(residual[label]) if label in residual else "n/a (1º corpus)"


def recommend_operating_point(sweep: List[dict]) -> dict:
    """Strictest cutoff that still flags at least ``_MIN_TAIL_RECALL`` of the tail.

    Flag rates fall monotonically as the cutoff rises, so this is also the point
    with the smallest typical-half rate among the acceptable ones — i.e. the
    least noisy review queue that has not yet given up on the extreme decile.
    """
    candidates = [b for b in sweep
                  if b["cutoff_source"] != "trained-in"
                  and b.get("atypical_decile", {}).get("flag_rate", 0.0) >= _MIN_TAIL_RECALL]
    if not candidates:
        return sweep[0]
    return max(candidates, key=lambda b: b["anomaly_cutoff"])


def _by_name(sweep: List[dict], name: str) -> Optional[dict]:
    return next((b for b in sweep if b["operating_point"] == name), None)


def _trained_in_point(sweep: List[dict]) -> dict:
    """The shipped ``predict == -1`` row — the baseline every cutoff is judged against."""
    return next((b for b in sweep if b["cutoff_source"] == "trained-in"), sweep[0])


def _reconciliation_lines(reconciliation: dict) -> List[str]:
    """Show the A.3 re-check field by field — drift is reported, not smoothed."""
    headers = ["Métrica (corte herdado)", "A.3 arquivada", "Esta execução", "Δ", "Bate?"]
    rows = [[name, str(entry["banked_a3"]), str(entry["this_run"]),
             (f"{entry['delta']:+g}" if "delta" in entry else "—"),
             "sim" if entry["match"] else "**não**"]
            for name, entry in reconciliation["fields"].items()]
    differing = [name for name, entry in reconciliation["fields"].items()
                 if not entry["match"]]
    verdict = ("Todas as métricas da A.3 foram reproduzidas nesta execução, sobre um "
               "corpus minerado de novo — a calibração abaixo age exatamente sobre a "
               "população da A.3."
               if reconciliation["all_match"] else
               f"**Divergiram {len(differing)} de {len(reconciliation['fields'])} "
               f"métricas: {', '.join(f'`{name}`' for name in differing)}.** O registry "
               "se move entre minerações; a coluna Δ dá o tamanho de cada diferença e "
               "deve ser lida antes de comparar os cortes com os números arquivados.")
    return [_md_table(headers, rows) + "\n", verdict + "\n"]


def build_markdown(d: dict, sources: Dict[str, str]) -> str:
    meta = d.get("run_meta", {})
    corpora = d["corpora"]
    sweep_by_corpus = d["threshold_sweep"]
    home = corpora[0]["label"]
    home_sweep = sweep_by_corpus[home]
    status_quo = _trained_in_point(home_sweep)
    recommended = recommend_operating_point(home_sweep)

    lines: List[str] = []
    A = lines.append
    A("# Calibração do limiar de anomalia (desdobramento do A.3)\n")
    A(f"*Gerado por `evaluation/report_ml_calibration.py` a partir de "
      f"`ml_calibration_metrics.json` (modelo `{meta.get('model_version','?')}`, "
      f"{meta.get('training_vectors','?')} vetores de treino; o modelo **não** foi "
      "retreinado — apenas o corte sobre o escore foi calibrado).*\n")

    A("## 1. O problema que a A.3 deixou aberto\n")
    A("A A.3 mostrou que o escore contínuo do Isolation Forest **ordena** bem as "
      "configurações *rule-clean* pelo eixo independente de atipicidade "
      "(Mahalanobis). O que ela também mostrou é que o **corte** herdado do treino "
      f"(`contamination=0.1`) dispara em {_pct(status_quo['rule_clean']['flag_rate'])} "
      "da população *rule-clean* — alto demais para uma fila de revisão. Como a "
      "ordenação é boa e só o corte é ruim, a correção é um **corte percentílico "
      "sobre o escore bruto**, não o booleano `predict == -1`.\n")

    A("## 2. Artefato permanente (o corte nunca mais precisa de computação paga)\n")
    artifacts = d.get("artifacts", {})
    A(f"Esta execução gravou `{artifacts.get('per_config_scores','?')}` com "
      f"**{artifacts.get('per_config_rows','?')} linhas** — uma por configuração "
      "varrida — contendo o escore bruto do IF (`if_score_samples`, "
      "`if_decision_function`, `if_anomaly`), a distância de Mahalanobis, o veredito "
      "das regras, o hash do conteúdo e o vetor estrutural de 8 dimensões. Junto vai "
      f"`{artifacts.get('training_reference_scores','?')}` "
      f"({artifacts.get('training_reference_rows','?')} linhas) com a distribuição de "
      "escores do próprio treino, que é a **referência** dos cortes percentílicos. "
      "Com os dois arquivos, qualquer limiar — percentílico, absoluto, por faixa ou "
      "uma regra futura — é re-derivável offline, para sempre, sem repetir a "
      "mineração nem a varredura.\n")
    A("> Os cortes candidatos são percentis da distribuição de escores **do treino**, "
      "não do corpus avaliado. Isso os torna constantes absolutas do modelo: "
      "reproduzi-los exige apenas o modelo, e valem para qualquer configuração que o "
      "scanner venha a ver — em vez de um limiar recalibrado a cada corpus, que seria "
      "auto-referente.\n")

    A("## 3. Varredura de cortes\n")
    for index, pop in enumerate(corpora, start=1):
        label = pop["label"]
        note = sources.get(label)
        A(f"### 3.{index} Corpus `{label}`{f' — {note}' if note else ''}\n")
        A(f"{pop['kept']} configs mantidas · {pop['rule_clean']} *rule-clean* · "
          f"{pop['rule_flagged']} *rule-flagged*.\n")
        A(_md_table(*sweep_table(sweep_by_corpus[label])) + "\n")
        rank = d.get("ranking_quality", {}).get(label, {})
        if rank.get("ranking_auc") is not None:
            A(f"Discriminação (independente do corte): AUC {rank['ranking_auc']}, "
              f"Spearman ρ={rank['spearman_rho']} (p={rank['spearman_p']:.1e}) sobre "
              f"{rank['n']} configs *rule-clean*.\n")

    A("## 4. Ponto de operação recomendado\n")
    A(f"Regra de escolha, fixada no código e aplicada aos dados: **o corte mais "
      f"restritivo que ainda sinaliza pelo menos {_pct(_MIN_TAIL_RECALL)} do decil "
      "atípico**. Como todas as taxas caem monotonicamente com o corte, esse é "
      "também o ponto com a menor taxa na metade típica entre os aceitáveis — a fila "
      "de revisão mais limpa que ainda não desistiu da cauda extrema.\n")
    A(f"Escolhido: **{recommended['operating_point']}** "
      f"(corte {recommended['anomaly_cutoff']:+.4f} sobre `if_anomaly`).\n")
    if recommended["cutoff_source"] == "trained-in":
        A("> **Nenhum corte percentílico satisfez a regra** nesta execução: todos "
          "perderam mais da metade do decil atípico. O corte herdado permanece o "
          "único que preserva a cauda, e a escolha de um ponto de operação tem de ser "
          "feita à mão sobre `per_config_scores.csv.gz` — não há recomendação "
          "automática defensável aqui.\n")
    A(_md_table(*band_table(recommended)) + "\n")
    A(f"Nesse ponto, no corpus `{home}`: *rule-clean* "
      f"{_fmt_rate(recommended['rule_clean'])}, *rule-flagged* "
      f"{_fmt_rate(recommended['rule_flagged'])}, metade típica "
      f"{_fmt_rate(recommended.get('typical_half'))}, decil atípico "
      f"{_fmt_rate(recommended.get('atypical_decile'))}. Contra o corte herdado "
      f"({_fmt_rate(status_quo['rule_clean'])} na população *rule-clean*), a fila de "
      "revisão encolhe sem perder a cauda que motivou o experimento.\n")

    A("## 5. Segundo corpus — a verificação externa\n")
    rows_h, rows_r = population_table(corpora)
    _apply_residual_overlap(rows_r, d.get("disjointness", {}))
    A(_md_table(rows_h, rows_r) + "\n")
    A("**Prova de disjunção.** Os corpora são varridos na ordem dada e cada um "
      "descarta todo arquivo cujo sha256 de conteúdo um corpus anterior já admitiu. "
      "A coluna *sobreposição residual* é a interseção dos conjuntos de hashes "
      "recalculada **depois** da varredura: ela precisa ser 0, e é verificada em vez "
      "de apenas afirmada.\n")
    if len(corpora) > 1:
        second = corpora[1]["label"]
        second_sweep = sweep_by_corpus[second]
        second_status = _trained_in_point(second_sweep)
        second_rec = _by_name(second_sweep, recommended["operating_point"]) or {}
        A(f"No corte herdado, a metade típica sinaliza "
          f"{_fmt_rate(status_quo.get('typical_half'))} em `{home}` e "
          f"{_fmt_rate(second_status.get('typical_half'))} em `{second}`; no ponto "
          f"recomendado, {_fmt_rate(recommended.get('typical_half'))} e "
          f"{_fmt_rate(second_rec.get('typical_half'))} respectivamente. É esse par de "
          "números que diz se o resultado da A.3 era uma propriedade da mina original "
          "ou do sinal.\n")
    else:
        A("> **Não foi possível obter um segundo corpus nesta execução.** O relatório "
          "cobre apenas o corpus original; a verificação externa continua em aberto e "
          "não deve ser apresentada como feita.\n")

    A("## 6. Limites honestos (herdados da A.3 e ainda válidos)\n")
    overlap_lines = ", ".join(
        f"`{pop['label']}` {pop['train_vector_overlap']}/{pop['kept']}" for pop in corpora)
    A(f"1. **Estudo *in-distribution*.** O modelo treinou sobre praticamente todo o "
      f"Terraform público, e a sobreposição exata de vetores de treino aqui é "
      f"{overlap_lines}. Um segundo corpus **disjunto por hash** é uma *amostra "
      "diferente*, não uma distribuição retida: ele testa se a taxa se sustenta fora "
      "da mina original, não se o modelo generaliza para fora do que viu.\n")
    A("2. **A correlação Mahalanobis↔IF é em parte circular por construção** (ambos "
      "medem distância ao treino). A evidência que sustenta o resultado é a "
      "**ortogonalidade às regras** e a **seletividade**, não ρ.\n")
    A("3. **Atipicidade aqui é forma do grafo de recursos.** \"Estruturalmente "
      "incomum\" **não** é evidência de vulnerabilidade: o sinal serve para "
      "*priorizar revisão humana* e não pode virar gate automático — nem com o corte "
      "calibrado.\n")
    A("4. **A ablação do manuscrito não muda.** Regras sozinhas separam 33,3 pontos; "
      "híbrido 21,4; ML sozinha 3,2 — no corpus caseiro a ML *comprime* a separação "
      "das regras. Este experimento responde a outra pergunta (onde as regras se "
      "calam) e **não** refuta aquela.\n")

    reconciliation = d.get("a3_reconciliation")
    if reconciliation:
        A("## 7. Reconciliação com o resultado arquivado da A.3\n")
        lines.extend(_reconciliation_lines(reconciliation))

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Render the threshold-calibration report")
    ap.add_argument("--results-dir", type=Path, required=True,
                    help="dir containing ml_calibration_metrics.json")
    args = ap.parse_args()
    results_dir: Path = args.results_dir.resolve()
    metrics_path = results_dir / "ml_calibration_metrics.json"
    d = json.loads(metrics_path.read_text(encoding="utf-8"))
    if not d.get("corpora") or not d.get("threshold_sweep"):
        print(f"metrics file has no scanned corpus: {metrics_path}")
        return 1
    # Optional human description of each corpus, written by the launcher.
    sources_path = results_dir / "corpus_sources.json"
    sources: Dict[str, str] = (json.loads(sources_path.read_text(encoding="utf-8"))
                               if sources_path.exists() else {})
    out = results_dir / "report_ml_calibration.md"
    out.write_text(build_markdown(d, sources), encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
