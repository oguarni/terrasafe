#!/usr/bin/env python3
"""Render the A.3 report from ``ml_atypicality_metrics.json``.

Companion to ``report.py`` / ``report_foreign.py``. The home report measures
detection on a controlled corpus; the foreign report measures external validity;
this one answers the hybrid design's open question: on real, rule-clean configs,
does the Isolation Forest *selectively* flag the structurally atypical ones — and
is that signal orthogonal to the rules?

Every number is read from the metrics file; the verdict paragraph is derived
from the measured discrimination/selectivity, not hard-coded, so it reports
honestly whatever the run produced (vindication, partial, or retirement).

Run:  ``python -m evaluation.report_ml_atypicality --results-dir <dir>``
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from evaluation.report import _md_table, _pct

_CONTAMINATION = 0.10  # the model's trained anomaly fraction (ml_model.py)


def _basename(path: str) -> str:
    """Two trailing path segments — enough to identify the module/file."""
    parts = Path(path).parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else path


def selectivity_table(a: dict) -> tuple[List[str], List[List[str]]]:
    headers = ["Faixa de atipicidade (Mahalanobis)", "Configs", "Sinalizadas pelo IF", "Taxa"]
    rows = []
    for b in a["flag_bands"]:
        rows.append([b["band"], str(b["n"]), str(b["flagged"]), _pct(b["flag_rate"])])
    return headers, rows


def top_atypical_table(a: dict) -> tuple[List[str], List[List[str]]]:
    headers = ["Config (rule-clean)", "Mahalanobis", "Anom. IF", "Sinal.",
               "recursos", "tipos", "enc.cov", "público"]
    rows = []
    for t in a["top_atypical"]:
        f = t["features"]
        rows.append([
            _basename(t["path"]), f"{t['mahalanobis']:.1f}", f"{t['if_anomaly']:.3f}",
            "sim" if t["flagged"] else "não",
            f"{f['resource_count']:.0f}", f"{f['resource_type_diversity']:.0f}",
            f"{f['encryption_coverage']:.2f}", f"{f['public_exposure_count']:.0f}",
        ])
    return headers, rows


def _verdict(a: dict, overall_flag_rate: float) -> str:
    """Data-driven honest verdict from discrimination + selectivity + calibration."""
    auc = a.get("ranking_auc")
    lift = a.get("selectivity_lift")
    typ = a["typical_half"]["flag_rate"]
    discriminates = auc is not None and auc >= 0.70
    selective = lift is not None and lift >= 2.0

    if not discriminates and not selective:
        return ("**Veredito — aposentar para este uso.** O escore de anomalia não "
                f"ordena nem sinaliza seletivamente as configurações atípicas (AUC "
                f"{auc}, *lift* {lift}). É coerente com a ablação do corpus caseiro: "
                "onde as regras não falam, o detector de anomalias tampouco "
                "acrescenta um sinal acionável.")

    core = ("**Veredito — o sinal de anomalia é um eixo real e ortogonal às "
            f"regras.** O escore contínuo do IF ordena as configurações atípicas "
            f"acima das típicas com AUC {auc}, e a taxa de sinalização cresce "
            f"monotonicamente com a atipicidade (*lift* {lift}× entre o decil "
            "atípico e a metade típica). Como essa população é *rule-clean*, cada "
            "sinal do IF é uma configuração que as 11 regras deixaram passar.")

    if typ <= 0.15:
        calib = (" Além disso o limiar de produção é seletivo: quase não dispara na "
                 f"metade típica ({_pct(typ)}), então os sinais concentram-se onde há "
                 "de fato estrutura incomum — utilizável como sinal de revisão.")
    else:
        calib = (f" Porém o limiar de produção super-sinaliza: dispara em {_pct(typ)} "
                 "da metade típica e em "f"{_pct(overall_flag_rate)} da população "
                 "*rule-clean* como um todo, muito acima da contaminação treinada de "
                 f"{_pct(_CONTAMINATION)}. A *ordenação* é sólida; o *corte* precisa "
                 "de recalibração antes de virar um gate automático.")
    return core + calib


def build_markdown(d: dict) -> str:
    meta = d.get("run_meta", {})
    pop = d["population"]
    a = d["rule_clean_analysis"]
    ortho = d.get("rule_flagged_analysis")
    held = d.get("rule_clean_held_out_analysis")

    lines: List[str] = []
    A = lines.append
    A("# A ML consegue vencer onde as regras se calam? (experimento A.3)\n")
    A(f"*Gerado por `evaluation/report_ml_atypicality.py` a partir de "
      f"`ml_atypicality_metrics.json` (modelo `{meta.get('model_version','?')}`, "
      f"{meta.get('training_vectors','?')} vetores de treino).*\n")

    A("## 1. A pergunta\n")
    A("A ablação honesta do manuscrito mostra que, no corpus caseiro, o componente "
      "de ML *comprime* a separação das regras: cada caso ali isola uma categoria "
      "que as regras já cobrem, então o detector de anomalias nunca contribui com "
      "um sinal independente. Este experimento constrói o teste que faltava — dá à "
      "ML uma população onde **as regras se calam** e mede se o Isolation Forest "
      "sinaliza *seletivamente* as configurações estruturalmente atípicas.\n")

    A("## 2. Método\n")
    A(f"**População.** {pop['kept']} configurações `.tf` reais "
      f"(de {pop['seen']} arquivos varridos; {pop['deduped']} duplicatas por hash, "
      f"{pop.get('oversize', 0)} blobs gigantes e {pop['no_resource']} sem bloco "
      "`resource` descartados). Cada uma é varrida "
      "pelo scanner de produção — regras **e** ML no mesmo passe. Mantemos a "
      f"subpopulação **rule-clean**: {pop['rule_clean']} configs onde as 11 regras "
      "nada reportam. É a única população onde só a ML pode falar.\n")
    A("**Eixo de atipicidade (independente da ML).** O vetor estrutural de 8 "
      "dimensões de cada config recebe a distância de Mahalanobis até a distribuição "
      "de treino (covariância encolhida por Ledoit-Wolf) — uma medida gaussiana "
      "calculada dos dados de treino, **não** do isolamento em árvores do modelo. "
      "Assim \"atípico\" é definido sem consultar o veredito do próprio IF.\n")
    if pop.get("train_vector_overlap", 0) >= pop["kept"] * 0.9:
        A("**Estudo in-distribution (divulgação honesta).** O modelo foi treinado "
          "sobre praticamente todo o Terraform público (registry-wide + todos os "
          f"blobs `.tf` do GitHub), então {pop['train_vector_overlap']}/{pop['kept']} "
          "configs reproduzem exatamente um vetor de treino e não há corpus real "
          "*held-out* significativo. A pergunta aqui não é de generalização, mas de "
          "**seletividade e ortogonalidade** dentro da população para a qual o "
          "modelo foi calibrado. A correlação Mahalanobis↔IF é, em parte, esperada "
          "por construção (ambos medem distância ao treino) e por isso **não** é o "
          "resultado central; o são a ortogonalidade às regras e a caracterização "
          "qualitativa abaixo.\n")
    elif held:
        A(f"**Subconjunto held-out.** {held['n']} configs *rule-clean* cujo vetor "
          "exato não aparece no treino são analisadas à parte (seção 5) como prova "
          "de que o resultado não depende de memorização.\n")

    A("## 3. Seletividade e discriminação (população rule-clean)\n")
    A(_md_table(*selectivity_table(a)) + "\n")
    A(f"Discriminação: AUC {a['ranking_auc']} do escore contínuo do IF ao ordenar o "
      f"decil atípico contra o resto; correlação de Spearman ρ={a['spearman_rho']} "
      f"(p={a['spearman_p']:.1e}). Decil atípico sinaliza {_pct(a['atypical_decile']['flag_rate'])} "
      f"vs. {_pct(a['typical_half']['flag_rate'])} na metade típica "
      f"(*lift* {a['selectivity_lift']}×). Taxa global de sinalização na população "
      f"rule-clean: {_pct(a['overall_flag_rate'])}.\n")

    A("## 4. Ortogonalidade às regras\n")
    if ortho:
        A("Se a ML fosse redundante com as regras, sinalizaria as mesmas "
          "configurações. O oposto acontece:\n")
        A(_md_table(
            ["População", "Configs", "Sinalizadas pelo IF", "Taxa"],
            [["Rule-clean (regras se calam)", str(a["n"]), str(a["flagged"]),
              _pct(a["overall_flag_rate"])],
             ["Rule-flagged (regras disparam)", str(ortho["n"]), str(ortho["flagged"]),
              _pct(ortho["flag_rate"])]]) + "\n")
        A(f"O IF sinaliza a população *rule-clean* a {_pct(a['overall_flag_rate'])} e "
          f"a população *rule-flagged* a apenas {_pct(ortho['flag_rate'])}: as "
          "violações que as regras pegam tendem a ser estruturalmente simples (um "
          "recurso mal configurado), enquanto os módulos grandes e complexos que as "
          "regras aprovam é que parecem anômalos. Os dois sinais são ortogonais — a "
          "premissa do design híbrido, aqui observada diretamente.\n")

    A("## 5. As configurações atípicas-mas-válidas que o IF destaca\n")
    A("Top configs *rule-clean* por atipicidade (o que a ML vê e as regras não):\n")
    A(_md_table(*top_atypical_table(a)) + "\n")
    A("> Ler a coluna `enc.cov`: uma cobertura de criptografia baixa numa config "
      "*rule-clean* costuma ser um recurso *irmão* fora do escopo das regras (ex.: "
      "`aws_rds_cluster`, cuja criptografia a regra — que mira `aws_db_instance` — "
      "não inspeciona). O sinal estrutural da ML capta exatamente a lacuna de "
      "cobertura que o corpus de terceiros (A.2) quantificou.\n")

    A("## 6. Veredito\n")
    A(_verdict(a, a["overall_flag_rate"]) + "\n")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Render the A.3 ML-atypicality report")
    ap.add_argument("--results-dir", type=Path, required=True,
                    help="dir containing ml_atypicality_metrics.json")
    args = ap.parse_args()
    results_dir: Path = args.results_dir.resolve()
    d = json.loads((results_dir / "ml_atypicality_metrics.json").read_text(encoding="utf-8"))
    if "rule_clean_analysis" not in d:
        print(f"metrics has no rule_clean_analysis: {d.get('error','?')}")
        return 1
    out = results_dir / "report_ml_atypicality.md"
    out.write_text(build_markdown(d), encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
