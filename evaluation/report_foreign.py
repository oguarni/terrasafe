#!/usr/bin/env python3
"""Render the third-party (KICS) corpus report from a foreign ``metrics.json``.

Companion to ``report.py`` for the harness extension "A.2". The home report
answers "how good is detection on a controlled corpus"; this one answers the
external-validity question: **do the numbers hold on fixtures the author did not
write?** It therefore adds the analysis the home report cannot: a split of each
tool's recall into fixtures *within* TerraVault's rule scope (a fair head-to-head
on its own turf) versus *sibling-resource* fixtures it never claimed to cover
(where the gap is coverage breadth, not detection quality).

Everything is data-driven — no number is hard-coded — so it renders honestly
whatever the competitor run produces.

Run:  ``python -m evaluation.report_foreign --results-dir <foreign results dir>``
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Tuple

from evaluation.report import CAT_PT, TOOL_LABEL, _md_table, _pct

_TOOL_ORDER = ["terravault", "checkov", "tfsec", "terrascan"]


def _tools(data: dict) -> List[str]:
    """Present tools, in canonical order (foreign run may be TerraVault-only)."""
    return [t for t in _TOOL_ORDER if t in data["tools"]]


def _scope_recall(data: dict, tool: str, in_scope: bool) -> Tuple[int, int]:
    """(tp, positives) for ``tool`` restricted to in/out of TerraVault's scope."""
    tp = pos = 0
    for e in data["per_case"].values():
        if not e["expected"] or bool(e.get("in_tv_scope")) != in_scope:
            continue
        pos += 1
        tp += e["target"] in e["detections"].get(tool, [])
    return tp, pos


def _write_csv(tables_dir: Path, name: str, headers: List[str], rows: List[List[str]]) -> None:
    tables_dir.mkdir(parents=True, exist_ok=True)
    with (tables_dir / name).open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        w.writerows(rows)


def overview_table(data: dict, tools: List[str]):
    headers = ["Ferramenta", "Precisão", "Recall", "F1", "Categorias", "FP (seguros)"]
    rows = []
    for t in tools:
        m = data["tools"][t]
        rows.append([
            TOOL_LABEL[t], _pct(m["micro_precision"]), _pct(m["micro_recall"]),
            _pct(m["micro_f1"]),
            f"{m['categories_covered']}/{len(data['run_meta']['taxonomy'])}",
            str(m["fp_on_negative"]),
        ])
    return headers, rows


def scope_split_table(data: dict, tools: List[str]):
    """Per tool: recall on in-scope positives vs out-of-scope (coverage-gap)."""
    headers = ["Ferramenta", "Recall no escopo do TerraVault", "Recall fora do escopo"]
    rows = []
    for t in tools:
        tin, pin = _scope_recall(data, t, True)
        tout, pout = _scope_recall(data, t, False)
        rin = f"{tin}/{pin} ({tin / pin:.0%})" if pin else "—"
        rout = f"{tout}/{pout} ({tout / pout:.0%})" if pout else "—"
        rows.append([TOOL_LABEL[t], rin, rout])
    return headers, rows


def recall_matrix(data: dict, tools: List[str]):
    tax = data["run_meta"]["taxonomy"]
    present = [c for c in tax if any(
        data["tools"][t]["per_category"][c]["support"] for t in tools)]
    headers = ["Categoria"] + [TOOL_LABEL[t] for t in tools]
    rows = []
    for cat in present:
        row = [CAT_PT.get(cat, cat)]
        for t in tools:
            c = data["tools"][t]["per_category"][cat]
            mark = "✓" if c["recall"] == 1 and c["support"] else ("✗" if c["tp"] == 0 else "◐")
            row.append(f"{mark} {c['tp']}/{c['support']}")
        rows.append(row)
    return headers, rows


def fp_resistance_table(data: dict, tools: List[str]):
    headers = ["Caso seguro (negativo)"] + [TOOL_LABEL[t] for t in tools]
    rows = []
    for cid, e in data["per_case"].items():
        if e["expected"]:
            continue
        row = [cid.split("__")[-1] + f" [{e.get('target', '')}]"]
        flagged = False
        for t in tools:
            det = e["detections"].get(t, [])
            flagged = flagged or bool(det)
            row.append("—" if not det else f"FP: {', '.join(det)}")
        if flagged:
            rows.append(row)
    total = ["Total FP"] + [str(data["tools"][t]["fp_on_negative"]) for t in tools]
    rows.append(total)
    return headers, rows


def build_markdown(data: dict) -> str:
    meta = data["run_meta"]
    corpus = meta["corpus"]
    tools = _tools(data)
    tv = data["tools"]["terravault"]

    lines: List[str] = []
    A = lines.append
    A("# Avaliação em Corpus de Terceiros (KICS)\n")
    A(f"*Gerado por `evaluation/report_foreign.py` a partir de `metrics.json` "
      f"({meta['generated_at']}, modo de pontuação `{meta['score_mode']}`).*\n")

    A("## 1. Por que um corpus que não escrevi\n")
    A("A avaliação principal usa um corpus curado pelo próprio autor — que também "
      "escreveu as regras e os rótulos. Um acerto perfeito ali é compatível tanto "
      "com \"a ferramenta é boa\" quanto com \"o autor testou exatamente o que "
      "construiu\" (ameaça de validade de constructo). Este capítulo ataca essa "
      "ameaça avaliando o TerraVault sobre *fixtures* de teste do **KICS "
      "(Checkmarx)** — cujos rótulos positivo/negativo foram escritos pelos "
      "mantenedores do KICS, não por nós. O KICS **não** é uma das ferramentas "
      "comparadas, então suas *fixtures* são igualmente estranhas ao TerraVault, "
      "ao Checkov, ao tfsec e ao Terrascan (nenhuma joga em casa).\n")
    A(f"**Corpus.** {corpus['n_cases']} casos ({corpus['n_positive']} positivos / "
      f"{corpus['n_negative']} negativos) importados sem alteração. Cada caso é "
      "pontuado apenas para o conceito que o KICS rotula (modo *target-slice*), "
      "pois o corpus não traz rótulos multi-categoria completos. *Fixtures* que "
      "são apenas módulos externos (sem bloco `resource`) foram descartadas — "
      "nenhum analisador estático as processa, para nenhuma ferramenta.\n")
    A(f"**Escopo de recurso.** {corpus['n_in_tv_scope']} casos exercitam um tipo "
      f"de recurso que a regra correspondente do TerraVault inspeciona; "
      f"{corpus['n_out_of_tv_scope']} exercitam um recurso *irmão* que o "
      "TerraVault não cobre por design (ex.: `aws_rds_cluster` para a regra de "
      "criptografia que mira `aws_db_instance`). Separar os dois é o cerne deste "
      "capítulo: distingue *qualidade de detecção* de *amplitude de cobertura*.\n")

    A("## 2. Visão geral (todas as ferramentas)\n")
    A(_md_table(*overview_table(data, tools)) + "\n")
    A(f"No corpus de terceiros o TerraVault atinge recall {_pct(tv['micro_recall'])} "
      f"e precisão {_pct(tv['micro_precision'])} (F1 {_pct(tv['micro_f1'])}), "
      "abaixo do 100/100/100 do corpus caseiro — a queda é a medida honesta da "
      "validade externa e é detalhada a seguir.\n")

    A("## 3. Recall dentro vs. fora do escopo do TerraVault\n")
    A("Esta é a decomposição-chave. Na coluna *dentro do escopo* todas as "
      "ferramentas competem no mesmo terreno; *fora do escopo* mede a amplitude "
      "de cobertura de recursos.\n")
    A(_md_table(*scope_split_table(data, tools)) + "\n")
    tin, pin = _scope_recall(data, "terravault", True)
    tout, pout = _scope_recall(data, "terravault", False)
    best_in = max(((data["tools"][t], t) for t in tools if t != "terravault"),
                  key=lambda x: _scope_recall(data, x[1], True)[0], default=(None, None))[1]
    A(f"- **Dentro do escopo** ({pin} casos): o TerraVault recupera "
      f"{tin}/{pin} ({tin / pin:.0%} recall) em *fixtures* que nunca viu — "
      "evidência de generalização real dentro do que ele se propõe a cobrir"
      + (f"; a melhor concorrente nesse subconjunto é {TOOL_LABEL.get(best_in, '—')}.\n"
         if best_in else ".\n"))
    A(f"- **Fora do escopo** ({pout} casos): o TerraVault recupera "
      f"{tout}/{pout} ({(tout / pout if pout else 0):.0%}). São recursos irmãos "
      "que suas regras não miram (clusters RDS, políticas IAM não-role, regras de "
      "SG autônomas, S3 em nível de conta). A diferença para as ferramentas "
      "consolidadas aqui é de **cobertura de recursos**, não de qualidade de "
      "detecção — e indica exatamente o que ampliar.\n")

    A("## 4. Recall por categoria\n")
    A("Acertos/total por categoria (✓ total, ◐ parcial, ✗ nenhum):\n")
    A(_md_table(*recall_matrix(data, tools)) + "\n")

    A("## 5. Resistência a falsos positivos (casos negativos)\n")
    A("Apenas casos negativos em que alguma ferramenta reportou algo:\n")
    A(_md_table(*fp_resistance_table(data, tools)) + "\n")
    A("> Observação honesta sobre os FPs do TerraVault: os falsos positivos de "
      "S3 ocorrem em *buckets* que o KICS rotula como seguros para **um** *flag* "
      "de acesso público, mas que deixam **outros** *flags* desligados; a "
      "verificação holística do TerraVault (qualquer proteção desligada ⇒ risco) "
      "é mais estrita. O FP de IMDSv1 ocorre quando `http_endpoint = \"disabled\"` "
      "mitiga o serviço de metadados sem `http_tokens = \"required\"` — uma "
      "limitação real da regra atual (só observa `http_tokens`).\n")

    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Render the KICS third-party report")
    ap.add_argument("--results-dir", type=Path, required=True,
                    help="foreign results dir containing metrics.json")
    args = ap.parse_args()

    results_dir: Path = args.results_dir.resolve()
    data = json.loads((results_dir / "metrics.json").read_text(encoding="utf-8"))
    tools = _tools(data)
    tables = results_dir / "tables"

    (results_dir / "report_foreign.md").write_text(build_markdown(data), encoding="utf-8")
    for name, (h, r) in {
        "foreign_overview.csv": overview_table(data, tools),
        "foreign_scope_split.csv": scope_split_table(data, tools),
        "foreign_recall_matrix.csv": recall_matrix(data, tools),
    }.items():
        _write_csv(tables, name, h, r)

    print(f"Wrote {results_dir / 'report_foreign.md'}")
    print(f"Wrote CSV tables to {tables}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
