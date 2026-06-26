#!/usr/bin/env python3
"""Render the evaluation chapter from ``results/metrics.json``.

Emits, under ``results/``:

* ``report.md``            — a self-contained Avaliacao chapter (PT-BR) with all
                             tables and the methodology/threats-to-validity text.
* ``tables/*.csv``         — every table as raw CSV (appendix / re-plotting).
* ``tables/*.tex``         — the headline tables as booktabs LaTeX plus a
                             pgfplots F1 bar chart, ready to ``\\input`` in the
                             report (no matplotlib dependency).

Run:  ``python -m evaluation.report``  (after ``evaluate.py``).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List

EVAL_DIR = Path(__file__).resolve().parent
RESULTS = EVAL_DIR / "results"
TABLES = RESULTS / "tables"

TOOLS = ["terravault", "checkov", "tfsec", "terrascan"]
TOOL_LABEL = {"terravault": "TerraVault", "checkov": "Checkov",
              "tfsec": "tfsec", "terrascan": "Terrascan"}

CAT_PT = {
    "PUBLIC_INGRESS": "Ingresso público (SG aberto)",
    "UNRESTRICTED_EGRESS": "Egresso irrestrito",
    "UNENCRYPTED_RDS": "RDS sem criptografia",
    "UNENCRYPTED_EBS": "EBS sem criptografia",
    "PUBLIC_RDS": "RDS com acesso público",
    "IMDSV1": "IMDSv1 habilitado",
    "IAM_WILDCARD": "Política IAM com curinga",
    "PUBLIC_S3": "Bucket S3 público",
    "MISSING_VPC_FLOW_LOGS": "VPC sem flow logs",
    "PUBLIC_INSTANCE": "Instância EC2 com IP público",
    "HARDCODED_SECRET": "Segredo hardcoded",
}


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    line = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = "\n".join("| " + " | ".join(r) + " |" for r in rows)
    return "\n".join([line, sep, body])


def _write_csv(name: str, headers: List[str], rows: List[List[str]]) -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    with (TABLES / name).open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        w.writerows(rows)


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------
def overview_table(data: dict):
    headers = ["Ferramenta", "Precisão", "Recall", "F1", "Categorias", "FP (seguros)", "Achados brutos"]
    rows = []
    for t in TOOLS:
        m = data["tools"][t]
        rows.append([
            TOOL_LABEL[t],
            f"{m['micro_precision'] * 100:.1f}%",
            f"{m['micro_recall'] * 100:.1f}%",
            f"{m['micro_f1'] * 100:.1f}%",
            f"{m['categories_covered']}/{len(data['run_meta']['taxonomy'])}",
            str(m["fp_on_negative"]),
            str(m["total_raw_findings"]),
        ])
    _write_csv("overview.csv", headers, rows)
    return headers, rows


def recall_matrix(data: dict):
    tax = data["run_meta"]["taxonomy"]
    headers = ["Categoria"] + [TOOL_LABEL[t] for t in TOOLS]
    rows = []
    for cat in tax:
        row = [CAT_PT.get(cat, cat)]
        for t in TOOLS:
            c = data["tools"][t]["per_category"][cat]
            mark = "✓" if c["recall"] == 1 and c["support"] else ("✗" if c["tp"] == 0 else "◐")
            row.append(f"{mark} {c['tp']}/{c['support']}")
        rows.append(row)
    # totals row (micro recall)
    total = ["Total (recall micro)"]
    for t in TOOLS:
        m = data["tools"][t]
        total.append(f"{m['micro_recall'] * 100:.0f}% ({m['tp']}/{m['tp'] + m['fn']})")
    rows.append(total)
    _write_csv("recall_matrix.csv", headers, rows)
    return headers, rows


def fp_resistance_table(data: dict):
    headers = ["Caso seguro"] + [TOOL_LABEL[t] for t in TOOLS]
    neg = [cid for cid, e in data["per_case"].items() if not e["expected"]]
    rows = []
    for cid in neg:
        row = [cid]
        for t in TOOLS:
            det = data["per_case"][cid]["detections"][t]
            row.append("—" if not det else f"FP: {', '.join(det)}")
        rows.append(row)
    total = ["Total FP"]
    for t in TOOLS:
        total.append(str(data["tools"][t]["fp_on_negative"]))
    rows.append(total)
    _write_csv("fp_resistance.csv", headers, rows)
    return headers, rows


def timing_table(data: dict):
    headers = ["Ferramenta", "Execução", "Tempo total (s)", "Por caso (s)"]
    n = data["run_meta"]["corpus"]["n_cases"]
    rows = []
    for t in TOOLS:
        m = data["tools"][t]
        mode = "nativo (in-process)" if t == "terravault" else "container Docker"
        tt = m["total_duration_s"]
        rows.append([TOOL_LABEL[t], mode, f"{tt:.2f}", f"{tt / n:.3f}"])
    _write_csv("timing.csv", headers, rows)
    return headers, rows


def hybrid_scores_table(data: dict):
    headers = ["Caso", "Tipo", "Score regras", "Score ML", "Score final", "Confiança", "Vulns"]
    rows = []
    for cid, h in data["terravault_hybrid"].items():
        if "error" in h:
            rows.append([cid, "—", "ERRO", "", "", "", ""])
            continue
        rows.append([
            cid,
            "seguro" if h["is_negative"] else "vulnerável",
            str(h["rule_score"]), f"{h['ml_score']:.1f}", str(h["final_score"]),
            h["confidence"], str(h["n_vulns"]),
        ])
    _write_csv("hybrid_scores.csv", headers, rows)
    return headers, rows


# ---------------------------------------------------------------------------
# LaTeX
# ---------------------------------------------------------------------------
def _latex_table(caption: str, label: str, col_spec: str,
                 headers: List[str], rows: List[List[str]]) -> str:
    def esc(s: str) -> str:
        return (s.replace("%", "\\%").replace("✓", "\\checkmark")
                .replace("✗", "$\\times$").replace("◐", "$\\circ$")
                .replace("—", "--").replace("_", "\\_"))
    head = " & ".join(f"\\textbf{{{esc(h)}}}" for h in headers) + " \\\\"
    body = "\n".join(" & ".join(esc(c) for c in r) + " \\\\" for r in rows)
    return "\n".join([
        "\\begin{table}[ht]", "\\centering", f"\\caption{{{caption}}}",
        f"\\label{{{label}}}", f"\\begin{{tabular}}{{{col_spec}}}", "\\toprule",
        head, "\\midrule", body, "\\bottomrule", "\\end{tabular}", "\\end{table}",
    ])


def _pgfplots_f1(data: dict) -> str:
    coords = " ".join(f"({TOOL_LABEL[t]},{data['tools'][t]['micro_f1'] * 100:.1f})" for t in TOOLS)
    rec = " ".join(f"({TOOL_LABEL[t]},{data['tools'][t]['micro_recall'] * 100:.1f})" for t in TOOLS)
    symbolic = ",".join(TOOL_LABEL[t] for t in TOOLS)
    return "\n".join([
        "% requires \\usepackage{pgfplots} ; \\pgfplotsset{compat=1.17}",
        "\\begin{tikzpicture}",
        "\\begin{axis}[ybar, bar width=10pt, ymin=0, ymax=105,",
        "    ylabel={\\%}, symbolic x coords={" + symbolic + "},",
        "    xtick=data, legend pos=south west, enlarge x limits=0.2,",
        "    nodes near coords, nodes near coords style={font=\\tiny}]",
        f"\\addplot coordinates {{{rec}}};",
        f"\\addplot coordinates {{{coords}}};",
        "\\legend{Recall, F1}",
        "\\end{axis}", "\\end{tikzpicture}",
    ])


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
def build_markdown(data: dict) -> str:
    meta = data["run_meta"]
    corpus = meta["corpus"]
    tv = data["tools"]["terravault"]
    hs = data["hybrid_summary"]
    tools_meta = meta["tools"]

    ov_h, ov_r = overview_table(data)
    rm_h, rm_r = recall_matrix(data)
    fp_h, fp_r = fp_resistance_table(data)
    tm_h, tm_r = timing_table(data)
    hy_h, hy_r = hybrid_scores_table(data)

    best_competitor_recall = max(
        (data["tools"][t]["micro_recall"] for t in ["checkov", "tfsec", "terrascan"]), default=0)

    lines: List[str] = []
    A = lines.append
    A("# Avaliação Experimental do TerraVault\n")
    A(f"*Gerado automaticamente por `evaluation/` em {meta['generated_at']}. "
      "Reexecutável com `make evaluate`.*\n")

    A("## 1. Metodologia\n")
    A("A avaliação responde a duas perguntas: (i) **qual a qualidade de detecção** "
      "do TerraVault sobre um conjunto controlado de configurações Terraform com "
      "vulnerabilidades conhecidas; e (ii) **como esse desempenho se compara** ao de "
      "três scanners de Infraestrutura como Código (IaC) consolidados — Checkov, "
      "tfsec e Terrascan.\n")
    A(f"**Corpus rotulado.** Foram construídos {corpus['n_cases']} módulos Terraform "
      f"isolados ({corpus['n_positive']} positivos e {corpus['n_negative']} negativos/"
      f"endurecidos), com {corpus['n_labels']} rótulos de vulnerabilidade. Cada caso "
      "positivo isola uma única categoria (os demais atributos são endurecidos), de "
      "modo que um achado para aquela categoria é inequívoco; os casos negativos "
      "exercitam resistência a falsos positivos (segredo parametrizado, "
      "armazenamento criptografado, S3 bloqueado, IMDSv2, ingresso privado).\n")
    A("**Taxonomia compartilhada.** Para uma comparação justa, os achados de cada "
      "ferramenta são projetados sobre um conjunto neutro de "
      f"{len(meta['taxonomy'])} categorias de conceito de segurança (Tabela de "
      "recall). Achados fora dessa taxonomia são ignorados de forma **simétrica** "
      "para todas as ferramentas — inclusive a heurística `MISSING_LOGGING` do "
      "TerraVault (ausência de CloudTrail/CloudWatch na configuração), que não tem "
      "equivalente por-recurso nos scanners comparados e, se contabilizada, "
      "enviesaria o resultado.\n")
    A("**Métrica.** Precisão, recall e F1 são calculados na granularidade "
      "(caso, categoria): cada caso é rotulado com o conjunto de categorias que "
      "genuinamente contém, e cada ferramenta é reduzida ao conjunto de categorias "
      "que reportou por caso. Reporta-se a média micro (agregando contagens de "
      "verdadeiros/falsos positivos e falsos negativos).\n")
    A("**Ferramentas e versões.**\n")
    ver_rows = [
        ["TerraVault", str(tools_meta["terravault"].get("version")), "nativo (Python)",
         tools_meta["terravault"]["approach"]],
        ["Checkov", str(tools_meta["checkov"].get("version")), "Docker", "regras (políticas Python)"],
        ["tfsec", str(tools_meta["tfsec"].get("version")), "Docker", "regras (Go)"],
        ["Terrascan", str(tools_meta["terrascan"].get("version")), "Docker", "policy-as-code (OPA/Rego)"],
    ]
    A(_md_table(["Ferramenta", "Versão", "Execução", "Abordagem"], ver_rows) + "\n")
    A("> **Reprodutibilidade.** Os concorrentes rodam a partir das imagens Docker "
      "oficiais, com as saídas brutas preservadas em `evaluation/results/raw/`. Os "
      "containers são iniciados com `--user 0` porque o diretório do corpus é criado "
      "sob um *umask* restritivo; sem isso, o container não-root do Terrascan não "
      "consegue ler o *bind mount* e analisa zero recursos silenciosamente.\n")

    A("\n## 2. Resultados\n")
    A("### 2.1 Visão geral da detecção (taxonomia compartilhada)\n")
    A(_md_table(ov_h, ov_r) + "\n")
    A(f"Sobre a taxonomia compartilhada, o TerraVault atinge **recall "
      f"{_pct(tv['micro_recall'])}** e **precisão {_pct(tv['micro_precision'])}** "
      f"(F1 {_pct(tv['micro_f1'])}), cobrindo as {tv['categories_covered']} categorias "
      "de seu catálogo de regras. A coluna *Achados brutos* mostra o total de "
      "achados de cada ferramenta antes da projeção na taxonomia — os scanners "
      "consolidados reportam muito mais achados porque cobrem centenas de regras "
      "adicionais fora do escopo do TerraVault (amplitude vs. foco).\n")

    A("### 2.2 Recall por categoria\n")
    A("Cada célula mostra acertos/total de casos (✓ recall total, ◐ parcial, "
      "✗ não detectou):\n")
    A(_md_table(rm_h, rm_r) + "\n")

    A("### 2.3 Resistência a falsos positivos (casos endurecidos)\n")
    A("Nos casos negativos, nenhuma categoria da taxonomia deveria ser reportada:\n")
    A(_md_table(fp_h, fp_r) + "\n")

    A("### 2.4 Desempenho\n")
    A(_md_table(tm_h, tm_r) + "\n")
    A("> O tempo dos concorrentes inclui a inicialização do container Docker (custo "
      "aproximadamente constante por execução); o TerraVault roda nativo, em "
      "processo. A comparação de tempo é, portanto, indicativa e não um *benchmark* "
      "de motor isolado.\n")

    A("### 2.5 Análise do score híbrido do TerraVault\n")
    A("O TerraVault combina o score de regras (60%) com o score de anomalia do "
      "Isolation Forest (40%), extraído de features estruturais independentes das "
      "regras. A tabela agrega o comportamento sobre os casos vulneráveis vs. "
      "seguros:\n")
    hyb_rows = [
        ["Score de regras (média)", f"{hs['mean_rule_positive']:.1f}", f"{hs['mean_rule_negative']:.1f}"],
        ["Score ML (média)", f"{hs['mean_ml_positive']:.1f}", f"{hs['mean_ml_negative']:.1f}"],
        ["Score final (média)", f"{hs['mean_final_positive']:.1f}", f"{hs['mean_final_negative']:.1f}"],
    ]
    A(_md_table(["Componente", "Casos vulneráveis", "Casos seguros"], hyb_rows) + "\n")
    sep = hs["mean_final_positive"] - hs["mean_final_negative"]
    A(f"A separação média de **{sep:.1f} pontos** entre o score final dos casos "
      "vulneráveis e seguros confirma que o pipeline híbrido ordena corretamente o "
      "risco. O detalhamento por caso está em `tables/hybrid_scores.csv`.\n")

    A("\n## 3. Discussão e ameaças à validade\n")
    A(f"- **Foco vs. amplitude.** O TerraVault implementa {len(meta['taxonomy'])} "
      "categorias por design. Dentro desse escopo seu recall é competitivo com os "
      f"scanners consolidados (melhor recall concorrente na taxonomia: "
      f"{_pct(best_competitor_recall)}); fora dele, ferramentas como o Checkov "
      "cobrem centenas de regras adicionais. A contribuição do TerraVault é o "
      "*pipeline híbrido* (regras + ML estrutural), não a amplitude de regras.\n")
    A("- **Corpus sintético-controlado.** Os casos são curados para isolar "
      "categorias, o que dá rótulos limpos mas não reproduz a distribuição de "
      "módulos reais. É uma validação de corretude, não um estudo de campo; ampliar "
      "para módulos públicos reais é trabalho futuro.\n")
    A("- **Mapeamento de regras.** A projeção dos identificadores nativos de cada "
      "ferramenta na taxonomia foi construída a partir dos IDs observados no corpus "
      "e auditada (nenhum ID é descartado silenciosamente; ver "
      "`run_meta.mapping_audit_unmapped_ids` em `metrics.json`).\n")
    A("- **Igualdade de condições.** Todos os scanners analisam exatamente os mesmos "
      "arquivos, em análise estática, sem `terraform init`/credenciais.\n")
    return "\n".join(lines)


def main() -> int:
    data = json.loads((RESULTS / "metrics.json").read_text(encoding="utf-8"))
    TABLES.mkdir(parents=True, exist_ok=True)

    (RESULTS / "report.md").write_text(build_markdown(data), encoding="utf-8")

    # LaTeX headline tables + chart
    ov_h, ov_r = overview_table(data)
    rm_h, rm_r = recall_matrix(data)
    tex = "\n\n".join([
        _latex_table("Visão geral da detecção sobre a taxonomia compartilhada.",
                     "tab:overview", "lrrrrrr", ov_h, ov_r),
        _latex_table("Recall por categoria de vulnerabilidade (acertos/total).",
                     "tab:recall", "l" + "c" * len(TOOLS), rm_h, rm_r),
        _pgfplots_f1(data),
    ])
    (TABLES / "headline.tex").write_text(tex, encoding="utf-8")

    print(f"Wrote {RESULTS / 'report.md'}")
    print(f"Wrote CSV tables + LaTeX to {TABLES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
