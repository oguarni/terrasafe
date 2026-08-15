# Calibração do limiar de anomalia (desdobramento do A.3)

*Gerado por `evaluation/report_ml_calibration.py` a partir de `ml_calibration_metrics.json` (modelo `v20260708_015533`, 35594 vetores de treino; o modelo **não** foi retreinado — apenas o corte sobre o escore foi calibrado).*

## 1. O problema que a A.3 deixou aberto

A A.3 mostrou que o escore contínuo do Isolation Forest **ordena** bem as configurações *rule-clean* pelo eixo independente de atipicidade (Mahalanobis). O que ela também mostrou é que o **corte** herdado do treino (`contamination=0.1`) dispara em 37.5% da população *rule-clean* — alto demais para uma fila de revisão. Como a ordenação é boa e só o corte é ruim, a correção é um **corte percentílico sobre o escore bruto**, não o booleano `predict == -1`.

## 2. Artefato permanente (o corte nunca mais precisa de computação paga)

Esta execução gravou `per_config_scores.csv.gz` com **18041 linhas** — uma por configuração varrida — contendo o escore bruto do IF (`if_score_samples`, `if_decision_function`, `if_anomaly`), a distância de Mahalanobis, o veredito das regras, o hash do conteúdo e o vetor estrutural de 8 dimensões. Junto vai `training_reference_scores.csv.gz` (35594 linhas) com a distribuição de escores do próprio treino, que é a **referência** dos cortes percentílicos. Com os dois arquivos, qualquer limiar — percentílico, absoluto, por faixa ou uma regra futura — é re-derivável offline, para sempre, sem repetir a mineração nem a varredura.

> Os cortes candidatos são percentis da distribuição de escores **do treino**, não do corpus avaliado. Isso os torna constantes absolutas do modelo: reproduzi-los exige apenas o modelo, e valem para qualquer configuração que o scanner venha a ver — em vez de um limiar recalibrado a cada corpus, que seria auto-referente.

## 3. Varredura de cortes

### 3.1 Corpus `home` — Terraform Registry (registry-wide, top 1500 by downloads) + public GitHub .tf blobs (BigQuery export) — the A.3 mine, re-mined

18041 configs mantidas · 437 *rule-clean* · 17604 *rule-flagged*.

| Ponto de operação | Corte (score) | Rule-clean | Rule-flagged | Metade típica | Decil atípico | Lift |
| --- | --- | --- | --- | --- | --- | --- |
| contamination=0.1 (predict == -1) | +0.0000 | 164/437 (37.5%) | 1571/17604 (8.9%) | 4/201 (2.0%) | 47/47 (100.0%) | 50.251× |
| train p90 | +0.0000 | 164/437 (37.5%) | 1571/17604 (8.9%) | 4/201 (2.0%) | 47/47 (100.0%) | 50.251× |
| train p95 | +0.0670 | 49/437 (11.2%) | 833/17604 (4.7%) | 0/201 (0.0%) | 27/47 (57.5%) | ∞ (0 na base) |
| train p97.5 | +0.1265 | 19/437 (4.3%) | 407/17604 (2.3%) | 0/201 (0.0%) | 16/47 (34.0%) | ∞ (0 na base) |
| train p99 | +0.1994 | 2/437 (0.5%) | 203/17604 (1.1%) | 0/201 (0.0%) | 2/47 (4.3%) | ∞ (0 na base) |
| train p99.5 | +0.2317 | 1/437 (0.2%) | 115/17604 (0.7%) | 0/201 (0.0%) | 1/47 (2.1%) | ∞ (0 na base) |
| train p99.9 | +0.2758 | 0/437 (0.0%) | 25/17604 (0.1%) | 0/201 (0.0%) | 0/47 (0.0%) | ∞ (0 na base) |

Discriminação (independente do corte): AUC 0.9151, Spearman ρ=0.7478 (p=2.1e-79) sobre 437 configs *rule-clean*.

## 4. Ponto de operação recomendado

Regra de escolha, fixada no código e aplicada aos dados: **o corte mais restritivo que ainda sinaliza pelo menos 50.0% do decil atípico**. Como todas as taxas caem monotonicamente com o corte, esse é também o ponto com a menor taxa na metade típica entre os aceitáveis — a fila de revisão mais limpa que ainda não desistiu da cauda extrema.

Escolhido: **train p95** (corte +0.0670 sobre `if_anomaly`).

| Faixa de atipicidade (Mahalanobis) | Configs | Sinalizadas | Taxa |
| --- | --- | --- | --- |
| <p50 (typical) | 201 | 0 | 0.0% |
| p50-p90 | 189 | 22 | 11.6% |
| p90-p99 | 42 | 24 | 57.1% |
| >=p99 (extreme) | 5 | 3 | 60.0% |

Nesse ponto, no corpus `home`: *rule-clean* 49/437 (11.2%), *rule-flagged* 833/17604 (4.7%), metade típica 0/201 (0.0%), decil atípico 27/47 (57.5%). Contra o corte herdado (164/437 (37.5%) na população *rule-clean*), a fila de revisão encolhe sem perder a cauda que motivou o experimento.

## 5. Segundo corpus — a verificação externa

| Corpus | Configs mantidas | Rule-clean | Descartadas por hash já visto | Sobreposição residual | Vetor idêntico ao treino |
| --- | --- | --- | --- | --- | --- |
| `home` | 18041 | 437 | 0 | n/a (1º corpus) | 18013/18041 |

**Prova de disjunção.** Os corpora são varridos na ordem dada e cada um descarta todo arquivo cujo sha256 de conteúdo um corpus anterior já admitiu. A coluna *sobreposição residual* é a interseção dos conjuntos de hashes recalculada **depois** da varredura: ela precisa ser 0, e é verificada em vez de apenas afirmada.

> **Não foi possível obter um segundo corpus nesta execução.** O relatório cobre apenas o corpus original; a verificação externa continua em aberto e não deve ser apresentada como feita.

## 6. Limites honestos (herdados da A.3 e ainda válidos)

1. **Estudo *in-distribution*.** O modelo treinou sobre praticamente todo o Terraform público, e a sobreposição exata de vetores de treino aqui é `home` 18013/18041. Um segundo corpus **disjunto por hash** é uma *amostra diferente*, não uma distribuição retida: ele testa se a taxa se sustenta fora da mina original, não se o modelo generaliza para fora do que viu.

2. **A correlação Mahalanobis↔IF é em parte circular por construção** (ambos medem distância ao treino). A evidência que sustenta o resultado é a **ortogonalidade às regras** e a **seletividade**, não ρ.

3. **Atipicidade aqui é forma do grafo de recursos.** "Estruturalmente incomum" **não** é evidência de vulnerabilidade: o sinal serve para *priorizar revisão humana* e não pode virar gate automático — nem com o corte calibrado.

4. **A ablação do manuscrito não muda.** Regras sozinhas separam 33,3 pontos; híbrido 21,4; ML sozinha 3,2 — no corpus caseiro a ML *comprime* a separação das regras. Este experimento responde a outra pergunta (onde as regras se calam) e **não** refuta aquela.

## 7. Reconciliação com o resultado arquivado da A.3

| Métrica (corte herdado) | A.3 arquivada | Esta execução | Δ | Bate? |
| --- | --- | --- | --- | --- |
| kept | 18041 | 18041 | +0 | sim |
| rule_clean | 437 | 437 | +0 | sim |
| rule_flagged | 17604 | 17604 | +0 | sim |
| rule_clean_flag_rate | 0.3753 | 0.3753 | +0 | sim |
| atypical_decile_flag_rate | 1.0 | 1.0 | +0 | sim |
| typical_half_flag_rate | 0.0199 | 0.0199 | +0 | sim |
| selectivity_lift | 50.25 | 50.251 | +0.001 | **não** |
| ranking_auc | 0.9151 | 0.9151 | +0 | sim |
| spearman_rho | 0.7478 | 0.7478 | +0 | sim |
| rule_flagged_flag_rate | 0.0892 | 0.0892 | +0 | sim |

**Nem todas as métricas bateram.** O registry se move entre minerações; as diferenças estão na tabela e devem ser lidas antes de comparar os cortes com os números arquivados.
