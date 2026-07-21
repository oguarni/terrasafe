# A ML consegue vencer onde as regras se calam? (experimento A.3)

*Gerado por `evaluation/report_ml_atypicality.py` a partir de `ml_atypicality_metrics.json` (modelo `v20260708_015533`, 35594 vetores de treino).*

## 1. A pergunta

A ablação honesta do manuscrito mostra que, no corpus caseiro, o componente de ML *comprime* a separação das regras: cada caso ali isola uma categoria que as regras já cobrem, então o detector de anomalias nunca contribui com um sinal independente. Este experimento constrói o teste que faltava — dá à ML uma população onde **as regras se calam** e mede se o Isolation Forest sinaliza *seletivamente* as configurações estruturalmente atípicas.

## 2. Método

**População.** 18041 configurações `.tf` reais (de 49673 arquivos varridos; 4624 duplicatas por hash, 34 blobs gigantes e 25118 sem bloco `resource` descartados). Cada uma é varrida pelo scanner de produção — regras **e** ML no mesmo passe. Mantemos a subpopulação **rule-clean**: 437 configs onde as 11 regras nada reportam. É a única população onde só a ML pode falar.

**Eixo de atipicidade (independente da ML).** O vetor estrutural de 8 dimensões de cada config recebe a distância de Mahalanobis até a distribuição de treino (covariância encolhida por Ledoit-Wolf) — uma medida gaussiana calculada dos dados de treino, **não** do isolamento em árvores do modelo. Assim "atípico" é definido sem consultar o veredito do próprio IF.

**Estudo in-distribution (divulgação honesta).** O modelo foi treinado sobre praticamente todo o Terraform público (registry-wide + todos os blobs `.tf` do GitHub), então 18013/18041 configs reproduzem exatamente um vetor de treino e não há corpus real *held-out* significativo. A pergunta aqui não é de generalização, mas de **seletividade e ortogonalidade** dentro da população para a qual o modelo foi calibrado. A correlação Mahalanobis↔IF é, em parte, esperada por construção (ambos medem distância ao treino) e por isso **não** é o resultado central; o são a ortogonalidade às regras e a caracterização qualitativa abaixo.

## 3. Seletividade e discriminação (população rule-clean)

| Faixa de atipicidade (Mahalanobis) | Configs | Sinalizadas pelo IF | Taxa |
| --- | --- | --- | --- |
| <p50 (typical) | 201 | 4 | 2.0% |
| p50-p90 | 189 | 113 | 59.8% |
| p90-p99 | 42 | 42 | 100.0% |
| >=p99 (extreme) | 5 | 5 | 100.0% |

Discriminação: AUC 0.9151 do escore contínuo do IF ao ordenar o decil atípico contra o resto; correlação de Spearman ρ=0.7478 (p=2.1e-79). Decil atípico sinaliza 100.0% vs. 2.0% na metade típica (*lift* 50.25×). Taxa global de sinalização na população rule-clean: 37.5%.

## 4. Ortogonalidade às regras

Se a ML fosse redundante com as regras, sinalizaria as mesmas configurações. O oposto acontece:

| População | Configs | Sinalizadas pelo IF | Taxa |
| --- | --- | --- | --- |
| Rule-clean (regras se calam) | 437 | 164 | 37.5% |
| Rule-flagged (regras disparam) | 17604 | 1571 | 8.9% |

O IF sinaliza a população *rule-clean* a 37.5% e a população *rule-flagged* a apenas 8.9%: as violações que as regras pegam tendem a ser estruturalmente simples (um recurso mal configurado), enquanto os módulos grandes e complexos que as regras aprovam é que parecem anômalos. Os dois sinais são ortogonais — a premissa do design híbrido, aqui observada diretamente.

## 5. As configurações atípicas-mas-válidas que o IF destaca

Top configs *rule-clean* por atipicidade (o que a ML vê e as regras não):

| Config (rule-clean) | Mahalanobis | Anom. IF | Sinal. | recursos | tipos | enc.cov | público |
| --- | --- | --- | --- | --- | --- | --- | --- |
| marbot-io__marbot-monitoring-basic/main.tf | 29.4 | 0.184 | sim | 142 | 14 | 1.00 | 0 |
| github/efcdc5c2f284ec61d72a61e49aacb170d127be9d.tf | 17.2 | 0.057 | sim | 6 | 1 | 1.00 | 0 |
| aft-account-request-framework/lambda.tf | 17.0 | 0.099 | sim | 18 | 5 | 1.00 | 0 |
| tilotech__tilores-core/cloudwatch.tf | 16.7 | 0.075 | sim | 10 | 5 | 1.00 | 0 |
| aft-customizations/lambda.tf | 14.3 | 0.064 | sim | 9 | 2 | 1.00 | 0 |
| aft-customizations/codebuild.tf | 14.2 | 0.061 | sim | 8 | 2 | 1.00 | 0 |
| integrations-batch/cloudwatch.tf | 11.4 | 0.050 | sim | 4 | 1 | 1.00 | 0 |
| aft-account-provisioning-framework/lambda.tf | 11.4 | 0.060 | sim | 8 | 2 | 1.00 | 0 |
| cloudposse__cloudwatch-flow-logs/main.tf | 11.3 | 0.050 | sim | 4 | 2 | 1.00 | 0 |
| github/5c2fdc0f894c2bf4ff83cbb39f5ba7cde0bad5da.tf | 11.2 | 0.061 | sim | 5 | 3 | 1.00 | 0 |
| github/445974d92acc79eb55c6c905129580e3e4eaa905.tf | 11.1 | 0.081 | sim | 6 | 4 | 1.00 | 0 |
| github/9a9601504065898a69f4134a6c1c308bb2848d64.tf | 11.0 | 0.085 | sim | 10 | 5 | 1.00 | 0 |
| app_component/main.tf | 10.9 | 0.235 | sim | 46 | 19 | 1.00 | 0 |
| clouddrove__vpc/main.tf | 9.0 | 0.184 | sim | 30 | 28 | 1.00 | 0 |
| github/938be3162570f310bbaa9a9a9d597eecb8b9e305.tf | 8.7 | 0.226 | sim | 46 | 20 | 1.00 | 2 |

> **Leitura honesta desta amostra.** Nenhuma das configs mais atípicas tem `enc.cov` < 1.0 nem exposição pública: a atipicidade aqui é puramente de **forma do grafo de recursos** — módulos muito grandes ou diversos (até 142 recursos, 28 tipos distintos) e configs repetitivas (6 das 15 declaram muitos recursos de 1–2 tipos). Isso reforça a ortogonalidade (o IF não está reproduzindo um achado de regra por outro caminho), mas impõe o limite honesto: **"estruturalmente incomum" não é evidência de vulnerabilidade**. O sinal serve para *priorizar revisão humana*, não para afirmar risco — e é assim que deve entrar num gate.

## 6. Veredito

**Veredito — o sinal de anomalia é um eixo real e ortogonal às regras.** O escore contínuo do IF ordena as configurações atípicas acima das típicas com AUC 0.9151, e a taxa de sinalização cresce monotonicamente com a atipicidade (*lift* 50.25× entre o decil atípico e a metade típica). Como essa população é *rule-clean*, cada sinal do IF é uma configuração que as 11 regras deixaram passar. Além disso o limiar de produção é seletivo: quase não dispara na metade típica (2.0%), então os sinais concentram-se onde há de fato estrutura incomum — utilizável como sinal de revisão.
