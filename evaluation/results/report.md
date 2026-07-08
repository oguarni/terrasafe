# Avaliação Experimental do TerraVault

*Gerado automaticamente por `evaluation/` em 2026-07-07T23:24:54. Reexecutável com `make evaluate`.*

## 1. Metodologia

A avaliação responde a duas perguntas: (i) **qual a qualidade de detecção** do TerraVault sobre um conjunto controlado de configurações Terraform com vulnerabilidades conhecidas; e (ii) **como esse desempenho se compara** ao de três scanners de Infraestrutura como Código (IaC) consolidados — Checkov, tfsec e Terrascan.

**Corpus rotulado.** Foram construídos 22 módulos Terraform isolados (16 positivos e 6 negativos/endurecidos), com 23 rótulos de vulnerabilidade. Cada caso positivo isola uma única categoria (os demais atributos são endurecidos), de modo que um achado para aquela categoria é inequívoco; os casos negativos exercitam resistência a falsos positivos (segredo parametrizado, armazenamento criptografado, S3 bloqueado, IMDSv2, ingresso privado).

**Taxonomia compartilhada.** Para uma comparação justa, os achados de cada ferramenta são projetados sobre um conjunto neutro de 11 categorias de conceito de segurança (Tabela de recall). Achados fora dessa taxonomia são ignorados de forma **simétrica** para todas as ferramentas — inclusive a heurística `MISSING_LOGGING` do TerraVault (ausência de CloudTrail/CloudWatch na configuração), que não tem equivalente por-recurso nos scanners comparados e, se contabilizada, enviesaria o resultado.

**Métrica.** Precisão, recall e F1 são calculados na granularidade (caso, categoria): cada caso é rotulado com o conjunto de categorias que genuinamente contém, e cada ferramenta é reduzida ao conjunto de categorias que reportou por caso. Reporta-se a média micro (agregando contagens de verdadeiros/falsos positivos e falsos negativos).

**Ferramentas e versões.**

| Ferramenta | Versão | Execução | Abordagem |
| --- | --- | --- | --- |
| TerraVault | 1.0.0 | nativo (Python) | rules (60%) + Isolation Forest ML (40%) |
| Checkov | 3.3.0 | Docker | regras (políticas Python) |
| tfsec | v1.28.14 | Docker | regras (Go) |
| Terrascan | v1.19.9 | Docker | policy-as-code (OPA/Rego) |

> **Reprodutibilidade.** Os concorrentes rodam a partir das imagens Docker oficiais, com as saídas brutas preservadas em `evaluation/results/raw/`. Os containers são iniciados com `--user 0` porque o diretório do corpus é criado sob um *umask* restritivo; sem isso, o container não-root do Terrascan não consegue ler o *bind mount* e analisa zero recursos silenciosamente.


## 2. Resultados

### 2.1 Visão geral da detecção (taxonomia compartilhada)

| Ferramenta | Precisão | Recall | F1 | Categorias | FP (seguros) | Achados brutos |
| --- | --- | --- | --- | --- | --- | --- |
| TerraVault | 100.0% | 100.0% | 100.0% | 11/11 | 0 | 23 |
| Checkov | 100.0% | 95.7% | 97.8% | 10/11 | 0 | 187 |
| tfsec | 100.0% | 87.0% | 93.0% | 9/11 | 0 | 107 |
| Terrascan | 100.0% | 47.8% | 64.7% | 5/11 | 0 | 63 |

Sobre a taxonomia compartilhada, o TerraVault atinge **recall 100.0%** e **precisão 100.0%** (F1 100.0%), cobrindo as 11 categorias de seu catálogo de regras. A coluna *Achados brutos* mostra o total de achados de cada ferramenta antes da projeção na taxonomia — os scanners consolidados reportam muito mais achados porque cobrem centenas de regras adicionais fora do escopo do TerraVault (amplitude vs. foco).

### 2.2 Recall por categoria

Cada célula mostra acertos/total de casos (✓ recall total, ◐ parcial, ✗ não detectou):

| Categoria | TerraVault | Checkov | tfsec | Terrascan |
| --- | --- | --- | --- | --- |
| Ingresso público (SG aberto) | ✓ 5/5 | ✓ 5/5 | ✓ 5/5 | ◐ 4/5 |
| Egresso irrestrito | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✗ 0/2 |
| RDS sem criptografia | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 |
| EBS sem criptografia | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✗ 0/2 |
| RDS com acesso público | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 |
| IMDSv1 habilitado | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 |
| Política IAM com curinga | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✗ 0/2 |
| Bucket S3 público | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✗ 0/2 |
| VPC sem flow logs | ✓ 1/1 | ✓ 1/1 | ✓ 1/1 | ✓ 1/1 |
| Instância EC2 com IP público | ✓ 2/2 | ✓ 2/2 | ✗ 0/2 | ✗ 0/2 |
| Segredo hardcoded | ✓ 1/1 | ✗ 0/1 | ✗ 0/1 | ✗ 0/1 |
| Total (recall micro) | 100% (23/23) | 96% (22/23) | 87% (20/23) | 48% (11/23) |

### 2.3 Resistência a falsos positivos (casos endurecidos)

Nos casos negativos, nenhuma categoria da taxonomia deveria ser reportada:

| Caso seguro | TerraVault | Checkov | tfsec | Terrascan |
| --- | --- | --- | --- | --- |
| secure_full_stack | — | — | — | — |
| private_ingress | — | — | — | — |
| encrypted_storage | — | — | — | — |
| s3_fully_blocked | — | — | — | — |
| imdsv2_enforced | — | — | — | — |
| parametrized_secret | — | — | — | — |
| Total FP | 0 | 0 | 0 | 0 |

### 2.4 Desempenho

| Ferramenta | Execução | Tempo total (s) | Por caso (s) |
| --- | --- | --- | --- |
| TerraVault | nativo (in-process) | 1.27 | 0.058 |
| Checkov | container Docker | 230.49 | 10.477 |
| tfsec | container Docker | 58.71 | 2.669 |
| Terrascan | container Docker | 217.72 | 9.896 |

> O tempo dos concorrentes inclui a inicialização do container Docker (custo aproximadamente constante por execução); o TerraVault roda nativo, em processo. A comparação de tempo é, portanto, indicativa e não um *benchmark* de motor isolado.

### 2.5 Análise do score híbrido do TerraVault

O TerraVault combina o score de regras (60%) com o score de anomalia do Isolation Forest (40%), extraído de features estruturais independentes das regras. A tabela agrega o comportamento sobre os casos vulneráveis vs. seguros:

| Componente | Casos vulneráveis | Casos seguros |
| --- | --- | --- |
| Score de regras (média) | 50.0 | 16.7 |
| Score ML (média) | 48.7 | 45.5 |
| Score final (média) | 49.1 | 27.7 |

A separação média de **21.4 pontos** entre o score final dos casos vulneráveis e seguros confirma que o pipeline híbrido ordena corretamente o risco. O detalhamento por caso está em `tables/hybrid_scores.csv`.


## 3. Discussão e ameaças à validade

- **Foco vs. amplitude.** O TerraVault implementa 11 categorias por design. Dentro desse escopo seu recall é competitivo com os scanners consolidados (melhor recall concorrente na taxonomia: 95.7%); fora dele, ferramentas como o Checkov cobrem centenas de regras adicionais. A contribuição do TerraVault é o *pipeline híbrido* (regras + ML estrutural), não a amplitude de regras.

- **Corpus sintético-controlado.** Os casos são curados para isolar categorias, o que dá rótulos limpos mas não reproduz a distribuição de módulos reais. É uma validação de corretude, não um estudo de campo; ampliar para módulos públicos reais é trabalho futuro.

- **Mapeamento de regras.** A projeção dos identificadores nativos de cada ferramenta na taxonomia foi construída a partir dos IDs observados no corpus e auditada (nenhum ID é descartado silenciosamente; ver `run_meta.mapping_audit_unmapped_ids` em `metrics.json`).

- **Igualdade de condições.** Todos os scanners analisam exatamente os mesmos arquivos, em análise estática, sem `terraform init`/credenciais.
