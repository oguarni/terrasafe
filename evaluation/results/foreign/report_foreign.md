# Avaliação em Corpus de Terceiros (KICS)

*Gerado por `evaluation/report_foreign.py` a partir de `metrics.json` (2026-07-16T03:59:03, modo de pontuação `target_slice`).*

## 1. Por que um corpus que não escrevi

A avaliação principal usa um corpus curado pelo próprio autor — que também escreveu as regras e os rótulos. Um acerto perfeito ali é compatível tanto com "a ferramenta é boa" quanto com "o autor testou exatamente o que construiu" (ameaça de validade de constructo). Este capítulo ataca essa ameaça avaliando o TerraVault sobre *fixtures* de teste do **KICS (Checkmarx)** — cujos rótulos positivo/negativo foram escritos pelos mantenedores do KICS, não por nós. O KICS **não** é uma das ferramentas comparadas, então suas *fixtures* são igualmente estranhas ao TerraVault, ao Checkov, ao tfsec e ao Terrascan (nenhuma joga em casa).

**Corpus.** 57 casos (32 positivos / 25 negativos) importados sem alteração. Cada caso é pontuado apenas para o conceito que o KICS rotula (modo *target-slice*), pois o corpus não traz rótulos multi-categoria completos. *Fixtures* que são apenas módulos externos (sem bloco `resource`) foram descartadas — nenhum analisador estático as processa, para nenhuma ferramenta.

**Escopo de recurso.** 38 casos exercitam um tipo de recurso que a regra correspondente do TerraVault inspeciona; 19 exercitam um recurso *irmão* que o TerraVault não cobre por design (ex.: `aws_rds_cluster` para a regra de criptografia que mira `aws_db_instance`). Separar os dois é o cerne deste capítulo: distingue *qualidade de detecção* de *amplitude de cobertura*.

## 2. Visão geral (todas as ferramentas)

| Ferramenta | Precisão | Recall | F1 | Categorias | FP (seguros) |
| --- | --- | --- | --- | --- | --- |
| TerraVault | 70.4% | 59.4% | 64.4% | 6/11 | 8 |
| Checkov | 69.4% | 78.1% | 73.5% | 6/11 | 11 |
| tfsec | 74.1% | 62.5% | 67.8% | 6/11 | 7 |
| Terrascan | 100.0% | 18.8% | 31.6% | 2/11 | 0 |

No corpus de terceiros o TerraVault atinge recall 59.4% e precisão 70.4% (F1 64.4%), abaixo do 100/100/100 do corpus caseiro — a queda é a medida honesta da validade externa e é detalhada a seguir.

## 3. Recall dentro vs. fora do escopo do TerraVault

Esta é a decomposição-chave. Na coluna *dentro do escopo* todas as ferramentas competem no mesmo terreno; *fora do escopo* mede a amplitude de cobertura de recursos.

| Ferramenta | Recall no escopo do TerraVault | Recall fora do escopo |
| --- | --- | --- |
| TerraVault | 19/23 (83%) | 0/9 (0%) |
| Checkov | 22/23 (96%) | 3/9 (33%) |
| tfsec | 18/23 (78%) | 2/9 (22%) |
| Terrascan | 6/23 (26%) | 0/9 (0%) |

- **Dentro do escopo** (23 casos): o TerraVault recupera 19/23 (83% recall) em *fixtures* que nunca viu — evidência de generalização real dentro do que ele se propõe a cobrir; a melhor concorrente nesse subconjunto é Checkov.

- **Fora do escopo** (9 casos): o TerraVault recupera 0/9 (0%). São recursos irmãos que suas regras não miram (clusters RDS, políticas IAM não-role, regras de SG autônomas, S3 em nível de conta). A diferença para as ferramentas consolidadas aqui é de **cobertura de recursos**, não de qualidade de detecção — e indica exatamente o que ampliar.

## 4. Recall por categoria

Acertos/total por categoria (✓ total, ◐ parcial, ✗ nenhum):

| Categoria | TerraVault | Checkov | tfsec | Terrascan |
| --- | --- | --- | --- | --- |
| Ingresso público (SG aberto) | ◐ 1/3 | ✗ 0/3 | ◐ 2/3 | ✗ 0/3 |
| RDS sem criptografia | ✗ 0/2 | ✗ 0/2 | ✗ 0/2 | ✗ 0/2 |
| EBS sem criptografia | ✓ 2/2 | ✓ 2/2 | ✓ 2/2 | ✗ 0/2 |
| RDS com acesso público | ✓ 1/1 | ✓ 1/1 | ✓ 1/1 | ✓ 1/1 |
| IMDSv1 habilitado | ✓ 5/5 | ✓ 5/5 | ✓ 5/5 | ✓ 5/5 |
| Política IAM com curinga | ✗ 0/3 | ✓ 3/3 | ◐ 1/3 | ✗ 0/3 |
| Bucket S3 público | ◐ 9/15 | ◐ 13/15 | ◐ 9/15 | ✗ 0/15 |
| Instância EC2 com IP público | ✓ 1/1 | ✓ 1/1 | ✗ 0/1 | ✗ 0/1 |

## 5. Resistência a falsos positivos (casos negativos)

Apenas casos negativos em que alguma ferramenta reportou algo:

| Caso seguro (negativo) | TerraVault | Checkov | tfsec | Terrascan |
| --- | --- | --- | --- | --- |
| negative1 [PUBLIC_INGRESS] | — | — | FP: PUBLIC_INGRESS | — |
| negative3 [PUBLIC_INGRESS] | — | — | FP: PUBLIC_INGRESS | — |
| negative3 [IMDSV1] | FP: IMDSV1 | — | — | — |
| negative1 [PUBLIC_S3] | FP: PUBLIC_S3 | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — |
| negative1 [PUBLIC_S3] | — | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — |
| negative1 [PUBLIC_S3] | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — | — |
| negative2 [PUBLIC_S3] | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — | — |
| negative1 [PUBLIC_S3] | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — | — |
| negative2 [PUBLIC_S3] | — | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — |
| negative3 [PUBLIC_S3] | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — | — |
| negative4 [PUBLIC_S3] | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — | — |
| negative5 [PUBLIC_S3] | FP: PUBLIC_S3 | FP: PUBLIC_S3 | — | — |
| negative2 [IAM_WILDCARD] | — | — | FP: IAM_WILDCARD | — |
| negative3 [IAM_WILDCARD] | — | FP: IAM_WILDCARD | FP: IAM_WILDCARD | — |
| negative4 [IAM_WILDCARD] | — | FP: IAM_WILDCARD | — | — |
| Total FP | 8 | 11 | 7 | 0 |

> Observação honesta sobre os FPs do TerraVault: os falsos positivos de S3 ocorrem em *buckets* que o KICS rotula como seguros para **um** *flag* de acesso público, mas que deixam **outros** *flags* desligados; a verificação holística do TerraVault (qualquer proteção desligada ⇒ risco) é mais estrita. O FP de IMDSv1 ocorre quando `http_endpoint = "disabled"` mitiga o serviço de metadados sem `http_tokens = "required"` — uma limitação real da regra atual (só observa `http_tokens`).
