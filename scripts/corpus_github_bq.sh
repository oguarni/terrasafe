#!/usr/bin/env bash
# corpus_github_bq.sh - rebuild the GitHub .tf corpus shards from BigQuery.
#
# Pulls every distinct, non-binary .tf blob from the public GitHub dataset
# (bigquery-public-data.github_repos) into <project>.corpus.tf_blobs, then
# exports it to GCS as gzipped newline-delimited JSON shards that
# scripts/corpus_train.py github-fetch consumes on the training VM.
#
# Cost honesty: the CTAS scans the full contents table (~2.7 TiB processed,
# roughly USD 15-20 at on-demand pricing). Run it once; the shards are
# reusable across training runs. The dataset is a snapshot of open-licensed
# GitHub - expect ~30k distinct .tf blobs (~90 MB raw).
#
# Usage:
#   scripts/corpus_github_bq.sh [PROJECT_ID] [BUCKET]
set -euo pipefail

PROJECT_ID="${1:-terravault}"
BUCKET="${2:-terravault-ml-artifacts}"

echo "==> Ensuring dataset $PROJECT_ID:corpus exists (location US, same as the public dataset)"
bq mk --dataset --location=US --description "TerraVault ML corpus staging" "$PROJECT_ID:corpus" 2>/dev/null || true

echo "==> Extracting distinct .tf blobs (full contents scan - this is the expensive step)"
bq --project_id="$PROJECT_ID" query --use_legacy_sql=false --maximum_bytes_billed=4398046511104 "
CREATE OR REPLACE TABLE \`$PROJECT_ID.corpus.tf_blobs\` AS
SELECT
  c.id,
  ANY_VALUE(f.path) AS path,
  ANY_VALUE(f.repo_name) AS repo_name,
  ANY_VALUE(c.size) AS size,
  ANY_VALUE(c.content) AS content
FROM \`bigquery-public-data.github_repos.contents\` c
JOIN \`bigquery-public-data.github_repos.files\` f ON c.id = f.id
WHERE f.path LIKE '%.tf' AND c.binary = FALSE AND c.content IS NOT NULL
GROUP BY c.id
"

echo "==> Exporting shards to gs://$BUCKET/github_corpus/"
bq extract --project_id="$PROJECT_ID" \
    --destination_format=NEWLINE_DELIMITED_JSON --compression=GZIP \
    "$PROJECT_ID:corpus.tf_blobs" "gs://$BUCKET/github_corpus/tf-*.json.gz"

echo "==> Done:"
gcloud storage ls -l "gs://$BUCKET/github_corpus/"
