#!/usr/bin/env bash
# One-time (idempotent) setup of ARVO resources in the GCP project named "ARVO".
# Usage: deploy/gcp/setup.sh <metadata-dir>
#   <metadata-dir>: output of `arvo collect` (contains metadata.jsonl and Issues/)
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh

DATA_DIR=${1:?usage: setup.sh <metadata-dir>}
[ -f "$DATA_DIR/metadata.jsonl" ] || { echo "no metadata.jsonl in $DATA_DIR"; exit 1; }

gcloud config set project "$PROJECT_ID" >/dev/null
gcloud services enable compute.googleapis.com artifactregistry.googleapis.com \
    storage.googleapis.com logging.googleapis.com

# Image registry for vul/fix images
gcloud artifacts repositories describe "$AR_REPO" --location "$REGION" >/dev/null 2>&1 ||
    gcloud artifacts repositories create "$AR_REPO" --repository-format=docker \
        --location "$REGION" --description "ARVO reproducible vulnerability images"

# Bucket for code, metadata, per-issue results and logs
gcloud storage buckets describe "gs://$BUCKET" >/dev/null 2>&1 ||
    gcloud storage buckets create "gs://$BUCKET" --location "$REGION" --uniform-bucket-level-access

# Worker service account (least privilege)
gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1 ||
    gcloud iam service-accounts create "$SA_NAME" --display-name "ARVO worker"
# A new service account takes a while to become visible to IAM, so retry the grants
retry() { for i in 1 2 3 4 5 6; do "$@" >/dev/null && return 0; sleep $((i * 10)); done; return 1; }
retry gcloud artifacts repositories add-iam-policy-binding "$AR_REPO" --location "$REGION" \
    --member "serviceAccount:$SA_EMAIL" --role roles/artifactregistry.writer
retry gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
    --member "serviceAccount:$SA_EMAIL" --role roles/storage.objectAdmin
retry gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member "serviceAccount:$SA_EMAIL" --role roles/logging.logWriter --condition=None

# Upload code (working tree, incl. uncommitted changes) and metadata
REPO_ROOT=$(git rev-parse --show-toplevel)
TMP=$(mktemp -d)
tar -C "$REPO_ROOT" --exclude=.git --exclude='arvo/_profile.py' --exclude='*.egg-info' \
    --exclude='arvo/NewTracker' -czf "$TMP/arvo-src.tgz" .
tar -C "$DATA_DIR" -czf "$TMP/meta.tgz" metadata.jsonl Issues
python3 -c "import json,sys; [print(json.loads(l)['localId']) for l in open(sys.argv[1])]" \
    "$DATA_DIR/metadata.jsonl" > "$TMP/ids.txt"
gcloud storage cp "$TMP/arvo-src.tgz" "$TMP/meta.tgz" "$TMP/ids.txt" "gs://$BUCKET/input/"
rm -rf "$TMP"
echo "Setup done: project=$PROJECT_ID bucket=gs://$BUCKET registry=$AR_HOST/$PROJECT_ID/$AR_REPO ids=$(wc -l < "$DATA_DIR/metadata.jsonl")"
