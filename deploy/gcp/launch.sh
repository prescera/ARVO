#!/usr/bin/env bash
# Start ARVO worker VMs (standard, not Spot: Spot n2 capacity in asia-south1 was preempted within minutes) that reproduce the IDs in gs://$BUCKET/input/<ids-object>.
# Usage:
#   deploy/gcp/launch.sh pilot 50     # 1 VM, random sample of 50 IDs (Phase 4)
#   deploy/gcp/launch.sh full 8       # 8 VMs over all IDs (Phase 5)
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
MODE=${1:?usage: launch.sh pilot <n-ids> | full <n-vms>}; N=${2:?}

if [ "$MODE" = pilot ]; then
    IDS_OBJ=pilot-ids.txt; VMS=1
    gcloud storage cat "gs://$BUCKET/input/ids.txt" | shuf -n "$N" --random-source=<(yes) |
        gcloud storage cp - "gs://$BUCKET/input/$IDS_OBJ"
else
    IDS_OBJ=ids.txt; VMS=$N
fi

for ((i = 0; i < VMS; i++)); do
    NAME="arvo-$MODE-$i"
    gcloud compute instances create "$NAME" --project "$PROJECT_ID" --zone "$ZONE" \
        --machine-type "$MACHINE_TYPE" --provisioning-model STANDARD --maintenance-policy MIGRATE \
        --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
        --boot-disk-size "${DISK_GB}GB" --boot-disk-type pd-balanced \
        --service-account "$SA_EMAIL" --scopes cloud-platform \
        --metadata-from-file startup-script=worker-startup.sh \
        --metadata "arvo-bucket=$BUCKET,arvo-image-prefix=$AR_HOST/$PROJECT_ID/$AR_REPO/arvo,arvo-ids=$IDS_OBJ,arvo-shard=$i,arvo-shards=$VMS,arvo-jobs=$JOBS_PER_VM,arvo-timeout=$ISSUE_TIMEOUT"
done
echo "Started $VMS VM(s). Progress: gcloud storage ls gs://$BUCKET/results/ | wc -l"
echo "Each VM powers itself off when its shard is done (gs://$BUCKET/workers/<host>.done)"
