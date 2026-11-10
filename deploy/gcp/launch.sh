#!/usr/bin/env bash
# Start ARVO worker VMs (standard, not Spot: Spot n2 capacity in asia-south1 was preempted within minutes).
# Usage:
#   deploy/gcp/launch.sh pilot 50          # reproduce: 1 VM, random sample of 50 IDs
#   deploy/gcp/launch.sh full 8            # reproduce: 8 VMs over all IDs (input/ids.txt)
#   deploy/gcp/launch.sh locate-pilot 20   # locate: 1 VM, 20 random reproduced IDs
#   deploy/gcp/launch.sh locate 8          # locate: 8 VMs over all reproduced IDs
# The locate modes take their IDs from gs://$BUCKET/results/ (status "reproduced") at launch time.
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
KIND=${1:?usage: launch.sh pilot|full|locate-pilot|locate <n>}; N=${2:?}

MODE=reproduce
reproduced_ids() {
    gcloud storage cat "gs://$BUCKET/results/*.json" | sed 's/}{/}\n{/g' |
        python3 -c 'import sys,json; [print(r["localId"]) for r in map(json.loads, filter(str.strip, sys.stdin)) if r["status"]=="reproduced"]'
}
case "$KIND" in
    pilot)
        IDS_OBJ=pilot-ids.txt; VMS=1
        gcloud storage cat "gs://$BUCKET/input/ids.txt" | shuf -n "$N" --random-source=<(yes) |
            gcloud storage cp - "gs://$BUCKET/input/$IDS_OBJ" ;;
    full)
        IDS_OBJ=ids.txt; VMS=$N ;;
    locate-pilot)
        MODE=locate; IDS_OBJ=locate-pilot-ids.txt; VMS=1
        reproduced_ids | shuf -n "$N" --random-source=<(yes) | gcloud storage cp - "gs://$BUCKET/input/$IDS_OBJ" ;;
    locate)
        MODE=locate; IDS_OBJ=locate-ids.txt; VMS=$N
        reproduced_ids | gcloud storage cp - "gs://$BUCKET/input/$IDS_OBJ" ;;
    *) echo "unknown kind $KIND"; exit 1 ;;
esac

for ((i = 0; i < VMS; i++)); do
    NAME="arvo-$KIND-$i"
    gcloud compute instances create "$NAME" --project "$PROJECT_ID" --zone "$ZONE" \
        --machine-type "$MACHINE_TYPE" --provisioning-model STANDARD --maintenance-policy MIGRATE \
        --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
        --boot-disk-size "${DISK_GB}GB" --boot-disk-type pd-balanced \
        --service-account "$SA_EMAIL" --scopes cloud-platform \
        --metadata-from-file startup-script=worker-startup.sh \
        --metadata "arvo-mode=$MODE,arvo-bucket=$BUCKET,arvo-image-prefix=$AR_HOST/$PROJECT_ID/$AR_REPO/arvo,arvo-ids=$IDS_OBJ,arvo-shard=$i,arvo-shards=$VMS,arvo-jobs=$JOBS_PER_VM,arvo-timeout=$ISSUE_TIMEOUT"
done
echo "Started $VMS VM(s) in mode $MODE over gs://$BUCKET/input/$IDS_OBJ"
echo "Each VM powers itself off when its shard is done (gs://$BUCKET/workers/<host>.$MODE.done)"
