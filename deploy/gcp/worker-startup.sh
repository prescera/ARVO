#!/usr/bin/env bash
# GCE startup script for an ARVO worker VM (Ubuntu 24.04).
# Reproduces its shard of OSS-Fuzz issue IDs, pushes vul/fix images to Artifact Registry,
# writes gs://$BUCKET/results/<id>.json + logs, then powers the VM off.
# Re-running (e.g. after a Spot preemption) skips IDs that already have a result.
set -uo pipefail
export HOME=${HOME:-/root}   # startup scripts run without HOME; git config --global needs it
md() { curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
BUCKET=$(md arvo-bucket); IMAGE_PREFIX=$(md arvo-image-prefix); IDS_OBJ=$(md arvo-ids)
SHARD=$(md arvo-shard); SHARDS=$(md arvo-shards); JOBS=$(md arvo-jobs); ISSUE_TIMEOUT=$(md arvo-timeout)
HOST=$(hostname)
exec > >(tee -a /var/log/arvo-worker.log) 2>&1
echo "[arvo] $HOST shard $SHARD/$SHARDS bucket=$BUCKET"

# Kernels >= 6.5 default to 32 mmap random bits, which breaks ASan/MSan shadow mapping
sysctl -w vm.mmap_rnd_bits=28

if [ ! -f /src/.arvo-packages ]; then   # system packages: once per VM
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y docker.io git git-lfs subversion mercurial python3-venv python3-pip curl unzip
    systemctl enable --now docker
    git config --global --add safe.directory '*'
    mkdir -p /src && touch /src/.arvo-packages
fi
# Code and metadata: refreshed on every boot, so a restarted VM picks up fixes
mkdir -p /data/{oss-lock,oss-img,oss-out,oss-work,oss-db,tmp,docker-push-queue,XxX,ZDC}
rm -rf /src/ARVO /data/meta && mkdir -p /src/ARVO /data/meta
gcloud storage cp "gs://$BUCKET/input/arvo-src.tgz" "gs://$BUCKET/input/meta.tgz" /tmp/
tar -C /src/ARVO -xzf /tmp/arvo-src.tgz
tar -C /data/meta -xzf /tmp/meta.tgz
[ -x /src/arvo_venv/bin/pip ] || python3 -m venv /src/arvo_venv
/src/arvo_venv/bin/pip install -q -e /src/ARVO
sed -e "s|^NEW_ISSUE_TRACKER .*|NEW_ISSUE_TRACKER   = '/data/meta'|" /src/ARVO/profile.template > /src/ARVO/arvo/_profile.py
# Drop half-finished work from a previous boot (stop/preemption); no builds are running yet,
# so pruning stopped containers here is safe
rm -rf /data/results /data/oss-out/* /data/oss-work/* /data/tmp/* /data/docker-push-queue/*
docker container prune -f >/dev/null 2>&1
gcloud auth configure-docker "${IMAGE_PREFIX%%/*}" --quiet

run_one() {
    local id=$1 out=/data/results/$1 status=failed
    gcloud storage ls "gs://$BUCKET/results/$id.json" >/dev/null 2>&1 && return 0
    mkdir -p "$out"
    local start=$(date -u +%FT%TZ)
    # Docker pruning must never overlap a build/load/push, or containerd deletes the other jobs'
    # in-flight layers. Each job holds a shared lock on arvo-docker.lock for its whole Docker work;
    # the pruner takes it exclusively. The pruner also holds arvo-gate.lock so that no new job
    # starts while it waits (flock alone would let shared holders starve it).
    flock /run/arvo-gate.lock true
    exec 9>/run/arvo-docker.lock; flock -s 9
    local rc attempt
    for attempt in 1 2; do
        ( cd /data && timeout "$ISSUE_TIMEOUT" /src/arvo_venv/bin/arvo reproduce --save-img "$id" ) > "$out/reproduce.log" 2>&1
        rc=$?
        [ -f "/data/docker-push-queue/$id-fix.tar" ] && break
        # Retry once if the failure looks like a transient network problem (apt mirror, HTTP 50x, DNS)
        grep -qE "Unable to connect to|Temporary failure resolving|Could not resolve host|HTTP Error 50[234]|returned error: 50[234]|Gateway Time-?out|Connection timed out|Connection reset by peer" \
            "$out/reproduce.log" /src/ARVO/arvo/CrashLog/"${id}"_*.log 2>/dev/null || break
        [ $attempt -eq 1 ] && { echo "[arvo] $id: network error, retrying"; mv "$out/reproduce.log" "$out/reproduce.attempt1.log"; }
    done
    if [ -f "/data/docker-push-queue/$id-vul.tar" ] && [ -f "/data/docker-push-queue/$id-fix.tar" ]; then
        status=reproduced
        for tag in vul fix; do
            docker load -q -i "/data/docker-push-queue/$id-$tag.tar" &&
            docker tag "n132/arvo:$id-$tag" "$IMAGE_PREFIX:$id-$tag" &&
            docker push -q "$IMAGE_PREFIX:$id-$tag" || status=push_failed
            docker rmi -f "n132/arvo:$id-$tag" "$IMAGE_PREFIX:$id-$tag" >/dev/null 2>&1
            rm -f "/data/docker-push-queue/$id-$tag.tar"
        done
    fi
    [ $rc -eq 124 ] && status=timeout
    cp /src/ARVO/arvo/CrashLog/"${id}"_*.log /src/ARVO/arvo/Log/FuzzerExecution/"${id}"_*.log "$out/" 2>/dev/null
    grep -hF "$id" /src/ARVO/arvo/_CrashLOGs /src/ARVO/arvo/Log/_Event.log > "$out/diagnostics.txt" 2>/dev/null
    # All recorded reasons, most specific (first) to most generic (last)
    local reason; reason=$(grep -F "| $id |" /src/ARVO/arvo/_CrashLOGs 2>/dev/null | awk -F'|' '{gsub(/^ +| +$/,"",$4); print $4}' | paste -sd ';' | sed 's/"/\\"/g')
    gcloud storage cp -r "$out" "gs://$BUCKET/logs/" >/dev/null 2>&1
    printf '{"localId": %s, "status": "%s", "reason": "%s", "image_prefix": "%s", "worker": "%s", "started": "%s", "finished": "%s"}\n' \
        "$id" "$status" "$reason" "$IMAGE_PREFIX" "$HOST" "$start" "$(date -u +%FT%TZ)" > "$out/result.json"
    gcloud storage cp "$out/result.json" "gs://$BUCKET/results/$id.json" >/dev/null
    rm -rf "$out"
    cleanup_issue "$id"
    echo "[arvo] $id -> $status"
}

# Remove one issue's own containers and images, release the shared Docker lock, prune if needed.
# ARVO only cleans up on a normal exit, so timeouts and failures otherwise leak tens of GB.
# Safe during other builds: nothing else references these names (unlike `docker image prune`,
# which races in-flight layers).
cleanup_issue() {
    local id=$1
    docker ps -aq --filter "name=^reproducer_${id}$" --filter "name=^arvo_rf_${id}_(vul|fix)$" | xargs -r docker rm -f >/dev/null 2>&1
    docker ps -aq --filter "ancestor=gcr.io/oss-fuzz/$id" | xargs -r docker rm -f >/dev/null 2>&1
    docker rmi -f "gcr.io/oss-fuzz/$id" "n132/arvo:$id-vul" "n132/arvo:$id-fix" "$IMAGE_PREFIX:$id-vul" "$IMAGE_PREFIX:$id-fix" >/dev/null 2>&1
    rm -f /data/docker-push-queue/"$id"-*.tar
    exec 9>&-   # release the shared Docker lock
    # Base images (one ~3 GB digest per bug date) accumulate; the disk is sized so this rarely
    # triggers. When it does, it drains running builds first (see the locks above).
    if [ "$(df --output=pcent /var/lib | tail -1 | tr -dc 0-9)" -gt 85 ]; then
        flock -x /run/arvo-gate.lock flock -x /run/arvo-docker.lock docker image prune -af >/dev/null 2>&1
    fi
}

# Second pass (arvo-mode=locate): for a reproduced issue, bisect to the fix commit and capture
# fuzz target + crash output from the published images -> gs://$BUCKET/patches/<id>.json, an
# arvo.db record (`arvo build-db` merges them). Failures go to patches_failed/ so reruns skip them.
locate_one() {
    local id=$1 out=/data/results/$1 status=failed
    gcloud storage ls "gs://$BUCKET/patches/$id.json" "gs://$BUCKET/patches_failed/$id.json" >/dev/null 2>&1 && return 0
    mkdir -p "$out"
    local start=$(date -u +%FT%TZ)
    flock /run/arvo-gate.lock true
    exec 9>/run/arvo-docker.lock; flock -s 9
    ( cd /data && timeout "$ISSUE_TIMEOUT" /src/arvo_venv/bin/arvo locate "$id" --image-prefix "$IMAGE_PREFIX" --out "$out/record.json" ) > "$out/locate.log" 2>&1
    local rc=$?
    cp -r /src/ARVO/arvo/Log/bisect/"$id" "$out/bisect" 2>/dev/null
    grep -hF "$id" /src/ARVO/arvo/_CrashLOGs /src/ARVO/arvo/Log/_Event.log > "$out/diagnostics.txt" 2>/dev/null
    gcloud storage cp -r "$out" "gs://$BUCKET/logs-locate/" >/dev/null 2>&1
    if [ $rc -eq 0 ] && [ -s "$out/record.json" ]; then
        status=$(python3 -c "import json,sys; print('located' if json.load(open(sys.argv[1]))['patch_located'] else 'not_located')" "$out/record.json")
        python3 - "$out/record.json" "$start" "$HOST" <<'PY'
import json, sys, datetime
p, start, host = sys.argv[1:]
r = json.load(open(p)); r["_started"] = start; r["_finished"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"); r["_worker"] = host
json.dump(r, open(p, "w"))
PY
        gcloud storage cp "$out/record.json" "gs://$BUCKET/patches/$id.json" >/dev/null
    else
        [ $rc -eq 124 ] && status=timeout
        printf '{"localId": %s, "status": "%s", "rc": %s, "worker": "%s", "_started": "%s", "_finished": "%s"}\n' \
            "$id" "$status" "$rc" "$HOST" "$start" "$(date -u +%FT%TZ)" > "$out/failed.json"
        gcloud storage cp "$out/failed.json" "gs://$BUCKET/patches_failed/$id.json" >/dev/null
    fi
    rm -rf "$out"
    cleanup_issue "$id"
    echo "[arvo] locate $id -> $status"
}
export -f run_one locate_one cleanup_issue
export BUCKET IMAGE_PREFIX ISSUE_TIMEOUT HOST

MODE=$(md arvo-mode || true); MODE=${MODE:-reproduce}
FN=run_one; [ "$MODE" = locate ] && FN=locate_one
gcloud storage cat "gs://$BUCKET/input/$IDS_OBJ" | awk -v s="$SHARD" -v n="$SHARDS" 'NF && (NR-1)%n==s' |
    xargs -P "$JOBS" -I{} bash -c "$FN {}"

echo done | gcloud storage cp - "gs://$BUCKET/workers/$HOST.$MODE.done"
echo "[arvo] $HOST finished shard $SHARD"
poweroff
