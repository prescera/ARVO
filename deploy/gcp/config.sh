# Shared settings for the ARVO GCP deployment. Override any value via the environment.
# The project is looked up by its display name ("ARVO"); set PROJECT_ID to skip the lookup.
PROJECT_NAME=${PROJECT_NAME:-ARVO}
if [ -z "${PROJECT_ID:-}" ]; then
    PROJECT_ID=$(gcloud projects list --filter="name=$PROJECT_NAME" --format="value(projectId)" | head -n1)
    [ -n "$PROJECT_ID" ] || { echo "No GCP project named '$PROJECT_NAME' visible to $(gcloud config get-value account 2>/dev/null)"; exit 1; }
fi
REGION=${REGION:-asia-south1}          # Mumbai: all ARVO resources stay in India
ZONE=${ZONE:-asia-south1-a}
AR_REPO=${AR_REPO:-arvo}
AR_HOST="$REGION-docker.pkg.dev"
BUCKET=${BUCKET:-$PROJECT_ID-arvo}
SA_NAME=${SA_NAME:-arvo-worker}
SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
MACHINE_TYPE=${MACHINE_TYPE:-n2-standard-16}
DISK_GB=${DISK_GB:-1500}              # ~3 GB base image per bug date x ~170 issues/VM, plus 4 builds in flight
JOBS_PER_VM=${JOBS_PER_VM:-4}         # concurrent reproductions per VM (CPU averaged ~50% at 3)
ISSUE_TIMEOUT=${ISSUE_TIMEOUT:-14400} # seconds per issue (vul + fix build)
