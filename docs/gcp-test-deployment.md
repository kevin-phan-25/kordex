# Google Cloud test deployment

This guide creates a disposable Google Kubernetes Engine (GKE) Standard cluster and connects it to a locally running Kordex control plane. It is intended to answer a narrow first question: can the current agent authenticate to a real GKE API, report cluster identity and node inventory, and recover its connection after a restart?

## What this tests

The GKE cluster runs in your Google Cloud project. For this first pilot, the Kordex control plane, PostgreSQL, and agent process run on your workstation. The agent uses your local `kubectl` credentials to read GKE and makes outbound HTTP requests to the control plane on loopback. This avoids exposing a development API to the internet.

This does **not** deploy the Kordex hub into Google Cloud. The current repository does not yet package the complete GCP-hosted path: public HTTPS ingress, production OIDC setup, Cloud SQL connectivity and TLS, cloud service identity, or an end-to-end cloud deployment. The existing GCP Terraform foundation creates Artifact Registry and Secret Manager resource containers in an existing project; it does not deploy Kordex services.

The steps below test GKE registration, agent enrollment, heartbeat, inventory, and local process restart. They do not test the dashboard login, operator maintenance, node drains, host package/kernel updates, or reboots. A current dashboard PKCE issue also needs correction and browser testing before relying on dashboard authentication against a real OIDC provider. Do not use this guide to run maintenance on production nodes.

## 1. Prerequisites

On your workstation, install and configure:

- Google Cloud CLI (`gcloud`) and `kubectl`.
- Docker with Docker Compose.
- Go 1.26 or the version specified by the repository's `go.mod`/CI.
- `jq` and OpenSSL.
- A checked-out Kordex repository.
- A Google account with permission to create projects, link billing, enable APIs, and create GKE clusters. Your organization may require an administrator to perform some of these actions.

GKE resources incur charges while they exist. Create a separate test project, set a billing budget alert in Cloud Billing, and delete the cluster when finished. A billing budget sends alerts; it does not automatically cap or stop spend. Review the current [GKE pricing](https://cloud.google.com/kubernetes-engine/pricing) and [Cloud Billing budget behavior](https://cloud.google.com/billing/docs/how-to/budgets) before provisioning.

## 2. Create and select a dedicated Google Cloud project

Choose a globally unique project ID. Project IDs cannot be changed after creation. Replace the example values below; keep the variables in the same terminal session for later commands.

```sh
export PROJECT_ID="kordex-test-REPLACE-WITH-UNIQUE-SUFFIX"
export REGION="us-central1"
export ZONE="us-central1-a"
export CLUSTER="kordex-gke-test"

gcloud auth login
gcloud projects create "$PROJECT_ID" --name="Kordex disposable test"
gcloud billing accounts list
```

Copy the billing account ID you are authorized to use, then link it:

```sh
export BILLING_ACCOUNT_ID="REPLACE_WITH_BILLING_ACCOUNT_ID"
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT_ID"
gcloud config set project "$PROJECT_ID"
```

Confirm the selected project and billing state in the Cloud Console before continuing. If your organization does not allow you to create projects or link billing, ask its Google Cloud administrator to create a dedicated project and grant you the required GKE permissions.

## 3. Enable the APIs needed for this pilot

The pilot uses GKE and its Compute Engine networking. It does not need Artifact Registry, Cloud Run, Pub/Sub, Cloud SQL, or Secret Manager because the Kordex services run locally and no images are pushed to Google Cloud.

```sh
gcloud services enable \
  container.googleapis.com \
  compute.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project="$PROJECT_ID"
```

Wait for the command to finish, then confirm the APIs are enabled:

```sh
gcloud services list --enabled --project="$PROJECT_ID" \
  --filter='name:(container.googleapis.com OR compute.googleapis.com OR cloudresourcemanager.googleapis.com)' \
  --format='value(name)'
```

## 4. Create a disposable GKE Standard cluster

Use a small, zonal Standard cluster for the inventory test. Two nodes are enough to check that inventory is reported; three nodes are a better starting point for later, carefully controlled maintenance testing. Standard is used here because it exposes ordinary node pools and node behavior. This command creates billable resources.

```sh
gcloud container clusters create "$CLUSTER" \
  --project="$PROJECT_ID" \
  --zone="$ZONE" \
  --num-nodes=2 \
  --machine-type=e2-standard-2 \
  --release-channel=regular \
  --enable-ip-alias
```

Get credentials and verify that the nodes are ready:

```sh
gcloud container clusters get-credentials "$CLUSTER" \
  --project="$PROJECT_ID" \
  --zone="$ZONE"
kubectl config current-context
kubectl get nodes -o wide
kubectl auth can-i list nodes
```

The last command must say `yes`. Keep this terminal's kubeconfig context pointed at the disposable test cluster for the next step. The agent reads node inventory; it does not need cluster-admin access for this pilot, but the current agent deployment permissions should be reviewed before installing it in a real cluster.

## 5. Start the local Kordex control plane

From the Kordex repository root, create a local-only environment file and generate two separate random values:

```sh
cp deployments/local/.env.example deployments/local/.env
openssl rand -hex 32
openssl rand -hex 32
```

Put the first value in `POSTGRES_PASSWORD` and the second in `KORDEX_ADMIN_TOKEN` in `deployments/local/.env`. Do not commit or share this file. The repository ignores `.env` files.

Start PostgreSQL, apply migrations, and start the API:

```sh
docker compose --env-file deployments/local/.env \
  -f deployments/local/compose.yaml up --build -d
curl --fail http://127.0.0.1:8080/readyz
```

The readiness response should contain `"status":"ready"`. The API is bound to loopback. Keep it there; do not expose this local development configuration publicly.

## 6. Create the organization, site, fleet, cluster, and enrollment token

Keep the following commands in one terminal session. Load the local bootstrap token without putting its value directly in a command argument, then write a private curl config file:

```sh
set -a
. deployments/local/.env
set +a
umask 077
mkdir -p "$HOME/.kordex-test"
printf 'header = "Authorization: Bearer %s"\n' "$KORDEX_ADMIN_TOKEN" \
  > "$HOME/.kordex-test/curl.conf"
chmod 600 "$HOME/.kordex-test/curl.conf"
export KORDEX_API="http://127.0.0.1:8080"
```

Create the initial organization. Bootstrap authentication is only for this isolated local test setup:

```sh
ORG_JSON=$(curl --fail --silent --show-error --config "$HOME/.kordex-test/curl.conf" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Kordex GCP Test"}' "$KORDEX_API/v1/organizations")
export ORG_ID=$(printf '%s' "$ORG_JSON" | jq -r '.id')
```

Create a site and fleet, then register the GKE cluster. The provider value `gke` is inventory metadata; it does not enable GKE lifecycle API operations.

```sh
SITE_JSON=$(curl --fail --silent --show-error --config "$HOME/.kordex-test/curl.conf" \
  -H 'Content-Type: application/json' \
  -d '{"name":"gcp-test-site","region":"us-central1"}' \
  "$KORDEX_API/v1/organizations/$ORG_ID/sites")
export SITE_ID=$(printf '%s' "$SITE_JSON" | jq -r '.id')

FLEET_JSON=$(curl --fail --silent --show-error --config "$HOME/.kordex-test/curl.conf" \
  -H 'Content-Type: application/json' \
  -d '{"name":"gcp-test-fleet"}' \
  "$KORDEX_API/v1/organizations/$ORG_ID/fleets")
export FLEET_ID=$(printf '%s' "$FLEET_JSON" | jq -r '.id')

CLUSTER_JSON=$(curl --fail --silent --show-error --config "$HOME/.kordex-test/curl.conf" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$CLUSTER\",\"siteId\":\"$SITE_ID\",\"fleetId\":\"$FLEET_ID\",\"provider\":\"gke\"}" \
  "$KORDEX_API/v1/organizations/$ORG_ID/clusters")
export CLUSTER_ID=$(printf '%s' "$CLUSTER_JSON" | jq -r '.id')

TOKEN_JSON=$(curl --fail --silent --show-error --config "$HOME/.kordex-test/curl.conf" \
  -X POST "$KORDEX_API/v1/organizations/$ORG_ID/clusters/$CLUSTER_ID/enrollment-tokens")
```

Enrollment tokens are one-time credentials and expire after ten minutes. Store the returned token in a mode-0600 file and do not print it or place it in source control:

```sh
export TOKEN_FILE="$HOME/.kordex-test/enrollment-token"
printf '%s' "$TOKEN_JSON" | jq -er '.token' > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
unset TOKEN_JSON
```

If enrollment fails because the token expired or was already used, request a new token and replace the file immediately before starting the agent.

## 7. Build and run the agent against GKE

Build the agent from the repository root:

```sh
mkdir -p bin
go build -o bin/kordex-agent ./agent/cmd/kordex-agent
```

Create a private, durable identity-state directory, set the agent to the registered cluster, and run it in local-development mode. The agent reads the active kubeconfig, gathers inventory, enrolls once, and signs subsequent requests using its persisted identity.

```sh
mkdir -p "$HOME/.kordex-test/agent-state"
chmod 700 "$HOME/.kordex-test/agent-state"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
export KORDEX_CONTROL_PLANE_URL="$KORDEX_API"
export KORDEX_CLUSTER_ID="$CLUSTER_ID"
export KORDEX_ENROLLMENT_TOKEN_FILE="$TOKEN_FILE"
export KORDEX_STATE_FILE="$HOME/.kordex-test/agent-state/identity.json"
export KORDEX_LOCAL_DEVELOPMENT=true
./bin/kordex-agent
```

Leave the agent running. It needs outbound access to `127.0.0.1:8080` and access through the active kubeconfig to the GKE Kubernetes API. This is a workstation test arrangement; it is not the production outbound agent deployment model. In a real cluster, deploy the agent using the [Helm chart instructions](../deployments/helm/README.md), HTTPS, a trusted management CA, and Kubernetes-backed durable state.

## 8. Verify registration and node inventory

In another terminal, set `ORG_ID`, `CLUSTER_ID`, and `KORDEX_API` to the values from the setup session. Create the same protected curl config as above or reuse the existing file. Then check the registered cluster and its nodes:

```sh
curl --fail --silent --show-error --config "$HOME/.kordex-test/curl.conf" \
  "$KORDEX_API/v1/organizations/$ORG_ID/clusters" | jq

curl --fail --silent --show-error --config "$HOME/.kordex-test/curl.conf" \
  "$KORDEX_API/v1/organizations/$ORG_ID/clusters/$CLUSTER_ID/nodes?limit=100" | jq
```

Confirm the cluster has a reported Kubernetes version, a recent heartbeat, and a cluster UID. Confirm node inventory includes the GKE node names, readiness, operating-system image, and kernel version. Compare the node list with:

```sh
kubectl get nodes -o wide
```

The API response is the source of truth for what Kordex has actually persisted. An empty or stale node list means the agent has not completed a report; inspect its structured logs and verify kubeconfig access and API readiness.

## 9. Exercise agent restart and reconnection

Stop the agent with Ctrl+C. Wait for the cluster heartbeat to become stale in the API, then restart the exact same agent command with the same state file. On restart, remove `KORDEX_ENROLLMENT_TOKEN_FILE` from the environment (or unset it); the saved agent identity should be reused without consuming another enrollment token.

```sh
unset KORDEX_ENROLLMENT_TOKEN_FILE
./bin/kordex-agent
```

Verify that heartbeats and node reports resume for the same registered cluster, without creating a second cluster or enrolling a new agent. This checks a basic process restart path; it does not simulate loss of the state file, loss of control-plane database, or a prolonged network partition.

## 10. What to do before testing maintenance

Do not create a `NodeMaintenance` request as part of this inventory pilot. Before attempting a drain, use a disposable cluster and review [the maintenance workflow limits](maintenance-operator.md). The current workflow is scoped to opted-in stateless workers and has conservative safety gates. A cluster-wide persistent volume or unrelated unhealthy workload may block maintenance; never bypass a block to make a test pass. The current provider metadata does not call GKE APIs, and package updates, kernel updates, storage maintenance, and host reboot execution are not implemented.

The reliability review also identified two qualifications to address before a browser-based or unattended test: the dashboard PKCE authorization request needs correction and live IdP testing; and unexpected node replacement/reboot can require operator intervention during recovery. A useful next real-cluster qualification should use disposable workers and explicitly test PDB blockage, cancellation after cordon, insufficient capacity, agent/operator restart, network interruption, and node replacement. Record results and inspect audit history before widening the scope.

## 11. Clean up billable resources

Delete the GKE cluster when the test is complete:

```sh
gcloud container clusters delete "$CLUSTER" \
  --project="$PROJECT_ID" \
  --zone="$ZONE"
```

Stop the local services. This preserves the local PostgreSQL volume so you can inspect the data later:

```sh
docker compose --env-file deployments/local/.env \
  -f deployments/local/compose.yaml down
```

If you are finished with the dedicated project, review its resources and billing first, then delete the project in the Cloud Console or with `gcloud projects delete "$PROJECT_ID"`. Project deletion is destructive and affects every resource in that project. Removing the cluster alone stops the cluster resources but does not delete the project.

## Later: hosting the Kordex management plane in Google Cloud

That is a separate implementation/deployment milestone, not a continuation of the commands above. The repository does not currently provide a complete production GCP deployment. Before hosting the control plane, implement and verify a supported Cloud SQL TLS connection path (or a supported GKE/Cloud SQL Auth Proxy path), public HTTPS ingress, production OIDC configuration and callback, service identity/IAM, secret delivery, database backup and restore, and deployment automation. Only enable additional APIs such as Cloud SQL Admin, Artifact Registry, Secret Manager, or Pub/Sub when the selected deployment design actually uses those services.

## Official Google Cloud references

- [Create a project](https://cloud.google.com/resource-manager/docs/creating-managing-projects)
- [Link a project to a billing account](https://cloud.google.com/billing/docs/how-to/modify-project)
- [Enable and disable services](https://cloud.google.com/service-usage/docs/enable-disable)
- [Create a zonal GKE Standard cluster](https://cloud.google.com/kubernetes-engine/docs/how-to/creating-a-zonal-cluster)
- [Connect to a GKE cluster with `gcloud`](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl)
- [GKE pricing](https://cloud.google.com/kubernetes-engine/pricing)
- [Cloud Billing budgets](https://cloud.google.com/billing/docs/how-to/budgets)
