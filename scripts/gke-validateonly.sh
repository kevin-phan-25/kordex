#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: ORG_ID=<uuid> CLUSTER_ID=<uuid> NODE_NAME=<name> scripts/gke-validateonly.sh

Requires KORDEX_ADMIN_TOKEN in the environment, kubectl configured for the
disposable GKE cluster, and the GKE maintenance policy/PDB samples already
installed. This script submits ValidateOnly only; it never labels or drains a node.
EOF
  exit 2
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

: "${ORG_ID:?$(usage)}"
: "${CLUSTER_ID:?$(usage)}"
: "${NODE_NAME:?$(usage)}"
: "${KORDEX_ADMIN_TOKEN:?Load KORDEX_ADMIN_TOKEN from deployments/local/.env first}"

KORDEX_API="${KORDEX_API:-http://127.0.0.1:8080}"
POLICY_NAME="${POLICY_NAME:-gke-stateless-workers}"
NAMESPACE="${KORDEX_NAMESPACE:-kordex-system}"

for command in curl jq kubectl python3 mktemp; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

context="$(kubectl config current-context)" || fail "kubectl has no current context"
printf 'Kubernetes context: %s\n' "$context" >&2

lease_holder="$(kubectl get lease kordex-hub-connection -n "$NAMESPACE" -o jsonpath='{.spec.holderIdentity}')" || fail "cannot read hub-connection Lease"
[[ "$lease_holder" == "$CLUSTER_ID" ]] || fail "hub-connection Lease holder does not match CLUSTER_ID"

node_json="$(kubectl get node "$NODE_NAME" -o json)" || fail "target node not found"
node_uid="$(jq -er '.metadata.uid' <<<"$node_json")" || fail "target node has no UID"
node_opt_in="$(jq -r '.metadata.labels["operations.kordex.local/maintenance"] // ""' <<<"$node_json")"
[[ "$node_opt_in" == "stateless" ]] || fail "target node is not explicitly opted in with the stateless maintenance label"

policy_json="$(kubectl get maintenancepolicy "$POLICY_NAME" -n "$NAMESPACE" -o json)" || fail "GKE MaintenancePolicy not found"
jq -e '.spec.allowGKESystemWorkloads == true' <<<"$policy_json" >/dev/null || fail "policy does not enable the GKE system workload evaluator"
policy_uid="$(jq -er '.metadata.uid' <<<"$policy_json")"
policy_generation="$(jq -er '.metadata.generation' <<<"$policy_json")"

for pdb in kordex-kube-dns kordex-konnectivity-agent; do
  pdb_json="$(kubectl get pdb "$pdb" -n kube-system -o json)" || fail "required PDB $pdb not found"
  jq -e '.status.observedGeneration >= .metadata.generation and .status.disruptionsAllowed >= 1' <<<"$pdb_json" >/dev/null || fail "PDB $pdb is not current with at least one allowed disruption"
done

umask 077
auth_config="$(mktemp "${TMPDIR:-/tmp}/kordex-validateonly-curl.XXXXXX")" || fail "cannot create a private curl config"
trap 'rm -f "$auth_config"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$KORDEX_ADMIN_TOKEN" >"$auth_config"

clusters_json="$(curl --fail --silent --show-error --config "$auth_config" "$KORDEX_API/v1/organizations/$ORG_ID/clusters?limit=500")" || fail "cannot read cluster state from the management API"
connected="$(jq -r --arg id "$CLUSTER_ID" '[.items[]? | select(.id == $id) | .connected] | first // false' <<<"$clusters_json")"
[[ "$connected" == "true" ]] || fail "management API does not report this cluster as connected"

operations_json="$(curl --fail --silent --show-error --config "$auth_config" "$KORDEX_API/v1/organizations/$ORG_ID/clusters/$CLUSTER_ID/operations?limit=500")" || fail "cannot read existing operations"
active="$(jq -r '.items[]? | select(.phase != "Succeeded" and .phase != "Failed" and .phase != "Cancelled") | [.id, .phase] | @tsv' <<<"$operations_json")"
[[ -z "$active" ]] || fail "another operation is still active; wait for it to reach Succeeded, Failed, or Cancelled: $active"

operation_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
request_json="$(jq -n \
  --arg operationId "$operation_id" \
  --arg nodeName "$NODE_NAME" \
  --arg nodeUid "$node_uid" \
  --arg policyName "$POLICY_NAME" \
  --arg policyUid "$policy_uid" \
  --argjson generation "$policy_generation" \
  '{operationId:$operationId,nodeName:$nodeName,nodeUid:$nodeUid,policy:{name:$policyName,uid:$policyUid,generation:$generation},action:"ValidateOnly"}')"

response="$(curl --fail --silent --show-error \
  --config "$auth_config" \
  -H 'Content-Type: application/json' \
  -d "$request_json" \
  "$KORDEX_API/v1/organizations/$ORG_ID/clusters/$CLUSTER_ID/operations")" || fail "management API rejected the ValidateOnly request"

jq -e --arg id "$operation_id" '.request.operationId == $id and .request.action == "ValidateOnly"' <<<"$response" >/dev/null || fail "management API returned an unexpected operation"
printf '%s\n' "$response" | jq '{id, phase, request, expiresAt}'
printf '\nWatch local status with:\nkubectl get nodemaintenance -n %s op-%s -w\n' "$NAMESPACE" "$operation_id"
