#!/usr/bin/env bash
# Shared fail-closed target validation for future isolated private lab commands.
# This file is sourced; it deliberately performs no kubectl/gcloud operations.

kordex_private_lab_expected_context() {
  : "${KORDEX_EXPECTED_GCP_PROJECT:?Set KORDEX_EXPECTED_GCP_PROJECT explicitly}"
  : "${KORDEX_EXPECTED_GKE_LOCATION:?Set KORDEX_EXPECTED_GKE_LOCATION explicitly}"
  : "${KORDEX_EXPECTED_GKE_CLUSTER:?Set KORDEX_EXPECTED_GKE_CLUSTER explicitly}"
  : "${KORDEX_EXPECTED_KUBE_CONTEXT:?Set KORDEX_EXPECTED_KUBE_CONTEXT explicitly}"

  [[ "$KORDEX_EXPECTED_GCP_PROJECT" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || {
    echo 'Expected GCP project ID is malformed.' >&2; return 2;
  }
  [[ "$KORDEX_EXPECTED_GCP_PROJECT" != 'kordex-fleet-platform' ]] || {
    echo 'The shared Kordex product project is prohibited for private-lab operations.' >&2; return 2;
  }
  [[ "$KORDEX_EXPECTED_GKE_LOCATION" =~ ^[a-z]+-[a-z]+[0-9]-[a-z]$ ]] || {
    echo 'Expected GKE location must be a zonal location such as us-east1-b.' >&2; return 2;
  }
  [[ "$KORDEX_EXPECTED_GKE_CLUSTER" == 'kordex-pmlab-gke' ]] || {
    echo 'Expected GKE cluster must be the isolated module cluster kordex-pmlab-gke.' >&2; return 2;
  }
  local canonical="gke_${KORDEX_EXPECTED_GCP_PROJECT}_${KORDEX_EXPECTED_GKE_LOCATION}_${KORDEX_EXPECTED_GKE_CLUSTER}"
  [[ "$KORDEX_EXPECTED_KUBE_CONTEXT" == "$canonical" ]] || {
    echo 'Kubernetes context must be the canonical context for the explicitly named private lab project, location, and cluster.' >&2; return 2;
  }
  printf '%s' "$canonical"
}

kordex_verify_private_lab_cluster() {
  local context="$1" description
  command -v gcloud >/dev/null || { echo 'gcloud is required to verify the private lab project and cluster.' >&2; return 2; }
  description="$(gcloud container clusters describe "$KORDEX_EXPECTED_GKE_CLUSTER" \
    --project="$KORDEX_EXPECTED_GCP_PROJECT" --zone="$KORDEX_EXPECTED_GKE_LOCATION" --format=json)" || {
      echo 'The explicitly selected private lab cluster could not be verified through GKE.' >&2; return 2;
    }
  python3 - "$description" "$KORDEX_EXPECTED_GKE_CLUSTER" "$KORDEX_EXPECTED_GKE_LOCATION" <<'PY'
import json, sys
cluster = json.loads(sys.argv[1])
if cluster.get("name") != sys.argv[2] or cluster.get("location") != sys.argv[3]:
    raise SystemExit("GKE returned a different cluster identity or location.")
private = cluster.get("privateClusterConfig") or {}
endpoints = cluster.get("controlPlaneEndpointsConfig") or {}
ip = endpoints.get("ipEndpointsConfig") or {}
dns = endpoints.get("dnsEndpointConfig") or {}
if private.get("enablePrivateNodes") is not True or private.get("enablePrivateEndpoint") is not True:
    raise SystemExit("GKE cluster must use private nodes and a private control-plane endpoint.")
if ip.get("enabled") is not True or any((ip.get("publicEndpoint"), private.get("publicEndpoint"))):
    raise SystemExit("GKE public IP endpoint must be disabled while the private IP endpoint remains enabled.")
if dns.get("allowExternalTraffic") is not False:
    raise SystemExit("GKE cluster must have external control-plane endpoints disabled.")
network = cluster.get("networkConfig") or {}
if network.get("datapathProvider") != "ADVANCED_DATAPATH":
    raise SystemExit("GKE cluster must use the isolated lab's Dataplane V2 configuration.")
PY
  [[ "$context" == "$KORDEX_EXPECTED_KUBE_CONTEXT" ]] || { echo 'Private lab Kubernetes context changed during target verification.' >&2; return 2; }
}
