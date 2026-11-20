#!/usr/bin/env python3
"""Render and fail closed on unresolved or non-private GKE management manifests."""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys

import yaml

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "deployments/kustomize/hub/overlays/gke-private-lab"
IMAGE_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def fail(message):
    raise SystemExit(message)


def expected_target():
    project = os.environ.get("KORDEX_EXPECTED_GCP_PROJECT", "")
    location = os.environ.get("KORDEX_EXPECTED_GKE_LOCATION", "")
    cluster_name = os.environ.get("KORDEX_EXPECTED_GKE_CLUSTER", "")
    context = os.environ.get("KORDEX_EXPECTED_KUBE_CONTEXT", "")
    if not all((project, location, cluster_name, context)):
        fail("set KORDEX_EXPECTED_GCP_PROJECT, KORDEX_EXPECTED_GKE_LOCATION, KORDEX_EXPECTED_GKE_CLUSTER, and KORDEX_EXPECTED_KUBE_CONTEXT for live validation")
    if project == "kordex-fleet-platform":
        fail("the shared Kordex product project is prohibited for private-lab validation")
    if cluster_name != "kordex-pmlab-gke":
        fail("live validation is restricted to the isolated module cluster kordex-pmlab-gke")
    canonical = f"gke_{project}_{location}_{cluster_name}"
    if context != canonical:
        fail("expected context must be the canonical GKE context for the supplied private lab target")
    return project, location, cluster_name, context


def render():
    result = subprocess.run(["kubectl", "kustomize", str(OVERLAY)], check=True, text=True, capture_output=True)
    return [item for item in yaml.safe_load_all(result.stdout) if item]


def inspect(docs, template=False):
    text = yaml.safe_dump_all(docs)
    unresolved = "REPLACE_WITH" in text
    if unresolved and not template:
        fail("unresolved deployment placeholders; no resources should be applied")
    kinds = [item.get("kind") for item in docs]
    forbidden = {"Secret", "Ingress", "CustomResourceDefinition", "Job"}
    if forbidden.intersection(kinds):
        fail("private management base must not render Secrets, Ingress, CRDs, or Jobs")
    workloads = [item for item in docs if item.get("kind") in {"Deployment", "StatefulSet"}]
    names = {item.get("metadata", {}).get("name") for item in workloads}
    if names != {"kordex-api", "kordex-postgres", "kordex-keycloak"}:
        fail(f"unexpected workload set: {sorted(str(name) for name in names)}")
    for item in docs:
        if item.get("kind") == "Service" and item.get("spec", {}).get("type") != "ClusterIP":
            fail("all management plane Services must be explicit ClusterIP")
        if item.get("kind") == "Service" and item.get("metadata", {}).get("name") == "kordex-api":
            ports = item["spec"].get("ports", [])
            if [port.get("port") for port in ports] != [8443]:
                fail("the API Service may expose only its private TLS port 8443")
    api = next(item for item in workloads if item["metadata"]["name"] == "kordex-api")
    pod = api["spec"]["template"]["spec"]
    if pod.get("hostNetwork") or pod.get("hostPID") or pod.get("hostIPC"):
        fail("host namespaces are forbidden")
    if pod.get("hostAliases", [{}])[0].get("ip") != next(
        item["spec"].get("clusterIP") for item in docs
        if item.get("kind") == "Service" and item.get("metadata", {}).get("name") == "kordex-keycloak"
    ):
        fail("API issuer host alias must match the fixed Keycloak ClusterIP")
    for workload in workloads:
        spec = workload["spec"].get("template", {}).get("spec", {})
        for container in [*spec.get("initContainers", []), *spec.get("containers", [])]:
            image = container.get("image", "")
            if not IMAGE_RE.search(image) and not (template and re.search(r"@sha256:REPLACE_WITH_[A-Z0-9_]+$", image)):
                fail(f"container image is not digest pinned: {container.get('name')}")
            destination = ("us-east1-docker.pkg.dev/REPLACE_WITH_DISPOSABLE_PROJECT_ID/kordex-pmlab-images/"
                           if template else f"us-east1-docker.pkg.dev/{os.environ.get('KORDEX_EXPECTED_GCP_PROJECT', '')}/kordex-pmlab-images/")
            if destination not in image:
                fail("every container image must be mirrored to the isolated lab Artifact Registry")
            if any(secret.get("secretName", "").startswith("REPLACE") for volume in spec.get("volumes", [])
                   for secret in [volume.get("secret", {})]):
                fail("secret names must be stable references; values stay out of manifests")
    postgres = next(item for item in workloads if item["metadata"]["name"] == "kordex-postgres")
    claim = postgres["spec"]["volumeClaimTemplates"][0]
    if claim["spec"]["storageClassName"] != "kordex-pd-balanced-retain" or claim["spec"]["resources"]["requests"]["storage"] != "20Gi":
        fail("PostgreSQL must use the dedicated 20Gi pd-balanced Retain claim")
    storage_classes = [item for item in docs if item.get("kind") == "StorageClass"]
    if len(storage_classes) != 1:
        fail("the package must declare exactly one dedicated StorageClass")
    storage = storage_classes[0]
    if (storage.get("metadata", {}).get("name") != "kordex-pd-balanced-retain" or
        storage.get("provisioner") != "pd.csi.storage.gke.io" or
        storage.get("parameters", {}).get("type") != "pd-balanced" or
        storage.get("reclaimPolicy") != "Retain" or
        storage.get("volumeBindingMode") != "WaitForFirstConsumer"):
        fail("PostgreSQL StorageClass must be GCE PD Balanced with Retain and WaitForFirstConsumer")
    if not template:
        project, location, cluster_name, expected_context = expected_target()
        if subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip() != expected_context:
            fail("unexpected Kubernetes context")
        cluster = json.loads(subprocess.check_output([
            "gcloud", "container", "clusters", "describe", cluster_name,
            f"--project={project}", f"--zone={location}",
            "--format=json",
        ], text=True))
        if not network_policy_enforced(cluster):
            fail("GKE NetworkPolicy enforcement is not enabled and confirmed; no resource should be applied")
        cidr_text = subprocess.check_output([
            "gcloud", "container", "clusters", "describe", cluster_name,
            f"--project={project}", f"--zone={location}",
            "--format=value(ipAllocationPolicy.servicesIpv4CidrBlock)",
        ], text=True).strip()
        cidr = ipaddress.ip_network(cidr_text)
        service = next(item for item in docs if item.get("kind") == "Service" and item.get("metadata", {}).get("name") == "kordex-keycloak")
        address = ipaddress.ip_address(service["spec"]["clusterIP"])
        if address not in cidr:
            fail("Keycloak ClusterIP is outside the live GKE Service CIDR")
        current = json.loads(subprocess.check_output([
            "kubectl", "--context", expected_context, "get", "services", "-A", "-o", "json"
        ], text=True))
        if any(item.get("spec", {}).get("clusterIP") == str(address) for item in current.get("items", [])):
            fail("Keycloak ClusterIP is already allocated")


def network_policy_enforced(cluster):
    """Return true only when GKE config and runtime evidence both show an enforcer."""
    network = cluster.get("networkConfig") or {}
    datapath = network.get("datapathProvider") or cluster.get("datapathProvider")
    legacy = cluster.get("networkPolicy") or {}
    if datapath == "ADVANCED_DATAPATH":
        return daemonset_ready("anetd")
    if legacy.get("enabled") is True and legacy.get("provider") == "CALICO":
        if not daemonset_ready("calico-node"):
            return False
        nodes = subprocess.run(
            ["kubectl", "--context", os.environ.get("KORDEX_EXPECTED_KUBE_CONTEXT", ""), "get", "nodes", "-o", "json"],
            text=True, capture_output=True,
        )
        if nodes.returncode != 0:
            return False
        node_items = json.loads(nodes.stdout).get("items", [])
        return bool(node_items) and all(
            item.get("metadata", {}).get("labels", {}).get("projectcalico.org/ds-ready") == "true"
            for item in node_items
        )
    return False


def daemonset_ready(name):
    context = os.environ.get("KORDEX_EXPECTED_KUBE_CONTEXT", "")
    if not context:
        return False
    result = subprocess.run(
        ["kubectl", "--context", context, "-n", "kube-system", "get", "daemonset", name, "-o", "json"],
        text=True, capture_output=True,
    )
    if result.returncode != 0:
        return False
    status = json.loads(result.stdout).get("status", {})
    desired = status.get("desiredNumberScheduled", 0)
    return desired > 0 and status.get("numberReady", 0) >= desired


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", action="store_true", help="check structure while expected placeholders remain")
    args = parser.parse_args()
    inspect(render(), template=args.template)
    print("GKE private management manifests passed structural checks" + (" (template only)" if args.template else ""))


if __name__ == "__main__":
    main()
