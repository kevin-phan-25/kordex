#!/usr/bin/env python3
"""Render and fail closed on unresolved or non-private GKE management manifests."""
import argparse
import ipaddress
import json
import re
import subprocess
import sys

import yaml

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "deployments/kustomize/hub/overlays/gke-private-lab"
EXPECTED_CONTEXT = "gke_kordex-fleet-platform_us-east1-b_kordex-gke-test"
IMAGE_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def fail(message):
    raise SystemExit(message)


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
            if not IMAGE_RE.search(image) and not (template and "REPLACE_WITH_PUBLISHED_CONTROL_PLANE_IMAGE_DIGEST" in image):
                fail(f"container image is not digest pinned: {container.get('name')}")
            if any(secret.get("secretName", "").startswith("REPLACE") for volume in spec.get("volumes", [])
                   for secret in [volume.get("secret", {})]):
                fail("secret names must be stable references; values stay out of manifests")
    postgres = next(item for item in workloads if item["metadata"]["name"] == "kordex-postgres")
    claim = postgres["spec"]["volumeClaimTemplates"][0]
    if claim["spec"]["storageClassName"] != "standard-rwo" or claim["spec"]["resources"]["requests"]["storage"] != "20Gi":
        fail("PostgreSQL must use the reviewed 20Gi standard-rwo claim")
    if not template:
        if subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip() != EXPECTED_CONTEXT:
            fail("unexpected Kubernetes context")
        cidr_text = subprocess.check_output([
            "gcloud", "container", "clusters", "describe", "kordex-gke-test",
            "--project=kordex-fleet-platform", "--zone=us-east1-b",
            "--format=value(ipAllocationPolicy.servicesIpv4CidrBlock)",
        ], text=True).strip()
        cidr = ipaddress.ip_network(cidr_text)
        service = next(item for item in docs if item.get("kind") == "Service" and item.get("metadata", {}).get("name") == "kordex-keycloak")
        address = ipaddress.ip_address(service["spec"]["clusterIP"])
        if address not in cidr:
            fail("Keycloak ClusterIP is outside the live GKE Service CIDR")
        current = json.loads(subprocess.check_output(["kubectl", "get", "services", "-A", "-o", "json"], text=True))
        if any(item.get("spec", {}).get("clusterIP") == str(address) for item in current.get("items", [])):
            fail("Keycloak ClusterIP is already allocated")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", action="store_true", help="check structure while expected placeholders remain")
    args = parser.parse_args()
    inspect(render(), template=args.template)
    print("GKE private management manifests passed structural checks" + (" (template only)" if args.template else ""))


if __name__ == "__main__":
    main()
