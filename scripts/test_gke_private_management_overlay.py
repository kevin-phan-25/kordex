#!/usr/bin/env python3
import subprocess
from pathlib import Path

import yaml

root = Path(__file__).resolve().parents[1]
overlay = root / "deployments/kustomize/hub/overlays/gke-private-lab"
rendered = subprocess.run(["kubectl", "kustomize", str(overlay)], check=True, text=True, capture_output=True).stdout
docs = [doc for doc in yaml.safe_load_all(rendered) if doc]
kinds = {doc["kind"] for doc in docs}
assert not kinds.intersection({"Secret", "Ingress", "CustomResourceDefinition", "Job", "DaemonSet"})
workloads = [doc for doc in docs if doc["kind"] in {"Deployment", "StatefulSet"}]
assert {doc["metadata"]["name"] for doc in workloads} == {"kordex-api", "kordex-postgres", "kordex-keycloak"}
assert all(doc["spec"].get("type") == "ClusterIP" for doc in docs if doc["kind"] == "Service")
assert not any("operator" in str(doc).lower() or "kordex-agent" in str(doc) for doc in workloads)
api_service = next(doc for doc in docs if doc.get("kind") == "Service" and doc["metadata"]["name"] == "kordex-api")
assert [port["port"] for port in api_service["spec"]["ports"]] == [8443]
keycloak_service = next(doc for doc in docs if doc.get("kind") == "Service" and doc["metadata"]["name"] == "kordex-keycloak")
api_deployment = next(doc for doc in workloads if doc["metadata"]["name"] == "kordex-api")
assert api_deployment["spec"]["template"]["spec"]["hostAliases"][0]["ip"] == keycloak_service["spec"]["clusterIP"]
pg = next(doc for doc in workloads if doc["metadata"]["name"] == "kordex-postgres")
claim = pg["spec"]["volumeClaimTemplates"][0]["spec"]
assert claim["storageClassName"] == "standard-rwo"
assert claim["resources"]["requests"]["storage"] == "20Gi"
for doc in workloads:
    spec = doc["spec"]["template"]["spec"]
    for container in [*spec.get("initContainers", []), *spec.get("containers", [])]:
        image = container["image"]
        assert "@sha256:" in image
        assert "latest" not in image
assert "keycloak.localhost:8443/realms/kordex" in rendered
assert "KORDEX_LOCAL_DEVELOPMENT" in rendered and 'value: "false"' in rendered

strict = subprocess.run(["python3", str(root / "scripts/validate-gke-private-lab.py")], text=True, capture_output=True)
assert strict.returncode != 0
assert "unresolved deployment placeholders" in strict.stderr
print("GKE private management overlay template safety checks passed")
