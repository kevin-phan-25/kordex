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
assert api_deployment["spec"]["replicas"] == 0
assert api_deployment["spec"]["template"]["spec"]["hostAliases"][0]["ip"] == keycloak_service["spec"]["clusterIP"]
pg = next(doc for doc in workloads if doc["metadata"]["name"] == "kordex-postgres")
claim = pg["spec"]["volumeClaimTemplates"][0]["spec"]
assert claim["storageClassName"] == "kordex-pd-balanced-retain"
assert claim["resources"]["requests"]["storage"] == "20Gi"
storage = next(doc for doc in docs if doc["kind"] == "StorageClass")
assert storage["metadata"]["name"] == "kordex-pd-balanced-retain"
assert storage["provisioner"] == "pd.csi.storage.gke.io"
assert storage["parameters"]["type"] == "pd-balanced"
assert storage["reclaimPolicy"] == "Retain"
assert storage["volumeBindingMode"] == "WaitForFirstConsumer"
for doc in workloads:
    spec = doc["spec"]["template"]["spec"]
    for container in [*spec.get("initContainers", []), *spec.get("containers", [])]:
        image = container["image"]
        assert "@sha256:" in image
        assert "latest" not in image
        assert "us-east1-docker.pkg.dev/REPLACE_WITH_DISPOSABLE_PROJECT_ID/kordex-pmlab-images/" in image
        assert "kordex-fleet-platform" not in image
assert "keycloak.localhost:8443/realms/kordex" in rendered
assert "KORDEX_LOCAL_DEVELOPMENT" in rendered and 'value: "false"' in rendered

keycloak = next(doc for doc in workloads if doc["metadata"]["name"] == "kordex-keycloak")
assert keycloak["spec"]["replicas"] == 0
kc_container = keycloak["spec"]["template"]["spec"]["containers"][0]
kc_env = {item["name"]: item.get("value") for item in kc_container["env"]}
assert kc_env["KC_DB_TLS_MODE"] == "verify-server"
assert kc_env["KC_DB_TLS_TRUST_STORE_FILE"] == "/run/postgres-ca/ca.pem"
assert "kordex-postgres.kordex-management.svc.cluster.local" in kc_env["KC_DB_URL"]
assert any(mount["name"] == "postgres-ca" and mount["mountPath"] == "/run/postgres-ca" for mount in kc_container["volumeMounts"])
ca_volume = next(volume for volume in keycloak["spec"]["template"]["spec"]["volumes"] if volume["name"] == "postgres-ca")
assert ca_volume["secret"]["secretName"] == "kordex-management-ca"
assert ca_volume["secret"]["items"] == [{"key": "ca.crt", "path": "ca.pem"}]
assert any(mount["name"] == "init" and mount["mountPath"] == "/etc/postgresql-config" for mount in pg["spec"]["template"]["spec"]["containers"][0]["volumeMounts"])
postgres_args = pg["spec"]["template"]["spec"]["containers"][0]["args"]
assert "hostnossl all all all reject" in next(doc for doc in docs if doc.get("kind") == "ConfigMap" and doc["metadata"]["name"] == "kordex-postgres-init")["data"]["pg_hba.conf"]
assert "hba_file=/etc/postgresql-config/pg_hba.conf" in postgres_args
stage = keycloak["spec"]["template"]["spec"]["initContainers"][0]
assert "cp /realm/*.json /data/import/" in stage["args"][0]

policies = {doc["metadata"]["name"]: doc for doc in docs if doc["kind"] == "NetworkPolicy"}
assert "kordex-management-default-deny" in policies
default_deny = policies["kordex-management-default-deny"]["spec"]
assert default_deny["podSelector"] == {} and set(default_deny["policyTypes"]) == {"Ingress", "Egress"}
assert set(policies) == {
    "kordex-management-default-deny", "kordex-management-dns-egress",
    "kordex-postgres-traffic", "kordex-keycloak-traffic", "kordex-api-traffic",
}
assert {"Secret", "NodePort", "LoadBalancer"}.isdisjoint(kinds)
dns = policies["kordex-management-dns-egress"]["spec"]["egress"][0]
assert dns["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == "kube-system"
assert dns["to"][0]["podSelector"]["matchLabels"] == {"k8s-app": "kube-dns"}
assert {(p["protocol"], p["port"]) for p in dns["ports"]} == {("UDP", 53), ("TCP", 53)}
for name, policy in policies.items():
    assert "ipBlock" not in str(policy), f"{name} must not add broad CIDR exceptions"
postgres_policy = policies["kordex-postgres-traffic"]["spec"]
assert {(p["protocol"], p["port"]) for rule in postgres_policy["ingress"] for p in rule["ports"]} == {("TCP", 5432)}
assert {tuple(sorted(peer.get("podSelector", {}).get("matchLabels", {}).items())) for rule in postgres_policy["ingress"] for peer in rule["from"]} == {
    (("app.kubernetes.io/component", "api"),), (("app.kubernetes.io/name", "kordex-keycloak"),),
}
keycloak_policy = policies["kordex-keycloak-traffic"]["spec"]
assert {(p["protocol"], p["port"]) for rule in keycloak_policy["ingress"] for p in rule["ports"]} == {("TCP", 8443)}
assert {(p["protocol"], p["port"]) for rule in keycloak_policy["egress"] for p in rule["ports"]} == {("TCP", 5432)}
api_policy = policies["kordex-api-traffic"]["spec"]
assert {(p["protocol"], p["port"]) for rule in api_policy["ingress"] for p in rule["ports"]} == {("TCP", 8443)}
assert {(p["protocol"], p["port"]) for rule in api_policy["egress"] for p in rule["ports"]} == {("TCP", 5432), ("TCP", 8443)}
agent_peer = api_policy["ingress"][0]["from"][0]
assert agent_peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == "kordex-system"
assert agent_peer["podSelector"]["matchLabels"]["app.kubernetes.io/name"] == "kordex-agent"

strict = subprocess.run(["python3", str(root / "scripts/validate-gke-private-lab.py")], text=True, capture_output=True)
assert strict.returncode != 0
assert "unresolved deployment placeholders" in strict.stderr
print("GKE private management overlay template safety checks passed")
