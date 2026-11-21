#!/usr/bin/env python3
"""Static safety contract for the standalone private relay Helm chart."""

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deployments/helm/kordex-agent-relay"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    chart = (CHART / "Chart.yaml").read_text()
    values = (CHART / "values.yaml").read_text()
    deploy = (CHART / "templates/deployment.yaml").read_text()
    service = (CHART / "templates/service.yaml").read_text()
    policy = (CHART / "templates/networkpolicy.yaml").read_text()
    helper = (CHART / "templates/_helpers.tpl").read_text()
    schema = json.loads((CHART / "values.schema.json").read_text())

    require("name: kordex-agent-relay" in chart, "standalone relay chart metadata missing")
    require('required "image.digest must be a reviewed immutable sha256 digest"' in helper, "digest is not mandatory")
    require("^sha256:[a-f0-9]{64}$" in helper, "digest format is not checked")
    require('type: ClusterIP' in service, "relay Service must be ClusterIP")
    require("LoadBalancer" not in service and "NodePort" not in service, "public-capable Service type found")
    require("kind: Ingress" not in "\n".join(p.read_text() for p in (CHART / "templates").glob("*")), "Ingress template found")
    require("networkPolicy.allowedCIDRs must restrict private relay ingress" in deploy, "empty ingress policy is accepted")
    require("networkPolicy.allowedCIDRs cannot include a universal source" in deploy, "universal ingress CIDR is accepted")
    require("policyTypes: [Ingress, Egress]" in policy, "relay ingress/egress isolation policy missing")
    require("app.kubernetes.io/component: api" in values and "port: 8080" in values, "default API peer is not the API Service")
    require("automountServiceAccountToken: false" in deploy, "Pod unnecessarily receives a ServiceAccount token")
    require("runAsUser: 65532" in deploy and "readOnlyRootFilesystem: true" in deploy, "Pod hardening is incomplete")
    require("capabilities:" in deploy and "drop: [ALL]" in deploy, "container capabilities are not dropped")
    require("secretName: {{ $serverSecret }}" in deploy and "secretName: {{ $clientCA }}" in deploy, "customer Secret mounts missing")
    require("kind: Secret" not in deploy, "chart must not create TLS Secrets")
    require("RequireAndVerifyClientCert" not in deploy, "TLS enforcement must be implemented in the relay process")
    require("clientMappings" in values and "mappings.json" in (CHART / "templates/configmap.yaml").read_text(), "certificate mapping configuration missing")
    require(schema["properties"]["image"]["properties"]["digest"]["pattern"] == "^sha256:[a-f0-9]{64}$", "values schema does not require digest format")
    cidr_pattern = schema["properties"]["networkPolicy"]["properties"]["allowedCIDRs"]["items"]["pattern"]
    require(re.fullmatch(cidr_pattern, "10.84.0.0/16") is not None, "RFC1918 ingress CIDR rejected")
    require(re.fullmatch(cidr_pattern, "8.8.8.8/32") is None, "public ingress CIDR accepted")
    require(re.fullmatch(cidr_pattern, "10.0.0.0/0") is None, "universal ingress CIDR accepted")
    print("private agent relay Helm chart static safety checks passed")


if __name__ == "__main__":
    main()
