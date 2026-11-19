#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
HELM="${HELM:-helm}"
KUBECTL="${KUBECTL:-kubectl}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$HELM" template inventory-test "$ROOT/deployments/helm/kordex-agent" \
  --namespace kordex-system \
  --set controlPlaneURL=https://hub.example \
  --set clusterID=80bd80f9-f097-4474-86f4-b80986fd5423 \
  --set enrollmentSecretName=enrollment > "$TMP/helm.yaml"
"$KUBECTL" kustomize "$ROOT/deployments/kustomize/components/agent" > "$TMP/kustomize.yaml"

grep -Fq 'resources: [csinodes, storageclasses]' "$TMP/helm.yaml"
grep -Fq 'resources: [mutatingwebhookconfigurations, validatingwebhookconfigurations, validatingadmissionpolicies, validatingadmissionpolicybindings]' "$TMP/helm.yaml"
grep -Fq 'apiGroups: [admissionregistration.k8s.io]' "$TMP/helm.yaml"
grep -Fq 'nonResourceURLs: [/version, /api, /api/*, /apis, /apis/*]' "$TMP/helm.yaml"
grep -Fq 'resources: [daemonsets]' "$TMP/helm.yaml"
grep -Fq 'namespace: kube-system' "$TMP/helm.yaml"
grep -Fq 'startupProbe:' "$TMP/helm.yaml"
grep -Fq 'path: /healthz' "$TMP/helm.yaml"
grep -Fq 'path: /readyz' "$TMP/helm.yaml"

grep -Fq -- '- csinodes' "$TMP/kustomize.yaml"
grep -Fq -- '- storageclasses' "$TMP/kustomize.yaml"
grep -Fq -- '- validatingadmissionpolicies' "$TMP/kustomize.yaml"
grep -Fq -- '- admissionregistration.k8s.io' "$TMP/kustomize.yaml"
grep -Fq -- '- /api/*' "$TMP/kustomize.yaml"
grep -Fq -- '- /apis/*' "$TMP/kustomize.yaml"
grep -Fq -- '- daemonsets' "$TMP/kustomize.yaml"
grep -Fq 'name: kordex-agent-discovery' "$TMP/kustomize.yaml"
grep -Fq 'namespace: kube-system' "$TMP/kustomize.yaml"
grep -Fq 'startupProbe:' "$TMP/kustomize.yaml"
grep -Fq 'path: /healthz' "$TMP/kustomize.yaml"
grep -Fq 'path: /readyz' "$TMP/kustomize.yaml"
grep -Fq -- '- kordex-system' "$TMP/kustomize.yaml"
echo 'agent inventory RBAC render checks passed'
