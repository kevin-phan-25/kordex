# Kubernetes distribution compatibility

This registry separates Kubernetes API-level compatibility from cloud-provider
lifecycle integrations. Registry presence is not approval to run maintenance.
Unknown and conflicting signals remain unqualified. No Kubernetes distribution,
Kubernetes version, node operating system, or architecture is currently marked
qualified here.

## Current registry

The authoritative machine-readable data is returned by
`GET /v1/organizations/{organizationID}/kubernetes-compatibility` and by
`go run ./integrations/cmd/kordex-discover -kubernetes-matrix`.

| Target | Current status | Detection boundary | Mutating operations |
|---|---|---|---|
| Upstream Kubernetes | Unverified | Not reliably identified from Node metadata alone | Provider, control-plane, storage mutations unsupported; common validation/drain paths unqualified |
| K3s | Unverified | Exact kubelet version suffix is an advisory hint, not control-plane attestation | Host package/reboot unqualified; provider and control-plane mutations unsupported |
| RKE2 | Unverified | Exact kubelet version suffix is an advisory hint, not control-plane attestation | Host package/reboot unqualified; provider and control-plane mutations unsupported |
| GKE | Unverified | Node-pool label plus GCE provider ID are advisory; the GKE executor separately checks live cloud identity | GKE node-pool update is unqualified; host package/reboot unqualified |
| EKS | Unverified | Node-group label plus AWS provider ID are advisory | EKS node-group executor is not implemented |
| AKS | Unverified | Agent-pool label plus Azure provider ID are advisory | AKS node-pool executor is not implemented |
| OpenShift | Unverified | Machine-configuration node label is advisory, not cluster attestation | OpenShift admission/SCC compatibility is unqualified |
| kubeadm | Unverified | Not distinguishable from generic upstream by current Node metadata | Control-plane maintenance unsupported |
| Talos | Unverified | No reliable Talos classifier in the current agent inventory | Generic host package/SSH execution unsupported |
| MicroK8s | Unverified | No MicroK8s classifier in the current agent inventory | All distribution-specific operations unqualified |

For every row, the registry reports no qualified Kubernetes version, node OS,
or architecture. The common `ValidateOnly`, `DrainAndVerify`, and
`HostPackageReboot` entries remain `Unverified`; they describe code paths, not
distribution certification. GKE node-pool update remains opt-in and
`Unverified`. EKS, AKS, Kubernetes control-plane changes, and storage mutations
are not enabled by this registry.

The CI Kind v1.37.0 registration and PDB-aware drain tests are automated test
coverage. They do not qualify an upstream distribution release, K3s, or another
vendor distribution. A GCP K3s Terraform module is a lab definition, not
qualification evidence. See the
[authoritative upgrade matrix](production-upgrade-requirements.md) for host and
provider execution qualification.

## Permissions and runtime requirements

The API response includes the Kubernetes RBAC permission profiles represented
by the checked-in agent and operator Helm/Kustomize manifests:

- `agent-inventory` is the read-only inventory profile: node facts, counts of
  configured admission webhook/policy objects, CSI node drivers, storage
  provisioners, Pod Security labels on the agent namespace, and advisory CNI
  DaemonSet name hints in `kube-system`.

- `operator-default` describes node, workload, eviction, CRD, lease, ledger,
  PV/service, readiness, read-only Ceph and Longhorn API permissions, and
  creation of self-scoped `SelfSubjectAccessReview` objects. The operator uses
  these reviews to check effective drain/recovery permissions and publishes
  the result as an advisory capability. A denied or indeterminate check blocks
  hub campaign preview/admission; Kubernetes still authorizes every request
  independently.
- `self-managed-host-execution` is the additional namespaced SSH Secret and
  execution NetworkPolicy permission profile. Use only with a separately
  reviewed lab-only gate and execution environment. When enabled, the operator
  checks its effective permissions for the SSH Secret, known-hosts ConfigMap,
  execution Jobs/Pods/NetworkPolicies, and durable receipt ledger. A denied,
  indeterminate, or unavailable review disables the local executor and
  publishes host execution as unavailable. Kubernetes still authorizes every
  actual request independently.
- `gke-node-pool-upgrade` lists GKE API actions requiring the separately
  configured Workload Identity adapter.

The three operator CRDs and common network requirements are included in each
entry. Optional provider and host-execution network requirements are listed
separately. Validate the rendered permissions and network policies against the
actual cluster CNI and deployment overlay before enabling an adapter.

The agent's TCP/8081 health endpoint is pod-local diagnostics for kubelet
startup/liveness/readiness probes and is not exposed through a Kubernetes
Service. Readiness requires a leader with a recent successful signed sync.

## Cluster capability inventory

Signed agent reports can include bounded, timestamped cluster signals for CNI
hints, CSI drivers, storage provisioners, counts of admission webhook and
policy configuration objects, and Pod Security labels on the agent namespace.
Failed or denied reads are recorded as
`Unknown` with a stable reason code; this inventory never grants an operation
or claims compatibility. The fleet view labels old observations as stale.
Deploy the control plane before the agent because the current API rejects
unknown JSON fields.

The signals have narrow meanings. CNI results are inferred from recognized
DaemonSet names and do not prove which CNI is active. CSI drivers come from
`CSINode.spec.drivers`, and provisioners from StorageClasses; neither proves
volume health or safe node maintenance. Admission values report counts of
served webhook configurations, admission policies, and policy bindings (or
`unserved`). The agent uses Kubernetes metadata-only list responses and sends
counts only; it does not fetch admission specs or send object metadata. Counts
do not identify
which policies are bound, or establish effective enforcement. If the agent
lacks permission to list a served resource, the complete admission observation
is `Unknown`; partial counts are discarded. Pod Security results contain only
`pod-security.kubernetes.io/*` labels on the Kordex agent namespace, not
effective admission configuration across customer namespaces. Every
distribution and operation remains unqualified until its separate qualification
criteria pass.

The fleet API also returns a read-only cluster compatibility summary based on
the node inventory currently stored by the control plane. It reports the node
count, distinct Kubernetes OS display strings, distinct architectures, and
distribution hints. `Unknown` means inventory or distribution identity is
incomplete; `MixedSignals` means multiple known distribution hints conflict;
`Unqualified` means a known hint is not registered or lacks qualification
evidence. An unknown hint alongside one known hint remains `Unknown`, because
the cluster identity is incomplete rather than demonstrably conflicting.
Kubernetes `Node.status.nodeInfo.osImage` is a display string and does not
provide normalized host `os-release` ID/major, so the summary cannot promote a
cluster to qualified. No cluster compatibility path currently returns
`Qualified`, and the summary is not an authorization input for maintenance.

## Inventory identity

Kubernetes Node metadata is advisory. K3s, RKE2, and k0s version suffixes are
matched as complete version forms; arbitrary substrings do not identify a
distribution. Managed-provider hints require both a provider ID and the
provider-specific node-pool label. Multiple conflicting hints result in
`unknown`. Talos, MicroK8s, kubeadm, and generic upstream clusters are not
reliably distinguished by the current Node metadata collector and must not be
promoted from `unknown` by package-manager or cloud-VM similarity.

The registry is descriptive only. It has no execution API and refuses
`Supported` or `Qualified` claims. An evidence-backed activation process must
be designed and reviewed before a row can change status. Until then, use
`Unverified` or `Unsupported` and retain local operator fail-closed checks.
