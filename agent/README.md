# Outbound inventory agent

The Go agent enrolls a cluster, authenticates with persisted Ed25519 identity, rotates keys, sends heartbeats and reports Kubernetes node/OS inventory. With KORDEX_ENABLE_MAINTENANCE=true, it also delivers signed permits to the operator CRD inbox and renews a short-lived hub-connection Lease only after durable synchronization. It has no node/eviction, host maintenance or shell-execution permission.

Build from the repository root:

```sh
go build -o bin/kordex-agent ./agent/cmd/kordex-agent
```

For an isolated local run, set KUBECONFIG, KORDEX_CONTROL_PLANE_URL, KORDEX_CLUSTER_ID, KORDEX_ENROLLMENT_TOKEN_FILE and KORDEX_STATE_FILE. Set KORDEX_LOCAL_DEVELOPMENT=true only for local loopback HTTP/file-state testing. The enrollment file should have mode 0600. A subsequent restart can omit the token file when durable identity is intact.

For cluster deployment, use deployments/helm/kordex-agent. Kubernetes state uses one retained identity Secret projected read-only by kubelet; the agent patches only its named `state.json` key with compare-and-swap and has no Kubernetes API Secret read permission. Leader election uses one pre-created Lease. The opt-in command path requires operator CRDs in the same namespace. Terminal status acknowledgements survive restarts. The agent cannot evict pods, patch nodes, read workload Secrets or execute host commands. See docs/agent-protocol.md for identity recovery and expiry semantics.

The default inventory cycle is every 30 seconds with bounded exponential retry
and jitter. Node reports include Kubernetes UID/name, complete bounded labels,
taints, conditions, readiness, schedulability, capacity/allocatable quantities,
addresses, provider ID, OS image and conservative OS ID/version hints, kernel,
architecture, kubelet, container runtime, and GKE node-pool labels. Unrecognized
OS images are reported as `unknown`. Reports also include the Kubernetes server
version and the existing bounded CSI, StorageClass, admission, and CNI hint
observations. No workload environment, application Secret, or Secret object is
collected. See [the GKE live inventory runbook](../docs/gke-live-inventory.md)
for registration, routing, deployment, and verification requirements.

Outbound agent API calls emit sampled OpenTelemetry spans and inject W3C
trace-context headers so API request spans can continue the trace. The span
route is selected from a fixed agent API allowlist; request/response bodies,
cluster IDs, unrecognized paths, and raw errors are excluded. OTLP/HTTP export
is disabled by default. Configure Helm `telemetry.otlpEndpoint` or the
Kustomize setting `otelExporterOtlpEndpoint` to enable it, and permit only the
collector's peer and port in any enabled restricted-egress policy.
