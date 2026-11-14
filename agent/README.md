# Outbound inventory agent

The Go agent enrolls a cluster, authenticates with persisted Ed25519 identity, rotates keys, sends heartbeats and reports Kubernetes node/OS inventory. It has no maintenance or shell-execution interface.

Build from the repository root:

```sh
go build -o bin/kordex-agent ./agent/cmd/kordex-agent
```

For an isolated local run, set KUBECONFIG, KORDEX_CONTROL_PLANE_URL, KORDEX_CLUSTER_ID, KORDEX_ENROLLMENT_TOKEN_FILE and KORDEX_STATE_FILE. Set KORDEX_LOCAL_DEVELOPMENT=true only for local loopback HTTP/file-state testing. The enrollment file should have mode 0600. A subsequent restart can omit the token file when durable identity is intact.

For cluster deployment, use deployments/helm/kordex-agent. Kubernetes state uses one pre-created Secret; leader election uses one pre-created Lease. The agent cannot evict pods, patch nodes, read workload Secrets or execute host commands. Its Secret permissions are restricted by resource name. See docs/agent-protocol.md for identity recovery and expiry semantics.
