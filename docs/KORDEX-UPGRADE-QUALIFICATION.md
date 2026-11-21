# Kordex upgrade qualification

The authoritative [matrix, lab prerequisites and evidence rules](production-upgrade-requirements.md)
remain unchanged. Every disposable-host result is NOT RUN. There is no
lab-qualified or production-qualified upgrade driver.

## Executable tooling

Use the existing `tests/integration/self_managed_upgrade_smoke.py`,
`record_host_upgrade_fault.py`, pinned `host_upgrade_failure_matrix.json`, and
`scripts/verify-host-upgrade-qualification.py`. The runner checks all missing
settings and kube context before API access. Execution needs an exact disposable
cluster/node/UID confirmation and a lab-only enabled executor. `--execute`
creates a new operation; observation must use `--observe-evidence` instead.

No cloud resource or customer production target may be used implicitly. Restore
the reviewed disposable baseline between independent cases and preserve the
same operation/checkpoint/journal during restart/recovery cases.

Ubuntu 24.04 is supplemental only. The M3 canonical Linux platform evidence must separately cover Debian 13 Trixie at the latest stable point release current when provisioned and RHEL 9.8 or later (prefer the latest verified RHEL 9 minor). Derivatives such as AlmaLinux and Rocky Linux do not satisfy RHEL evidence. Fedora and other distributions remain outside this qualification target.
SUSE/APK/Pacman/image and additional Kubernetes adapters remain Unsupported.
Driver registration, ID_LIKE, package-manager presence and a successful test on
another distribution never qualify a target.

Each evidence record must bind actual OS release/image, architecture, Kubernetes
distribution/version, driver/catalog and EE artifacts, plan digest, node UID,
machine/boot identities, actor and independent approval, phase/request events,
receipts, workloads, cordon owner and reservation. Archive evidence off-cluster
with SHA-256 manifests and independently retained immutable references.

## Current verification boundary

Unit/race tests cover discovery ambiguity, registry isolation and fail-closed
selection. Controller tests and local API-server envtest exercise checkpoints,
recovery, cancellation and kured ownership. PostgreSQL tests exercise approval,
tenant isolation, durable scheduling and reservations. These environments do
not execute real package transactions or host reboots. See the
[verification report](KORDEX-PRODUCTION-READINESS.md) for actual commands.

The final 10-cluster/500-node customer workflow, restart/partition matrix and
measured multi-tool comparison remain NOT RUN. A fenced RecoveryRequired result
proves preservation of uncertainty, not a successful rollback or recovery.
