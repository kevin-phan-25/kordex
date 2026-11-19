# Kordex Fleet Platform implementation roadmap

These are delivery workstreams, not a reset of existing release versions or
promises of release dates. Branding remains configurable through
`KORDEX_PRODUCT_NAME` / Helm `productName`; sites can use `Kordex Fleet Platform`.
Capability and qualification decisions remain authoritative in
[production upgrade requirements](production-upgrade-requirements.md).

## Release 0.1 — safe maintenance foundation

| Work | Implementation / evidence | Remaining acceptance work |
|---|---|---|
| Repository audit and baseline | [Assessment](hardening-assessment.md); five Go modules, frontend, CI and database checks | Independent security review and deployment drills |
| Typed Linux discovery | [Parser and tests](../api/lifecycle/discovery.go), bounded filesystem discovery and exclusive os-release fallback | Connect driver-specific host probes to retained, identity-bound remote receipts |
| Driver compatibility | Immutable registry, explicit OS/version/architecture/package-manager matches, kind-specific operations and blocked execution | Qualification-backed registration/activation and integration with signed execution plans |
| Kubernetes inventory | Agent sends versioned advisory distribution/provider/role/pool hints; existing JSON inventory persists them | Native API discovery for definitive kubeadm/MicroK8s/OpenShift/etc. topology; bare-metal and non-Kubernetes inventory |
| Existing APT/DNF catalogs | Preserve fixed signed Ansible EE package/reboot paths and their offline checks | First real Ubuntu 24.04 matrix; each additional OS/architecture qualified separately |
| Campaigns and safety | Existing independent approvals, PostgreSQL reservations, operator safety and receipt recovery | VM interruption, cancellation, partition and recovery evidence |
| Operator visibility | Existing fleet, campaign and operation views; new read-only compatibility page/API | Measured SRE usability and complete reference workflow |
| Security regressions | [Security model](KORDEX-SECURITY-MODEL.md), proxy/stream limits, tenant checks, bootstrap isolation, OIDC party validation, and opt-in RFC 9068 API access-token contract | Provider-backed login, scope-mapping, key-rotation, and API resource-audience qualification |
| Disposable VM qualification | Existing runner, fault recorder, matrix and evidence verifier | BLOCKED: no existing disposable Ubuntu context/worker is configured; all live scenarios remain NOT RUN |

## Subsequent workstreams

| Scope | Current boundary | Exit evidence |
|---|---|---|
| 0.2 Integrated SRE workflow | Existing approvals, health summaries, operation checkpoint views and audit are reused | Patch-advisory provenance, recovery center, exports and measured end-to-end workflow |
| 0.3 Multi-distribution | Zypper/APK/Pacman/YUM/Portage/XBPS entries are explicitly Unsupported; descriptors are not executors | Fixed typed adapter implementations, transaction/recovery tests and OS-specific disposable evidence |
| 0.4 Kubernetes lifecycle | Preserve the existing gated GKE node-pool adapter; other native adapters unsupported | Native discovery, version/skew checks, ordering, workload recovery and vendor-specific qualification |
| 0.5 Infrastructure lifecycle | Image adapter contracts exist; bootc/rpm-ostree/Talos/Flatcar/Kairos execution, Redfish, provisioning and virtualization remain unsupported | Reviewed native APIs, explicit destructive authorization, identity and rollback evidence |
| 0.6 Enterprise platform | Existing scheduler, telemetry, audit chain, backup/restore scripts and offline release tooling | HA/restore, disconnected installation, measured scale, pilot validation; licensing must never prevent recovery |

No placeholder navigation or arbitrary privileged shell service is added for
these workstreams. Only implemented actions may appear as executable choices.
Unknown health remains unknown. New unqualified adapters cannot mutate nodes.

## Implementation record

Baseline commit: `ab843a3`. Current patches are uncommitted; no commit or merge
is claimed. [Production readiness](KORDEX-PRODUCTION-READINESS.md) records actual
verification and limitations. Record review/commit identities here when patches
are committed, and attach real evidence before checking qualification complete.
