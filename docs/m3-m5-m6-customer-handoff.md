# M3/M5/M6 customer handoff

This handoff consolidates customer-owned inputs and authorization boundaries.
It does not report customer evidence as received or any milestone as complete.

## M3: real-host qualification

The acceptance target remains 11 scenarios on Debian 13 and 11 on genuine,
entitled RHEL 9.8 or later. Each row needs real execution, identity-bound
signed evidence, replay rejection, verified baseline restoration, and a
separate independent acceptance.

| Owner | Required input or action | Format and verification | Authorizes |
|---|---|---|---|
| Customer security/trust owner | Trust root, signed trust configuration, trust-state adapter, isolated HTTPS backend and public attestor identity | Root-owned Ed25519 PEM, canonical `qualification-trust.json` plus detached signature, customer runtime adapter implementing `TrustStateTransport`; run `run_conformance` as in [adapter contract](m3-trust-state-adapter.md). A distinct reviewer signs the accepted conformance report. | Trust stage evaluation only; does not authorize any GCP mutation or scenario. |
| Customer security/platform owner | Durable replay-registry service | Customer-operated isolated endpoint; run the existing replay-registry conformance contract, then obtain separate reviewer acceptance. | Replay-protection input evaluation only. |
| Debian image/package owners | Current approved Debian 13 image identity, Trixie/security repository metadata, exact signed package artifacts and approved package policy | Signed image approval binds project/image self-link, immutable image ID, exact Debian point release and architecture. Package policy binds exact names/versions/architecture/digests and expected kernel/reboot result. Validate with the M3 artifact preflight and image approval verifier documented in [platform handoff](m3-platform-qualification-handoff.md). | Debian artifact/image preflight only. |
| Red Hat subscription/image/package owners | Genuine RHEL 9.8+ image, active entitlement, exact signed RPM metadata/artifacts and approved package policy | Red Hat-supported image identity and immutable ID, non-secret entitlement status, signed private repository metadata, exact RPM NEVRA/architecture/SHA-256. Use the RHEL artifact preflight documented in [deployment readiness](m3-deployment-readiness.md). Derivatives do not qualify. | RHEL artifact/image preflight only. |
| Release/supply-chain owner | K3s binary and system-image locks; Kordex image lock; private registry content | Signed digest-bound locks plus detached signatures and independently delivered trust; verify with the existing `kordex-artifact-lock`, image-lock, and private-registry verification commands in [deployment readiness](m3-deployment-readiness.md). | Artifact preflight and reviewed Terraform inputs only. |
| Lab/project owner | Project ownership/isolation, required IAM identities, private network/routes/DNS, IAP/OS Login/recovery, quota and billing evidence | Live project review and current inventory; customer-controlled project-specific evidence. Budget must cover all 90 days under $300, with actual headroom and RHEL stopped-instance billing treatment confirmed. | Project review is read-only; separate plan/apply approvals remain required. |
| Connectivity/security owner | Private route, DNS, relay identity, PKI, firewall and recovery path | Customer-signed configuration/evidence with endpoint and certificate identities; exact acceptance details follow the existing connectivity verifier. | Connectivity test only. |
| Qualification operator | Customer manifest, host inventory, evidence custody and per-row run authorization | Manifest follows `docs/schemas/m3-customer-inputs-v1.json`; references bind SHA-256 and expiry. Use `python3 scripts/m3_qualification.py inputs --manifest PATH` and `status --manifest PATH`, then the existing preflight/execute/verifier workflow. Manifest intake alone is not trust verification. | One approved preflight or one scenario/OS operation, as separately authorized. |
| Independent reviewer | Review every exact evidence package and baseline restoration | Customer-authorized identity distinct from collector/operator; signed row-bound acceptance stored in customer evidence custody. | Acceptance of that row only. |

The trust adapter's Python protocol exists, but there is no repository package
installer, package signer, or package digest field. The customer must bind its
adapter source/runtime artifact through its approved supply-chain process; a
local import or synthetic adapter cannot satisfy M3.

## M5: recovery, retention, and operations

The repository has local backup/restore, audit-export, and recovery tests. The
local PostgreSQL interruption result is not production evidence. Customer
policy, immutable custody, key management, HA, approved objectives, and
independent review remain required. Details and current verifier limits are in
[M5 recovery requirements](m5-customer-recovery-requirements.md).

The service/data owner must approve retention and deletion rules; platform
operations must provide immutable backup/audit destination and failover
evidence; security/key-management must provide external checkpoint custody,
KMS/HSM custody, and rotation/recovery evidence; the service owner must approve
numeric RPO/RTO and measurement boundaries; and a distinct independent
security/operations reviewer must accept the evidence. For several of these
items the repository has no schema or verifier. The customer and reviewer must
approve those contracts before repository validation can be implemented; no
retention period, objective, key policy, or pass result is inferred here.

## M6: customer control-plane deployment

The platform owner supplies an identified customer Kubernetes target and
namespace, database TLS service and separate migration/runtime credentials,
OIDC issuer/audience, ingress TLS/CA, protected Helm values and Secrets,
capacity, and fresh signed backup/restore evidence. The operator trust bundle
for maintenance signing keys must be distributed independently. The strict
manifest requires `trust.operatorPublicKeysFile` and
`trust.operatorPublicKeysSha256`; the operator also supplies the same digest
through `--maintenance-trust-sha256`, obtained through a separately approved
channel. The existing deployment preflight derives the public key from the
Kubernetes maintenance Secret in a protected temporary directory, validates
the complete JSON bundle, and requires the derived key ID to appear in the
bundle whose exact digest matches both bindings. It reports only the digest
and public key ID. The customer security owner must approve the signer and
bundle independently; matching bytes do not confer that approval.

The bundle format is the public JSON emitted by `kordex-trust-export`, mapping
SHA-256 key IDs to unpadded base64 Ed25519 public keys. If needed, the customer
can produce it from the protected source key without printing the private key:

```sh
go run ./api/cmd/kordex-trust-export \
  -private-file /protected/customer/maintenance-signing-key \
  -public-file /protected/customer/derived-maintenance-trust.json
```

Use protected customer paths and do not put private key material or secret
contents in shell arguments, logs, or Git. The output path must be a new path
because the exporter refuses to overwrite. The release owner supplies the
exact signed immutable image digest, source tag/commit, Cosign signature, and
verified provenance. The customer deployment operator runs the existing
preflight and deployment path in [control-plane deployment procedure](m3-control-plane-deployment.md):

```sh
python3 scripts/control_plane_deploy.py preflight --inputs CUSTOMER_INPUTS \
  --expected-api-server APPROVED_API_SERVER \
  --expected-cluster-uid APPROVED_CLUSTER_UID \
  --backup-key-sha256 OUT_OF_BAND_BACKUP_SIGNER_SHA256 \
  --maintenance-trust-sha256 OUT_OF_BAND_OPERATOR_BUNDLE_SHA256 \
  --report PREFLIGHT_REPORT
```

Only a fully passing preflight permits the helper to request its exact
target-bound typed phrase:
`APPROVE_KORDEX_CONTROL_PLANE_DEPLOY <cluster_uid> <namespace> <release_name> <sha256:image_digest> <manifest_sha256> <helm_values_sha256> <maintenance_trust_sha256>`.
That authorizes this deployment attempt only. An interrupted attempt remains
fenced for manual reconciliation; it does not authorize retry or rollback.

## Separate M3 authorization boundaries

Each phrase is operation-specific. A phrase does not authorize a later phase.

| Operation | Required phrase | Scope |
|---|---|---|
| Project review | `APPROVE_M3_PROJECT_REVIEW kordex-fleet-platform-515416` | Read-only project review |
| Terraform plan | `APPROVE_M3_PLAN kordex-fleet-platform-515416` | Plan only |
| Terraform apply | `APPROVE_M3_APPLY kordex-fleet-platform-515416` | Separately reviewed plan only |
| Connectivity | `APPROVE_M3_CONNECTIVITY_TEST` | One live connectivity check |
| Preflight | `APPROVE_M3_PREFLIGHT` | Read-only qualification preflight |
| Scenario execution | `APPROVE_M3_EXECUTE <scenario_id> <os_id>` | One scenario on one OS |
| Fault injection | `APPROVE_M3_FAULT_INJECT <scenario_id> <os_id>` | One approved fault on one OS |
| Evidence acceptance | `APPROVE_M3_EVIDENCE_ACCEPT <scenario_id> <os_id>` | Review/acceptance of one row |
| Final signoff | `APPROVE_M3_SIGNOFF` | Final signoff after all 22 rows are independently accepted |

The GCP project review, API, plan, and apply approvals use only project
`kordex-fleet-platform-515416`. The $300 ceiling over 90 days is not evidence
of available billing credit. Actual billing headroom and RHEL stopped-instance
licensing have not been verified; paid provisioning remains blocked until both
the estimate and billing evidence support the ceiling.
