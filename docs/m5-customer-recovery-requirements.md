# M5 customer recovery and security inputs

Repository-local backup, restore, audit-chain, and recovery tests demonstrate
implementation behavior only. They do not select customer policy or qualify
production recovery, retention, availability, or key custody. The customer
service owner and security/operations owners must supply and approve the
following before M5's external acceptance evidence can be evaluated.

## Customer decisions and evidence

| Requirement | Owner | Required input/evidence | Acceptance evidence |
|---|---|---|---|
| Backup and audit retention | Service/data owner | Approved retention duration, deletion/hold rules, data classes, jurisdiction, and restore-access policy | Policy record plus evidence that backup and signed audit exports are encrypted, immutable/WORM, independently administered, access-logged, and retained/deleted according to the approved policy |
| External checkpoint custody | Security/audit owner | Independent system of record, authorized custodians, checkpoint publication and comparison procedure | A checkpoint/high-water value held outside the application database and export path, with a reproducible comparison against signed audit exports |
| Signing-key custody | Security/key-management owner | Approved KMS/HSM or equivalent custody service, key roles, access policy, backup and break-glass procedure | Key identity, custody and access audit evidence; proof application cannot export private key material; recovery exercise |
| Key rotation and recovery | Security/key-management owner | Rotation overlap, revocation, recovery, emergency replacement and destruction policy | Reviewed rotation/revocation drill with old/new key identities, signatures, trust distribution, recovery outcome and audit records |
| HA/failover | Platform operations | Supported database and application topology, dependency failure behavior, failover runbook and test boundary | Independent failure/failover exercise recording component identities, outage, recovery steps, data integrity, and service health |
| RPO objective | Service owner | Approved numeric RPO and the authoritative transaction watermark to measure | Recovery drill binds source and recovered watermarks and computes a gap only when both are comparable; acceptance against the approved objective |
| RTO objective | Service owner | Approved numeric RTO and start/end event definitions | Independent timed recovery drill using the approved boundaries and comparing measured duration to the objective |
| Recovery/security review | Independent security or operations reviewer | Reviewer identity and independence, review scope, evidence custody location, checklist, findings severity policy | Signed review bound to exact software/configuration and recovery evidence, with findings and retest disposition |

Kordex does not choose a retention period, deletion schedule, RPO, RTO, HA
topology, or key-management policy. If any such policy is absent, the dependent
production acceptance item remains blocked. A local duration measurement must
not be described as a service RTO. A recovery-point difference is valid only
when source and restored durable transaction watermarks share the same
monotonic domain and the comparison boundary is recorded.

## Evidence package format

For each approved customer recovery drill, preserve a signed, access-controlled
package that includes:

- Customer environment and database identities, software revision, and
  configuration digest.
- Backup identity, creation time, byte size, format, SHA-256, and signed or
  independently protected manifest.
- Source transaction watermark at backup and at the declared recovery
  measurement boundary; recovered watermark and the method proving their
  comparability.
- Source and restore target identities, isolation evidence, PostgreSQL and
  migration versions, and every migration checksum.
- Restore start/end event definitions, UTC timestamps, monotonic elapsed time,
  command/result records, and operator identity.
- Application-level integrity checks and expected/observed results, including
  audit-chain and external-checkpoint verification where applicable.
- Failure/interruption results, recovery actions, final PASS/FAIL, and an
  independent reviewer decision bound to the package digest.

Do not include passwords, private keys, access tokens, or secret values in the
package. Keep the manifest and evidence in customer-controlled custody separate
from the database and backup operator.

## Machine-verifiability in this checkout

The repository does not define a universal M5 attestation schema. That is
intentional: customer retention law, key custody, HA design, and service
objectives are policy inputs, and selecting their fields, signer authority, or
expiry rules here would invent acceptance criteria. The following is the
current verifier boundary; missing contracts require customer policy plus
independent security/operations approval before a validator can be added.

| Evidence | Format and signer/identity | Time, digest, and reference binding | Existing verification and acceptance limit |
|---|---|---|---|
| Approved retention/deletion policy | No repository schema or signer role is defined. Customer must provide its approved policy record and name its policy authority. | No expiry rule is defined. The policy's customer-controlled version/reference and digest must be identified by the customer. | No Kordex verifier. Acceptance requires a customer-approved policy and independent confirmation that configured retention/deletion behavior matches it. |
| Immutable backup/audit destination | No object-lock or destination-attestation format is defined. Destination operator identity and independent owner must be customer-selected. | Provider object-lock mode, retention-until metadata, object version, audit log interval, and package digest need a customer-defined report format and freshness rule. | `backup-postgres.sh` verifies local archive readability and SHA-256 sidecars; it does not prove remote immutability. `kordex-audit-verify` verifies signed content, not destination controls. The M6 deployment helper accepts a narrow customer-signed backup/restore assertion pinned by public-key SHA-256, bound to target ID and current timestamps; this is not a WORM verifier. |
| External checkpoint custody | Audit exports use the existing signed checkpoint manifest and independent Ed25519 trust bundle. The signing key ID must resolve in that separately distributed bundle; the external high-water custodian is customer-selected. | The manifest binds creation time, checkpoint/high-water ID, record count, and export digest. Existing format has no expiry; the externally held high-water value must be independently referenced and preserved. | Verify content with `kordex-audit-verify -bundle -input EXPORT -trust-bundle TRUST_BUNDLE -through-id EXTERNAL_HIGH_WATER_ID` (or `-input EXPORT --checkpoint MANIFEST ...` for the CLI archive form). This verifies the export/checkpoint relation; it does not prove which external system held the checkpoint or its custody history. |
| KMS/HSM custody | No provider-neutral evidence schema, signer role, or KMS/HSM adapter exists. Customer key-management authority and service identity must be named. | Key/version identifiers, access-log range, exportability policy, backup state, and evidence digest need customer-defined freshness and retention rules. | No Kordex verifier. Acceptance requires the approved provider controls, access/key audit evidence, and independent review; a file-key signature is not evidence of KMS/HSM custody. |
| Key rotation/recovery drill | Audit exports and trust bundles can identify Ed25519 keys; no signed rotation-event schema exists. Customer key custodian and independent reviewer must be distinct identities. | Customer must define effective/overlap/revocation times, key IDs, evidence expiry, old-key retention, and package digest binding. | `kordex-audit-verify` can verify a signature when its key ID is in the supplied trusted bundle; it does not establish rotation ordering, custody, revocation timing, or recovery. No rotation/recovery acceptance validator exists. |
| HA/failover exercise | No standard machine-readable M5 failover record exists. The service operator supplies system identities and the independent reviewer supplies the acceptance decision. | Failure, detection, failover, recovery, and observation boundaries plus the evidence digest must be captured; no freshness window is defined. | No Kordex verifier or production HA harness. Acceptance requires the customer-approved failure plan, data-integrity checks, service health evidence, and independent review. |
| RPO/RTO objectives | No objective schema or customer signature role is defined. Service owner approves the numeric objectives; the independent operations reviewer accepts measurements. | Customer must define transaction watermark domain, start/end events, objective version, expiry/change policy, and signed measurement digest. | The local recovery script emits transaction IDs/times and monotonic restore duration. It is not a production verifier and cannot compare results to customer objectives. No RPO/RTO acceptance validator exists. |
| Independent security/operations review | No general M5 review schema exists. Reviewer identity must be customer-authorized and distinct from the operator and evidence producer. | Review must identify exact evidence/configuration digests, review time, findings, and retest dispositions. Expiry/review period is not defined by repository policy. | M3 trust code verifies a specific signed trust-state conformance review; it is not a general M5 review verifier. No general M5 review acceptance command exists. |

The only machine-verifiable evidence path already available for these areas is
the narrow audit export verifier and the M6 backup/restore preflight check. A
future validator must be based on customer-approved schemas for the remaining
rows, use separately provisioned signer identities, enforce customer-approved
time/freshness rules, and bind exact evidence digests. Until those contracts
exist, those rows remain `NOT VERIFIED`; unsigned statements, local drill
reports, and structurally valid manifest references do not pass them.
