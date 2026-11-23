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
