# M3 KIQT lab trust onboarding

This procedure configures the isolated, disposable M3 qualification trust
boundary (KIQT). It does not configure customer production trust, change any
trust loader, or make evidence accepted. M3 remains NOT COMPLETE until all 22
real-host results are independently accepted.

## What the current code supports

The artifact lock signer in `api/cmd/kordex-artifact-lock` accepts an existing
Ed25519 seed file encoded as unpadded Base64. It checks that the file is a
regular non-symlink with no group/world permissions and is stable while read.
Evidence detached signatures use OpenSSL Ed25519 PEM keys with `pkeyutl`.
Keep these role keys and formats separate. There is no KMS/HSM signing adapter
in this repository. Do not export a protected key to add one.

An isolated signing workstation or short-lived, access-controlled signing
runner can support this file interface if the security custodian approves the
key custody, mount, host hardening, audit logging, and artifact transfer
controls before use. The key file is mounted only for the signing step; the
signer receives canonical records and returns detached signatures. It must
not have cloud credentials, host credentials, or write access to the evidence
source. The signing identity is separate from the reviewer and corroborator.
No key or signature is created by this onboarding procedure.

This file-key capability does **not** close the end-to-end trust blocker.
Production trust loading now uses the durable monotonic trust-state integration
in `scripts/m3_trust_state.py`, selected through the single installed customer
adapter entry point pinned by distribution name and version in the root-signed
trust document. No customer adapter or trust configuration is present in this
checkout, so production trust remains blocked. Evidence acceptance also
requires the separately configured customer replay registry and its
independent conformance approval. Do not use a local file as rollback or
replay protection, and do not treat unit-test adapters as KIQT trust.

## Required designations and separation

| Responsibility | Current designation | Required boundary |
|---|---|---|
| Project owner | `kphan25@gmail.com` (already verified) | Approves project resource, spend, and lab-run decisions. This identity does not approve its own evidence. |
| Security custodian | **Not designated** | Owns KIQT trust root, protected signing workstation, trust bundle, key inventory, rotation/revocation, and audit records. |
| Lab artifact signer | **Not designated** | Signs only approved lab artifact digests with the existing Ed25519 file-key interface. Identity/key must be pinned in the artifact trust bundle and distinct from reviewer. |
| M3 release-lock verifier | **Not designated** | Runs pinned cryptographic pre-sign verification and signs the canonical manifest; root-authorized identity, fingerprint, and source commit are required. Distinct from lock signer and reviewer. |
| M3 release-lock signer | **Not designated** | Signs only the preverified six-image lock using the separate PEM/OpenSSL contract; root-authorized fingerprint and immutable signer/verifier source commits are required. |
| Evidence collector | **Not designated** | Signs the canonical evidence manifest. It cannot corroborate or accept its own collection. |
| Host corroborator | **Not designated** | Independently compares every evidence row with cloud, host, Kubernetes, and operation records; distinct key from collector and reviewer. |
| Independent reviewer | **Not designated** | Reviews the entire evidence/corroboration set and signs accept/reject; distinct from collector, every corroborator, and the replay-registry identity. |
| Protected signing process | **Not approved** | Security custodian documents workstation/runner identity, access control, file mount, audit source, transfer path, and key removal/rotation. |
| Evidence custodian | **Not designated** | Controls the immutable archive destination below and grants reviewers read-only access. |

Do not fill these roles with guessed names, shared accounts, Kordex developers,
or generated fixture identities. The project owner is already known; the
remaining identity designations are the external inputs still required.

## Onboarding sequence

1. The project owner records the lab-only project/run authorization and the
   `$300` spending ceiling. This approval does not authorize applying a plan
   or running host faults unless it says so separately.
2. The security custodian names the artifact signer, release-lock verifier,
   release-lock signer, collector, corroborator, reviewer, and evidence
   custodian, and records their distinct identities and Ed25519 public-key
   fingerprints in the approved lab trust inventory.
   The existing role schema in `scripts/m3_customer_trust.py` must be used.
   Release-lock verification and signing use separate root-signed
   `releaseLockVerification` and `releaseLockSigning` bindings. Neither role
   grants artifact-review authority. Artifact owners designate
   release/artifact accountability and cannot sign independent review of
   their own preflight report.
3. The security custodian documents and approves the isolated signing process.
   Verify its existing key file without reading or printing the key value:

   ```sh
   test -f "$KORDEX_M3_SIGNING_KEY_FILE"
   test ! -L "$KORDEX_M3_SIGNING_KEY_FILE"
   key_mode=$(stat -c '%a' -- "$KORDEX_M3_SIGNING_KEY_FILE")
   [[ "$key_mode" =~ ^[0-7]+$ ]]
   (( (8#$key_mode & 077) == 0 ))
   openssl pkey -in "$KORDEX_M3_SIGNING_KEY_FILE" -pubout -out /secure/kiqt/signer.pub
   openssl pkey -pubin -in /secure/kiqt/signer.pub -text -noout
   ```

   `KORDEX_M3_SIGNING_KEY_FILE` names a pre-existing, custodian-approved
   Ed25519 key file; it does not contain key material. Use the artifact
   signer's Base64 seed format for artifact locks and a separately trusted PEM
   key for evidence signatures. Stop if the key is not already approved, if
   the selected tool rejects the format, or if mode/ownership cannot be
   verified. Never generate a replacement key as a preflight workaround.
4. The custodian separately distributes the KIQT public root and signed trust
   configuration to the isolated lab verifier and signing workstation through
   the approved
   out-of-band channel. The signed configuration binds exact identities,
   roles, fingerprints, validity, revocation, and the approved replay/trust
   state services. The public root must not arrive through the artifact
   mirror or the signing workstation's unauthenticated output channel.
5. Each release owner supplies the actual artifact bytes, source/acquisition
   record, repository or mirror destination, architecture, digest, and approval
   reference. The signer signs only after the artifact digest and source have
   been independently reviewed. For the K3s artifact lock, use the existing
   command documented in
   [`m3-customer-artifact-approval.md`](m3-customer-artifact-approval.md);
   for the air-gap system-image archive, use
   [`m3-k3s-system-image-staging.md`](m3-k3s-system-image-staging.md). Those
   commands refuse overwrite and do not generate keys. No approved package,
   kernel, image, or container artifact may be substituted with a fixture.
6. The custodian creates a signed trust configuration and installs only the
   approved public material into the isolated lab verification environment.
   Record configuration digest, public-root fingerprint, signer identity,
   approval reference, validity, audit event, and installation result. Keep
   KIQT state and artifacts separate from production/customer trust. Do not
   install into `/etc/kordex/m3/` until the production trust-state and replay
   controls have their own independent approvals.
7. Before any scenario, the collector creates a unique run with
   `verify-m3-evidence-provenance.py new-run`; the customer replay registry
   must durably reserve it. After collection, the collector prepares and
   signs the canonical manifest. A distinct corroborator signs the
   host-origin record for each scenario/platform pair. A distinct reviewer
   compares all 22 rows, including the canonical matrix, exact OS release and
   image identity, host machine ID, cluster and Node identity, operation ID,
   package/artifact digests, fault record, and recovery evidence. The reviewer
   signs `accepted` only if all 22 pass; the durable registry must then return
   a fresh `newly-accepted` receipt. Any missing, duplicate, stale, replayed,
   fixture, or conflicting row is rejected.

The verifier does not provide a signing subcommand. For an approved canonical
record, the protected signing service may invoke the existing OpenSSL Ed25519
file-key interface without exposing the key bytes:

```sh
openssl pkeyutl -sign -rawin \
  -inkey "$KORDEX_M3_SIGNING_KEY_FILE" \
  -in /secure/kiqt/approved-record.json \
  -out /secure/kiqt/approved-record.json.sig
```

The caller must verify the resulting signature using the independently
distributed public key and retain the signer audit event. This command is a
signing interface example, not approval to sign the current absent records.

## Offline M3 release-lock signing ceremony

This is a separate signing purpose from the K3s artifact-lock seed, KIQT root,
host-evidence signer, and independent reviewer key. Never reuse their private
keys.

The release lock uses an OpenSSL Ed25519 PEM private key and an Ed25519 PEM
public key. The offline signer signs the exact bytes of `kordex-images.tsv` using
`openssl pkeyutl -sign -rawin`; the lock contains exactly six UTF-8 TSV rows
(`component<TAB>immutable-image-reference`) and a final newline. It derives
the public key from the private key, compares the DER SubjectPublicKeyInfo
bytes and independently approved SHA-256 fingerprint, then verifies the
signature with `scripts/verify-image-lock.sh`. The private file must be a
non-symlink regular file outside the checkout, owned by the signing process,
with mode `0600` or stricter. The public-key fingerprint is SHA-256 over the
Ed25519 SubjectPublicKeyInfo DER encoding. Public trust material and its
independently verified fingerprint must be delivered separately from the
release artifact.

The existing `api/cmd/kordex-artifact-lock` format is different: it consumes
an Ed25519 seed encoded as unpadded Base64 for K3s artifact approvals. The
image-lock signer must not consume that seed format. The independent artifact
review uses the root-authorized KIQT trust configuration and requires a
reviewer identity distinct from image/build owners and attestation signers.
The image-lock public key is independently fingerprinted in the artifact
preflight configuration; the reviewer later checks that signer identity and
signs a separate review record. A successful lock signature is not reviewer
acceptance.

The root-signed KIQT schema now supports a dedicated `release-lock-signer`
role and `releaseLockSigning` binding. It binds one signer identity and
Ed25519 SPKI-DER SHA-256 fingerprint to immutable, separately approved
`signerSourceCommit` and `verifierSourceCommit` revisions. The key must not
also be designated as artifact owner/signer, security custodian, or reviewer.
This role is distinct from artifact-review authorization. Validation rejects
missing, duplicate, or mismatched signer designations, expired or revoked
identities, and role conflicts. No real designation, trust configuration,
fingerprint, key, or signature is present in this repository.

The root-signed `releaseLockVerification` binding separately names the
`release-lock-verifier`, its Ed25519 public-key fingerprint, and immutable
verification `sourceCommit`. The signing policy's `verifierSourceCommit` must
equal that revision. The verifier signs the canonical verification manifest;
the lock signer verifies that detached signature before accessing its own key.
Both roles are required together and cannot share identities or fingerprints
with each other, artifact owner/signer, security custodian, or independent
reviewer. The trust loader still requires its separately approved durable
monotonic-state verifier before either designation can be used.

### Current workflow boundary

The hosted release job now packages evidence only. It has read-only artifact
and repository permissions, does not check out candidate source, does not
receive signing credentials, and emits no lock or signature. Build jobs may
use GitHub OIDC for image attestations; that capability is not the KIQT
release-lock key. Static workflow tests do not establish runtime runner or
repository settings.

Before enabling signing, the release owner and security custodian must approve
one of these boundaries:

| Option | Key exposure and isolation | Existing verifier fit | Decision |
|---|---|---|---|
| Dedicated isolated signing workstation | The key stays on a controlled host; an operator transfers only the exact lock bytes and verification manifest and receives the signature and receipt. No GitHub job sees the key. | Direct fit for the existing PEM/OpenSSL interface. | Selected first-release design; workstation, identities, key custody, and audit remain unconfigured. |
| Dedicated ephemeral signing runner | A one-job runner mounts the key for the signer process only, has no cloud/host credentials, and is inaccessible to PR jobs. The runner is destroyed after the job and forwards its audit logs to protected storage. | Direct fit for the existing PEM/OpenSSL interface. | Viable only after the workflow stops executing release-tag-controlled code while the key is present. Use a separately pinned signer implementation, verify the six input sets before key access, and configure protected runner-group and environment rules. GitHub recommends ephemeral runners for autoscaling and warns that persistent self-hosted runners can be compromised by untrusted workflows. |
| Isolated signing service | The service accepts a canonical lock plus independently verified evidence, authorizes a named caller, signs internally, and returns only the signature and audit reference. | Direct fit if the service emits a raw Ed25519 signature over the exact lock bytes. | Strong separation from build jobs; requires an approved service identity, API contract, authorization policy, audit retention, and a verifier integration/test. No such service is identified here. |
| HSM/KMS-backed signer | Non-exportable key; service identity is authorized for signing and audit logs record each operation. | Cloud KMS documents `EC_SIGN_ED25519`, but current code requires a local PEM key file. Adapting it needs a signer-provider interface while retaining the same public-key fingerprint and raw signature verification. | Technically possible, not implemented or authorized. It would require a separately approved service identity, narrowly scoped signing permission, key location/algorithm and protection-level approval, audit policy, and GCP authorization. Do not export the key to preserve file compatibility. |

The first release uses a dedicated offline signing workstation, separate from
the verifier identity. The verifier emits a canonical lock candidate and
verification manifest only after running the existing Sigstore
SBOM/provenance and repository metadata cryptographic verifiers, then signs
the exact canonical manifest with its separately authorized key. The signing
command consumes only the candidate, manifest, and detached verifier
signature; it verifies the signature and does not execute candidate release
code or inspect the release package. It
requires the workstation checkout to be clean and exactly match the
root-authorized signer source commit, checks the manifest's verifier commit,
validates all digest bindings, signs the exact lock bytes, verifies the
signature, and writes a digest-bound receipt. The private key is opened from an
absolute, non-symlink path outside the checkout with strict file ownership,
single-link, and mode checks, then passed to OpenSSL through an inherited file
descriptor. This code has not been exercised with real trust configuration or
a key. A durable trust-state rollback verifier is not yet integrated, so
production trust loading still fails closed.

### Required owner handoff and runtime evidence

The security custodian must designate the release verifier, release signer,
and independent reviewer by distinct, verifiable identities; approve each
key-custody and revocation/rotation process; and deliver the public PEM keys
and their SPKI-DER SHA-256 fingerprints through separate trusted channels.
The root-signed KIQT configuration must authorize the exact identities,
fingerprints, and immutable verifier/signer commits. Do not send private keys
through chat, email, repository files, GitHub variables/secrets, or ordinary
workflow artifacts. The verifier and signer owners must provide protected
runtime identities, key owner/mode evidence, audit-log destinations, and key
removal procedures. The reviewer must independently verify both identities,
the exact lock and manifest digests, release verification results, and signing
audit record, then return a separately signed review record. Neither verifier
nor signer may review its own work.

Before production release use, retain a runtime test report containing the
protected runner/service identity, signer authorization decision, canonical
lock SHA-256, signature-verification result, public-key fingerprint, audit
event reference, and proof that no private material entered logs or artifacts.
The report itself is not an M3 qualification row. No keys or signatures are
created by this procedure.

## Independent evidence archive and custody

Required archive URI template:

```text
gs://<customer-approved-immutable-evidence-bucket>/kordex/m3/<run-id>/<os-family>/
```

The bucket must be controlled by the customer evidence custodian, separate
from the lab project and signer account, with a locked retention policy
approved for the customer's required retention period. The collector has
create-only access; it cannot overwrite or delete. The reviewer has read-only
access. Retention-policy administration is restricted to a separate custody
administrator. Record bucket identity, locked retention duration, object
generation IDs, upload audit event, manifest/signature hashes, and a second
independent read-back hash check. Do not claim immutability from a local
checksum manifest, local file permissions, or an unlocked bucket policy.

`python3 scripts/self_managed_lab.py archive` creates a local tar archive,
SHA-256 file, and file manifest only. It does not upload, lock, or independently
preserve the archive. It is a staging/checksum utility and cannot satisfy the
archive acceptance criterion by itself. No destination bucket is designated
in the repository.

## Exact remaining external designations

- Name the security custodian, artifact signer, collector, host corroborator,
  independent reviewer, and evidence custodian; provide distinct identities
  and independently verifiable public-key fingerprints.
- Approve the protected Ed25519 file-key signing process and key inventory.
- Provide the approved public root/trust bundle and artifact digest-approval
  records through the independent custody channel.
- Provide independently reviewed replay-registry and monotonic trust-state
  implementations/reports required by the production verifier.
- Designate the immutable evidence bucket and locked retention/custody policy.
- Supply and independently review the actual Debian/RHEL artifact inputs and
  exact approved image records.

Until those dependencies exist, no production trust bundle can be installed,
no evidence can be signed as accepted, and KIQT remains blocked. This process
does not alter the 22-scenario M3 scope.
