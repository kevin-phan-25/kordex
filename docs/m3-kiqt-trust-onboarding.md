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
Production trust loading fails closed without the integrated durable monotonic
trust-state verifier (`scripts/m3_customer_trust.py`). Evidence acceptance
also requires the separately configured customer replay registry and its
independent conformance approval. Do not use a local file as rollback or
replay protection, and do not treat unit-test adapters as KIQT trust.

## Required designations and separation

| Responsibility | Current designation | Required boundary |
|---|---|---|
| Project owner | `kphan25@gmail.com` (already verified) | Approves project resource, spend, and lab-run decisions. This identity does not approve its own evidence. |
| Security custodian | **Not designated** | Owns KIQT trust root, protected signing workstation, trust bundle, key inventory, rotation/revocation, and audit records. |
| Lab artifact signer | **Not designated** | Signs only approved lab artifact digests with the existing Ed25519 file-key interface. Identity/key must be pinned in the artifact trust bundle and distinct from reviewer. |
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
2. The security custodian names the artifact signer, collector, corroborator,
   reviewer, and evidence custodian, and records their distinct identity and
   Ed25519 public-key fingerprints in the approved customer trust inventory.
   The existing role schema in `scripts/m3_customer_trust.py` must be used;
   it permits `collector`, `reviewer`, `corroborator`, `image-approver`,
   `artifact-owner`, `replay-registry`, and trust-state roles. Do not add an
   unrecognized role. Artifact owners designate release/artifact
   accountability; they cannot sign the independent review of their own
   preflight report.
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
   configuration to the isolated lab signer/verifier through the approved
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
