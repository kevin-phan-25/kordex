# Customer-controlled K3s artifact approval

This procedure provides a customer-owned integrity approval for the exact
K3s `v1.36.6+k3s1` `linux/amd64` binary. It does **not** establish upstream
provenance. For this release, the upstream binary and adjacent checksum are
not independently authenticated; HTTPS and a checksum from the same release
host do not change that fact. A customer approval says that the customer
reviewed and accepted specific bytes under its own process.

## Trust boundary

The artifact-approval key and bundle are a separate trust domain. Do not use
or substitute Kordex maintenance-operation signing trust, Kordex release
signing trust, or offline-tool provenance trust. Kordex never creates this
production key. A customer supply-chain custodian must use an already
organization-controlled Ed25519 artifact-approval key and must not send its
private seed to the Kordex development team.
The custodian must confirm its public key ID is distinct from the IDs used by
those other trust domains; the verifier cannot discover external key
inventories on the customer's behalf.

The customer public bundle is a sorted UTF-8 text file, distributed through a
channel independent of the artifact mirror:

```text
KORDEX-CUSTOMER-ARTIFACT-TRUST-V1
<lowercase SHA-256 public-key ID> <unpadded standard-base64 Ed25519 public key>
```

Each ID is the SHA-256 of the 32 raw public-key bytes. Multiple sorted entries
support rotation overlap. The `trust-export` command derives a public bundle
from an explicitly supplied existing key file; it does not create a key and
its output is not trusted until the custodian compares the key ID with the
organization's independently maintained key inventory and distributes it
through the independent channel. Supply an existing prior bundle to preserve
old verification keys during rotation.

The private key file follows Kordex's existing Ed25519 seed format: unpadded
standard Base64 encoding of a 32-byte seed or 64-byte private key, mode 0600
or stricter, regular file, not a symlink. Do not put the value in a command
argument or environment variable. Keep it mounted/readable only in the
custodian's authorized signing environment.

## Lock and signature

The lock is fixed-order UTF-8 text (`KORDEX-CUSTOMER-ARTIFACT-LOCK-V1`) with
one field per line. Its exact bytes are Ed25519-signed with the
`kordex.customer-artifact-approval.v1` domain prefix. Fields bind:

- artifact `k3s`, exact version `v1.36.6+k3s1`, and architecture `linux/amd64`;
- digest algorithm `sha256` and the digest of the exact local binary;
- the exact upstream release binary URL as the acquisition source;
- the exact customer internal mirror HTTPS URL;
- checksum-review evidence reference, acquisition record, approval reference,
  approver identity/reference, and UTC approval timestamp; and
- the signer key ID.

The `checksum_evidence_ref` identifies customer-reviewed evidence (for
example, a controlled acquisition record). It does not claim that the
unsigned upstream checksum is authenticated. The verifier fetches no URL and
does not use a digest until the detached signature succeeds. It then checks
the binary digest, Linux ELF amd64 architecture, and reported K3s version. To
check the version it executes only a private temporary copy of the local
binary, after signature and digest validation, with `--version` and a bounded
timeout. It does not execute a URL or follow redirects.

## Custodian workflow

1. Acquire the upstream artifact using the organization's independently
   approved process. Record the exact source and acquisition evidence. The
   upstream SHA-256 manifest can be recorded as an integrity observation but
   is not upstream authentication.
2. Review and approve the binary under the organization's supply-chain
   process. Publish the exact approved bytes to the approved internal mirror
   over HTTPS. The mirror URL must not contain credentials, query parameters,
   or fragments.
3. Provision the existing customer artifact-approval signing key into the
   authorized signing environment and obtain its corresponding public
   bundle through the independent trust channel. Do not substitute the
   maintenance, Kordex release, or tool-provenance key.
4. From a reviewed Kordex checkout, with Go available, export or extend the
   public bundle and sign the lock. Use only synthetic/non-production
   references until the actual customer approval exists:

   ```sh
   cd api
   umask 077
   go run ./cmd/kordex-artifact-lock trust-export \
     --private-key-file /custodian/secret-mount/k3s-artifact-approval.seed \
     --trust-out /custodian/staging/k3s-artifact-approval.trust

   # For rotation, also pass the prior bundle to preserve overlap:
   # --prior-trust-bundle /custodian/trust/k3s-artifact-approval.trust

   go run ./cmd/kordex-artifact-lock sign \
     --binary /custodian/incoming/k3s \
     --private-key-file /custodian/secret-mount/k3s-artifact-approval.seed \
     --trust-bundle /custodian/trusted/k3s-artifact-approval.trust \
     --mirror-url https://mirror.example.invalid/k3s/v1.36.6%2Bk3s1/linux-amd64/k3s \
     --checksum-evidence-ref CUSTOMER_EVIDENCE_REFERENCE \
     --acquisition-ref CUSTOMER_ACQUISITION_REFERENCE \
     --approval-ref CUSTOMER_APPROVAL_REFERENCE \
     --approved-by CUSTOMER_APPROVER_REFERENCE \
     --approved-at 2026-11-20T12:00:00Z \
     --lock-out /custodian/staging/k3s.artifact-lock \
     --signature-out /custodian/staging/k3s.artifact-lock.sig
   ```

   `trust-export` and `sign` refuse to overwrite output files. `sign` checks
   that its existing private key corresponds to a key in the independently
   supplied trust bundle. Compare the exported ID with the custodian's
   independently maintained key inventory and deliver the public bundle
   outside the mirror before using it as trust. It does not generate keys or
   print key material.
5. Deliver the binary and lock/signature to the internal mirror. Deliver the
   public trust bundle through the independent channel. Preserve the source
   review, acquisition, and approval records outside the mirror.
6. From a clean verification workstation, copy the binary from the mirror
   using the customer's approved transfer method and verify it offline:

   ```sh
   cd api
   go run ./cmd/kordex-artifact-lock verify \
     --binary /verified-transfer/k3s \
     --lock /verified-transfer/k3s.artifact-lock \
     --signature /verified-transfer/k3s.artifact-lock.sig \
     --trust-bundle /independent-trust/k3s-artifact-approval.trust
   ```

   The output identifies the signed digest, signer ID, and mirror URL. The
   command makes no network requests. Verify the downloaded-from-mirror copy,
   not only the incoming source copy.
7. Retain old public keys and trust entries while any approved artifact or
   qualification record signed by those keys needs verification. For key
   rotation, publish a new trust bundle containing both old and new public
   keys through the independent channel before signing with the new key.
   Remove an old entry only under the custodian's documented retention and
   revocation policy; a revoked signing key must not be accepted for new
   approvals.

## Lab handoff

The self-managed lab requires signed approval for both the standalone K3s
binary and the K3s system-image archive. The system-image lock uses this same
customer artifact trust bundle with a separate signature domain. Follow
[`m3-k3s-system-image-staging.md`](m3-k3s-system-image-staging.md) to approve,
verify, and stage the exact eight-image `v1.36.6+k3s1` OCI archive before using
the guarded helper. Supply both local archives/locks/signatures and the
independently delivered public trust bundle:

```sh
python3 scripts/self_managed_lab.py plan --project-id CUSTOMER_DISPOSABLE_PROJECT \
  --k3s-binary /verified-transfer/k3s \
  --k3s-artifact-lock /verified-transfer/k3s.artifact-lock \
  --k3s-artifact-signature /verified-transfer/k3s.artifact-lock.sig \
  --k3s-artifact-trust /independent-trust/k3s-artifact-approval.trust \
  --k3s-system-images-bundle /verified-transfer/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /verified-transfer/k3s-system-images.lock \
  --k3s-system-images-signature /verified-transfer/k3s-system-images.lock.sig \
  --k3s-system-images-trust /independent-trust/k3s-artifact-approval.trust
```

The helper verifies both customer signatures offline and passes their exact
lock-bound values explicitly to Terraform. The binary digest and mirror URL
must match the protected `terraform.tfvars`; system-image values are supplied
from the verified lock and have no defaults. It removes Terraform CLI-argument
and variable override environment settings and rejects automatically loaded
`.auto.tfvars` files. The helper verifies private snapshots of the bundle,
lock, signature, and trust files, fingerprints the inputs before and after
verification, and rechecks them before applying. `apply` repeats preflight,
saves and displays the reviewed plan, requires project-bound confirmation, and
checks both approvals again before applying that saved plan. If inputs or
trust change, rerun verification and create a new reviewed plan.

The VM startup scripts do not parse signatures. They retrieve the exact
content-addressed bundle URL without following redirects, verify its lock-bound
digest, and install it before K3s starts. They also use the private registry
configuration generated from the signed lock and disable K3s public registry
fallback. Direct Terraform plan/apply bypasses local signature verification
and is unsupported. Terraform inputs contain public URLs, versions, hosts, and
digests only, never signing keys. The VM-side digest comparison alone is not
signature verification.

No real customer trust bundle, approved digest, signature, mirror, or approval
record is included in this repository. All tests use explicitly synthetic
keys/records and the local Go test executable as a binary fixture. They prove
the verifier logic only, not the authenticity of K3s or M3 qualification.

Upstream references reviewed: the [pinned K3s release workflow](https://github.com/k3s-io/k3s/blob/v1.36.6%2Bk3s1/.github/workflows/release.yml)
creates and uploads checksum files alongside release artifacts; the
[pinned binary build workflow](https://github.com/k3s-io/k3s/blob/v1.36.6%2Bk3s1/.github/workflows/build-k3s.yaml)
has build provenance for its container build step, but no separately verified
attestation for the standalone release binary was established. GitHub's
[attestation API](https://docs.github.com/en/rest/repos/attestations) is a
separate mechanism and is not evidence that this artifact has an attestation.
