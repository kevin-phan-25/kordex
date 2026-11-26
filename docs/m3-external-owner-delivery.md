# M3 external-owner delivery instructions

M3 remains **NOT COMPLETE, 0/22 accepted**. This packet gives the owner roles,
required files, real validation commands, and delivery boundaries. The canonical
47-slot delivery ledger is [`m3-external-delivery-manifest.json`](m3-external-delivery-manifest.json);
its schema is [`m3-external-delivery-manifest-v1.json`](../schemas/m3-external-delivery-manifest-v1.json).
It derives its IDs and campaign scopes from `scripts/m3_qualification.py::INPUTS`.
All 47 slots currently read `NOT PROVIDED`. Each row names its owner role,
campaign/components, blocked gates, format and cryptographic bindings, secure
delivery location, domain validator, and approval authority. The exact payload
filename is the unique relative `reference` in the 47-slot customer input map;
its bytes and SHA-256 are bound there.

Deliver owner material outside Git under `/secure/m3`, with directories mode
`0700` and files mode `0600` or stricter. Preserve original deliveries in the
owner-controlled archive. The read-only intake command validates exact slot
coverage, unique safe relative paths, file mode, expiry, and SHA-256; it writes
a new mode-0600 report and never changes payloads or overwrites a report:

```sh
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
python3 scripts/m3_external_intake.py \
  --inputs /secure/m3/customer-inputs.json \
  --report "/secure/m3/intake-${RUN_ID}.json"
```

The intake report uses `NOT PROVIDED`, `RECEIVED`, `VERIFIED`, `APPROVED`, and
`REJECTED`. This command can emit only `NOT PROVIDED`, `RECEIVED`, or
`REJECTED`. `RECEIVED` means safe file/path/expiry and declared SHA-256 checks
passed; no signature, provenance, entitlement, identity, or approval is
implied. The exact domain validator must establish `VERIFIED`; a separate
authorized reviewer must sign the digest-bound scope for `APPROVED`. The
report records both domain verification and independent approval as `NOT RUN`,
advances zero qualification rows, and is not immutable custody evidence. The
existing controller's inventory remains available separately:

```sh
python3 scripts/m3_qualification.py inputs --manifest /secure/m3/customer-inputs.json
```

No person is designated by this packet. The
security custodian, artifact signer, six build-owner roles, image approvers,
OS repository custodians, and independent reviewers must be designated through
the lab's approved trust process. A reviewer must not be the signer or any
owner of the artifacts under review.

## A0. Trust backend owner and security custodian

The customer security custodian and backend owner deliver a canonical,
customer-root-signed adapter bootstrap at
`/secure/m3/trust-state-adapter-bootstrap.json` and its detached raw Ed25519
signature at `.sig`. The required schema is
[`m3-trust-state-conformance-bootstrap-v1.json`](../schemas/m3-trust-state-conformance-bootstrap-v1.json).
The bootstrap expires within 30 days and binds the customer ID, backend HTTPS
identity/endpoint, evidence reference, approved Kordex runner commit, adapter
distribution/version/installed-tree SHA-256, attestor public key/fingerprint,
isolated conformance-root public key, and root-signed trust-policy test
document/signature. Deliver the public qualification root out of band to the
protected path `/etc/kordex/m3/qualification-root.pub`. Do not send private
keys, passwords, tokens, service credentials, subscription keys, or registry
auth.

Install the adapter through the customer's protected runtime supply chain. It
must expose exactly one entry point named
`customer` in group `kordex.m3.trust_state.conformance`; its factory receives
only customer/backend/endpoint/evidence settings and returns exactly
`transportFactory(namespace)` and `signConformanceConfiguration(document)`.
The latter may use a test-only protected key for the isolated conformance
namespace; it must not expose or use the production root. The installed
distribution and every file must be root-owned and not group/world writable.
The runner checks the signed distribution tree digest before importing it; it
has no `PYTHONPATH`, module-path, endpoint, or transport override.

Run from a clean, immutable Kordex runner checkout whose commit equals the
root-signed `runnerSourceCommit` in the bootstrap, with the pinned adapter
installed into the protected system Python environment:

```sh
sudo /bin/sh -c '
  set -eu
  umask 077
  ROOT_KEY=/etc/kordex/m3/qualification-root.pub
  BOOTSTRAP=/secure/m3/trust-state-adapter-bootstrap.json
  BOOTSTRAP_SIG=/secure/m3/trust-state-adapter-bootstrap.json.sig
  RUNNER=/opt/kordex/m3-runner
  RUN_ID=$(/usr/bin/date -u +%Y%m%dT%H%M%SZ)
  OUT=/secure/m3/evidence/trust-state-conformance-$RUN_ID
  /usr/bin/openssl pkeyutl -verify -pubin -inkey "$ROOT_KEY" -rawin -in "$BOOTSTRAP" -sigfile "$BOOTSTRAP_SIG"
  EXPECTED=$(/usr/bin/jq -r .runnerSourceCommit "$BOOTSTRAP")
  test "$(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git --no-replace-objects -c core.fsmonitor=false -C "$RUNNER" rev-parse HEAD)" = "$EXPECTED"
  test -z "$(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null /usr/bin/git --no-replace-objects -c core.fsmonitor=false -C "$RUNNER" status --porcelain --untracked-files=all --ignored)"
  set +e
  /usr/bin/python3 -I "$RUNNER/scripts/run_m3_trust_state_conformance.py" \
    --bootstrap "$BOOTSTRAP" --signature "$BOOTSTRAP_SIG" \
    --output "$OUT.json" \
    > "$OUT.stdout" \
    2> "$OUT.stderr"
  rc=$?
  printf "%s\n" "$rc" > "$OUT.exit"
  exit "$rc"
'
```

The signature check above occurs before executing the pinned runner; the
runner repeats signature, expiry, canonical-JSON, adapter digest, and
clean-source checks.

The output directory must already be private (`0700`); the runner creates a
new report with mode `0600` and will not overwrite one. A passing runner means
the pinned adapter was exercised against a unique isolated backend namespace.
It still emits `productionTrustAccepted: false` and a pending-review candidate.
The owner must preserve full stdout/stderr, exit status, backend receipts and
audit IDs, observed sequence/digest values, restart evidence, backup/recovery
and availability evidence, adapter source/wheel digest, protected install
details, and the isolated namespace audit. All named contract cases must pass
and have supporting actual backend records; an exit code alone is insufficient.

Acceptance uses the exact test names from the report's suite hash:

| Cases | Required evidence and pass condition |
|---|---|
| `initial-empty-generation` | Signed read receipt reports sequence 0 and zero digest in the new isolated namespace. |
| `invalid-root-signature-rejected`, `backend-unauthorized-trust-update-rejected`, `configuration-digest-mismatch` | Invalid update is denied; before/after signed receipts show no unauthorized generation or digest change. |
| `root-authorized-test-generation`, `valid-consecutive-generation` | Signed CAS receipts bind consecutive sequence, canonical configuration digest, root fingerprint and root-signature digest. |
| `concurrent-identical-cas` | Concurrent calls converge on one durable sequence/digest; backend audit records show no divergent commit. |
| `restart-durability` | A newly initialized adapter/process reads the same committed sequence/digest with a signed receipt and backend restart record. |
| `generation-rollback`, `sequence-digest-conflict`, `unauthorized-stale-cas-conflict` | Rollback, skipped sequence and same-sequence/different-digest attempts fail or conflict; before/after state is unchanged. |
| `backend-unavailable-fail-closed`, `stale-state-fail-closed`, `corrupt-receipt-fail-closed` | Client rejects the failure and emits no trusted snapshot; retain the backend fault and audit evidence. |
| `lost-ack-reconciliation` | One-shot lost acknowledgement is resolved by one signed read of the exact transition; no blind mutation retry occurs. |
| `signed-audit-receipts` | Read/update receipts verify; audit IDs are unique and bind customer/backend/namespace/transition/sequence/digest/time/root authorization. |
| `root-signed-policy-accepted`, `invalid-root-signature-rejected`, `expired-trust-configuration-rejected`, `expired-role-rejected`, `revoked-role-rejected`, `duplicate-role-identity-rejected`, `signer-verifier-conflict-rejected`, `reviewer-signer-conflict-rejected`, `expired-conformance-review-rejected`, `missing-trust-state-rejected` | The valid policy verifies and each altered policy is rejected by the trust validator. Preserve the signed input and per-case output. |

Independent acceptance requires a canonical `decision: accepted` report and
detached signature from the distinct root-authorized reviewer, binding the
runner commit, bootstrap digest, adapter tree digest, suite/results digests,
backend and namespace identity, evidence reference, review time and expiry.
Retain stdout/stderr, exit status, backend receipts and audit logs. The runner
does not produce the review signature; the backend operator, attestor,
security custodian, and artifact signer cannot self-approve.

The customer-rooted production trust document must later pin the adapter's
distribution/version/tree digest and accepted conformance report digest. The
production loader remains `m3_trust_state.load_production_customer_trust`; the
conformance runner cannot install or accept production trust. This package
blocks production trust loading and artifact preflight until independently
reviewed and root-authorized.

The trust transport is protocol v2. The adapter must implement
`read_state(customer_id, namespace, transition_id, request_id)` and echo the
fresh 256-bit request ID in its Ed25519-signed receipt. Protocol-v1 receipts
are rejected; update the adapter package and root-signed adapter pin only
after its installed-file digest is independently reviewed. The runner output
uses `schemas/m3-trust-state-conformance-run-report-v2.json`; the separately
signed accepted conformance report uses schema version 2 as specified in the
adapter contract.

## A1. Independent trust reviewer

The reviewer must be a distinct, root-authorized identity, separate from the
backend operator, attestor, security custodian, adapter/build owner, and every
artifact signer. Review the exact runner source commit, bootstrap digest,
adapter installed-tree digest, complete output and error logs, suite/result
digests, customer/backend/namespace identity, signed receipts, audit IDs,
restart/backup/recovery and failure evidence. Deliver a canonical accepted
conformance report plus detached Ed25519 signature using the report contract
in [`m3-trust-state-adapter.md`](m3-trust-state-adapter.md); bind its digest and
reviewer identity in the subsequent root-signed trust configuration. A
passing harness is not independent approval and authorizes no cloud or host
operation.

## A. Debian 13.8 image and repository owner

Deliver to `/secure/m3`:

- Image metadata JSON and signed image approval package at
  `/secure/m3/image-approval.debian.json`, `.sig`, `.review.json`, and
  `.review.json.sig`. Bind the exact `debian-cloud` self-link, decimal image
  ID, `X86_64`, project, Debian 13, point release `13.8`, package-policy
  SHA-256, evidence reference, approval identity, approval time and expiry.
- An independently signed review of that exact approval. The `image-approver`
  and `reviewer` identities must be separate and root-authorized.
- Signed Trixie and security repository snapshots: `InRelease` or `Release`
  plus `Release.gpg`, detached public keyring and independently approved full
  OpenPGP fingerprints, immutable snapshot ID, compressed package indexes,
  and selected `.deb` artifacts.
- `/secure/m3/debian13-policy.json` and its independently approved digest.
  Bind package name/version/architecture/SHA-256, installed baseline, target,
  actual package delta, kernel expectation, reboot behavior and repository
  snapshot identity.
- Populate `/secure/m3/customer-artifact-inputs.debian.json` with paths and
  public trust references only. Keep registry credentials in the separate
  protected auth file; do not place credentials in JSON.

The image owner must query the publisher's current catalog and preserve the
returned JSON as source evidence; do not reuse a prior image name or infer the
point release from the family:

```sh
gcloud compute images list --project=debian-cloud \
  --filter='name~^debian-13-trixie' \
  --format='table(name,id,architecture,family,status,creationTimestamp)'
gcloud compute images describe <exact-image-name> --project=debian-cloud --format=json
```

The signatures must verify against separately delivered keys/fingerprints;
repository identity, Trixie distribution, origin/label, amd64 indexes,
`Valid-Until`, package hashes and policy must agree. Image metadata alone does
not prove the guest is 13.8: after separately approved provisioning, verify
`/etc/debian_version` equals `13.8`, `/etc/os-release` reports Debian 13, and
`dpkg --print-architecture` reports `amd64`.

Run artifact verification after all files arrive:

```sh
python3 scripts/m3_artifact_preflight.py \
  --inputs /secure/m3/customer-artifact-inputs.debian.json \
  --report /secure/m3/artifact-preflight.debian.json
```

Validate image approval together with the actual package report, network
record, complete secret-free Terraform input document and signed Terraform
principal attestation. The image-approval check runs only when this entire
bound input set is supplied; omitting any required input leaves plan binding
blocked:

```sh
python3 scripts/m3_deployment_readiness.py \
  --project-id kordex-fleet-platform-515416 \
  --network-inputs /secure/m3/network-inputs.json \
  --artifact-inputs /secure/m3/customer-artifact-inputs.debian.json \
  --artifact-report /secure/m3/artifact-preflight.debian.json \
  --image-approval /secure/m3/image-approval.debian.json \
  --terraform-inputs /secure/m3/terraform-inputs.debian.json \
  --terraform-principal-attestation /secure/m3/terraform-principal-attestation.debian.json \
  --output /secure/m3/deployment-readiness.debian.json
```

The `imageOwnerApproval` and `imageIdentityHumanReview` results are meaningful
only when `planInputBinding` passes. This local readiness report does not
contact GCP, establish current billing headroom, or authorize planning.

No Debian 13.8 image approval, signed package snapshot, or package policy is
present. Without them the Debian artifact report cannot pass, so no Debian
qualification host may be planned or executed.

## B. Genuine RHEL 9.8+ image and repository owner

Deliver to `/secure/m3`:

- Exact Red Hat-supported image metadata and the signed approval package at
  `/secure/m3/image-approval.rhel.json` with `.sig`, `.review.json`, and
  `.review.json.sig`. Bind the GCP project, immutable self-link and numeric
  image ID, exact RHEL 9.8+ minor, x86_64, PAYG/EUS license URI, entitlement,
  package-policy digest and evidence reference.
- Independent image approval review by an authorized identity distinct from
  the image approver.
- Non-secret RHUI/subscription entitlement evidence and the billing owner's
  written running/stopped license treatment. Do not send subscription
  credentials or activation keys.
- Signed private `repomd.xml` plus detached signature, independently
  delivered OpenPGP keyring and full approved fingerprint, immutable snapshot
  ID, authenticated primary metadata and exact RPM artifacts.
- `/secure/m3/rhel98-policy.json` and independently approved digest binding
  exact NEVRA, architecture, SHA-256, baseline/target package delta, kernel,
  reboot, SELinux and repository identity policy.
- `/secure/m3/customer-artifact-inputs.rhel.json` with safe local paths and
  public trust references only.

The RHEL image owner must capture the current publisher catalog metadata and
verify the exact Red Hat license identity. A family label is not proof of
RHEL 9.8+ or entitlement:

```sh
gcloud compute images list --project=rhel-cloud \
  --filter='name~^rhel-9' \
  --format='table(name,id,architecture,family,status,creationTimestamp,licenses)'
gcloud compute images describe <exact-image-name> --project=rhel-cloud --format=json
```

The verifier rejects unsigned, stale, substituted, wrong-minor or untrusted
metadata and RPMs. A derivative distribution is not acceptable.

```sh
python3 scripts/m3_artifact_preflight.py \
  --inputs /secure/m3/customer-artifact-inputs.rhel.json \
  --report /secure/m3/artifact-preflight.rhel.json

python3 scripts/m3_deployment_readiness.py \
  --project-id kordex-fleet-platform-515416 \
  --network-inputs /secure/m3/network-inputs.json \
  --artifact-inputs /secure/m3/customer-artifact-inputs.rhel.json \
  --artifact-report /secure/m3/artifact-preflight.rhel.json \
  --image-approval /secure/m3/image-approval.rhel.json \
  --terraform-inputs /secure/m3/terraform-inputs.rhel.json \
  --terraform-principal-attestation /secure/m3/terraform-principal-attestation.rhel.json \
  --output /secure/m3/deployment-readiness.rhel.json
```

No genuine RHEL image, entitlement, signed RPM snapshot or stopped-instance
license treatment is provided. RHEL qualification remains blocked until those
inputs are validated and the budget gate passes.

## C. Six Kordex image build owners

The release job must bind a manual `vMAJOR.MINOR.PATCH` tag to the exact event
commit in `kevin-phan-25/kordex`, workflow
`.github/workflows/ci.yaml`, using the approved GitHub-hosted Actions builder.
The verifier pins builder ID
`https://github.com/actions/runner/github-hosted`, workflow
`kevin-phan-25/kordex/.github/workflows/ci.yaml`, and requires the SLSA
workflow parameters, `workflow_dispatch` event, full source commit and exact
resolved materials to match each input-map entry.
For each component deliver its immutable published OCI reference and SHA-256
manifest digest, CycloneDX SBOM document and signed SBOM attestation bundle,
SLSA provenance bundle, build tag/full commit, builder/workflow identity and
complete resolved material identities. The provenance subject and SBOM must
bind the same image digest. No component may be tag-only or omitted.

| Component | Build owner role and expected materials |
|---|---|
| `control-plane` | Kordex control-plane build owner; pinned Go builder/runtime, control-plane/API source and Go module locks. |
| `agent` | Kordex agent build owner; pinned Go builder/runtime, agent/API source and Go module locks. |
| `operator` | Kordex operator build owner; pinned Go builder/runtime, operator/API source and Go module locks. |
| `dashboard` | Kordex dashboard build owner; digest-pinned Node base, dashboard source, `package.json` and `package-lock.json`. |
| `ansible-ee` | Kordex Ansible EE build owner; `integrations/ansible-ee/Containerfile`, repository-qualified digest-pinned `KORDEX_ANSIBLE_EE_BASE`, Debian/RHEL playbooks and `collections.lock` digests. |
| `postgres` | Kordex PostgreSQL image build owner; `integrations/postgres/Containerfile` and repository-qualified digest-pinned `KORDEX_POSTGRES_BASE`. |

After a successful tag-dispatch run, download the combined
`kordex-m3-six-image-release-<tag>-<run-id>-<attempt>` Actions artifact and
extract it under `/secure/m3/release/<approved-tag>/`, with the directory mode
`0700` and public files mode `0600` or stricter. The artifact has this layout:

```text
kordex-m3-six-image/
  kordex-images.tsv
  kordex-images.tsv.sig
  manifest.json
  SHA256SUMS
  components/<component>/
    image-reference.txt
    <component>.cdx.json
    <component>.sbom.bundle.jsonl
    <component>.provenance.bundle.jsonl
    component.json
    SHA256SUMS
```

The per-component artifacts are named
`kordex-m3-image-evidence-<component>-<tag>-<run-id>-<attempt>` and are
retained for 90 days. The final artifact is also retained for 90 days. This is
GitHub Actions artifact retention, not immutable or independent evidence
custody; archive the verified release bundle through the separately approved
evidence-custody process. Supplemental `agent-relay` is retained separately
and is excluded from the combined M3 lock.

The aggregate contains these exact release-owner outputs:

- `kordex-images.tsv` and `.sig`: exactly the six M3 immutable OCI references
  and digests, signed by the independently trusted Kordex release identity.
- For each `components/<component>/`: `<component>.cdx.json`,
  `<component>.sbom.bundle.jsonl`, and
  `<component>.provenance.bundle.jsonl`, `component.json`, and `SHA256SUMS`;
  these bind exact source tag/commit, builder/workflow identity, resolved
  material digests, image identity, and this workflow run.
- Root `manifest.json` and `SHA256SUMS`, covering all six output sets and the
  lock/signature digests.
- Deliver the independently acquired Sigstore trusted root and its pinned
  SHA-256 separately under `/trusted/`; it is not included in the release
  artifact or sourced from the signed attestation bundle itself.
- The release run ID and attempt recorded in the manifest.

Do not include GitHub tokens, registry auth files, private signing keys or
credentials in this directory or any input map. The hosted aggregation job
only emits this verification-ready package with read-only permissions; it
does not check out candidate source, receive signing credentials, or produce
the combined lock/signature. The first release uses a separate offline
workstation. Its signer key remains outside the checkout and is never placed
in GitHub variables, secrets, workflow environment variables, or artifacts.
The root-signed KIQT `releaseLockSigning` and `releaseLockVerification`
policies separately authorize the lock signer and verification-manifest
signer, with fingerprints and immutable source commits. The two identities
must differ from each other and from the artifact owner/signer, security
custodian, and independent reviewer. No workstation, designation, trust
configuration, or key is configured in this checkout.

For the last two components, provide the actual protected repository-variable
values as public digest-pinned image references and provenance materials. Do
not send CI tokens or credentials. Missing/mutable base references must fail
the build. The release helper writes only digest/hash build arguments to the
GitHub step output; these are not credentials.

The verifier consumes `release.imageDigestLock`, all six `release.imageAttestations`
entries and the independently delivered Sigstore trusted root in each
platform's artifact map. The static workflow checks are:

```sh
python3 -m unittest scripts.test_release_image_workflow -v
bash scripts/test_prepare_release_image_build_args.sh
```

Those commands check repository source and test-only build references; they do
not run the release. The source matrix in this worktree covers the six M3
components plus supplemental `agent-relay`; the committed baseline still lacks
the two added components until these changes are reviewed and committed. No
release was dispatched and no published image/SBOM/provenance was verified.
The actual per-OS cryptographic coverage command is the artifact preflight
shown in sections A and B: its signed-lock parser requires exactly the six M3
components and the attestation verifier checks every component against the
approved builder, workflow, source revision and materials. Static matrix
coverage is not release evidence.

The workflow builds each candidate from a digest-pinned base where required,
scans the candidate digest, creates and validates CycloneDX SBOMs, retains the
`actions/attest` SBOM and SLSA `bundle-path` outputs in the existing `.jsonl`
intake format, signs image digests through GitHub OIDC, and promotes the
version tag only after the digest check. The component packager checks bundle
shape, subject digest, SBOM document/predicate equality, source revision,
builder/workflow identity, and checksums. Those are structural/policy checks;
the offline verification command performs cryptographic bundle checks against
the independently delivered Sigstore trusted root. The Ansible EE and
PostgreSQL build helper rejects missing or mutable repository variables. The
hosted aggregate requires exactly six components and excludes `agent-relay`,
but only packages verification inputs; it does not create or sign a lock. No
actual Actions release has run, so no published artifact has been verified.

For offline signing, the verifier must run from a clean immutable revision
matching the root-authorized `verifierSourceCommit`, validate all six image,
SBOM, provenance, and repository metadata inputs, and write a canonical lock
candidate plus digest-bound verification manifest. Transfer only those two
data files to the isolated workstation over the approved channel; compare
their SHA-256 values at both ends. The workstation must run the exact clean
immutable `signerSourceCommit`, validate the manifest and its trust bindings,
and sign the exact UTF-8 lock bytes with the separately designated PEM key.
Return the lock, detached signature, signing receipt, and checksums. Verify
the signature against the independently delivered public key, then require a
distinct reviewer to verify the receipt, signer authorization, artifact
digests, audit event, and separate review record. This sequence is
implemented, but no trust configuration, workstation, key, signature, or
release run is present.

## D. Artifact signer and security custodian

Designate the lab security custodian and protected artifact signer in the
root-authorized KIQT trust configuration. The signer must be an actual
authorized identity using the existing Ed25519 protected-key interface with
mode `0600` or stricter. Deliver only public trust material independently from
the signed artifact. Provide signer key ID/fingerprint, role authorization,
validity/revocation state and immutable audit references. Never send a private
key, seed, access token, password, service-account key, registry auth file or
cloud credential.

The security custodian supplies the root-signed trust configuration and its
detached signature through the approved public-trust channel; production trust
is not interchangeable with KIQT lab trust. Existing trust loads from
`/etc/kordex/m3/qualification-root.pub`, `qualification-trust.json` and
`qualification-trust.json.sig`. This checkout has no KMS/HSM adapter for the
key-file signer. The custodian must confirm an actually protected signer
integration before any signature is produced. No identities, keys or audit
records are designated in this packet.

The signer signs artifact approvals only; the signer cannot create or sign the
independent review. Trust and signed artifacts are checked by the existing
Kordex artifact verifiers, `scripts/m3_customer_trust.py::load_trust`, and the
per-OS artifact preflight. Missing protected signing, trust or audit custody
blocks artifact validation and all downstream qualification.

## E. Independent artifact reviewer

Designate a separate, root-authorized `reviewer` identity. It must differ from
the artifact signer, every image/build owner, and every repository/package
approver. After the first per-OS preflight is cryptographically complete, the
reviewer inspects that exact canonical report and signs a canonical record
conforming to `schemas/m3-artifact-review-v1.json`. Bind campaign and OS
identity, all six image refs/digests, repository snapshot/signature digests,
SBOM and provenance digests/subjects/materials, all verified input hashes,
preflight report digest, trust configuration/root fingerprint, reviewer,
decision, review time and expiry.

The review is checked by the actual preflight path, not a separate ad hoc
signature command. Put the record and detached signature at
`/secure/m3/artifact-review.debian.json[.sig]` or
`/secure/m3/artifact-review.rhel.json[.sig]`, then set
`release.artifactReview.record` and `.signature` in the respective input map
and rerun:

```sh
python3 scripts/m3_artifact_preflight.py \
  --inputs /secure/m3/customer-artifact-inputs.debian.json \
  --report /secure/m3/artifact-preflight.debian.reviewed.json
```

Use the RHEL map/report paths for the RHEL campaign. There is no standalone
artifact-review CLI: the second preflight pass shown above is the actual
validator and invokes `m3_artifact_review.validate_review`. Wrong campaign,
stale/expired/revoked
reviewer, signature failure, self-review or changed digest is rejected. Image
identity approval is separate and cannot replace this artifact review. No
reviewer identity or approval is currently supplied.

## F. Billing owner

Supply signed, timestamped billing evidence under
`/secure/m3/evidence/gcpBillingBudget/` from the billing account/project owner.
It must include actual spend, credits and restrictions, committed charges,
available headroom, evidence as-of/expiry, and confirmation that the full
90-day program fits the $300 ceiling with at least $60 contingency reserve.
Attach SKU/rate/source exports or quotes with upper bounds for:

- RHEL PAYG/EUS charges while running, stopped and deleted; separate any
  external subscription charges.
- Three-node e2-medium compute runtime, boot disks while running/stopped,
  snapshots and retention.
- Egress and all artifact/package transfer, including retry/rebuild allowance.
- Artifact Registry, Cloud Storage/evidence archive, DNS and Secret Manager
  operations/storage.
- Logging ingestion/retention, monitoring metrics, and other required services.

Also provide conservative scenario-hours and disk/snapshot/traffic/logging
volume bounds for `scripts/m3_cost_model.py`. That tool calculates an estimate;
it never verifies billing headroom. No budget alert is a spending cap, and an
unbounded line cannot be treated as zero. Current RHEL stopped-instance
licensing, live headroom, transfer/storage/logging volumes and retry costs are
not verified, so affordability is **NOT VERIFIED**.

After replacing every angle-bracket value with the billing owner's documented
upper bound, run the exact existing estimate interface:

```sh
python3 scripts/m3_cost_model.py \
  --machine-type e2-medium --boot-disk-size-gib <approved-disk-size-gib> \
  --debian-scenario-hours-per-vm <debian-hours> \
  --debian-cleanup-restore-hours-per-vm <debian-cleanup-hours> \
  --rhel-scenario-hours-per-vm <rhel-hours> \
  --rhel-cleanup-restore-hours-per-vm <rhel-cleanup-hours> \
  --wrong-machine-id-extra-host-hours-per-os <extra-host-hours> \
  --rhel-license-mode payg --rhel-license-hours-per-vm <rhel-billable-hours-per-vm> \
  --wrong-machine-id-extra-rhel-license-hours <extra-rhel-host-billable-hours> \
  --snapshot-stored-gib-hours <snapshot-gib-hours> \
  --debian-boot-disk-gib-hours <debian-disk-gib-hours> \
  --rhel-boot-disk-gib-hours <rhel-disk-gib-hours> \
  --wrong-machine-id-extra-host-disk-gib-hours-per-os <extra-host-disk-gib-hours> \
  --private-dns-query-bound <dns-query-count> \
  --monthly-logging-gib <month-1-gib> <month-2-gib> <month-3-gib> \
  --logging-retention-cost-bound-usd <logging-retention-usd> \
  --network-cost-bound-usd <network-usd> \
  --artifact-storage-cost-bound-usd <artifact-storage-usd> \
  --registry-storage-cost-bound-usd <registry-storage-usd> \
  --rhel-subscription-cost-bound-usd <external-subscription-usd> \
  --other-cost-bound-usd <other-bounded-services-usd> \
  --billing-headroom-usd <owner-reported-headroom-usd> \
  --output /secure/m3/cost-estimate.json
```

For PAYG, the selected estimate uses separate customer-supplied billable-hour
bounds for the three RHEL cluster VMs and the extra wrong-machine-ID host. It
also reports a continuous 90-day, four-VM stress scenario. The current
Terraform profile requires the Google Cloud RHEL 9 EUS PAYG image; BYOS is not
valid for that profile. The billing owner must establish actual stopped-
instance treatment before the supplied hour bounds can be accepted. Supplied
headroom is only an input to the estimate, never proof of credit or available
budget. No cost-plan approval or provisioning is authorized by this packet.

## G. Private registry and network owners

The registry administrator supplies the approved private registry DNS name,
private CIDR(s), certificate chain and expiry, digest-preserving source-to-
destination map for all eight K3s and six Kordex images, and a read-only
destination verification report. Include exact immutable digests and
architecture; importing an archive is not proof that the destination has the
approved content. Keep credentials in the customer-protected auth file (for
example `/run/customer-secrets/skopeo-auth.json`), never in the input map or
report. Use the manifest's `privateRegistryVerification` command after the
signed locks and private registry are available.

The network administrator supplies private DNS, route and firewall evidence
for the workstation, registry, package mirrors and recovery access, plus the
secret-free network input document and signed approval. Public VM IPs, public
SSH/RDP, default-VPC reuse, and public package or registry fallback are
prohibited. Actual connectivity evidence is produced only by the separately
authorized live connectivity test. These inputs block private artifact
readiness, deployment readiness, and host enrollment.

## Dependency-ordered execution checklist

1. The project/lab authority designates the security custodian, trust
   attestor, artifact signer, image approvers, six build owners, and distinct
   independent reviewers. These are roles only until actual root-authorized
   identities are delivered.
2. The trust custodian delivers the public root, root-signed trust policy,
   pinned adapter bootstrap and adapter installation evidence; the backend
   owner installs it in a protected runtime and runs isolated conformance.
3. A separate reviewer accepts the backend report; only then may the
   custodian root-sign the production trust configuration that pins its digest.
   This blocks production trust and artifact preflight.
4. Debian and RHEL image/repository owners can deliver their independent image,
   repository, package-policy, and entitlement evidence in parallel after
   roles/trust delivery paths are established. Run each campaign's artifact
   preflight separately; neither platform substitutes for the other.
5. All six build owners and the release owner deliver the immutable release
   bundle, SBOMs, provenance, trust roots, and lock evidence. Release artifact
   checks can run in parallel with OS artifact intake, but the combined
   artifact preflight requires the relevant complete profile inputs and
   trusted backend.
6. The artifact reviewer performs the distinct signed review for each OS
   campaign. Private registry and network owners can prepare their signed
   digest/routing evidence in parallel, but live connectivity is a separate
   approval and operation.
7. The billing owner supplies bounded rates, usage assumptions, current
   headroom/credits, and RHEL stopped-instance treatment. Cost estimation is
   not headroom evidence. The $300/90-day hard ceiling remains a stop condition.
8. Project/IAM/network/image/billing evidence and per-OS readiness must pass
   before any plan authorization is requested. A separately approved plan is
   reviewed by digest; apply remains a separate authorization.
9. After deployment, verify three-node identity and baseline, then obtain
   scenario-specific execution and fault-injection approvals one row at a
   time. Preserve every failed attempt. Each evidence package requires its
   own independent evidence acceptance. Signoff is a final separate gate.

Steps 4 and 5 may proceed in parallel after trust roles and secure delivery
are established. Steps 6 and 7 may also proceed in parallel. No later approval
is implied by delivery or validation of an earlier input.

## Commands after delivery

The independent review is a second pass of the same per-OS artifact preflight.
Once both per-OS maps, outputs, network inputs, Terraform inputs, image
approvals and principal attestation are delivered, the local deployment
readiness command is:

```sh
python3 scripts/m3_deployment_readiness.py \
  --project-id kordex-fleet-platform-515416 \
  --network-inputs /secure/m3/network-inputs.json \
  --artifact-inputs /secure/m3/customer-artifact-inputs.debian.json \
  --artifact-report /secure/m3/artifact-preflight.debian.reviewed.json \
  --terraform-inputs /secure/m3/terraform-inputs.debian.json \
  --image-approval /secure/m3/image-approval.debian.json \
  --terraform-principal-attestation /secure/m3/terraform-principal-attestation.json \
  --output /secure/m3/deployment-readiness.debian.json
```

This is local readiness validation; it is not a Terraform plan or apply. After
the customer-input manifest has references and hashes for all required
evidence, the supported combined stage/matrix status command is:

```sh
python3 scripts/m3_qualification.py status \
  --manifest /secure/m3/customer-inputs.json \
  --evidence-directory /secure/m3/evidence
```

It does not promote hash-only inputs to approval. The artifact preflight,
deployment readiness, guarded plan/apply, real-host scenario execution,
fault-injection approval, evidence acceptance and M3 signoff remain distinct
gates.
