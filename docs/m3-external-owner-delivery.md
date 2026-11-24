# M3 external-owner delivery instructions

M3 remains **NOT COMPLETE, 0/22 accepted**. This packet gives the owner roles,
required files, real validation commands, and delivery boundaries. The canonical
47-slot delivery ledger is [`m3-external-delivery-manifest.json`](m3-external-delivery-manifest.json);
its schema is [`m3-external-delivery-manifest-v1.json`](../schemas/m3-external-delivery-manifest-v1.json).
It derives its IDs and campaign scopes from `scripts/m3_qualification.py::INPUTS`.
All slots currently read `NOT PROVIDED`.

Deliver owner material outside Git under `/secure/m3`, with directories mode
`0700` and files mode `0600` or stricter. The customer-input manifest stores
only safe relative paths, SHA-256 and expiry. Its command reports a hash match
as `UNVERIFIED`; it does not verify a signature or approval:

```sh
python3 scripts/m3_qualification.py inputs --manifest /secure/m3/customer-inputs.json
```

The status values are `NOT PROVIDED` (not delivered), `PROVIDED` (received but
unchecked), `VALIDATED` (named domain verifier passed), `APPROVED` (authorized
approval binds the validated scope), and `REJECTED` (failed; preserve original
material and failure evidence). No person is designated by this packet. The
security custodian, artifact signer, six build-owner roles, image approvers,
OS repository custodians, and independent reviewers must be designated through
the lab's approved trust process. A reviewer must not be the signer or any
owner of the artifacts under review.

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
credentials in this directory or any input map. The lock signing job uses the
protected `kordex-m3-release-signing` GitHub Environment and the existing
`KORDEX_RELEASE_PRIVATE_KEY` / `KORDEX_RELEASE_PUBLIC_KEY` file-path interface,
plus independently approved `KORDEX_RELEASE_PUBLIC_KEY_SHA256` (SHA-256 over
Ed25519 SubjectPublicKeyInfo DER). An approved protected signing runtime must
provide the private-key file outside the checkout, mode `0600` or stricter.
Do not place private key bytes in GitHub variables/secrets or workflow
environment variables. No protected signing runtime or key file is configured
in this checkout; on the current hosted runner, the combined lock step fails
closed until an approved signing integration exists. Component artifacts may
remain, but the combined artifact is not uploaded. Configure Environment
reviewer protection separately from the signer.

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
intake format, signs the image digest through GitHub OIDC, and promotes the
version tag only after the digest check. Its component packager checks the
bundle JSON shape, subject digest, CycloneDX predicate/document equality,
source revision, builder/workflow identity, and checksum manifest. Those are
structural/policy consistency checks: only the later preflight with the
independently pinned Sigstore trusted root performs cryptographic bundle
verification. The Ansible EE and PostgreSQL build helper rejects missing or
mutable repository variables; their Containerfiles repeat the digest and
content checks. The aggregation job requires all six components, excludes
`agent-relay`, builds the existing six-row TSV lock and signs/verifies it
through `verify-image-lock.sh`. It fails closed if the protected signing
environment and matching public-key fingerprint are not configured. No actual
Actions release has run in this worktree, so no published image, signature,
bundle, or secret-free release log has been independently verified here.

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

For PAYG, the model includes a continuous 90-day stopped-instance licensing
scenario as a conservative bound. The billing owner must separately establish
actual stopped-instance treatment. The supplied headroom is only an input to
the estimate, never proof of credit or available budget. No cost-plan approval
or provisioning is authorized by this packet.

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
