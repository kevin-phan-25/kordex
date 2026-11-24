# M3 customer artifact intake and private registry preflight

This workflow composes the existing Kordex verifiers before any M3 lab plan. It
does not add a signing format, publish or push artifacts, or create trust. The
JSON report is an unsigned, deterministic point-in-time summary. `PASS` means
the listed existing checks passed with the supplied local inputs; it is not
upstream provenance, a qualification result, or a substitute for approval.

For the 47-role input-to-owner mapping and exact delivery destinations, use
the canonical [external delivery manifest](m3-external-delivery-manifest.json)
and [owner handoff instructions](m3-external-owner-delivery.md). The manifest
tracks receipt and validation state separately; the artifact path map below
remains the executable schema enforced by this preflight.

## Separate trust domains and owners

| Input | Owner | Existing verification and consumption |
|---|---|---|
| Maintenance public trust bundle (`keys.json`) | Maintenance signing-key custodian | JSON maps SHA-256 Ed25519 key IDs to canonical base64 public keys. The custodian supplies independently confirmed key IDs. The operator consumes it as `KORDEX_HUB_PUBLIC_KEYS_FILE`; it does not verify release or artifact signatures. |
| Customer artifact-approval trust | Supply-chain custodian | `KORDEX-CUSTOMER-ARTIFACT-TRUST-V1`; existing `kordex-artifact-lock` verifies K3s binary and system-image signatures in separate domains. |
| Kordex release public key | Release owner | Existing signed offline bundle and image-lock verifiers (`verify-offline-bundle.sh`, `verify-image-lock.sh`). Expected SHA-256 fingerprint arrives independently. |
| Tool provenance public key and Helm signer allowlist | Tool/release owner | Existing `verify-offline-tools-lock.sh` and bundle verifier require the separately trusted tool signer and byte-identical allowlist. |
| K3s binary and system images | Supply-chain custodian | Signed locks bind `v1.36.6+k3s1`, `linux/amd64`, mirror references, digests, and approval references. A customer-selected maximum age of 1–365 days is enforced using signed UTC `approvedAt`; the lock format has no native expiry field. |
| Host package plan and `.deb`/`.rpm` archive | Kordex administrator and package custodian | Existing package verifier binds the exact policy digest, package name/version and SHA-256. It accepts only the maintenance runner's exact supported OS identities, checks Debian package architecture `amd64`/`all` or RPM architecture `x86_64`/`noarch`, requires a baseline with at least one version delta, and enforces kernel/reboot consistency. It fetches the exact archive from the configured HTTPS private source, pins the connection to approved private CIDRs while verifying the DNS hostname certificate, rejects redirects, compares the served archive to the selected local archive SHA-256, then stages and validates packages from the fetched bytes. This verifier support does not imply the Terraform lab can currently boot Debian or RHEL hosts. |

Maintenance, customer artifact-approval, release-signing, and tool-provenance
keys must not be merged. Release formats without an expiry field rely on their
owner's release process for revocation and freshness; this report does not
invent an expiry policy for them.

## Private registry ingestion and read-only verification

The system-image staging command verifies and stages a local OCI archive but
does not push it. The supply-chain custodian must use the customer's approved
registry ingestion procedure to publish the eight signed mappings. The release
owner separately populates the six digest-pinned Kordex images: agent,
operator, control-plane, dashboard, Ansible EE, and PostgreSQL.

`verify-private-registry.py` re-verifies the signed K3s lock/archive and signed
Kordex image lock before inspection. It uses Skopeo `inspect --raw` and
`inspect --config` with TLS verification, checks the exact OCI manifest digest
and `linux/amd64`, then copies the approved digest to a temporary local OCI
layout to verify that the referenced image content is present. This downloads
the checked blobs to temporary local storage but never pushes. It requires
signed private-host mappings and writes a deterministic per-image report.
Registry credentials are read only through a customer-managed Skopeo auth file
supplied by path; the file must be a private regular file (mode 0600 or
stricter). Kordex never reads,
copies, logs, or reports its contents. Never put credentials in JSON, command
values, Git, or shell history.

There is no public-registry fallback. Skopeo runs without proxy environment
variables. The approved lab CIDR egress policy remains necessary to constrain
DNS changes and registry blob redirects; this local check does not replace
firewall enforcement.

The offline release-bundle OCI verifier accepts direct multi-platform OCI
indexes and Podman wrapper-index archives. An OCI index may omit its own
`mediaType`; when present it must be
`application/vnd.oci.image.index.v1+json`. This compatibility rule does not
change signed image-lock requirements: descriptor/blob SHA-256 digests,
platforms, archive checksums, and the approved private registry mapping remain
mandatory. Run `bash scripts/test-offline-bundle-integrity.sh` for synthetic
fixture coverage and `bash scripts/test-offline-oci-podman.sh` for real local
rootless-Podman archives. Neither command verifies customer-owned artifact
trust or writes to a registry unless the separate optional local-registry test
is explicitly configured.

## Ordered offline pipeline

The generic Kordex release bundle and the customer-approved K3s airgap bundle
are separate inputs with separate trust checks. Building or extracting one
does not approve or populate the other.

1. Build the generic Kordex bundle on the approved build host using
   [`air-gapped-deployment.md`](air-gapped-deployment.md#build-and-transfer-an-offline-bundle).
   `build-offline-bundle.sh` creates the OCI archives, image metadata, client
   binaries, manifests, charts, and `SHA256SUMS`; the release custodian signs
   that inventory separately.
2. Verify the release signature and every file from a separately trusted
   checkout using `verify-offline-bundle.sh`. Extract or stage only after this
   command succeeds. The builder itself runs `stage-offline-assets.sh` to
   populate Kustomize and Ansible content; see the linked build procedure.
3. Verify and stage the customer-signed K3s archive using the separate
   `kordex-artifact-lock system-images verify` and `stage` commands in
   [`m3-k3s-system-image-staging.md`](m3-k3s-system-image-staging.md). That
   stage operation writes an archive, signed lock, signature, registry
   configuration, and inventory under a content-addressed directory. It does
   **not** publish OCI image tags.
4. The supply-chain custodian publishes each of the eight K3s image mappings
   from that archive with the Skopeo procedure in the staging guide. The
   release custodian publishes the six Kordex images through the existing
   `push-offline-bundle.sh` release process. Both operations write to the
   customer registry; neither is performed by artifact preflight.
5. Run `verify-private-registry.py` after both ingestions. It is read-only and
   must report exactly 14 image results, all with `status: PASS`, the signed
   digest, and `linux/amd64`. A successful local archive check or staging
   operation is not evidence that the registry has been populated.
6. Run `m3_artifact_preflight.py` with the local customer input file. Overall
   `PASS` requires every required artifact row to pass, including signed
   repository metadata, per-image SBOM and SLSA provenance attestations, and
   independent approval. Missing inputs remain `NOT PROVIDED`; supplied
   invalid or inconsistent inputs are `FAIL`. Only an overall `PASS` is
   accepted by the guarded lab helper.

The offline Go lock checks set `GOPROXY=off`, `GOSUMDB=off`, and
`GOTOOLCHAIN=local`. The local Go toolchain and required modules must already
be available; otherwise verification stops instead of downloading code. Skopeo
source reads are local OCI archive reads. Registry inspection or publication
requires the approved customer-private route, TLS, DNS, and credentials, and
never has a public-registry fallback. The report and bundle contain no registry
credentials. Synthetic fixtures exercise these transitions but do not count
as customer trust, artifact approval, registry population, or M3 evidence.

## Customer-local input file

Create a mode-0600 JSON file outside the repository. It contains paths and
public identifiers only. Keep registry credentials in a separate auth file
managed by the customer's secret system. Replace placeholders; do not use
synthetic fixtures from the repository.

```json
{
  "schemaVersion": 1,
  "trust": {
    "maintenanceBundle": "/trusted/maintenance/keys.json",
    "maintenanceExpectedKeyIds": ["<independently-confirmed-key-id>"],
    "artifactApprovalBundle": "/trusted/customer-artifact.trust",
    "artifactApprovalExpectedKeyIds": ["<independently-confirmed-key-id>"],
    "artifactApprovalMaxAgeDays": 30,
    "releasePublicKey": "/trusted/kordex-release.pub",
    "releaseExpectedFingerprint": "<independently-confirmed-sha256-fingerprint>",
    "toolProvenancePublicKey": "/trusted/offline-tools.pub",
    "toolProvenanceExpectedFingerprint": "<independently-confirmed-sha256-fingerprint>",
    "helmSignerAllowlist": "/trusted/helm-signers.txt"
  },
  "release": {
    "bundleDirectory": "/artifacts/kordex-release",
    "imageDigestLock": "/artifacts/kordex-images.tsv",
    "imageDigestSignature": "/artifacts/kordex-images.tsv.sig",
    "sigstoreTrustedRoot": "/trusted/sigstore-trusted-root.jsonl",
    "sigstoreTrustedRootSHA256": "<independently-delivered-root-sha256>",
    "imageAttestationMaxAgeDays": 30,
    "imageAttestations": {
      "agent": {"sbom": "/artifacts/kordex-m3-six-image/components/agent/agent.cdx.json", "sbomBundle": "/artifacts/kordex-m3-six-image/components/agent/agent.sbom.bundle.jsonl", "provenanceBundle": "/artifacts/kordex-m3-six-image/components/agent/agent.provenance.bundle.jsonl", "sourceRef": "refs/tags/v<release>", "sourceCommit": "<full-git-commit>", "buildMaterials": [{"uri": "<exact-material-uri-from-verified-SLSA>", "digest": {"sha256": "<approved-material-digest>"}}]},
      "operator": {"sbom": "/artifacts/kordex-m3-six-image/components/operator/operator.cdx.json", "sbomBundle": "/artifacts/kordex-m3-six-image/components/operator/operator.sbom.bundle.jsonl", "provenanceBundle": "/artifacts/kordex-m3-six-image/components/operator/operator.provenance.bundle.jsonl", "sourceRef": "refs/tags/v<release>", "sourceCommit": "<full-git-commit>", "buildMaterials": [{"uri": "<exact-material-uri-from-verified-SLSA>", "digest": {"sha256": "<approved-material-digest>"}}]},
      "control-plane": {"sbom": "/artifacts/kordex-m3-six-image/components/control-plane/control-plane.cdx.json", "sbomBundle": "/artifacts/kordex-m3-six-image/components/control-plane/control-plane.sbom.bundle.jsonl", "provenanceBundle": "/artifacts/kordex-m3-six-image/components/control-plane/control-plane.provenance.bundle.jsonl", "sourceRef": "refs/tags/v<release>", "sourceCommit": "<full-git-commit>", "buildMaterials": [{"uri": "<exact-material-uri-from-verified-SLSA>", "digest": {"sha256": "<approved-material-digest>"}}]},
      "dashboard": {"sbom": "/artifacts/kordex-m3-six-image/components/dashboard/dashboard.cdx.json", "sbomBundle": "/artifacts/kordex-m3-six-image/components/dashboard/dashboard.sbom.bundle.jsonl", "provenanceBundle": "/artifacts/kordex-m3-six-image/components/dashboard/dashboard.provenance.bundle.jsonl", "sourceRef": "refs/tags/v<release>", "sourceCommit": "<full-git-commit>", "buildMaterials": [{"uri": "<exact-material-uri-from-verified-SLSA>", "digest": {"sha256": "<approved-material-digest>"}}]},
      "ansible-ee": {"sbom": "/artifacts/kordex-m3-six-image/components/ansible-ee/ansible-ee.cdx.json", "sbomBundle": "/artifacts/kordex-m3-six-image/components/ansible-ee/ansible-ee.sbom.bundle.jsonl", "provenanceBundle": "/artifacts/kordex-m3-six-image/components/ansible-ee/ansible-ee.provenance.bundle.jsonl", "sourceRef": "refs/tags/v<release>", "sourceCommit": "<full-git-commit>", "buildMaterials": [{"uri": "<exact-pinned-base-image-uri>", "digest": {"sha256": "<base-image-digest>"}}]},
      "postgres": {"sbom": "/artifacts/kordex-m3-six-image/components/postgres/postgres.cdx.json", "sbomBundle": "/artifacts/kordex-m3-six-image/components/postgres/postgres.sbom.bundle.jsonl", "provenanceBundle": "/artifacts/kordex-m3-six-image/components/postgres/postgres.provenance.bundle.jsonl", "sourceRef": "refs/tags/v<release>", "sourceCommit": "<full-git-commit>", "buildMaterials": [{"uri": "<exact-pinned-base-image-uri>", "digest": {"sha256": "<base-image-digest>"}}]}
    }
  },
  "k3sBinary": {
    "binary": "/artifacts/k3s",
    "lock": "/artifacts/k3s.lock",
    "signature": "/artifacts/k3s.lock.sig",
    "trustBundle": "/trusted/customer-artifact.trust"
  },
  "k3sSystemImages": {
    "bundle": "/artifacts/k3s-airgap-images-amd64.tar",
    "lock": "/artifacts/k3s-system-images.lock",
    "signature": "/artifacts/k3s-system-images.lock.sig",
    "trustBundle": "/trusted/customer-artifact.trust"
  },
  "network": {"privateMirrorCIDRs": ["<approved-private-cidr>"]},
  "privateRegistry": {
    "host": "<private-registry-host>",
    "privateCIDRs": ["<approved-private-cidr>"],
    "authFile": "/run/customer-secrets/registry-auth.json"
  },
  "packageArtifacts": {
    "policy": "/artifacts/<exact-os-profile>-policy.json",
    "archive": "/artifacts/<exact-os-profile>-packages.tar",
    "approvedPolicySHA256": "<approved-policy-sha256>",
    "osPointRelease": "<Debian-13-point-or-RHEL-9-minor; empty-for-Ubuntu>",
    "baselineVersions": {"<package-name>": "<currently-installed-version>"},
    "privateMirrorURL": "https://<private-package-mirror>/<exact-package-bundle-path>",
    "privateMirrorCIDRs": ["<approved-private-cidr>"],
    "repositoryMetadata": {
      "family": "debian",
      "keyring": "/trusted/repository-signing-keys.gpg",
      "approvedFingerprints": ["<independently-approved-full-openpgp-fingerprint>"],
      "maxAgeSeconds": 86400,
      "repositories": [{
        "id": "debian-trixie-main",
        "root": "/artifacts/debian-trixie/dists/trixie",
        "baseURL": "https://<private-package-mirror>/debian/dists/trixie",
        "snapshotID": "<same-approved-immutable-snapshot-id>",
        "distribution": "trixie",
        "origin": "Debian",
        "label": "Debian",
        "codename": "trixie",
        "architectures": ["amd64"],
        "components": ["main"]
      }]
    }
  }
}
```

`repositoryMetadata.repositories` entries have closed schemas. A Debian
record contains exactly `id`, `root`, `baseURL`, `snapshotID`, `distribution`,
`origin`, `label`, `codename`, `architectures`, and `components`. The local
snapshot root contains a signed `InRelease`, signed detached `Release` plus
`Release.gpg`, or both; if both exist their signed payloads must match. The
signed Release must bind the configured distribution identity, include
`Valid-Until`, and hash each selected amd64 `Packages` index. Those indexes
must list each approved package exactly once with the policy version,
architecture, and package SHA-256.

A RHEL record contains exactly `id`, `root`, `baseURL`, `snapshotID`,
`releasever`, and `architecture`. The root contains `repodata/repomd.xml`, its
detached `repomd.xml.asc`, and the signed primary metadata referenced by
repomd. Verification checks the signature against independently approved full
fingerprints, metadata freshness, exact RHEL minor and x86_64 architecture,
the compressed/open primary SHA-256 chain, and each policy RPM's exact EVR,
architecture, and package digest. Keyrings and approved fingerprints require
separate trusted delivery; data supplied together cannot establish its own
trust.

Every image attestation entry refers to an immutable digest in the signed
image lock, an actual CycloneDX 1.4/1.5/1.6 SBOM and its offline GitHub
attestation bundle, and an offline SLSA provenance v1 bundle. The SBOM is
validated against the repository's official hash-pinned CycloneDX schemas;
the signed CycloneDX predicate must equal the document. The provenance
verifier pins the Kordex repository and CI workflow, release tag, full source
commit, builder identity, build parameters and resolved source material, then
checks the attested image subject digest and freshness. `gh attestation verify`
is required and there is no unsigned or online fallback. Independently approve
the trusted-root digest and OpenPGP fingerprints outside this input JSON.

The release workflow packages the pinned `actions/attest@v4.2.2` action's
`bundle-path` outputs as one compact Sigstore bundle per line. Its 90-day
Actions artifact `kordex-m3-six-image-release-<tag>-<run-id>-<attempt>` is a
verification-ready package, **not a signed lock**. It contains
`package-manifest.json`, root `SHA256SUMS`, and the six component directories
with `<component>.cdx.json`, `<component>.sbom.bundle.jsonl`,
`<component>.provenance.bundle.jsonl`, `component.json`, and component
`SHA256SUMS`. The package manifest records the immutable image reference,
source commit, workflow run, and explicitly says cryptographic verification,
lock candidate, and signature are `NOT RUN` / `NOT PRODUCED`. Supplemental
`agent-relay` is excluded. The hosted job has read-only artifact/repository
permissions, does not check out candidate source, and has no lock-signing
environment or key paths.

The legacy `assemble_m3_release_evidence.py assemble` command is disabled. An
offline verification workstation must run the fixed verifier from the
root-approved clean immutable revision, using the schema
`schemas/m3-release-lock-verification-input-v1.json`:

```sh
python3 scripts/m3_offline_release_lock.py verify \
  --inputs /secure/m3/release-lock-verification-input.debian.json \
  --components-root /secure/transfer/kordex-m3-six-image/components \
  --verification-key /protected/kiqt/release-lock-verifier.pem \
  --output-dir /secure/m3/candidate/debian
```

For RHEL, use an independently approved RHEL 9.8+ package policy and repository
snapshot, `campaign: "rhel-9.8+"`, and a separate output directory. The command
validates all six component sets, cryptographically verifies every Sigstore
SBOM/provenance bundle against the separately delivered pinned trusted root,
verifies the signed Debian or RPM repository metadata and index digest chain,
then emits `kordex-images.tsv`, `verification-manifest.json` (schema
`schemas/m3-release-lock-verification-v1.json`), its detached
`verification-manifest.json.sig`, the raw input-map digest, and `SHA256SUMS`.
The manifest binds the full component/image/SBOM/provenance identities,
repository result, every input digest, KIQT trust identities, and exact clean
verifier source revision. The command fails unless root-authorized
release-lock signer and verifier identities exist in KIQT, trust-state
rollback and source-revision checks pass, and the verifier key matches its
independently approved Ed25519 fingerprint. The detached manifest signature
authenticates the exact canonical result and is produced by a verifier identity
distinct from the release-lock signer.

Transfer the candidate lock, manifest, detached manifest signature, and
checksum file to the dedicated signing workstation after comparing their
SHA-256 values over the approved separate channel. The workstation must run
the exact clean source revision named by the independently root-signed KIQT
`releaseLockSigning.signerSourceCommit`; the manifest-signature key belongs
to the separately authorized release-lock verifier, whose source revision
equals `verifierSourceCommit`. The protected
Ed25519 PEM key stays outside the checkout, signer-owned, single-link,
non-symlink, and mode `0600` or stricter. Its public key and SPKI-DER
SHA-256 fingerprint are in root-authorized KIQT trust. The signer accepts only
the lock, manifest, and verifier signature; it validates the verifier
signature and all manifest bindings, signs the exact UTF-8 lock bytes with
OpenSSL Ed25519, verifies the detached signature, and writes the receipt schema
`schemas/m3-release-lock-signing-receipt-v1.json`:

```sh
python3 scripts/m3_offline_release_lock.py sign \
  --lock-candidate /secure/transfer/kordex-images.tsv \
  --verification-manifest /secure/transfer/verification-manifest.json \
  --verification-manifest-signature /secure/transfer/verification-manifest.json.sig \
  --private-key /protected/kiqt/release-lock-signer.pem \
  --output-dir /secure/return/signed-kordex-lock
```

The signer returns `kordex-images.tsv`, `.sig`, `signing-receipt.json`, and
`SHA256SUMS`. Recompute transfer checksums at both ends and run
`bash scripts/verify-image-lock.sh ...` with the independently obtained public
PEM key. A distinct reviewer then checks the receipt, exact lock and manifest
digests, signer authorization, trust roots, release evidence, and signing
audit record. A valid lock signature alone is not independent artifact review.
The workflow itself has not produced a signed lock, and no workstation, key,
KIQT identity, or trust configuration is represented as configured here.

The report separately reports structural input validation,
repository-metadata signature verification, SBOM verification,
build-provenance verification, independent artifact review, and overall
readiness. Repository signatures, image identity approval, and build
attestations do not substitute for independent artifact review.

## Independent artifact-review record

The customer-local map may include a unique campaign ID, root-designated
artifact owners, and signed review file paths:

```json
{
  "release": {
    "campaignId": "<unique-os-campaign-id>",
    "artifactOwners": {
      "release-bundle": "<root-designated-owner>",
      "release-image-lock": "<root-designated-owner>",
      "k3s-binary": "<root-designated-owner>",
      "k3s-system-images": "<root-designated-owner>",
      "image:agent": "<root-designated-owner>",
      "image:operator": "<root-designated-owner>",
      "image:control-plane": "<root-designated-owner>",
      "image:dashboard": "<root-designated-owner>",
      "image:ansible-ee": "<root-designated-owner>",
      "image:postgres": "<root-designated-owner>",
      "repository:<repository-id>": "<root-designated-owner>"
    },
    "artifactReview": {
      "record": "/secure/m3/artifact-review.debian.json",
      "signature": "/secure/m3/artifact-review.debian.json.sig"
    }
  }
}
```

Add one repository owner slot for every configured metadata repository. Each
identity must be present in the root-signed Kordex trust configuration with
role `artifact-owner`; the independent reviewer must have the distinct
`reviewer` role. The reviewer cannot be any designated artifact/build owner
or verified artifact signer.

Use two passes. First run preflight without `release.artifactReview` and
retain its exact canonical report. The independent reviewer validates that
report and prepares/signs a record conforming to
[`schemas/m3-artifact-review-v1.json`](../schemas/m3-artifact-review-v1.json)
using the already approved protected Ed25519 review identity. The signed
record binds the OS campaign and identity; all six immutable image
references/digests; each SBOM and provenance bundle digest, subject digest,
builder/workflow/source/material identities; every verified repository
metadata row and signed metadata/index digest; all verified input digests;
the preflight report and verification projection digests; trust configuration
digest and root fingerprint; reviewer identity, decision and validity
timestamps. `scripts/m3_artifact_review.py` recomputes the bindings from the
report and rejects any difference, missing component, stale record, revoked
or unauthorized reviewer, or invalid signature.

Then add the signed record and detached signature paths to the same input map
and rerun the preflight:

```sh
python3 scripts/m3_artifact_preflight.py \
  --inputs /secure/m3/customer-artifact-inputs.json \
  --report /secure/m3/artifact-preflight.json
```

The consolidated report is `PASS` only when every prior cryptographic check
and independent review pass. Missing review files remain `NOT PROVIDED`; an
invalid supplied record is `FAIL`. `validate_image_approval` remains a
separate platform/image-identity approval and cannot replace artifact review.

Image SBOM and provenance checks are staged and reported independently. A
missing SBOM is `NOT PROVIDED` for SBOM and provenance (provenance was not
checked); an invalid SBOM is `FAIL` for SBOM and `NOT PROVIDED` for provenance.
After all six SBOMs verify, a missing provenance bundle leaves SBOM `PASS` and
reports provenance `NOT PROVIDED`; an invalid attestation or provenance policy
is `FAIL` for provenance while the verified SBOM row remains `PASS`. None of
these partial states can make overall artifact readiness `PASS`.

## Six-component release and provenance policy

The release matrix in `.github/workflows/ci.yaml` now includes the exact six
M3 lock components (`control-plane`, `agent`, `operator`, `dashboard`,
`ansible-ee`, and `postgres`) plus supplemental `agent-relay`. For each image,
the release job checks out the selected immutable `vMAJOR.MINOR.PATCH` tag and
requires the checked-out commit to equal the event commit. It builds and scans
the candidate, generates and attests a CycloneDX SBOM, attests SLSA
provenance, signs the candidate digest, and publishes the release tag only by
that digest. The verified builder is GitHub-hosted Actions; the pinned source
is repository `kevin-phan-25/kordex`, workflow
`.github/workflows/ci.yaml`, and the event is `workflow_dispatch`.

The four root-context images use their component Dockerfiles. `ansible-ee`
uses `integrations/ansible-ee/Containerfile` and a base image from the
`KORDEX_ANSIBLE_EE_BASE` GitHub repository variable. `postgres` uses
`integrations/postgres/Containerfile` and `KORDEX_POSTGRES_BASE`. The release
helper rejects missing or mutable base references; the Ansible EE build also
binds playbook and collection digests into image labels. Exact per-image SLSA
materials, including the pinned base digests, must be supplied in
`buildMaterials` and match the verified provenance. The actual protected
repository variables, release run, six pushed images, SBOMs, and signed
attestations remain `NOT VERIFIED`. The Kordex release/build owner must
designate an accountable owner for each image in `artifactOwners` and provide
the actual release outputs. Static CI coverage is not proof of an artifact
build, approval, or qualification.

The current source-declared material policy is:

| Locked component | Source and build inputs that provenance must identify | Accountable owner/evidence |
|---|---|---|
| `control-plane` | `kevin-phan-25/kordex`, release tag plus matching commit; pinned Go builder `golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0`; pinned runtime `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`; checked-out API/control-plane sources and Go module lock files. | Kordex release/build owner; exact tag, source commit, SLSA material list, digest-pinned image, SBOM and attestation bundles. |
| `agent` | Same repository/tag/builder policy; pinned Go and distroless bases above; checked-out API/agent sources and Go module lock files. | Same release/build owner and per-image evidence. |
| `operator` | Same repository/tag/builder policy; pinned Go and distroless bases above; checked-out API/operator sources and Go module lock files. | Same release/build owner and per-image evidence. |
| `dashboard` | Same repository/tag/builder policy; pinned `node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a`; dashboard source, `package.json`, and `package-lock.json`. | Same release/build owner and per-image evidence. |
| `ansible-ee` | Same repository/tag/builder policy; `integrations/ansible-ee/Containerfile`; externally configured, repository-qualified digest-pinned `KORDEX_ANSIBLE_EE_BASE`; Debian/RHEL playbooks and `collections.lock` whose digests are embedded in image labels. | Kordex release/build owner must provide actual protected-variable identity/value evidence, exact SLSA materials, and per-image output evidence. |
| `postgres` | Same repository/tag/builder policy; `integrations/postgres/Containerfile`; externally configured, repository-qualified digest-pinned `KORDEX_POSTGRES_BASE`. | Kordex release/build owner must provide actual protected-variable identity/value evidence, exact SLSA materials, and per-image output evidence. |

These are source-declared expectations, not proof of the actual build. Each
`buildMaterials` entry in the private input map must match the exact verified
SLSA `resolvedDependencies`; the verifier also requires the source repository
and exact source commit. Any material not present in verified provenance is
rejected. `agent-relay` is built by the same job but is supplemental and is
not part of the six-image M3 lock.

`packageArtifacts` is platform-neutral, but the policy still binds one exact
supported OS identity and the archive contains only that policy's exact
`.deb` or `.rpm` files. RPM metadata is inspected with the locally installed
`rpm` command; this workflow performs no public downloads. The machine-readable
report uses the `hostPackageArtifacts` row and identifies the bound OS profile.
Synthetic RPM tests validate parser behavior only; they do not establish RHEL
image, repository, or host compatibility.

For Debian `ID=debian`, major `13`, provide `packageArtifacts.osPointRelease`
as the approved point release `13.8` independently confirmed from the
[Debian 13.8 release notice](https://www.debian.org/News/2026/20261121). The input is syntactically checked and
bound into the report and Terraform startup checks; Kordex does not query
Debian or determine “latest” offline. The customer package/release owner must
confirm Debian 13.8 from Debian's release notice and record that source
with the approval. For RHEL `9`, the field must be
the exact selected minor release (`9.8` or later) and match the policy's
`osMinor`. Ubuntu supplemental inputs leave it empty. Debian 12 and RHEL
before 9.8 are rejected for M3.

Run from a trusted checkout:

```sh
python3 scripts/m3_artifact_preflight.py \
  --inputs /secure/m3/customer-artifact-inputs.json \
  --report /secure/m3/artifact-preflight.json
```

The command prints only the final state and report SHA-256. It returns `PASS`
only when every mandatory row passes. Missing inputs are `NOT PROVIDED`;
supplied invalid or mismatched inputs are `FAIL`. The report omits paths,
auth-file contents, tokens, and key material. It includes key IDs/fingerprints,
digests, versions, architecture, package metadata, and bounded error codes. It
is not signed; retain the printed hash independently for review. The lab
wrapper checks the exact report bytes against the digest emitted by the verifier
before accepting the report or its K3s file bindings. The package URL must serve
the exact selected archive as a direct HTTP 200 response; a health-check URL is
insufficient. The report records the verified archive digest and byte size.

## Lab bootstrap and execution gate

Guarded lab `plan`, `apply`, and qualification `execute` require
`--m3-artifact-inputs` and `--m3-artifact-report`, plus the exact eight K3s
artifact paths. The helper runs the consolidated preflight, requires every row
to be `PASS`, and binds report K3s file hashes to the separately supplied K3s
files. It regenerates and compares the deterministic report before planning;
`apply` repeats the check after typed confirmation and before applying the
saved plan. `execute` checks the report before project confirmation, then
rechecks and compares it immediately before launching the qualification runner.
Existing individual K3s verifiers and Terraform variable checks remain in
place. Do not invoke Terraform or the qualification runner directly.

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id kordex-fleet-platform-515416 \
  --m3-artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --m3-artifact-report /secure/m3/artifact-preflight.json \
  --k3s-binary /artifacts/k3s \
  --k3s-artifact-lock /artifacts/k3s.lock \
  --k3s-artifact-signature /artifacts/k3s.lock.sig \
  --k3s-artifact-trust /trusted/customer-artifact.trust \
  --k3s-system-images-bundle /artifacts/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /artifacts/k3s-system-images.lock \
  --k3s-system-images-signature /artifacts/k3s-system-images.lock.sig \
  --k3s-system-images-trust /trusted/customer-artifact.trust
```

The command still stops if customer trust, release artifacts, package
artifacts, registry contents, private routes, or project approval are missing.
This repository contains no real customer trust/artifact/package/registry
inputs; no production preflight has passed.
