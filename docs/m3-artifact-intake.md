# M3 customer artifact intake and private registry preflight

This workflow composes the existing Kordex verifiers before any M3 lab plan. It
does not add a signing format, publish or push artifacts, or create trust. The
JSON report is an unsigned, deterministic point-in-time summary. `PASS` means
the listed existing checks passed with the supplied local inputs; it is not
upstream provenance, a qualification result, or a substitute for approval.

## Separate trust domains and owners

| Input | Owner | Existing verification and consumption |
|---|---|---|
| Maintenance public trust bundle (`keys.json`) | Maintenance signing-key custodian | JSON maps SHA-256 Ed25519 key IDs to canonical base64 public keys. The custodian supplies independently confirmed key IDs. The operator consumes it as `KORDEX_HUB_PUBLIC_KEYS_FILE`; it does not verify release or artifact signatures. |
| Customer artifact-approval trust | Supply-chain custodian | `KORDEX-CUSTOMER-ARTIFACT-TRUST-V1`; existing `kordex-artifact-lock` verifies K3s binary and system-image signatures in separate domains. |
| Kordex release public key | Release owner | Existing signed offline bundle and image-lock verifiers (`verify-offline-bundle.sh`, `verify-image-lock.sh`). Expected SHA-256 fingerprint arrives independently. |
| Tool provenance public key and Helm signer allowlist | Tool/release owner | Existing `verify-offline-tools-lock.sh` and bundle verifier require the separately trusted tool signer and byte-identical allowlist. |
| K3s binary and system images | Supply-chain custodian | Signed locks bind `v1.36.6+k3s1`, `linux/amd64`, mirror references, digests, and approval references. A customer-selected maximum age of 1–365 days is enforced using signed UTC `approvedAt`; the lock format has no native expiry field. |
| Ubuntu package plan and `.deb` archive | Kordex administrator and package custodian | Existing package verifier binds the exact policy digest, package name/version and SHA-256. Preflight requires Ubuntu 24.04, package architecture `amd64`/`all`, a baseline with at least one version delta, and kernel/reboot consistency. It fetches the exact archive from the configured HTTPS private source, pins the connection to approved private CIDRs while verifying the DNS hostname certificate, rejects redirects, compares the served archive to the selected local archive SHA-256, then stages and validates packages from the fetched bytes. |

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
   `PASS` requires all 12 required artifact rows to pass. Missing inputs remain
   `NOT PROVIDED`; supplied invalid or inconsistent inputs are `FAIL`. Only an
   overall `PASS` is accepted by the guarded lab helper.

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
    "imageDigestSignature": "/artifacts/kordex-images.tsv.sig"
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
  "ubuntuPackages": {
    "policy": "/artifacts/ubuntu-24.04-policy.json",
    "archive": "/artifacts/ubuntu-24.04-packages.tar",
    "approvedPolicySHA256": "<approved-policy-sha256>",
    "baselineVersions": {"<package-name>": "<currently-installed-version>"},
    "privateMirrorURL": "https://<private-package-mirror>/<exact-package-bundle-path>",
    "privateMirrorCIDRs": ["<approved-private-cidr>"]
  }
}
```

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
