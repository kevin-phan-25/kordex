# M3 trust recovery and release artifact handoff

This handoff prepares M3 trust recovery for Debian 13 Trixie and RHEL 9.8+;
Ubuntu 24.04 remains supplemental. It does not create or
rotate signing keys, assert that artifacts are authentic, enable maintenance,
or qualify an upgrade. The maintenance signer, release signer, and offline
tool-provenance signer are separate trust domains. Never substitute one key
for another.

## Maintenance signing trust: authorized custodian

The customer/operator owns the Ed25519 maintenance signing key. The Kordex
management service reads the existing key through
`KORDEX_MAINTENANCE_SIGNING_KEY_FILE`; the managed-cluster operator receives
only a public JSON trust bundle through `KORDEX_HUB_PUBLIC_KEYS_FILE`. There
is no public API for recovering the bundle. The custodian must use the
organization's approved secret-management system and an authorized,
controlled environment.

1. Locate the exact existing maintenance key and its key ID/rotation record in
   the approved secret-management system. Confirm the secret version and
   custodian authorization. Do not create a replacement key if the secret or
   public bundle cannot be found.
2. Materialize the existing key only in a protected temporary directory in
   that environment. The key file format accepted by the current loader and
   exporter is unpadded standard Base64 containing either the 32-byte Ed25519
   seed or its canonical 64-byte private key. Restrict access to the custodian
   and the process that needs it; do not put the value in a command argument,
   shell history, environment dump, ticket, log, or repository file.
3. From a reviewed Kordex checkout at the approved source revision, run the
   exporter with paths only (not key values):

   ```sh
   umask 077
   workdir="$(mktemp -d)"
   chmod 0700 "$workdir"
   go run ./api/cmd/kordex-trust-export \
     -private-file /approved/secret-mount/maintenance.seed \
     -public-file "$workdir/keys.json"
   ```

   The output must be a new file; the exporter refuses to overwrite it. The
   input must be a regular non-symlink file with safe permissions. The
   exporter writes only public trust data. Do not copy the private seed into
   the checkout, deployment bundle, managed cluster, or development team.
4. Independently validate the JSON shape, decode each public key, and verify
   that each JSON map key is the SHA-256 key ID of that decoded Ed25519 key.
   Compare the ID with the custodian's independently maintained key inventory
   or original provisioning record. Validate with an independently reviewed
   verifier or a second implementation; successful exporter output alone is
   not an independent trust decision. Record the public file checksum and
   verification result, not private material.
5. Deliver the public bundle and its checksum/key IDs through a channel whose
   identity is independent of the artifact transfer channel. The operator
   consumes the bundle as the file named by `KORDEX_HUB_PUBLIC_KEYS_FILE`
   (the deployment mounts it at `/var/run/kordex-trust/keys.json`). Do not
   place private data in a ConfigMap.
6. Preserve rotation overlap. Before changing the management signer, publish a
   trust bundle containing the old and new independently verified public keys
   to operators. Keep old key IDs trusted while permits/operations signed by
   them may still need verification. The exporter derives one key at a time;
   do not replace an existing multi-key bundle with its single-key output.
   Retain prior verified public entries and their IDs according to the
   custodian's rotation record. Remove an old key only after the authorized
   operation/recovery retention window has ended.

**Private keys and seeds must never be sent to the development team.** If the
custodian cannot run the exporter, request delivery of the independently
verified public bundle and its key IDs only. If the existing key is missing,
M3 trust recovery is blocked pending the customer's approved backup/secret
recovery process.

## Release owner: required handoff package

Request the following from the release owner. Obtain trust roots and their
fingerprints over a channel independent of the bundle and artifact transfer.
Do not accept a public key solely because it is included in the package it is
supposed to verify.

| Material | Purpose | Independent verification |
|---|---|---|
| Signed offline release bundle and detached signature | Authenticates the release files, chart archives, image archives, scripts, and qualification tooling listed in its manifest. | Verify with the independently delivered release public key; then verify every manifest checksum. Use the verifier from a separately trusted checkout/tooling path, not the unverified bundle. |
| Signed image digest lock and detached signature | Binds component names to immutable image references/digests for deployment and execution-environment allowlists. | Run `scripts/verify-image-lock.sh LOCK LOCK.sig RELEASE_PUBLIC_KEY`; validate the lock's required names, repository paths, and digest syntax before use. |
| Debian 13 Trixie or RHEL 9.8+ package artifacts and policy-bound package manifest | Supplies the exact `.deb`/`.rpm` files required for offline execution; the maintenance plan must bind each package digest. The Debian custodian records the current stable point release at provisioning; RHEL must bind an exact minor >=9.8. | Verify the signed/approved policy and its plan digest, then check each artifact SHA-256, package metadata, architecture, private repository snapshot, baseline delta, kernel and reboot policy. Run the offline artifact staging verifier on a synthetic fixture only as a local code test. |
| Release public verification key and fingerprint | Establishes the release-signature trust root. | Confirm fingerprint through the release owner's separate authenticated channel; use only for the release bundle and image lock. |
| Tool-provenance public verification key and fingerprint | Establishes the signer for the offline tool lock (including Helm/kubectl acquisition records). | Confirm independently; run `scripts/verify-offline-tools-lock.sh LOCK LOCK.sig TOOL_PUBLIC_KEY HELM_SIGNER_ALLOWLIST`. |
| Helm signer allowlist | Restricts which upstream Helm signing keys are accepted during tool acquisition. | Obtain the approved fingerprints separately; compare the bundle copy byte-for-byte and validate fingerprints with `scripts/verify-offline-tools-lock.sh --check-helm-signers FILE`. |
| Artifact manifest and checksums | Binds filenames, versions, source, architecture, and expected bytes to the release. | Verify manifest signature through the release bundle, then run the repository's manifest checker and `sha256sum -c` only after authenticating the signed manifest. |
| Source revision and release version | Identifies the source corresponding to the binaries, charts, image lock, and evidence. | Match the release statement to the signed bundle manifest and independently inspect the stated source tag/commit. Record discrepancies; do not infer provenance from filenames. |
| Exact verification instructions and tool versions | Makes verification reproducible without trusting ad hoc commands from the transfer. | Cross-check commands against the reviewed verifier scripts at the stated source revision. Preserve command output and tool versions in the evidence archive. |

Keep these trust roots distinct:

- **Maintenance trust** authorizes/verifies maintenance plans and permits in
  the operator. It is customer-controlled and derives from the existing
  maintenance key.
- **Release trust** verifies the signed Kordex release bundle and image lock.
- **Tool provenance trust** verifies the offline Helm/kubectl acquisition lock
  and approved Helm signing fingerprints.
- **Customer artifact-approval trust** verifies customer-signed acquisition
  approval locks such as the K3s qualification binary. It does not prove
  upstream provenance and is separate from all Kordex key roles. See
  `docs/m3-customer-artifact-approval.md`.

None of these trust roots authenticates the others. The signed bundle's copy
of a public key or allowlist is not an independent trust source.

## Existing local verification procedures

Run from a reviewed repository checkout. These commands verify actual supplied
artifacts only when the input files and independent trust roots are real and
authenticated. Current local fixture tests do not establish that any Kordex
release artifact has been signed or delivered.

```sh
# Bundle signature plus signed-manifest and file checksum checks.
KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY=/trusted/tools-acquisition-public.pem \
KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE=/trusted/helm-signers.txt \
  scripts/verify-offline-bundle.sh /verified-transfer/bundle \
  /trusted/kordex-release-public.pem

# Signed image lock.
scripts/verify-image-lock.sh /verified-transfer/images.tsv \
  /verified-transfer/images.tsv.sig /trusted/kordex-release-public.pem

# Signed tool provenance lock and Helm signer allowlist.
scripts/verify-offline-tools-lock.sh /verified-transfer/offline-tools.tsv \
  /verified-transfer/offline-tools.tsv.sig \
  /trusted/tool-provenance-public.pem /trusted/helm-signers.txt

# Policy-bound package artifacts: validate/stage against the reviewed policy.
python3 scripts/install-offline-package-artifacts.py --help
```

The exact package staging invocation depends on the approved policy and target
cache path; it must be taken from the matching release's runbook. The helper
checks package contents against policy-bound SHA-256 digests. This is not a
substitute for independently authenticating the policy and its signer.

For upstream Helm acquisition, `scripts/acquire-offline-tools.sh` checks the
Helm archive signature against the independently approved signer allowlist and
checks the pinned tool provenance lock. Helm chart archives carried inside a
release bundle are covered by the signed bundle manifest; the chart digest
alone does not authenticate a chart independently of that bundle.

Maintenance plan signature verification is performed by the operator using
the key ID and Ed25519 public key from `KORDEX_HUB_PUBLIC_KEYS_FILE`. Relevant
local contracts include `api/protocol/maintenance_test.go` and operator
controller signature/admission tests. These prove code behavior with test
keys, not trust in a production plan or recovered customer key.

## M3 preflight status checklist

| Stage | Evidence required | Current status |
|---|---|---|
| Local code validation | Exporter tests, protocol/operator tests, offline bundle/image-lock/tool/package fixture tests. | Can be checked locally; fixture-only results are not release evidence. |
| Maintenance trust recovery | Existing customer signing key in approved custody; matching independently checked public trust bundle with rotation overlap. | **Blocked** until the authorized custodian supplies the verified public bundle/key IDs. |
| Real release artifact verification | Actual signed release bundle, image lock, tool lock, release/tool public keys, Helm allowlist, Debian 13 Trixie or RHEL 9.8+ package artifacts and signed policy; Ubuntu 24.04 is supplemental. | **Blocked** until the release owner provides the complete handoff and independent trust roots. |
| Disposable Debian 13 or RHEL 9.8+ lab readiness | Approved disposable project/VM, reachable authenticated Kordex API, customer-approved image/repositories, cluster/operator/agent prerequisites, and clean baseline. Ubuntu 24.04 may be used only for supplemental tests. | **Not ready** until lab and connectivity prerequisites are supplied and reviewed. |
| Real maintenance execution | Approved target and plan, successful read-only preflight, explicit operator gate enabled only in the disposable lab, and human execution approval. | **Not run**; execution gate must remain off elsewhere. |
| Reboot and recovery | Real package transaction, reboot/boot-ID and kernel checks, node/workload readiness, reservation/cordon release evidence. | **Not run**. |
| Failure injection | Supported cancel/interruption/failure cases on a disposable baseline, with safe recovery for each case. | **Not run**. |
| Evidence archival | Signed/verified evidence bundle, checksums, test environment and source revision, stored off-cluster and independently reviewed. | **Not run**. |

M3 is **NOT READY** until the trust and release materials are independently
verified, the disposable Ubuntu lab is ready, and real maintenance, reboot,
recovery, failure-injection, and evidence-verification acceptance passes.
Production qualification must not be claimed from local tests or documents.
