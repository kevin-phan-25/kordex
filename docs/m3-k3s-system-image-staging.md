# M3 K3s system-image approval and private staging

This procedure stages the K3s system/container images for the disposable M3
K3s lab running the required Debian 13 and genuine RHEL 9.8-or-later profiles.
The archive is a K3s runtime input; it does not approve or identify either guest
OS. It supports only K3s `v1.36.6+k3s1`, `linux/amd64`, and manifest version
`1`.

The workflow reuses the customer artifact-approval Ed25519 trust bundle and a
dedicated signature domain. It does not use maintenance-operation trust,
Kordex release signing trust, or tool-provenance trust. Customer approval
records the customer's review; it is not authenticated upstream provenance.
The pinned upstream standalone binary and image archive do not gain upstream
authenticity from HTTPS or adjacent unsigned checksum files.

Verification and staging require a locally available Go toolchain and the
module dependencies already present in its cache. Commands set `GOPROXY=off`,
`GOSUMDB=off`, and `GOTOOLCHAIN=local`; they fail if a dependency/toolchain is
missing instead of downloading it. Skopeo registry ingestion and inspection
must use the customer's private route and registry only.

## Required image set

The expected source references are copied from the pinned upstream release's
[`scripts/airgap/image-list.txt`](https://github.com/k3s-io/k3s/blob/v1.36.6%2Bk3s1/scripts/airgap/image-list.txt).
The verifier requires exactly these references and does not trust this list as
a source of image digests:

```text
docker.io/rancher/klipper-helm:v0.13.3-build20261021
docker.io/rancher/klipper-lb:v0.4.17
docker.io/rancher/local-path-provisioner:v0.0.37
docker.io/rancher/mirrored-coredns-coredns:1.14.7
docker.io/rancher/mirrored-library-busybox:1.37.0
docker.io/rancher/mirrored-library-traefik:3.7.15
docker.io/rancher/mirrored-metrics-server:v0.9.0
docker.io/rancher/mirrored-pause:3.10.2
```

The signed OCI archive is bounded to 512 MiB and contains the actual
descriptors and blobs. The verifier
checks archive SHA-256, exact image references, platform, image manifest,
configuration, and every layer digest. No image is pulled during verify or
stage. The customer must acquire the release archive under its own approved
process and review the binary/image contents. Test fixtures are synthetic and
must never be used as production artifacts.

## Manifest format

`KORDEX-CUSTOMER-K3S-SYSTEM-IMAGES-LOCK-V1` is canonical UTF-8 text with
fixed-order fields, one field per line. The final rows are repeated in the
fixed upstream image-list order:

```text
image=<original-image-reference>\t<customer-private-image-reference>\tsha256:<manifest-digest>
```

The signed bytes bind manifest version, K3s version, architecture, archive
name, archive digest algorithm and digest, fixed upstream source URL, exact
private HTTPS archive URL, checksum/acquisition/approval evidence references,
approver, UTC approval time, signer key ID, image count, and every original to
private registry reference plus manifest digest mapping. The lock uses a
fixed-order line representation rather than JSON to reject duplicate or
ambiguous fields. Its Ed25519 signature uses the dedicated
`kordex.customer-artifact-approval.k3s-system-images.v1` domain and the
existing independently provisioned customer artifact trust bundle.

The private archive URL must point to the content-addressed staged object:

```text
<private-https-root>/k3s/v1.36.6+k3s1/linux-amd64/<archive-sha256>/k3s-airgap-images-amd64.tar
```

The `+` in the version may be percent-encoded as `%2B`. The lock verifier
normalizes the URL path and checks this suffix against the verified archive
digest. All K3s image mirror references must use one customer-controlled
registry host on TCP/443 and preserve each source repository path and tag.
Public registry hosts are rejected.

## Customer custodian procedure

The supply-chain custodian owns acquisition, review, approval, signing, and
registry publication. Kordex does not generate a production key or fetch an
artifact.

1. Obtain the exact K3s `v1.36.6+k3s1` amd64 airgap archive from the
organization's approved acquisition process. Keep source and acquisition
evidence. An upstream adjacent checksum may be recorded as an observation but
must not be described as upstream authentication.
2. Review/approve the archive and its eight required images under the
customer's supply-chain controls. Record the image manifest digests and an
immutable approval/evidence reference.
3. Copy the archive to a restricted signing workspace. Compute its SHA-256
only to construct the content-addressed mirror URL. This value is not trusted
until the approved lock is signed and independently verified:

   ```sh
   sha256sum /custodian/incoming/k3s-airgap-images-amd64.tar
   ```

   Set `ARCHIVE_SHA256` in the custodian shell to the lowercase digest from
   this output. The digest is not a credential; do not substitute a digest
   from an unsigned manifest as an approval.

4. Use the already existing customer-controlled artifact-approval key and
independently provisioned trust bundle. Do not use a maintenance, release, or
tool-provenance key. The signing key must stay in the custodian's approved key
system and must never be sent to the Kordex development team.
5. Create the signed lock. `<archive-sha256>` below must be the value computed
for the exact local archive, and `bundle-mirror-url` must map to the same
content-addressed path that `stage` will create under the mirror root:

   ```sh
   cd api
   GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go run ./cmd/kordex-artifact-lock system-images sign \
     --bundle /custodian/incoming/k3s-airgap-images-amd64.tar \
     --private-key-file /custodian/secret-mount/existing-artifact-approval.seed \
     --trust-bundle /custodian/independent-trust/customer-artifact.trust \
     --bundle-mirror-url "https://mirror.customer.invalid/k3s/v1.36.6+k3s1/linux-amd64/${ARCHIVE_SHA256}/k3s-airgap-images-amd64.tar" \
     --mirror-registry registry.customer.invalid \
     --checksum-evidence-ref CUSTOMER_EVIDENCE_REFERENCE \
     --acquisition-ref CUSTOMER_ACQUISITION_REFERENCE \
     --approval-ref CUSTOMER_APPROVAL_REFERENCE \
     --approved-by CUSTOMER_APPROVER_REFERENCE \
     --approved-at 2026-11-21T12:00:00Z \
     --lock-out /custodian/staging/k3s-system-images.lock \
     --signature-out /custodian/staging/k3s-system-images.lock.sig
   ```

   The command verifies that the existing signing key is represented in the
   independent trust bundle and refuses to overwrite lock/signature outputs.
6. Verify the lock and archive offline with the customer trust bundle:

   ```sh
   GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go run ./cmd/kordex-artifact-lock system-images verify \
     --bundle /custodian/incoming/k3s-airgap-images-amd64.tar \
     --lock /custodian/staging/k3s-system-images.lock \
     --signature /custodian/staging/k3s-system-images.lock.sig \
     --trust-bundle /custodian/independent-trust/customer-artifact.trust
   ```

7. Stage the verified content under an existing directory served by the
customer's private HTTPS artifact mirror:

   ```sh
   GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go run ./cmd/kordex-artifact-lock system-images stage \
     --bundle /custodian/incoming/k3s-airgap-images-amd64.tar \
     --lock /custodian/staging/k3s-system-images.lock \
     --signature /custodian/staging/k3s-system-images.lock.sig \
     --trust-bundle /custodian/independent-trust/customer-artifact.trust \
     --output-root /srv/private-artifacts
   ```

   This creates the content-addressed directory containing the archive,
   `k3s-system-images.lock`, detached signature, deterministic `inventory.json`,
   and `registries.yaml`. Staging is atomic and idempotent for identical
   content; a conflict is an error, not an overwrite. The customer must publish
   the mapped image tags to the named private OCI registry from this reviewed
   archive. The repository does not push the eight K3s images: the following
   customer-operated Skopeo procedure consumes the signed mapping and verifies
   the registry's returned digest for each push. It requires Skopeo, Python 3,
   `sha256sum`, an independently verified lock/trust bundle, and a customer
   registry auth file stored outside the repository. Skopeo's
   `oci-archive:<path>:<reference>` source selects the matching archive
   reference; `--preserve-digests` fails if the registry requires a manifest
   conversion that changes approved bytes.

   ```sh
   set -euo pipefail
   # Run from the repository root. The lock verifier has no registry write
   # capability; Skopeo below is the only command that publishes images.
   ARCHIVE=/srv/private-artifacts/k3s/v1.36.6+k3s1/linux-amd64/REPLACE_WITH_BUNDLE_SHA256/k3s-airgap-images-amd64.tar
   LOCK=/srv/private-artifacts/k3s/v1.36.6+k3s1/linux-amd64/REPLACE_WITH_BUNDLE_SHA256/k3s-system-images.lock
   SIGNATURE="${LOCK}.sig"
   TRUST=/etc/kordex/trust/customer-artifact.trust
   REGISTRY_AUTH_FILE=/run/customer-secrets/registry-auth.json

   # Re-verify the signed lock and exact archive immediately before ingestion.
   # The verified JSON inventory, not a second parse of the lock, supplies the
   # image references and digests consumed by the push loop.
   INGEST_TMP="$(mktemp -d)"
   trap 'rm -rf -- "$INGEST_TMP"' EXIT
   INVENTORY="$INGEST_TMP/verified-inventory.json"
   MAPPINGS="$INGEST_TMP/verified-mappings.tsv"
   GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go -C api run ./cmd/kordex-artifact-lock system-images verify \
     --bundle "$ARCHIVE" --lock "$LOCK" --signature "$SIGNATURE" \
     --trust-bundle "$TRUST" --json > "$INVENTORY"

   python3 - "$INVENTORY" > "$MAPPINGS" <<'PY'
   import json, re, sys
   with open(sys.argv[1], encoding="utf-8") as source:
       inventory = json.load(source)
   if (inventory.get("manifestVersion") != "1"
           or inventory.get("k3sVersion") != "v1.36.6+k3s1"
           or inventory.get("architecture") != "linux/amd64"
           or not isinstance(inventory.get("images"), list)
           or len(inventory["images"]) != 8):
       raise SystemExit("verified inventory is not the supported K3s image set")
   digest = re.compile(r"^sha256:[a-f0-9]{64}$")
   for image in inventory["images"]:
       source = image.get("SourceReference")
       mirror = image.get("MirrorReference")
       expected = image.get("Digest")
       if (not all(isinstance(value, str) for value in (source, mirror, expected))
               or any("\t" in value or "\n" in value for value in (source, mirror, expected))
               or not digest.fullmatch(expected)):
           raise SystemExit("verified inventory contains an invalid image mapping")
       print("\t".join((source, mirror, expected)))
   PY

   python3 - "$REGISTRY_AUTH_FILE" <<'PY'
   import os, stat, sys
   info = os.stat(sys.argv[1], follow_symlinks=False)
   if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or not 0 < info.st_size <= 1024 * 1024:
       raise SystemExit("registry auth file must be a private regular file (0600 or stricter)")
   PY

   while IFS=$'\t' read -r source_reference mirror_reference expected_digest; do
     digest_file="$INGEST_TMP/destination.digest"
     rm -f -- "$digest_file"
     if ! env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
       skopeo copy --quiet --preserve-digests --dest-tls-verify=true \
         --dest-authfile "$REGISTRY_AUTH_FILE" --digestfile "$digest_file" \
         "oci-archive:${ARCHIVE}:${source_reference}" \
         "docker://${mirror_reference}"; then
       echo "K3s image registry ingestion failed for ${source_reference}" >&2
       exit 1
     fi
     observed_digest="$(tr -d '\r\n' < "$digest_file")"
     if [[ "$observed_digest" != "$expected_digest" ]]; then
       echo "K3s registry digest differs from the signed lock for ${source_reference}" >&2
       exit 1
     fi
     printf 'PASS %s %s\n' "$source_reference" "$observed_digest"
   done < "$MAPPINGS"
   ```

   The lock fixes the source reference, mirror reference, and expected digest;
   the command takes no image or registry mapping from user input. Each printed
   `PASS` must show the exact signed digest. A failure can leave earlier
   references published, so treat the registry as partially populated and
   rerun the same verified process after correcting the destination. Never
   rewrite the lock or accept a changed digest to make ingestion pass.

   After the K3s images and the six Kordex release images have both been
   populated, run the read-only 14-image check used by the consolidated
   preflight. Supply the Kordex image lock/signature and release public key from
   their separate release trust domain. Replace the example registry hostname
   with the exact host in the signed K3s mirror mappings, and supply one
   `--private-cidr` for each approved private registry range. The output path
   must be new:

   ```sh
   python3 scripts/verify-private-registry.py \
     --system-image-bundle "$ARCHIVE" --system-image-lock "$LOCK" \
     --system-image-signature "$SIGNATURE" --artifact-trust "$TRUST" \
     --expected-host registry.customer.invalid --private-cidr 10.80.0.0/24 \
     --authfile "$REGISTRY_AUTH_FILE" \
     --output /secure/m3/private-registry-verification.json \
     --kordex-image-lock /secure/release/kordex-images.tsv \
     --kordex-image-signature /secure/release/kordex-images.tsv.sig \
     --release-public-key /etc/kordex/trust/kordex-release.pub
   ```

   Success exits `0` and writes a new mode-0600 deterministic JSON report with
   `status: PASS`, `architecture: linux/amd64`, and exactly 14 image results.
   The report contains references and digests, never credentials. This verifier
   is read-only: it inspects manifest/config data and copies approved content
   to a temporary local OCI layout; it never pushes. A missing image, tag that
   points at another digest, missing blob, wrong architecture, TLS/DNS failure,
   or registry auth failure is not a pass. The Skopeo source transport and
   digest-file behavior are documented in the [Skopeo copy reference](https://github.com/containers/skopeo/blob/main/docs/skopeo-copy.1.md)
   and [containers/image transport reference](https://github.com/containers/image/blob/main/docs/containers-transports.5.md).

   The K3s bundle remains the digest-verified node-local image source; the
   configured private registry is the only allowed pull source for a cache
   miss. Public fallback is disabled. Staging is not evidence that the OCI
   registry contains expected tags. This Skopeo loop is the customer-operated
   writer for the eight K3s image tags; the separate Kordex release image
   ingestion uses `push-offline-bundle.sh`. The consolidated
   preflight in [`m3-artifact-intake.md`](m3-artifact-intake.md) re-verifies
   both signed locks, inspects each private mirror manifest/config, and copies
   the approved digest into a temporary local OCI layout to validate the
   complete image content graph. The checker does not push to the registry.
   A customer auth file is supplied by path outside Git; no credential value is
   accepted on the command line.
8. Independently verify the HTTPS-served archive copy, lock, signature, and
inventory from a clean workstation. Deliver the public trust bundle by a
separate authenticated channel. Keep acquisition and approval evidence
outside the mirror. No real trust material or approved images are included in
this repository.

## Guarded lab preflight

Planning, applying, and qualification execution require the consolidated
report to be `PASS` for all trust domains, signed release artifacts, registry
contents, selected-profile Debian or RHEL package inputs, K3s binary, and system-image archive. The
helper regenerates the report before Terraform planning and applying, binds
report K3s hashes to the command-line artifacts, and retains the existing
direct signature checks and Terraform input binding. The guarded execution
command repeats this check after the disposable-project confirmation. No
customer inputs are present in this repository, so no production preflight or
plan has passed. Do not run Terraform or the qualification runner directly.

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id kordex-fleet-platform-515416 \
  --m3-artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --m3-artifact-report /secure/m3/artifact-preflight.json \
  --k3s-binary /verified/k3s \
  --k3s-artifact-lock /verified/k3s.artifact-lock \
  --k3s-artifact-signature /verified/k3s.artifact-lock.sig \
  --k3s-artifact-trust /independent-trust/customer-artifact.trust \
  --k3s-system-images-bundle /verified/k3s-airgap-images-amd64.tar \
  --k3s-system-images-lock /verified/k3s-system-images.lock \
  --k3s-system-images-signature /verified/k3s-system-images.lock.sig \
  --k3s-system-images-trust /independent-trust/customer-artifact.trust
```

At startup every VM checks manifest version `1`, K3s release, `linux/amd64`,
and the exact archive SHA-256 before placing the archive at
`/var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar`. Existing
unexpected cache files, a wrong archive, or conflicting `registries.yaml`
cause bootstrap to stop. K3s starts only after this succeeds and runs with
`--disable-default-registry-endpoint`; there is no public registry fallback.
The server and both workers use the same signed archive and registry mapping.

## Remaining external inputs and limitations

- An existing customer artifact-approval key and independently distributed
  public trust bundle.
- Customer-approved K3s executable and system-image archive, signed locks,
  signatures, acquisition/approval evidence, private archive URL, and private
  OCI registry contents.
- Customer private HTTPS mirror, TLS certificate chain, private route/DNS,
  registry availability, and approved egress CIDRs.
- The Kordex agent/operator/Ansible execution-environment images and their
  separate verified digest/release trust materials.
- No live lab, customer registry, signature, or artifact was verified here.
  Local synthetic tests do not qualify M3. The canonical M3 matrix remains
  NOT RUN until actual host maintenance, reboot/recovery, failure injection,
  and evidence verification pass.
