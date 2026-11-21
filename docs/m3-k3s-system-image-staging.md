# M3 K3s system-image approval and private staging

This procedure stages the K3s system/container images required by the
disposable Ubuntu 24.04 qualification cluster. It supports only K3s
`v1.36.6+k3s1`, `linux/amd64`, and manifest version `1`.

The workflow reuses the customer artifact-approval Ed25519 trust bundle and a
dedicated signature domain. It does not use maintenance-operation trust,
Kordex release signing trust, or tool-provenance trust. Customer approval
records the customer's review; it is not authenticated upstream provenance.
The pinned upstream standalone binary and image archive do not gain upstream
authenticity from HTTPS or adjacent unsigned checksum files.

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
   go run ./cmd/kordex-artifact-lock system-images sign \
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
   go run ./cmd/kordex-artifact-lock system-images verify \
     --bundle /custodian/incoming/k3s-airgap-images-amd64.tar \
     --lock /custodian/staging/k3s-system-images.lock \
     --signature /custodian/staging/k3s-system-images.lock.sig \
     --trust-bundle /custodian/independent-trust/customer-artifact.trust
   ```

7. Stage the verified content under an existing directory served by the
customer's private HTTPS artifact mirror:

   ```sh
   go run ./cmd/kordex-artifact-lock system-images stage \
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
   archive using its registry-ingestion procedure. The K3s bundle remains the
   digest-verified node-local image source; the configured private registry is
   the only allowed pull source for a cache miss. Public fallback is disabled.
8. Independently verify the HTTPS-served archive copy, lock, signature, and
inventory from a clean workstation. Deliver the public trust bundle by a
separate authenticated channel. Keep acquisition and approval evidence
outside the mirror. No real trust material or approved images are included in
this repository.

## Guarded lab preflight

Planning and applying require the binary and system-image approvals. The
helper verifies both locally before Terraform initialization, snapshots and
fingerprints all input files, passes only verified values as Terraform
variables, and rechecks inputs before applying the saved plan. The system
image lock binds the archive URL, digest, K3s version, architecture, manifest
version, registry host, and eight image digests. Terraform has no defaults for
these values and rejects mismatched version/architecture/URL/digest inputs.
Do not run Terraform plan/apply directly.

```sh
python3 scripts/self_managed_lab.py plan \
  --project-id CUSTOMER_DISPOSABLE_PROJECT \
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
