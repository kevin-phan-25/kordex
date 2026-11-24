# Kordex M3 disposable lab: customer handoff packet

**Current status: M3 is NOT QUALIFIED. No M3 matrix row is complete.** This
packet assigns the inputs and reviews needed before a disposable lab deployment
using Debian 13 Trixie or RHEL 9.8+; Ubuntu 24.04 is supplemental only. It does not authorize a Terraform plan or apply,
enable APIs, grant IAM, deploy workloads, or run maintenance.

Use the dependency-ordered [M3 qualification controller and customer execution
sequence](m3-qualification-controller.md) as the current operator entry point.
Its [version-1 customer input schema](schemas/m3-customer-inputs-v1.json)
identifies the required customer deliverables. The synthetic example cannot
pass production readiness.

The customer-facing readiness status and local read-only gate are maintained
in [`m3-deployment-readiness.md`](m3-deployment-readiness.md). The canonical
acceptance criteria remain in
[`production-upgrade-requirements.md`](production-upgrade-requirements.md).
This packet is a collection request, not a replacement for either document.
The current role-based delivery matrix and runnable owner checks are in
[`m3-external-owner-delivery.md`](m3-external-owner-delivery.md), with the
machine-readable 47-slot manifest at
[`m3-external-delivery-manifest.json`](m3-external-delivery-manifest.json).
For the concise Debian 13/RHEL 9 owner matrix, all 11 scenario-by-platform
evidence requests, and the exact NOT RUN status, see the
[platform qualification handoff](m3-platform-qualification-handoff.md).

## How to use this packet

Each owner should provide the named public artifacts, non-secret configuration,
or review evidence to the customer's designated M3 coordinator. Record the
actual path in the customer-local input map; the examples below are suggested
paths unless the underlying format fixes a filename. Keep the input map,
network details, reports, and evidence outside Git. Customer-owned signing
keys, private keys, tokens, passwords, and registry credentials stay in the
customer's approved secret-management system.

Use these statuses in the master checklist and sign-off:

| Status | Meaning |
|---|---|
| `NOT PROVIDED` | The required customer artifact or evidence has not been supplied. |
| `PROVIDED, NOT VERIFIED` | An owner supplied it, but the required independent validation has not passed. |
| `VERIFIED LOCALLY` | The repository's local verifier or tests passed. This does not prove customer provenance or live behavior. |
| `VERIFIED IN CUSTOMER ENVIRONMENT` | The named live customer-system check passed and its evidence reference is recorded. |
| `BLOCKED` | A dependent activity must not proceed until the item is accepted. |

The previous repository readiness snapshot is historical. The current local
environment has Skopeo 1.24.0; `gh` is not installed here, so the existing
offline GitHub attestation verifier cannot run in this shell. Customer
network and artifact inputs, live project state, APIs/IAM, billing, private
route/PKI, and actual Terraform inputs remain unverified in this packet. No
input is `VERIFIED IN CUSTOMER ENVIRONMENT` for this packet.

## A. Security and trust custodian

Keep these trust domains separate: maintenance operation signing, customer
artifact approval, Kordex release signing, and tool provenance. None
authenticates another. The root-signed Kordex trust configuration also
designates `artifact-owner` identities and a distinct `reviewer` for the
report-bound independent artifact-review record.

| Request and expected file | Source, format, and verification | Acceptance and blocked work |
|---|---|---|
| Existing maintenance public bundle: `keys.json` | Maintenance-key custodian recovers the existing signer through approved secret management and runs the exporter in that authorized environment: `go run ./api/cmd/kordex-trust-export -private-file /approved/secret-mount/maintenance.seed -public-file /approved/staging/keys.json`. The output is public JSON mapping SHA-256 Ed25519 key IDs to canonical unpadded Base64 public keys. Independently decode the public keys and compare each ID/fingerprint with the custodian inventory. The artifact preflight checks format and expected key IDs. The operator consumes it as `KORDEX_HUB_PUBLIC_KEYS_FILE`. | Accept only the existing custodian-approved key IDs and a bundle whose IDs match their public keys. Unknown/mismatched IDs block deployment, permit verification, and artifact preflight. **Kordex does not need private signing keys. Never send a key, seed, or signing credential.** See [`m3-trust-recovery-handoff.md`](m3-trust-recovery-handoff.md). |
| Maintenance key rotation/overlap evidence | Provide a change record or custodian attestation listing old/new key IDs, rotation and revocation dates, overlap/retention window, and treatment of outstanding operations. The repository does not define a machine-readable rotation-evidence file; provide an evidence reference and reviewer. | Accept only when the approved public bundle and rotation record agree and outstanding signed operations remain verifiable under the customer's policy. Blocks maintenance trust acceptance. |
| Customer artifact-approval trust: `customer-artifact.trust` (suggested basename) | Organization-controlled Ed25519 public bundle, exact header `KORDEX-CUSTOMER-ARTIFACT-TRUST-V1`, sorted key-ID/public-key entries. Independently confirm the key ID through a channel separate from the mirror. The same trust bundle verifies K3s binary and system-image locks in separate signature domains. | Accept only customer-custodian-approved key IDs and valid public encodings. This is customer approval, **not upstream K3s provenance**. Blocks K3s lock verification, artifact preflight, and the guarded lab plan. See [`m3-customer-artifact-approval.md`](m3-customer-artifact-approval.md). |
| Kordex release public verification key and fingerprint: for example `kordex-release.pub` | Release owner supplies the public key in the format accepted by OpenSSL Ed25519 verification and its SHA-256 fingerprint via an independent authenticated channel. Verify the fingerprint locally with `openssl pkey -pubin -in /trusted/kordex-release.pub -outform DER | sha256sum`. Configure that independently confirmed fingerprint in `trust.releaseExpectedFingerprint` in the customer-local input map. | Accept only when computed and independently supplied fingerprints match. This key is only for the Kordex release bundle/image lock. Blocks release bundle, image-lock, and artifact preflight. |
| Tool-provenance public key, signed lock, and Helm signer allowlist: `offline-tools.tsv`, `offline-tools.tsv.sig`, `offline-tools.signer.pub`, `offline-tools.helm-signers.txt` | Tool/release owner supplies the public key and independent fingerprint, detached Ed25519 signature, four-row tool lock, and non-empty text allowlist of 40–64 hex fingerprints. Verify the fingerprint with `openssl pkey -pubin -in /trusted/offline-tools.signer.pub -outform DER | sha256sum`; verify the lock with `scripts/verify-offline-tools-lock.sh /verified/offline-tools.tsv /verified/offline-tools.tsv.sig /trusted/offline-tools.signer.pub /trusted/offline-tools.helm-signers.txt`; validate the allowlist alone with `scripts/verify-offline-tools-lock.sh --check-helm-signers /trusted/offline-tools.helm-signers.txt`. | Accept only if lock signature, tool identities/versions/architectures/digests, Helm signer allowlist, and independent key fingerprint all validate. Keep tool provenance separate from release signing. Blocks offline tool acquisition and release bundle verification. |

Public-key basenames above are transfer conventions, not all enforced names;
the local input-map schema accepts customer-selected paths. Do not send
private keys, passwords, tokens, or values from a secret manager. For the
maintenance exporter, only the authorized custodian handles the private file;
only `keys.json` and independent public-key evidence are handed off.

## B. Release and platform artifact owner

Provide complete artifacts from the organization's approved acquisition and
release process. A filename, HTTPS download, adjacent checksum, or synthetic
fixture is not approval. Record source, owner, version, approval date, and
checksum or signed digest for each item. Except for fixed names inside the
signed release bundle, artifact paths are supplied through the customer-local
input map and are not hard-coded by Kordex; the names below match repository
examples and are recommended transfer names.

| Request and expected file(s) | Required format and validation | Acceptance and blocked work |
|---|---|---|
| Signed Kordex offline release bundle directory; contains `SHA256SUMS`, `SHA256SUMS.sig`, `bin/tools/offline-tools.signer.pub`, and `bin/tools/offline-tools.helm-signers.txt` | Release owner gives the release version/source revision and detached Ed25519 public key. Set only the public paths, then run `KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY=/trusted/offline-tools.signer.pub KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE=/trusted/offline-tools.helm-signers.txt scripts/verify-offline-bundle.sh /verified/kordex-offline /trusted/kordex-release.pub`. The verifier checks the bundle signature, embedded tool signer/allowlist equality, manifest safety, and every `SHA256SUMS` entry. | Accept only if the release key fingerprint was independently confirmed, signature and all checksums pass, tool trust matches, and version/revision are recorded. Blocks deployment and artifact preflight. Details: [`air-gapped-deployment.md`](air-gapped-deployment.md#build-and-transfer-an-offline-bundle). |
| Signed six-image lock and detached signature, e.g. `kordex-images.tsv` and `kordex-images.tsv.sig` | Lock contains the exact components `agent`, `operator`, `control-plane`, `dashboard`, `ansible-ee`, and `postgres`, with immutable OCI references/digests. Verify `bash scripts/verify-image-lock.sh /verified/kordex-images.tsv /verified/kordex-images.tsv.sig /trusted/kordex-release.pub`. The registry verifier separately checks private destinations and `linux/amd64` image content. | Accept only if the independent release key verifies the lock and it has the exact required components with immutable digests. Blocks image ingestion, artifact preflight, and deployment. |
| K3s binary, signed lock, detached signature, customer artifact trust, and acquisition record: `k3s`, `k3s.artifact-lock`, `k3s.artifact-lock.sig`, `customer-artifact.trust` | Required version `v1.36.6+k3s1`, platform `linux/amd64`. The signed lock binds artifact, version, architecture, SHA-256, upstream source URL, exact private HTTPS mirror URL, approval/acquisition/checksum-evidence references, approver, UTC timestamp, and key ID. Customer-selected `trust.artifactApprovalMaxAgeDays` must be an integer from 1 through 365. Verify offline: `cd api && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go run ./cmd/kordex-artifact-lock verify --binary /verified/k3s --lock /verified/k3s.artifact-lock --signature /verified/k3s.artifact-lock.sig --trust-bundle /trusted/customer-artifact.trust`. | Accept only if signature is verified against independently distributed trust and binary digest, ELF architecture, version, and approval age match. The customer record must identify the acquisition/review/approval authority. Customer approval is not upstream provenance. Blocks bootstrap and plan. |
| K3s system-image archive and signed lock: `k3s-airgap-images-amd64.tar`, `k3s-system-images.lock`, `k3s-system-images.lock.sig`, same customer artifact trust | Exactly eight K3s system images, `v1.36.6+k3s1`, `linux/amd64`, manifest version `1`. Verify offline: `cd api && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go run ./cmd/kordex-artifact-lock system-images verify --bundle /verified/k3s-airgap-images-amd64.tar --lock /verified/k3s-system-images.lock --signature /verified/k3s-system-images.lock.sig --trust-bundle /trusted/customer-artifact.trust --json`. | Accept only the exact signed references, private mirror map, architecture, archive, manifest/config/layer digests, and approval age. Blocks bootstrap and plan. Staging does not populate the registry. See [`m3-k3s-system-image-staging.md`](m3-k3s-system-image-staging.md#customer-custodian-procedure). |
| Platform package policy, metadata, archive, and baseline: suggested local names `<os-profile>-policy.json`, `<os-profile>-packages.tar` | Customer package custodian provides approved policy and independently approved policy SHA-256, exact package names/versions/architecture/digests, baseline versions, private HTTPS mirror URL/CIDRs, expected package delta, and kernel/reboot policy. The generic `packageArtifacts` preflight validates supported `.deb`/`.rpm` policy-bound archives with `python3 scripts/m3_artifact_preflight.py --inputs /secure/m3/customer-artifact-inputs.json --report /secure/m3/artifact-preflight.json`. Debian and RPM package metadata are parsed with `dpkg-deb` and `rpm` respectively. The lab has Ubuntu 24.04 supplemental, Debian 13 Trixie, and RHEL 9.8+ bootstrap profiles. Debian requires the owner-approved 13.8 point release. RHEL requires an approved exact image and signed private RPM/SELinux inputs; RPM parsing alone does not make the profile deployable. The policy schema is in [`m3-artifact-intake.md`](m3-artifact-intake.md). | At least one real package version must change. Package hashes and metadata must match the approved policy; baseline delta, kernel expectation, reboot behavior, and private source must be consistent. Customer tests with synthetic RPM bytes are not production artifact evidence. |

### Artifact verification and handoff files

Use a customer-local input map outside the checkout, conventionally
`/secure/m3/customer-artifact-inputs.json`, mode `0600`. Its keys and example
paths are defined in [`m3-artifact-intake.md`](m3-artifact-intake.md#customer-local-input-file);
do not add credential values. The preflight report is conventionally
`/secure/m3/artifact-preflight.json`. Run:

```sh
python3 scripts/m3_artifact_preflight.py \
  --inputs /secure/m3/customer-artifact-inputs.json \
  --report /secure/m3/artifact-preflight.json
```

Expected acceptance is exit status `0`, overall `PASS`, and every required
artifact row `PASS`, including independent artifact review. The preflight
separates structural manifest validation, repository metadata signatures,
SBOM verification, provenance verification, independent review, and the
overall result. For the review, use the two-pass process and exact signed
record contract in [`m3-artifact-intake.md`](m3-artifact-intake.md#independent-artifact-review-record).
SBOM and provenance rows are evaluated separately; a missing/invalid
provenance bundle leaves the independently verified SBOM row visible, while
provenance remains `NOT PROVIDED` or `FAIL`. A partial report cannot pass.
The record must be signed by a currently root-authorized reviewer distinct
from all designated artifact owners/build owners and verified artifact
signers. Image identity approval remains a separate gate. `NOT PROVIDED`
means a required owner input is absent; `FAIL` means supplied input is
invalid, untrusted, stale, or inconsistent. Preserve the printed report SHA-256
in the controlled review record. The report does not contain credential
contents or private keys. A passed local preflight is still not a real-host
qualification result.

The CI release matrix now contains all six M3 image-lock components plus
supplemental `agent-relay`. This is source/workflow coverage only. The release
owner must supply the actual tag/commit outputs, immutable image digests,
CycloneDX SBOMs, signed SBOM and SLSA bundles, per-image resolved materials,
and root-designated owner identities. In particular, the EE and PostgreSQL
builds require digest-pinned `KORDEX_ANSIBLE_EE_BASE` and
`KORDEX_POSTGRES_BASE` repository variables. Missing variables cause release
build failure; static CI configuration does not prove a successful build or
approval.

After the non-secret network document and artifact inputs/report exist, run
the local readiness summary from the trusted checkout:

```sh
python3 scripts/m3_deployment_readiness.py \
  --project-id kordex-fleet-platform-515416 \
  --network-inputs /secure/m3/network-inputs.json \
  --artifact-inputs /secure/m3/customer-artifact-inputs.json \
  --artifact-report /secure/m3/artifact-preflight.json \
  --output /secure/m3/deployment-readiness.json
```

This read-only command makes no cloud or network requests and never reads the
ignored Terraform variables. It validates tracked source, local tool presence,
network-input syntax, and freshness/hash binding of the artifact report. Its
live project/API/IAM/billing/private-route and actual Terraform-input rows
remain `NOT PROVIDED` by design; the project owner and reviewer must record
those checks separately, and the guarded lab helper rechecks live project and
actual Terraform inputs. The local summary is not a pass-to-plan token. In the
current local environment Skopeo 1.24.0 is installed, but the `gh` executable
required by the offline attestation verifier is absent.

## C. Private registry administrator

Registry population is a customer-operated write step. The K3s staging
command validates the signed archive and writes a content-addressed local
mirror layout; it does not push OCI tags. `scripts/verify-private-registry.py`
is read-only. It verifies the signed K3s lock/archive and signed Kordex image
lock, inspects manifests/configs, checks digest and `linux/amd64`, and copies
the approved registry object into a temporary local OCI layout to verify
content. It does not publish anything.

### Publish eight K3s images

The supply-chain custodian first verifies/stages the signed archive as shown
in [`m3-k3s-system-image-staging.md`](m3-k3s-system-image-staging.md#customer-custodian-procedure),
then follows that document's customer-operated Skopeo ingestion block. The
verified inventory supplies exactly eight source references, private mirror
references, and signed manifest digests. The procedure re-verifies the lock
and archive immediately before each ingestion pass, invokes
`skopeo copy --preserve-digests --dest-tls-verify=true` for each signed
mapping, checks each returned digest against the signed lock, and prints a
per-image `PASS`. Do not derive mappings from arbitrary user input. A partial
push is not success; repeat the verified process after correcting the
customer registry without changing the signed lock.

The readiness input map uses `privateRegistry.host`, `privateRegistry.privateCIDRs`,
and `privateRegistry.authFile`; signed locks carry image source-to-destination
references. The JSON contains only the auth-file path, never registry auth
data. The repository does not pin a minimum Skopeo version. The environment must
provide a customer-approved Skopeo with the `oci-archive:` and `docker:`
transports, `copy --preserve-digests`, `--dest-authfile`, and digest-file
behavior used by the documented procedure. Record `skopeo --version` in the
customer change record. The local readiness command reports Skopeo missing if
it is absent; it does not install it.

### Publish six Kordex images

The release owner uses the signed offline bundle and its existing
`push-offline-bundle.sh` workflow to publish all six components. It uses the
customer-approved container engine (Podman by default), constructs/pushes
multi-platform OCI indexes, and writes an image-digest lock plus adjacent
signature only after all six pushes succeed. The approved release private key
must stay in the release custodian's protected signing environment; registry
authentication stays in the customer's protected container-engine auth
mechanism. Follow [`air-gapped-deployment.md`](air-gapped-deployment.md#mirror-images-into-an-internal-registry).
The private registry administrator must not sign or alter the lock unless
they are also the authorized release custodian.

### Verify all 14 private destinations

After both writers finish, run the documented read-only verifier with the
expected registry host, private CIDRs, customer auth-file path, signed K3s
inputs, and signed Kordex image lock. The input path is not a credential
value; the auth file must be a private regular file with mode `0600` or
stricter and is never added to the report/input map as content.

```sh
APPROVED_PRIVATE_REGISTRY_CIDR='REPLACE_WITH_APPROVED_PRIVATE_CIDR'
python3 scripts/verify-private-registry.py \
  --system-image-bundle /verified/k3s-airgap-images-amd64.tar \
  --system-image-lock /verified/k3s-system-images.lock \
  --system-image-signature /verified/k3s-system-images.lock.sig \
  --artifact-trust /trusted/customer-artifact.trust \
  --expected-host registry.customer.invalid \
  --private-cidr "$APPROVED_PRIVATE_REGISTRY_CIDR" \
  --authfile /run/customer-secrets/registry-auth.json \
  --output /secure/m3/private-registry-verification.json \
  --kordex-image-lock /verified/kordex-images.tsv \
  --kordex-image-signature /verified/kordex-images.tsv.sig \
  --release-public-key /trusted/kordex-release.pub
```

Use one `--private-cidr` for each approved private registry range; replace
`registry.customer.invalid` with the host bound by the signed mappings. The
output path must not already exist. Accept only exit status `0`, report
`status: PASS`, exactly 14 image rows, and `linux/amd64` with each digest
matching its own signed lock. Missing tags/blobs, wrong digest/architecture,
TLS/DNS failure, authentication failure, or an unexpected registry host
blocks bootstrap and artifact preflight. A successful local archive
verification is not evidence that any private registry was populated.

**Never include registry credentials or auth-file contents** in this packet,
the artifact input JSON, image inventory, command-line values, reports, Git,
ordinary email, or shell history. Pass only the protected auth-file path to
the documented verifier. Kordex's verifier is read-only; only the documented
customer Skopeo/Podman writers publish image content.

## D. Network and PKI administrator

The intended lab connection is private and outbound from the VMs:

```text
Selected-profile K3s workers (10.76.0.0/24)
  -- private route; TCP/18443 + mTLS --> workstation private-interface relay
  -- relay fixed upstream on loopback --> API 127.0.0.1:8080

Lab VMs -- private route; TCP/443 --> approved OS/K3s/package/OCI mirrors
Lab VMs -- TCP/443 --> restricted Google APIs VIP 199.36.153.4/30
IAP forwarding range 35.235.240.0/20 --> lab TCP/22 (SSH only)
Within lab subnet 10.76.0.0/24: TCP/22,6443,10250 and UDP/8472 as configured
Lab subnet DNS --> metadata resolver (UDP/TCP 53)
```

The workstation API remains bound to loopback. The relay binds only to an
explicit private interface on TCP/18443, allows only the configured private
lab source CIDRs, requires mTLS, maps one verified client URI SAN to one
enabled cluster, and forwards only the five agent method/path combinations.
The separate relay health listener is loopback-only on
`127.0.0.1:18444`; it is not exposed on 18443. The API independently verifies
the agent's Ed25519 signature/proof, identity, organization/cluster
authorization, and operation authorization. Do not expose the workstation API,
database, dashboard, Keycloak administration, or relay health port publicly.
A public tunnel is not a substitute for the required private route.

| Request and expected evidence | Required configuration/verification | Acceptance and blocked work |
|---|---|---|
| Relay server certificate/private key and agent client CA | Server certificate DNS SAN exactly matches the private relay DNS name used by the agent HTTPS origin and `KORDEX_MTLS_SERVER_NAME`; TLS 1.2+, chain trusted by the agent's independent CA file. Relay Secret requires `tls.crt`/`tls.key`; client CA Secret requires `ca.crt`. Install Secrets through the customer's secret controller; do not commit them. | Accept only a valid server chain/SAN and customer client CA. Private key values never enter this packet. Blocks relay startup and authenticated agent path. |
| Agent client certificate/key and server CA | Agent Client Secret keys: `tls.crt`, `tls.key`; server CA Secret key: `ca.crt`. Suggested existing names are `kordex-agent-mtls-client` and `kordex-agent-mtls-ca`. Client certificate has clientAuth EKU, digital-signature key usage, one URI SAN, valid lifetime, and matches its private key. Agent verifies server CA and hostname; no insecure mode/fallback. | Accept only certificate/key match, valid chain/EKU/SAN, independent CA trust, expiry/rotation/revocation plan, mounted read-only through customer secret management. Blocks mTLS connection. |
| Certificate-to-cluster mapping and rotation/revocation | Map exactly one URI SAN to exactly one enabled registered cluster UUID. Duplicate/unknown/disabled entries reject. Document expiry, renew-before-expiry, overlap, rollout/restart, and revocation steps. Relay does not dynamically reload cert files or use CRL/OCSP; rollout is required after trust/config changes. | Accept only exact URI-SAN-to-approved-cluster mapping and negative tests for unknown/disabled identities. Blocks secure relay acceptance. |
| Private relay DNS, destination addresses, and source allowlist | Supply `relayDNSName`, `approvedPrivateRelayCIDRs`, and the source CIDR as non-secret fields in `/secure/m3/network-inputs.json`. Lab source subnet is `10.76.0.0/24`; its destination relay prefixes must be canonical RFC1918 IPv4 CIDRs no broader than `/24`. Use the actual observed source address/range at workstation ingress, not an assumed pre-NAT source. | Accept DNS answers only inside approved relay prefixes, route in both directions, and workstation host firewall ingress only from approved lab source(s) to TCP/18443. Blocks plan and live connectivity. |
| Mirror DNS, addresses and firewall paths | Supply distinct `mirrorDNSNames` and `approvedPrivateMirrorCIDRs` for the selected OS, K3s binary/package, and OCI sources. Allow lab egress TCP/443 only to those private prefixes; allow only `199.36.153.4/30:443` for restricted Google APIs. No NAT or public VM addresses are in the tracked design. | Verify allowed private flows and denied arbitrary/public egress from the deployed lab. Hostname-only firewall rules do not satisfy destination restriction. Blocks bootstrap and plan approval. |

Agent TLS configuration is opt-in and already represented by the self-managed
deployment patch. The existing Secrets are customer-created; Kustomize does
not generate their values. The connectivity command must run only after the
spoke is installed, enrolled, and the customer route/PKI are active:

```sh
: "${KORDEX_CONTEXT:?set the approved disposable-lab kube context}"
: "${APPROVED_PRIVATE_RELAY_CIDR:?set the approved relay destination CIDR}"
curl --fail --silent --show-error http://127.0.0.1:18444/livez
curl --fail --silent --show-error http://127.0.0.1:18444/readyz

kubectl --context "$KORDEX_CONTEXT" -n kordex-system exec deploy/kordex-agent -- \
  /kordex-agent connectivity-check \
  --allowed-cidr "$APPROVED_PRIVATE_RELAY_CIDR"
```

Repeat `--allowed-cidr` for each approved relay prefix. Expected relay health
responses are HTTP 204. Connectivity-check must exit 0 and report
`status: verified`; this establishes the signed identity route, verified TLS
name/CA, client mTLS, configured cluster identity and Ed25519 key ID. The
checker does not read relay mapping contents, and its success alone does not
prove the firewall denies every unapproved source. Retain a sanitized report,
relay-side mapping review, certificate chain/SAN verification, route/firewall
allow/deny evidence, and proof that the API listener remains loopback-only.
See [`private-agent-relay-operations.md`](private-agent-relay-operations.md)
and [`agent-mtls-configuration.md`](agent-mtls-configuration.md).

## E. Kubernetes and cluster administrator

The target is a disposable self-managed K3s lab only: one K3s server plus two
workers using the same selected OS profile. Tracked qualification profiles are
Debian 13 Trixie and RHEL 9.8 or later; Ubuntu 24.04 is supplemental. Debian
must use the approved Debian 13.8 point release. RHEL requires an
approved exact image and private RPM/SELinux bootstrap inputs. The server is never a maintenance target; each worker
must be Ready and schedulable while the other remains an eligible worker peer.
This is not GKE, COS, or a production cluster.

| Request | Format/source and acceptance | Blocked work |
|---|---|---|
| Confirm existing organization, fleet, and site association; register a distinct `self-managed` lab cluster | Kordex administrator confirms organization/fleet/site IDs through the authenticated tenant-scoped API/dashboard. Register using the existing organization-scoped `POST /v1/organizations/{org}/clusters` API; do not create a tenant or grant admin implicitly. Provide the resulting cluster UUID and non-secret API origin to the protected local config. | Accept only approved organization membership/role, intended site, unique cluster identity, and successful authenticated registration. Blocks enrollment and inventory. |
| Enrollment configuration | Issue one short-lived, single-use enrollment token using the existing authorized workflow `POST /v1/organizations/{org}/clusters/{cluster}/enrollment-tokens`; put the token only in a customer secret/file mechanism. Confirm token consumption, stable agent identity, fresh inventory and heartbeat via authenticated API/dashboard. | Accept only consumed token, expected cluster/tenant binding, current heartbeat and three expected nodes. Token values must not appear in this packet, input JSON, report, email, shell history, or Git. Blocks agent acceptance. |
| K3s node and OS topology | Verify `v1.36.6+k3s1`, one server plus two workers of the selected profile, node names/UIDs/machine IDs, kernel and package baseline. Source outputs after deployment: `terraform output -json k3s_node_names`, `terraform output -json worker_names`, and `kubectl get nodes -o wide` through the documented IAP kubeconfig. | Accept exactly three nodes, both workers Ready/eligible peers, exact selected OS release/amd64 and server excluded from maintenance target selection. Ubuntu is supplemental; Debian 13 Trixie is required for the canonical Debian column, and RHEL must be 9.8 or later. Blocks host preflight. |
| Host execution access and workload safety | Supply the approved executor user, customer-provisioned SSH private key through a protected secret mechanism, matching pinned `known_hosts` entry, reviewed fixed sudo scope and digest-pinned Ansible EE image. Confirm workload/PDB behavior and drain readiness on the disposable cluster before execution. | Accept host identity/key pin, SSH reachability, constrained sudo, eligible peer and passing workload checks. Blocks drain/maintenance. Do not share private SSH key. |
| Storage/Ceph dependency, if used by the test workload | The lab module does not deploy Ceph. If the selected workload depends on Rook/Ceph, provide the read-only health evidence required by the existing policy and ensure storage checks pass before the node is selected; otherwise document `not applicable` for this disposable workload. | Any applicable degraded or unverified storage condition blocks maintenance under existing local safety checks. Do not add storage components solely to satisfy this packet. |

Kordex generates deployment and runtime identities only through the existing
authorized workflows. The customer chooses the organization/site association,
supplies trust and secrets, and authorizes enrollment. No cluster registration,
token issuance, deployment, or maintenance has been performed for this packet.

## F. GCP project and billing owner

The user-designated target is project **`kordex-fleet-platform-515416`**
(number `209068399397`), region `us-east1`, zone `us-east1-b`, with intended
label `kordex-disposable=qualification`. The project ID/number are provided
values, not live proof of project state, ownership, billing, API status, or
label. Do not target the deleted `kordex-fleet-platform` project or another
unrelated project. Use an explicit `--project` on every GCP command; do not
change the global gcloud project.

### Read-only project confirmation

```sh
gcloud projects describe kordex-fleet-platform-515416 \
  --project=kordex-fleet-platform-515416

gcloud services list --enabled \
  --project=kordex-fleet-platform-515416
```

The project owner must confirm `lifecycleState: ACTIVE`, the exact project
number and qualification label through the approved read-only project view.
Record only the project identity and check result in the handoff; do not attach
credentials or unrelated IAM policy dumps.

| Request | Existing lab requirement / accepted evidence | Blocked work |
|---|---|---|
| Project ownership and designation | Confirm ID/number, `ACTIVE`, `kordex-disposable=qualification`, region/zone, project allowlist and confirmation values. Existing guard permits only the designated ID. | Wrong/unlabeled/unverified project blocks any plan. |
| APIs and service identities | Owner reviews `compute.googleapis.com`, `iam.googleapis.com`, `cloudresourcemanager.googleapis.com`, `secretmanager.googleapis.com`, `iap.googleapis.com`, `dns.googleapis.com`, and `serviceusage.googleapis.com` (only as needed to enable services). `artifactregistry.googleapis.com` is conditional on the chosen private registry. Confirm current enabled state; this packet does not assert it and any disabled API remains disabled until separately approved and enabled by the owner. | Missing APIs/permissions block plan/apply/bootstrap. This packet does not enable APIs. |
| IAM and administration | Review the lab README's exact Terraform permissions for custom VPC/subnet/firewall/DNS, VM/disk/service accounts, Secret Manager and `iam.serviceAccounts.actAs`. For IAP/OS Login, review scoped `roles/iap.tunnelResourceAccessor`, `roles/compute.osAdminLogin`, and `roles/iam.serviceAccountUser`. Recovery tooling also needs scoped snapshot create/get/list/delete and `compute.instances.getSerialPortOutput` permissions. | Accept only a least-privilege reviewed IAM change and tested authorized IAP/OS Login path. This packet grants nothing. |
| Quota, recovery, and access | Confirm regional CPU/disk quota, IAP availability, per-instance serial access, snapshot/restore permissions and approved evidence location. Follow the exact recovery commands in [`self-managed lab README`](../infrastructure/terraform/gcp/self-managed-lab/README.md#recovery-baseline-snapshots-and-controlled-faults). | Missing quota or out-of-band recovery blocks provisioning/qualification. |
| Billing and budget | Review current project/account actuals and remaining authorized spend. Treat `$300` as the user's total M3–M6 spending ceiling, **not** as confirmed credits. Include runtime, 120 GiB boot disks, snapshots/retention, DNS queries, registry/package storage, logs, network transfer, tax, and any customer VPN/private route charges. Record region-specific price inputs, expected duration, upper bound, teardown owner, and post-session billing check. Budget alerts are not caps. | No plan approval until the owner confirms remaining budget/headroom and cost calculation from current price sources. This packet makes no current-price or credit claim. |
| Terraform input and plan review | After all prior gates, prepare the actual protected local `terraform.tfvars` using the existing example. Keep it mode `0600`; do not submit or commit it. Run tracked-source validation with `python3 scripts/self_managed_lab.py validate`. The guarded `plan` validates real local variables, current project designation, and the full artifact preflight. | Accept only after independent plan/resource/firewall/cost review and separate explicit approval. This handoff is not plan/apply authorization. |

Tracked lab design: three `e2-medium` VMs (one server, two selected-profile
workers), three 40-GiB `pd-balanced` boot disks, a dedicated custom VPC/subnet,
no default-VPC dependency, no VM external IPs, no Cloud NAT, IAP-only SSH
ingress, and egress limited to private mirror CIDRs on TCP/443, relay CIDRs on
TCP/18443, restricted Google APIs VIP `199.36.153.4/30:443`, and required
internal/DNS flows, with deny-other egress. This is tracked source, not live
enforcement. Snapshots, retained artifacts, logs, storage, DNS queries, and
network transfer can add charges, including after VMs stop.

Cost review worksheet (owner completes from current regional prices):

| Input | Owner entry |
|---|---|
| Three VM machine-hour rate × approved runtime, including bootstrap/recovery/teardown buffer | `________________` |
| 120 GiB balanced disk provisioned-hours and any retained disk time | `________________` |
| Snapshot stored GiB × retention period and recycle/retention behavior | `________________` |
| Private DNS zone/query charges | `________________` |
| OCI/package/K3s artifact registry storage and request/transfer charges | `________________` |
| Logs/monitoring, cross-region transfer, tax, route/VPN charges | `________________` |
| Estimated total, contingency, remaining $300 ceiling, billing reviewer/date | `________________` |

Do not provision if this estimate plus committed M3–M6 spend exceeds the
customer-approved ceiling. After a session, use the guarded destroy command
only with separate approval, then verify VMs, disks, snapshots, temporary
firewall rules, addresses, DNS records/zones, secrets, and registry/project
artifacts are removed or intentionally retained and priced. Verify actual
billing after reporting delay. Never delete the default VPC or unrelated
resources. Full teardown and recovery procedure: [self-managed lab README](../infrastructure/terraform/gcp/self-managed-lab/README.md#session-and-teardown-procedure).

For rollback, preserve Terraform state and the failed-operation evidence.
Do not manually replace disks, delete snapshots, or run raw
`terraform destroy`. Use the guarded snapshot/restore, serial-diagnostic, and
fault-restoration procedures in the [recovery section](../infrastructure/terraform/gcp/self-managed-lab/README.md#recovery-baseline-snapshots-and-controlled-faults)
with the approved project/lab/instance confirmations. If automatic fault
restoration fails, stop further scenarios, follow the documented manual
recovery procedure, and retain the lab until ownership and network state are
verified.

## Master acceptance checklist

The checklist reflects the latest repository readiness report, not this
packet's test fixtures. No artifact below is accepted solely because a local
synthetic test passed.

| Requirement | Owner | Deliverable | Verification/acceptance | Current status |
|---|---|---|---|---|
| Maintenance trust and rotation overlap | Security/trust custodian | Existing `keys.json`, key IDs, rotation/revocation evidence | Public-key-derived IDs match independently confirmed inventory; overlap/revocation record reviewed | `NOT PROVIDED` |
| Customer artifact trust and K3s binary approval | Security/trust + release owner | `.trust`, `k3s`, lock, `.sig`, acquisition record | Offline signature/digest/version/amd64 and approval evidence pass | `NOT PROVIDED` |
| K3s system-image approval | Release/platform artifact owner | 8-image archive, signed lock/signature | Exact eight references and all OCI descriptor/config/layer digests pass | `NOT PROVIDED` |
| Kordex release trust and signed bundle | Security/trust + release owner | Public key/fingerprint, bundle, signed `SHA256SUMS` | Independent fingerprint, detached signature and every checksum pass | `NOT PROVIDED` |
| Tool provenance and Helm allowlist | Security/trust custodian | Public key/fingerprint, signed `offline-tools.tsv`, `.sig`, allowlist | Four pinned tool rows and approved Helm identities pass | `NOT PROVIDED` |
| Debian 13 package policy and artifacts | Release/platform artifact owner | Trixie metadata, Debian 13.8 point release, policy, exact `.deb` archive, baseline and reboot policy | Approved policy digest, package hashes/version/amd64, real version delta, kernel/reboot consistency | `NOT PROVIDED` |
| RHEL 9.8+ package policy and artifacts | Release/platform artifact owner | Exact RHEL image approval, signed RPM metadata/repository and SELinux dependency set | Independently verified exact image and RPM policy/digests; minimum minor is 9.8 | `BLOCKED` |
| Ubuntu 24.04 supplemental package policy and artifacts | Release/platform artifact owner | Noble metadata, policy, exact `.deb` archive, baseline and reboot policy | Approved policy digest, package hashes/version/amd64 and real package delta; does not satisfy Debian/RHEL rows | `NOT PROVIDED` |
| 8 K3s + 6 Kordex registry images | Private registry admin + artifact owners | Private mappings and populated registry | Read-only 14-image report: all `PASS`, `linux/amd64`, signed digests | `NOT PROVIDED` |
| Relay/client PKI and cluster mapping | Network/PKI admin | Server/client certs via secret system, CA bundle, URI-SAN mapping | TLS SAN/chain, clientAuth, mapping and rotation/revocation checks | `NOT PROVIDED` |
| Private route/DNS/firewall and no-public-egress evidence | Network/PKI admin | CIDRs, DNS, route, firewall allow/deny evidence | Private TCP/18443 and TCP/443 paths work; arbitrary public egress fails | `NOT PROVIDED` |
| Organization, cluster registration, enrollment, fresh inventory | Kubernetes/Kordex admin | Approved org/fleet/site, registered cluster, single-use enrollment flow | Authenticated cluster binding and fresh three-node heartbeat/inventory | `NOT PROVIDED` |
| Project identity, label, APIs/IAM, quota, IAP/recovery | GCP project owner | Read-only project/API status and approved IAM/quota changes | Explicit project guard, least privilege, IAP/OS Login and recovery verified | `PROVIDED, NOT VERIFIED` for ID only; remaining checks `NOT PROVIDED` |
| Cost/spend approval | GCP project/billing owner | Current estimate, remaining ceiling and teardown owner | Expected total within $300 user ceiling; post-run billing check assigned | `NOT PROVIDED` |
| Local readiness and artifact preflight | M3 coordinator | `deployment-readiness.json`, `artifact-preflight.json` | Artifact report has all 16 `PASS`; supplied local gate checks have no `FAIL`. Its live-cloud and actual-Terraform-input rows remain `NOT PROVIDED` until the guarded helper/reviewer checks them. | `VERIFIED LOCALLY` for gate behavior only; customer report `NOT PROVIDED` |
| Reviewed Terraform plan and deployment approval | GCP owner + independent reviewer | Saved plan and explicit approval | Exact resources, project, firewall, cost, recovery and cleanup reviewed | `BLOCKED` |
| Real-host M3 qualification | Independent lab reviewer + M3 operator | Canonical evidence archive | Actual package update, drain/reboot/recovery, health and failure-injection evidence verified against unchanged matrix | `BLOCKED`; matrix `NOT RUN` |

`VERIFIED IN CUSTOMER ENVIRONMENT`: none. A `VERIFIED LOCALLY` entry refers
only to repository implementation/test evidence, never to customer-provided
trust, registry content, route, deployed resources, or maintenance behavior.

## Dependency-ordered execution sequence

1. **Assign owners and collect public trust/evidence.** Security custodian and
   release/platform owners hand off independently authenticated trust roots,
   acquisition records, signed bundle/locks, package policy, and artifacts.
   Stop on unknown key IDs, fingerprint mismatch, invalid signature, digest,
   version, architecture, or approval-age failure.
2. **Verify the offline bundle and local artifact inputs.** Validate release
   signature/checksums and tool provenance first; validate maintenance,
   customer-artifact, release and tool trust as separate domains; run K3s and
   package verifiers. Save the generated reports outside Git.
3. **Stage/ingest approved images.** Stage the verified K3s archive to the
   customer private mirror, publish exactly eight K3s and six Kordex mappings
   with the customer-controlled writers, then run read-only 14-image registry
   verification. Stop if any destination is missing or differs.
4. **Approve private network and PKI.** Network owner supplies CIDRs, split
   DNS, private route, firewall rules, certificates, CA trust, URI-SAN mapping
   and rotation/revocation plan. Confirm private flows and public-deny behavior.
5. **Configure/register the disposable cluster.** Kordex administrator
   confirms organization/fleet/site, registers the distinct lab cluster and
   arranges protected single-use enrollment. No production cluster access is
   requested.
6. **Complete GCP owner review.** Verify project ID/number/label/status,
   enabled APIs, quotas, IAM, IAP/OS Login, serial/snapshot access, current
   actual billing, cost estimate, and protected Terraform inputs. API/IAM
   changes require their own approval.
7. **Test private connectivity and rerun gates.** After separate approved
   customer network/relay and spoke setup, run the loopback relay health checks
   and agent `connectivity-check`; collect allowed/denied network evidence.
   Run `m3_artifact_preflight.py` and `m3_deployment_readiness.py` again. The
   local summary still reports live cloud/actual Terraform inputs as
   `NOT PROVIDED`; the owner/reviewer records those checks separately. Stop if
   any mandatory artifact is not `PASS` or any external review is incomplete.
8. **Request separate plan authorization.** After approval is recorded, the
   exact guarded command is below. Replace only file paths with reviewed
   customer locations. Do not run it before explicit authorization:

   ```sh
   python3 scripts/self_managed_lab.py plan \
     --project-id kordex-fleet-platform-515416 \
     --m3-artifact-inputs /secure/m3/customer-artifact-inputs.json \
     --m3-artifact-report /secure/m3/artifact-preflight.json \
     --k3s-binary /verified/k3s \
     --k3s-artifact-lock /verified/k3s.artifact-lock \
     --k3s-artifact-signature /verified/k3s.artifact-lock.sig \
     --k3s-artifact-trust /trusted/customer-artifact.trust \
     --k3s-system-images-bundle /verified/k3s-airgap-images-amd64.tar \
     --k3s-system-images-lock /verified/k3s-system-images.lock \
     --k3s-system-images-signature /verified/k3s-system-images.lock.sig \
     --k3s-system-images-trust /trusted/customer-artifact.trust
   ```

   Review the saved plan and cost; plan approval is not apply approval.
9. **Request separate apply/deployment authorization.** Apply only after the
   plan is reviewed and a distinct explicit approval is recorded, following
   the guarded apply procedure in the [self-managed lab README](../infrastructure/terraform/gcp/self-managed-lab/README.md#prepare-and-validate-locally).
   This packet is not that approval.
10. **Run the canonical M3 qualification and teardown.** Follow the approved
    read-only preflight, record the target confirmation for human review,
    execute only after separate approval, and archive/verify evidence. After
    separate teardown approval, use the guarded command:

    ```sh
    python3 scripts/self_managed_lab.py destroy \
      --project-id kordex-fleet-platform-515416
    ```

    Verify resource cleanup and actual billing after reporting lag.

## Qualification and safety boundaries

M3 remains **NOT QUALIFIED**. Every canonical matrix row remains **NOT RUN**
until real evidence is collected and independently reviewed. Synthetic unit,
integration, envtest, fixture, or simulator results are implementation tests,
not customer qualification. Artifact approval, private registry verification,
network connectivity, and project readiness do not prove safe host maintenance.
The canonical Debian and RHEL-family qualification requirements remain
intact. Ubuntu 24.04 is supplemental and cannot mark Debian or RHEL rows
complete; Debian 12 or pre-9.8 RHEL evidence cannot satisfy the updated platform baseline.
Do not weaken either host-upgrade gate, local safety veto, signature or
approval check to make a readiness report pass.

## Customer sign-off record

Complete this record in the customer's controlled change system; do not put
secret values here or commit a completed copy to the repository.

| Owner/role | Date | Evidence reference(s) | Status | Approval / limitations |
|---|---|---|---|---|
| Security/trust custodian |  |  |  |  |
| Release/platform artifact owner |  |  |  |  |
| Private registry administrator |  |  |  |  |
| Network/PKI administrator |  |  |  |  |
| Kubernetes/Kordex administrator |  |  |  |  |
| GCP project/billing owner |  |  |  |  |
| Independent lab reviewer |  |  |  |  |

### Final authorization record

| Decision | Authorized owner | Date | Evidence/approval reference |
|---|---|---|---|
| Terraform plan review authorized |  |  |  |
| Apply/deployment separately authorized |  |  |  |
| Host maintenance execution separately authorized |  |  |  |
| Qualification evidence independently accepted |  |  |  |
