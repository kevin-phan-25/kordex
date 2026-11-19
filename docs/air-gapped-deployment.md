# Air-gapped and private-network deployment

For an optional disposable Ubuntu/K3s VM lab on GCP, see the
[self-managed qualification lab guide](../infrastructure/terraform/gcp/self-managed-lab/README.md).
That lab uses public internet for first-boot downloads and does not represent
an air-gapped installation.

Kordex's central API, scheduler, agent, operator, database integration, audit,
campaign engine, and fixed-catalog Ansible executor do not require Google,
AWS, or Azure APIs at runtime. A cluster agent initiates its management
connection outbound. GKE node-pool maintenance is an optional adapter and is
disabled by default. The normal host-upgrade path is a digest-pinned Ansible
Execution Environment with fixed Debian/Ubuntu and RPM-family catalogs,
including an explicit Amazon Linux 2023 DNF match; its operator gate is also
disabled by default until disposable VM qualification is complete.

## Connectivity boundaries and campaign scope

For an air-gapped site, deploy the Kordex control plane, PostgreSQL, and any
OIDC service inside that site's trusted network. Managed clusters initiate
outbound TLS connections to that control plane; Kordex never opens a route
from the hub into a cluster. A campaign can mix self-managed and cloud clusters
registered to the same control plane, and each snapshotted target keeps its
own signed action and plan digest. Provider credentials are needed only by a
target whose explicitly selected provider adapter uses them.

A fully disconnected cluster cannot receive a new central command or provide
fresh inventory to a central scheduler. The scheduler therefore stops issuing
new work when the required heartbeat or safety evidence becomes stale. The
local operator remains responsible for fail-closed checks and recovery of an
operation already accepted there. Reconnect the agent before central
orchestration resumes. Separate Kordex control planes in isolated network
islands do not currently share campaigns or synchronize state; a single
campaign across those islands requires a common reachable control plane or a
future, separately designed relay mechanism.

## Build and transfer an offline bundle

Build the release bundle on a connected, trusted build host. It contains OCI
archives for the Kordex control plane, agent, operator, dashboard, dual-catalog
Debian/RPM-family Ansible EE (including the Amazon Linux 2023 DNF match), and
PostgreSQL 17; Linux amd64 and arm64 binaries for the control
plane, scheduler, agent, operator, key generator, audit signer, and audit verifier; Helm and
kubectl client binaries for Linux amd64 and arm64 plus their version/checksum
inventory and license notices; packaged Helm charts; Kustomize manifests and CRDs; source playbook/catalog files; the
deployment and upgrade qualification documents; the guarded self-managed
qualification runner, case-specific fault evidence recorder, failure matrix,
and evidence verifier under `qualification/`; policy generation and offline
package archive/staging tools are in `scripts/`. The bundle also includes
`SHA256SUMS`. Cluster-specific public trust keys are
excluded from the generic bundle and supplied when creating a cluster
overlay. The EE source copy contains only explicit source and test files,
never Python bytecode caches. Use a new or empty output directory for each
build; the builder refuses a non-empty directory to prevent stale files from
being silently included.
The Kustomize staging step rejects Secret resources and payloads except the
empty metadata-only agent identity object, plus private-key files, kubeconfigs,
environment files, and embedded PEM private keys. Public hub trust
keys remain cluster-specific and are added only when generating an overlay.

The generic release bundle does **not** include site-specific `.deb`/`.rpm`
payloads. Policy schema v2 supports `OfflineArtifacts`, binding each package
file SHA-256 and requiring it on the target worker at
`/var/cache/kordex/artifacts/<sha256>.deb` or `.rpm`. The EE checks the file
hash and embedded package identity before cordon, then disables repository
access during installation. Debian and RPM transactions use private,
per-operation APT/DNF caches, so ambient package files from the host's normal
cache or a previous operation cannot satisfy an omitted dependency.
Dependencies must therefore be included as explicit, digest-pinned artifacts
or already installed. Successful preflight and package application remove
their operation-scoped cache; a failed package-manager run leaves it for
recovery inspection.
The signed generic bundle includes tools to build
a deterministic policy-bound package archive and safely stage it on a worker;
the archive is transferred separately with the exact reviewed policy. This
transfer from the connected build host to offline media/site and onward to
target workers is a controlled operator or configuration-management step,
not an automatic multi-cluster file-transfer service. End-to-end artifact
distribution and disposable VM qualification remain open. Keep host-upgrade
gates disabled outside disposable labs until the distribution and recovery
workflow has been qualified.

Requirements on the connected acquisition/build host: Podman, Helm, Go,
OpenSSL, curl, GnuPG, Cosign, Python 3, a trusted Helm maintainer keyring, and
availability of all digest-pinned build bases. Helm's upstream guide documents
OpenPGP verification; Kubernetes documents Cosign verification for its client
binaries ([Helm](https://helm.sh/docs/intro/install/),
[Kubernetes](https://kubernetes.io/docs/tasks/administer-cluster/verify-signed-artifacts/)).

Acquire and verify both tools for amd64 and arm64 with the repository script.
Provide a pre-reviewed Helm fingerprint allowlist and GnuPG keyring, plus a
dedicated Ed25519 acquisition signing key. The acquisition key must be separate
from the Kordex bundle release key. The script downloads the version-pinned
official assets, checks published checksums, verifies Helm archive signatures
against the allowlist, verifies kubectl Cosign signatures against the Kubernetes
Release Engineering identity, calculates binary and upstream artifact hashes,
and signs the resulting lock. It exits without publishing a partial staging
directory if any check fails.

```sh
export GNUPGHOME=/release-trust/helm-gnupg
export KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE=/release-trust/helm-maintainer-fingerprints.txt
export KORDEX_TOOLS_LOCK_PRIVATE_KEY=/secure/release/tools-acquisition-private.pem
export KORDEX_TOOLS_LOCK_PUBLIC_KEY=/release-trust/tools-acquisition-public.pem
./scripts/acquire-offline-tools.sh v3.16.4 v1.31.3 /release-inputs/kordex-tools
```

The output directory contains `linux-amd64/{helm,kubectl}`,
`linux-arm64/{helm,kubectl}`, `LICENSES/{helm.txt,kubernetes.txt}`, the signed
`offline-tools.tsv` provenance lock, its detached signature, and the public
trust files. The lock binds tool name, exact version, architecture, executable
SHA-256, upstream artifact SHA-256, official artifact URL, verification method,
and verified signer identity. For Helm, the upstream artifact is the signed
tarball and the executable hash is calculated from the extracted binary; for
kubectl, both hashes cover the binary itself. The builder performs no tool
downloads and independently rechecks the signed lock and staged binary hashes.

Keep both signing private keys outside the repository, build host image, and
bundle. Upstream signature verification occurs on the connected acquisition
host; isolated clusters receive only the signed acquisition record, tools, and
Kordex bundle trust material.

The literal `<TAB>` above means one tab character. The signed bundle verifier
checks each client binary's ELF architecture and checksum against this signed
inventory. Set `KORDEX_OFFLINE_TOOLS_DIR`, `KORDEX_OFFLINE_TOOLS_LOCK`,
`KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE`, and
`KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY` to the staged directory and acquisition
record inputs, and `KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE` to the trusted
Helm signer allowlist. The bundle includes the signed record, its signer key,
and the approved Helm fingerprint allowlist, all
protected by the Kordex bundle signature. Record the acquisition signer's key
fingerprint through a separately trusted channel and compare it with
`openssl pkey -pubin -in bin/tools/offline-tools.signer.pub -outform DER | sha256sum`
when qualifying the bundle. Compare
`bin/tools/offline-tools.helm-signers.txt` with the independently provisioned
Helm signer allowlist as well. By default, every OCI image is built as a `linux/amd64` and
`linux/arm64` manifest index and the bundle records and verifies those exact
platforms. Podman must be able to execute non-native build stages (for example,
through registered QEMU/binfmt emulators); every base image must publish both
platforms. If the build host has no emulation, build a single-platform bundle
with `KORDEX_IMAGE_PLATFORMS=linux/amd64` or `linux/arm64`; such a bundle is
explicitly rejected on the other architecture. Binaries remain cross-compiled
for both architectures. Set `KORDEX_ANSIBLE_EE_BASE`, `KORDEX_GO_BUILDER_BASE`,
`KORDEX_RUNTIME_BASE`, `KORDEX_NODE_BASE`, `KORDEX_NODE_RUNTIME_BASE`, and
`KORDEX_POSTGRES_BASE` to repository-qualified OCI references pinned by
`@sha256:` digest. For disconnected or reproducible builds, mirror those bases
into a controlled build registry first. `images/image-metadata.tsv` records
the local image digest and archive checksum; after pushing, record the
destination registry digest printed by the mirror helper.

```sh
export KORDEX_ANSIBLE_EE_BASE='registry.example/ansible-ee-base@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_GO_BUILDER_BASE='registry.example/golang@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_RUNTIME_BASE='registry.example/debian@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_NODE_BASE='registry.example/node@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_NODE_RUNTIME_BASE='registry.example/node@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_POSTGRES_BASE='registry.example/postgres@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_OFFLINE_TOOLS_DIR='/release-inputs/kordex-tools'
export KORDEX_OFFLINE_TOOLS_LOCK='/release-inputs/kordex-tools/offline-tools.tsv'
export KORDEX_OFFLINE_TOOLS_LOCK_SIGNATURE='/release-inputs/kordex-tools/offline-tools.tsv.sig'
export KORDEX_OFFLINE_TOOLS_LOCK_PUBLIC_KEY='/release-inputs/kordex-tools/offline-tools.signer.pub'
export KORDEX_OFFLINE_TOOLS_HELM_SIGNERS_FILE='/release-trust/helm-maintainer-fingerprints.txt'
export KORDEX_ANSIBLE_EE_TAG='localhost/kordex/ansible-ee:0.8.0'
# Optional single-architecture release: linux/amd64 or linux/arm64.
# Default: linux/amd64,linux/arm64 (requires non-native build emulation).
# export KORDEX_IMAGE_PLATFORMS=linux/amd64
# The EE build uses actionMarkerVersion 1 and rejects markerless builds.
./scripts/build-offline-bundle.sh 0.8.0 ./dist/kordex-offline-0.8.0
```

The build host also needs Go and access to repository modules through your
approved Go module proxy. The resulting binaries are cross-compiled for Linux
amd64 and arm64, so Go is not needed in the disconnected environment.
On the isolated verification host, provision Bash, Python 3, OpenSSL, `find`,
`grep`, and `sha256sum` along with the independently trusted release verifier
scripts and public key before transferring a bundle. Python's standard library
checks that every OCI index really contains the platforms declared by the bundle,
that each binary's ELF architecture matches its directory, and that each signed
Helm archive contains a matching Helm v2 chart manifest, values file, and
templates. The offline verifier rejects missing, ambiguous, malformed, or
mismatched release artifacts before installation.
The PostgreSQL development image is built as a thin, labeled wrapper around the
digest-pinned PostgreSQL base for the selected platform set. This keeps the
bundle's index limited to the declared amd64/arm64 platforms even if the base
image also publishes other architectures.

The build defaults to action marker version `1`; the builder rejects other
versions. Every executable host-upgrade policy must include
`actionMarkerVersion: 1`, which binds the root-owned host journal protocol to
the signed plan and EE catalog. Markerless legacy policies are rejected. The
local upgrade gate remains disabled until disposable VM failure drills are
complete.

The bundle has an offline Ed25519 detached-signature workflow. Create and
protect a release key pair outside the bundle, distribute the public key
through a separately trusted channel, then sign the checksums on the connected
release host:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out kordex-release-private.pem
openssl pkey -in kordex-release-private.pem -pubout -out kordex-release-public.pem
chmod 600 kordex-release-private.pem
./scripts/sign-offline-bundle.sh ./dist/kordex-offline-0.8.0 kordex-release-private.pem
```

Do not generate a new release key for each bundle; follow your organization's
offline key custody and rotation process. Transfer the public key separately.
Before transfer, provision the release verifier scripts and trusted public key
through a separately authenticated channel or from an already trusted Kordex
checkout. Do not run `verify-offline-bundle.sh` or
`check-offline-manifest.sh` from the bundle being verified; a verifier inside
an untrusted bundle cannot establish that bundle's authenticity. The verifier
also rejects symbolic links and files omitted from the signed manifest.
After transfer, verify signature and all file checksums before loading images:

```sh
BUNDLE=/media/kordex-offline-0.8.0
export KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY=/etc/kordex/trust/tools-acquisition-public.pem
export KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE=/etc/kordex/trust/helm-maintainer-fingerprints.txt
/opt/kordex-release-tools/verify-offline-bundle.sh \
  "$BUNDLE" /etc/kordex/trust/release-public.pem
```

The verifier requires these independent tool-provenance trust inputs. It
compares them with the copies inside the signed bundle before validating the
acquisition signature and Helm key fingerprint. Provision both files through
the site's trusted software-acquisition channel, not from the bundle itself.

Use the bundled client tools for the following install steps. Select the
directory matching the admin workstation architecture; the node image
platforms are verified separately.

```sh
case "$(uname -m)" in
  x86_64) KORDEX_TOOL_ARCH=linux-amd64 ;;
  aarch64|arm64) KORDEX_TOOL_ARCH=linux-arm64 ;;
  *) echo "unsupported Kordex client-tool architecture" >&2; exit 1 ;;
esac
export PATH="$BUNDLE/bin/tools/$KORDEX_TOOL_ARCH:$PATH"
helm version --short
kubectl version --client
```

Image archives preserve OCI manifests and layers. The signature authenticates
the bundle file manifest; use the recorded registry digests after mirroring
for deployment policy and Ansible EE allowlists.

Transfer the directory to the isolated environment using approved media or a
controlled file gateway. Verify integrity before loading:

```sh
cd /media/kordex-offline-0.8.0
sha256sum -c SHA256SUMS
```

After signature verification, run the current read-only self-managed Linux
host qualification preflight from the bundle. It detects Debian/Ubuntu and
RHEL-family targets and validates that the signed policy uses the matching
fixed catalog:

```sh
python3 ./qualification/self_managed_upgrade_smoke.py \
  --evidence /var/tmp/kordex-qualification/preflight.json
```

The qualification workstation needs Python 3 and access only to the
configured Kordex management endpoint and disposable cluster API. For actual
execution, follow the bundled `docs/production-upgrade-requirements.md` and
use separate disposable Debian/Ubuntu and RHEL-family workers with snapshots
and console recovery. The failure matrix requires every case to be recorded
independently for each family. Do not enable the operator host-upgrade gate
until each case has independently reviewed evidence. The runner does not
create infrastructure or inject failures; its evidence is a record of a
drill, not a production readiness claim.

## Mirror images into an internal registry

The recommended air-gapped setup is a registry reachable by all cluster nodes.
Authenticate to it with your organization's registry credentials, then load
and push the bundle images:

```sh
export KORDEX_RELEASE_PUBLIC_KEY=/etc/kordex/trust/release-public.pem
export KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY=/etc/kordex/trust/tools-acquisition-public.pem
export KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE=/etc/kordex/trust/helm-maintainer-fingerprints.txt
export KORDEX_RELEASE_PRIVATE_KEY=/secure/release/kordex-release-private.pem
export KORDEX_TRUSTED_BUNDLE_VERIFIER=/opt/kordex-release-tools/verify-offline-bundle.sh
export KORDEX_REGISTRY_PULL_SECRET=kordex-registry
export KORDEX_UPGRADE_IMAGE_PULL_SECRETS=kordex-ee-registry
BUNDLE=/media/kordex-offline-0.8.0
"$BUNDLE/scripts/push-offline-bundle.sh" "$BUNDLE" registry.dc.example/platform
```

The registry argument is a lowercase host with an optional port and repository
path, without `https://`; authenticate the container engine separately before
running the helper.

The script invokes the independently trusted verifier path in
`KORDEX_TRUSTED_BUNDLE_VERIFIER` before loading any archive; it never trusts a
verifier copied from the bundle. It then loads each OCI archive, pushes it, and
captures the registry's returned manifest digest (not a local image ID). It
writes `kordex-offline-0.8.0-image-digests.tsv` beside the bundle by default;
set `KORDEX_IMAGE_LOCK_FILE` to choose another path outside the signed bundle.
For a multi-platform image, this must be the pushed OCI image-index/manifest-list
digest, not one architecture-specific image-manifest digest. The helper uses
Podman's `push --all` so the registry receives every platform represented by
the bundle. Confirm your private registry accepts OCI indexes; then use the
same signed digest lock on amd64 and arm64 clusters. Kubernetes/containerd will
select the matching platform manifest under that immutable index reference.
The selected lock file's parent directory must already exist.
The lock is replaced atomically only after every image push succeeds. Retain
it and its adjacent `.sig` detached signature as post-mirror release records.
The helper signs the lock with `KORDEX_RELEASE_PRIVATE_KEY`; keep that key
under the same offline custody controls as the bundle signing key. The public
key is used only to verify and must be obtained through the separate trusted
channel described above. A failed push leaves the prior lock and signature in
place. For authenticated registries, create
namespace-local pull Secrets. The self-managed Kustomize overlay expects
`kordex-registry`; Helm `imagePullSecrets` values configure pulls for the Kordex
pods. Ansible Jobs use a separate list. Create the same Secret before enabling
the executor. Its gate remains disabled by default.
Registry TLS verification remains enabled by default. The optional
`KORDEX_REGISTRY_TLS_VERIFY=false` setting is for disposable localhost HTTP
registries in integration tests only; production mirrors must use HTTPS with a
registry certificate chain trusted by the container engine. Set
`KORDEX_CONTAINER_ENGINE` only when using an executable wrapper for an
approved container engine; it defaults to `podman`.

Generate Helm values from the mirrored digest lock. These files contain
image settings, pull-secret references, and optional executor credential
references (never credential contents). The helper verifies the
detached signature at `$LOCK.sig` using the separately trusted public key;
it also re-verifies the bundle with the independently installed verifier
before reading chart inventory. Set `KORDEX_TRUSTED_BUNDLE_VERIFIER` to that
trusted verifier path and set `KORDEX_IMAGE_LOCK_SIGNATURE` only when the
signature file is stored at a different path. Add environment-specific
database, OIDC, ingress, and secret names in a separate reviewed values file:

```sh
export KORDEX_RELEASE_PUBLIC_KEY=/etc/kordex/trust/release-public.pem
export KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY=/etc/kordex/trust/tools-acquisition-public.pem
export KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE=/etc/kordex/trust/helm-maintainer-fingerprints.txt
export KORDEX_TRUSTED_BUNDLE_VERIFIER=/opt/kordex-release-tools/verify-offline-bundle.sh
export KORDEX_UPGRADE_SSH_USER=kordex
export KORDEX_UPGRADE_SSH_SECRET=kordex-upgrade-ssh
export KORDEX_UPGRADE_KNOWN_HOSTS=kordex-upgrade-known-hosts
BUNDLE=/media/kordex-offline-0.8.0
LOCK=/media/kordex-offline-0.8.0-image-digests.tsv
"$BUNDLE/scripts/configure-offline-helm.sh" \
  "$BUNDLE" "$LOCK" ./kordex-helm-images
```

## Install with Helm

The charts are standalone packaged archives in `charts/`. The image values
helper uses `KORDEX_REGISTRY_PULL_SECRET` for Kordex pods (default:
`kordex-registry`) and `KORDEX_UPGRADE_IMAGE_PULL_SECRETS` for the Ansible EE
Jobs (defaults to the workload Secret). Create those namespace-local Secrets
before installation. Install the operator
and agent into each managed cluster; install control-plane, dashboard, and
database according to your central-site design. Helm does not provision
PostgreSQL, ingress, OIDC, or TLS. Use internal DNS and a private CA accepted by
the agents. The helper writes the three optional SSH reference values when
`KORDEX_UPGRADE_SSH_USER`, `KORDEX_UPGRADE_SSH_SECRET`, and
`KORDEX_UPGRADE_KNOWN_HOSTS` are all set;
create the Secret and known-hosts ConfigMap separately with approved material.
The generated values keep `upgrade.enabled: false`.

Example operator install using internal image paths (replace the chart filename
with the versioned archive present in `charts/`):

```sh
helm upgrade --install kordex-operator ./charts/kordex-operator-CHART_VERSION.tgz \
  --namespace kordex-system --create-namespace \
  -f ./helm-values/kordex-operator.yaml \
  -f ./kordex-helm-images/kordex-operator-images.yaml
```

Use the generated `kordex-agent-images.yaml`, `kordex-control-plane-images.yaml`,
and `kordex-dashboard-images.yaml` with their respective charts. The helper
also writes the exact digest-pinned EE allowlist into the operator values while
leaving `upgrade.enabled: false`. Chart package versions are recorded in their
filenames and may have a different version from the image bundle; use the
actual versioned chart filename in the bundle.

The lock also contains `ansible-ee`. If host upgrades are later qualified and
explicitly enabled, set the operator chart's
`upgrade.executionEnvironmentAllowlist` to that exact digest reference. Do not
enable the executor based on bundle creation or mirroring alone.

## Install with Kustomize

The provider-neutral overlay is `deployments/kustomize/overlays/self-managed`
in the source checkout and `manifests/kustomize/overlays/self-managed` in the
offline bundle. The bundle includes a helper that creates a separate,
digest-pinned overlay from the mirrored image lock, registered cluster UUID,
internal HTTPS management origin, and public hub trust JSON:

```sh
export KORDEX_RELEASE_PUBLIC_KEY=/etc/kordex/trust/release-public.pem
export KORDEX_OFFLINE_TOOLS_TRUSTED_PUBLIC_KEY=/etc/kordex/trust/tools-acquisition-public.pem
export KORDEX_OFFLINE_TOOLS_TRUSTED_HELM_SIGNERS_FILE=/etc/kordex/trust/helm-maintainer-fingerprints.txt
export KORDEX_TRUSTED_BUNDLE_VERIFIER=/opt/kordex-release-tools/verify-offline-bundle.sh
# Optional: configure the self-hosted hub's duplicated OIDC settings in one run.
export KORDEX_HUB_OIDC_ISSUER=https://identity.dc.example/realms/platform
export KORDEX_HUB_OIDC_CLIENT_ID=kordex-dashboard
export KORDEX_HUB_OIDC_AUDIENCE=kordex-api
export KORDEX_HUB_OIDC_TOKEN_MODE=access_token
export KORDEX_HUB_OIDC_ACCESS_CLIENT_ID=kordex-dashboard
export KORDEX_HUB_OIDC_ACCESS_REQUIRED_SCOPES='kordex.read kordex.operate'
export KORDEX_HUB_DASHBOARD_URL=https://kordex-dashboard.dc.example
./scripts/configure-offline-kustomize.sh \
  ./kordex-offline-0.8.0 \
  ./kordex-offline-0.8.0-image-digests.tsv \
  733ff86d-5dd0-4ad9-8476-0910f9eac046 \
  https://kordex-api.dc.example \
  ./hub-public-keys.json \
  ./kordex-cluster-overlay
```

The Kustomize helper verifies the adjacent `<image-lock>.sig` detached
signature before generating any manifests. Obtain the release public key
independently of the bundle. If the signature is stored elsewhere, set
`KORDEX_IMAGE_LOCK_SIGNATURE` to its path.

The helper re-verifies the signed bundle with the independently installed
verifier before copying its manifests. It copies the full Kustomize tree so
relative base and component references remain valid, then configures the
self-managed and optional GKE workload overlays with immutable agent and
operator images, trust keys, cluster identity, and private-registry pull-secret
patches. `KORDEX_REGISTRY_PULL_SECRET` selects the Secret referenced by agent
and operator pods (default: `kordex-registry`).
`KORDEX_UPGRADE_IMAGE_PULL_SECRETS` configures the namespace-local Secrets used
by Ansible Execution Environment Jobs; create them in `kordex-system` before
enabling a host-upgrade policy. If unset, the Jobs use the value of
`KORDEX_REGISTRY_PULL_SECRET`. It also places the mirrored, digest-pinned Ansible EE in the
operator allowlist while keeping host-upgrade and GKE-upgrade gates disabled.
To prepare the self-managed executor configuration, set
`KORDEX_UPGRADE_SSH_USER`, `KORDEX_UPGRADE_SSH_SECRET`, and
`KORDEX_UPGRADE_KNOWN_HOSTS` together before running the helper. It writes those
references into operator settings and restricts the operator Role to the
selected SSH Secret; it still leaves `upgradeEnabled: "false"`. Create that
Secret and ConfigMap independently with verified SSH credentials and pinned
host keys.
The helper also configures the self-hosted management-plane image references
in `hub/overlays/self-hosted` and `hub/overlays/self-hosted-migration`, using
the control-plane and dashboard digests from the signed lock. It writes the
chosen registry pull Secret into the hub Deployments and migration Job.
Database, OIDC issuer/client, public HTTPS URLs, ingress/TLS, and Secret values
remain site-specific. The positional `HUB_HTTPS_ORIGIN` sets the dashboard's
`apiURL` in both Kustomize settings copies so it matches agent connectivity.
Set the optional `KORDEX_HUB_OIDC_ISSUER`,
`KORDEX_HUB_OIDC_CLIENT_ID`, and `KORDEX_HUB_DASHBOARD_URL` variables to
configure both hub settings copies consistently. In ID-token mode, the API
audience must equal the client ID. An API-specific audience requires the
explicit access-token mode and access-client/scope variables shown above.
Otherwise edit both
`hub/base/settings.yaml` and
`hub/overlays/self-hosted-migration/settings.yaml` identically. Provision the
referenced Secrets through the site's secret-management process. No Secret
payloads are copied into the bundle or generated manifests.
GKE provider identity and permissions remain a separate, optional setup; the
provider-neutral self-managed overlay does not require cloud identity or APIs.
Every generated workload overlay keeps command delivery disabled by default,
even if its source overlay was intended for an online validation workflow.
Set `maintenanceEnabled: "true"` only after reviewing the local operator and
trust configuration. The helper does not create credentials or enable host
or provider upgrades.

For the self-hosted management plane, follow
[`kustomize-hub.md`](kustomize-hub.md), which is included in the offline
bundle's `docs/` directory.
Provision internal PostgreSQL, OIDC, HTTPS ingress, and the required Secrets;
render and review `hub/overlays/self-hosted-migration`, apply it, and wait for
`job/kordex-migrate` to complete before applying
`hub/overlays/self-hosted`. Wait for API, scheduler, and dashboard rollouts.
For each upgrade, back up the database, delete the prior completed immutable
migration Job, apply the newly digest-pinned migration overlay and wait for
completion, then apply the workload overlay. The database and OIDC service may
be hosted on-premises or in a restricted internal network; neither cloud APIs
nor public internet access is required at runtime.
When those services use a private CA, create `kordex-management-ca` in the hub
namespace and use the hub `*-private-ca` overlays documented in
[`kustomize-hub.md`](kustomize-hub.md).

## Create a self-managed upgrade policy offline

The signed release bundle includes `scripts/generate-offline-upgrade-policy.py`.
It verifies the bundle and signed mirrored image lock, then fills in the exact
Ansible EE image, playbook digest, and collections digest from those reviewed
artifacts. Supply exact package versions already present in the site's
approved internal APT or DNF mirror and a selector that matches only the
intended worker nodes:

Set the independent release public key, trusted bundle verifier, tool-lock
public key, and Helm signer allowlist variables documented above before
running it. The bundled verifier must be independently installed outside the
bundle.

```sh
BUNDLE=./kordex-offline-0.8.0
LOCK=./kordex-offline-0.8.0-image-digests.tsv
python3 "$BUNDLE/scripts/generate-offline-upgrade-policy.py" \
  "$BUNDLE" "$LOCK" ./maintenance-policy.json \
  --family debian --os-id ubuntu --os-major 24 --os-minor 04 \
  --name debian-worker-maintenance \
  --selector operations.kordex.local/maintenance=stateless \
  --package openssl=3.0.2-1 \
  --reboot Never
```

Replace the package version with the exact version approved and mirrored for
the target OS; the example pin is illustrative. The OS arguments are required:
the fixed catalog accepts Ubuntu `24.04`, Debian major `12`, RHEL/Rocky/AlmaLinux
`9.5`, and Amazon Linux `2023` (major-only). For example, use
`--family rhel --os-id rocky --os-major 9 --os-minor 5` with exact RPM
version-release pins for Rocky Linux 9.5. The generator rejects every other
OS ID/release tuple. Kernel package pins also
require `--reboot IfNeeded` or `Required` and
`--expected-kernel-version` with the exact running kernel version. The
generator rejects floating versions, duplicate pins, unsafe selectors, and
incomplete kernel plans. It writes JSON for review; it does not apply the
object or enable the local host-upgrade gate. Verify the intended node labels,
SSH and known-host setup, private package mirrors or staged artifacts, local safety integrations,
and disposable VM qualification before applying it. The operator's
`KORDEX_ENABLE_HOST_UPGRADES` gate remains independently disabled by default.

For a repository-free upgrade, use the schema v2 artifact mode instead. Add
`--artifact-mode OfflineArtifacts` and one `--artifact-sha256 NAME=HEX` for
every `--package`. The hash must be the SHA-256 of the exact `.deb` or `.rpm`
payload. Before creating an operation, stage each file on the target worker as
`/var/cache/kordex/artifacts/<sha256>.deb` or `.rpm`, owned by root and not
group/world writable. Include all required dependencies as explicit package
pins and artifacts. The preflight checks the payload digest, embedded package
name/version, and local artifact directory, then simulates the package-manager
transaction with downloads/repositories disabled before the node is cordoned.
The apply command also disables repository downloads; missing dependencies
fail closed before disruption when they are not installed or included in the
artifact set.
The generic signed release contains a builder and a target-side staging tool.
On a trusted connected build host, create an archive from the exact reviewed
policy and package files (repeat `--artifact` once for every policy package):

```sh
python3 "$BUNDLE/scripts/build-offline-package-artifacts.py" \
  ./maintenance-policy.json ./maintenance-packages.tar \
  --artifact openssl=/media/repository/openssl_3.0.2-1_amd64.deb
```

The builder verifies each file hash against the policy and writes a stable tar
layout with a manifest bound to the policy plan digest. Transfer both
`maintenance-policy.json` and `maintenance-packages.tar` using approved
offline media or site configuration management. On each target worker, after
verifying the Kordex release and policy approval, stage the files with:

```sh
sudo python3 "$BUNDLE/scripts/install-offline-package-artifacts.py" \
  ./maintenance-policy.json ./maintenance-packages.tar
```

The stager verifies the full archive and all package hashes before writing any
artifact under `/var/cache/kordex/artifacts`. The policy and archive must be
the same pair for each worker. Include the complete dependency closure as
explicit policy packages and artifacts; a missing dependency stops preflight.
For RPM-family hosts, provision the approved package signing public keys into
the host RPM keyring through the site's offline trust process before use. The
preflight verifies each artifact against that existing keyring, and the EE
does not import keys during an operation.
The Kordex campaign does not transfer arbitrary package files to nodes. The
site's approved media/configuration workflow remains responsible for delivery.
This path is implemented but has not been qualified on disposable Debian or
RHEL-family VMs; keep host-upgrade gates disabled until the failure and
recovery drills are recorded.

Create the registry Secrets named by the configuration variables (or the
default `kordex-registry`), the enrollment Secret, SSH credentials,
known-hosts ConfigMap, and optional etcd TLS Secret separately using the
cluster's secret-management process. If the
hub uses a private CA, also create `kordex-management-ca` with key `ca.crt` and
run the helper with `--private-ca`. Render
`overlays/self-managed-private-ca` for the provider-neutral install; the same
option adds the CA mount to `overlays/gke-fleet` for the optional GKE workload
path. Never include a signing private key in the overlay.

The same configured tree can render `overlays/gke-fleet` or
`overlays/gke-operator` when an optional GKE deployment is needed. Those paths
use the same mirrored digests and registry Secret; configure their provider
identity separately. A fully isolated environment should use the self-managed
host executor path and must not enable a provider adapter that needs a cloud
API.

When using a public CA, render and review the configured overlay before apply:

```sh
kubectl kustomize ./kordex-cluster-overlay/overlays/self-managed > /tmp/kordex.yaml
kubectl diff -f /tmp/kordex.yaml
kubectl apply -f /tmp/kordex.yaml
```

Run the helper from the verified offline bundle root, with its `scripts/`
directory available. It uses that bundle's `manifests/kustomize` tree and
refuses to overwrite an existing output directory.
For a private CA, add `--private-ca` to the helper command; it prints the
`self-managed-private-ca` render path. Before applying that variant, create
`kordex-management-ca` in `kordex-system` with the trusted certificate as
`ca.crt`; Kustomize does not embed CA material.

The overlay keeps both host upgrades and GKE-native upgrades disabled. Enabling
host upgrades requires the remaining disposable VM failure/recovery drills;
GKE upgrades require Workload Identity and the separate GKE qualification.
Cloud provider adapters are not needed to install or operate self-managed
clusters.

## Operating without Internet access

Provide internal DNS, NTP, TLS trust, a reachable private registry, PostgreSQL,
OIDC provider (if enabled), and an internal management endpoint. Configure
NetworkPolicies and firewall rules for the required cluster-to-hub outbound
HTTPS connection and, only for the Ansible EE path, operator Job-to-node SSH.
The host-upgrade path requires a CNI that enforces Kubernetes NetworkPolicy:
each EE Job is isolated to its target node IP on TCP/22, with ingress denied.
A CNI that ignores NetworkPolicy is not an acceptable host-upgrade environment.
The executor blocks when another standard NetworkPolicy selects the EE pod and
adds egress allows. Audit vendor-specific CNI policy resources separately; they
are outside the standard Kubernetes NetworkPolicy API.
No inbound connection from the hub to a cluster is required. For self-managed
host upgrades, the fixed EE job communicates with its target over SSH and does
not call a cloud API or public package service. Repository-backed schema v1
preflight resolves exact pins from existing APT cache or DNF metadata without
refreshing it; schema v1 apply uses configured package sources, which must be
approved internal mirrors in a restricted environment. Offline schema v2
preflight verifies every staged package and simulates dependency resolution
without downloads or enabled DNF repositories; schema v2 apply uses only the
verified local files. Include the complete dependency closure in the policy
unless dependencies are already installed. Mirror synchronization is needed
only for schema v1 repository-backed plans. Mirror any organization-selected
monitoring images and OIDC software separately; they are outside the Kordex
image bundle.
Mirror any organization-selected monitoring images and OIDC software
separately; they are outside the Kordex image bundle.

The provider-neutral runtime paths are:

| Component | Required destination | Optional destination |
|---|---|---|
| Cluster agent | Configured Kordex management HTTPS origin | Private registry during image pull |
| Operator | Local Kubernetes API; configured Ceph/Rook metrics and etcd endpoints when enabled | Target-node SSH from the fixed Ansible Job; Google metadata token endpoint and Container API only when the GKE adapter is explicitly enabled |
| Control plane and scheduler | Configured PostgreSQL endpoint | Configured internal OIDC issuer/JWKS endpoints when OIDC is enabled |
| Dashboard | Same-origin Kordex API and configured OIDC issuer | Private registry during image pull |
| Ansible EE Job | Target-node SSH; target host reaches an approved APT/DNF mirror for schema v1 repository-backed plans | Private registry during image pull; schema v2 offline artifact plans require no package repository |

Core self-managed operation does not contact Google, AWS, Azure, public
container registries, or public identity services. The Google endpoints are
isolated to the optional GKE adapter, which is not constructed by default.
The Debian and RPM-family EE preflight is repository-free for schema v2: it
checks the complete staged package transaction without repository access before
cordoning. Schema v1 resolves pins against existing APT cache or DNF metadata
and does not refresh metadata; its apply step uses configured package sources,
which must point to approved internal mirrors in a disconnected site. Both
catalogs are bundled in the same digest-pinned EE image and are selected by a
signed OS-family/catalog pair; no provider API is needed for self-managed hosts.

Back up PostgreSQL, identity Secrets, trust bundles, policy catalogs, and
release metadata using site procedures. Rotate signing and TLS trust through
offline, reviewed key distribution. Keep the signing private key out of the
bundle and out of cluster namespaces.

## Limits

This packaging path makes installation artifacts transferable and runtime
images configurable. It does not by itself establish signed image provenance,
an air-gapped build system, a complete offline OIDC service, or production
qualification. The Ansible upgrade executor remains opt-in pending recorded
VM drills. Cloud-specific adapters may still require their provider's APIs
when explicitly enabled; core inventory, campaigns, local safety, and
self-managed host execution do not.
