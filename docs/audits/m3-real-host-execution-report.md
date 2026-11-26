# M3 Real-Host Execution Report

- **Last Verified:** 2026-11-26 01:54 UTC
- **Project:** `kordex-fleet-platform-515416` (`209068399397`)
- **Preferred Region / Zone:** `us-east1` / `us-east1-b`
- **Final M3 status:** **INCOMPLETE — 0/22 independently accepted**

This is the authoritative execution and qualification log for Kordex M3. It
records live GCP state, recalculated external dependencies, verified local
engineering integration waves, and remaining gates. No GCP resources were
created or modified; M3 spend remains **$0.00**.

## Repository and integration state

- Branch: `main`; pre-integration base commit: `7837551ae0265d323d735ebc532283d2e53e9ef4`
  (Waves 1–4 integrated, verified, committed, and pushed to `origin/main` per
  explicit user authorization on `2026-11-25`).
- **Wave-1 Engineering Integration (uncommitted in `main`, awaiting Codex Step 6 post-integration verification):**
  Antigravity independently reviewed, tested in isolated worktrees, and
  integrated 4 P0 Codex patches (`22` tracked files changed, `+928/-86` lines):
  1. `M3-DEMO-001` (diff SHA-256 `4bc99955466411c0074bf7fcc1569c0a0243c0ea2b35037ff58c3250636769a1`):
     fixed inverted `split(cidr, "/")` -> `split("/", cidr)` in
     `variables.tf:258-259,275-276`, added fail-closed `try(tonumber(var.qualification_os_minor) >= 8, false)`
     in `main.tf:114`, updated `test_qualification_project_guard.py:189`, and
     added offline `terraform console` HCL evaluation tests in `test_self_managed_lab.py`.
  2. `M3-BUNDLE-RCE-001` (diff SHA-256 `731b3aacaceff681eec0a13bdedc7fc32344e8b7c8e0a9d3181e5da1ee41d31a`):
     blocked running scripts inside `$BUNDLE` (`pwd -P` check), ran `sha256sum -c SHA256SUMS`
     after safe path/traversal/duplicate/symlink checks and before deep archive
     parsing, switched helper invocations in `check-offline-manifest.sh` from
     `$BUNDLE/scripts/*` to trusted `$SCRIPT_DIR` helpers (`python3 -I`), and
     added adversarial regression coverage in `scripts/test-offline-bundle-integrity.sh`.
  3. `M3-RECOVERY-FAULTS-001` (diff SHA-256 `395fb9eb1bc265c40a2f7a94ef60a77425a871b444d715aae162144d57a7d2c6`):
     reconciled `scripts/self_managed_lab_recovery.py` fault allowlist checks
     against the exact 3 Terraform private egress firewalls (`egress-private-mirrors`,
     `egress-private-relay`, `egress-restricted-googleapis`, priority `900`,
     exact ports & `199.36.153.4/30` VIP) and added `ContextVar`-bound
     `--terraform-principal-email` impersonation across all cloud-backed
     recovery subcommands in `scripts/self_managed_lab.py`.
  4. `M3-OPERATOR-EXEC-001` (diff SHA-256 `10f6d71a46c9c9346ade975fe1e7fe7db71b3dba8297500af76a248e37fac110`):
     normalized only kube-apiserver-verified EE Job defaults & UID-bound
     generated labels (validated against live `kubebuilder-envtest 1.37.0` with
     5 negative mutation rejections), scoped `durable.go` `slotBlockReason`
     `Reader.List` to the operation namespace, preserved `Failed` terminal
     checkpoint phase in `recovery.go`, and canonicalized checkpoint timestamps
     to Kubernetes persisted RFC3339 second precision.
- **Wave-1 integrated test receipt:** `docs/engineering/antigravity-integration-wave1-tests.txt`
  (`sha256=d1c0f09ae150e5afe659b6ecb4410aba13eb873998dc8615f7fd37f6f5308e52`):
  - `terraform fmt -check` + `terraform validate`: **PASS**
  - `bash scripts/test-offline-bundle-integrity.sh`: **PASS**
  - `make vet`: **PASS**
  - `KUBEBUILDER_ASSETS=.../1.37.0-linux-amd64 make test`: **PASS** (45 Go packages, 3 bash suites, 424 Python tests, 0 failures/skips)
  - `TestEnvtestJobDefaultsAndGeneratedLabels` (live kube-apiserver + etcd 1.37.0): **PASS** (5/5 mutation rejections)
  - `tests.infrastructure.test_multi_agent_board`: **20/20 PASS**
- **Wave-2 Engineering Integration (integrated into `main` with Antigravity review fixes, authorized for commit & push `2026-11-25`, awaiting Codex Step 6 verification):**
  5. `M3-CI-DEPLOY-001` (combined diff SHA-256 `4c8926554a896a8c5872296ef424c5e38a86492478015ca853ea980d35599909`):
     added `ansible-ee` and `postgres` to `create_image_sbom_manifest.py`, fixed
     `assemble-m3-release-evidence` in `.github/workflows/ci.yaml:692-732` and
     `m3_offline_release_lock.py:discover_components` to validate & exclude at
     most one supplemental `agent-relay` without crashing the 6-core-component
     assembly (with live inline-script execution test in
     `scripts/test_release_image_workflow.py`), fixed `control_plane_deploy.py`
     `helm_render()` `UnboundLocalError` and `--kube-context` pinning on `helm status`
     and `helm upgrade`, and wired `scripts/test_m3_{cost_model,lab_lifecycle,terraform_identity}.py`
     into `Makefile` and `.github/workflows/ci.yaml`.
  6. `M3-ANSIBLE-EE-001` (combined diff SHA-256 `4124b12ebaf73dfc8b56a889687c1501b4b07e5838d37fa16bdb6a96f8ab3900`):
     split dependent `kordex_kernel_packages` `set_fact` tasks into ordered
     steps in both `upgrade-debian.yml` and `upgrade-rhel.yml`, fixed both
     preflight (`:101,115`) and post-apply (`:636,652`) `rpm -q` queries in
     `upgrade-rhel.yml` to delimit multi-install kernel EVRs with `\n` (joining
     preflight `stdout_lines` with `,` to satisfy `ansible_job.go:931` and
     matching exact target EVR in post-apply `stdout_lines`).
  7. `M3-TRUST-LOADER-001` (combined diff SHA-256 `f5f2bea299f94a81b9901afa5cf236830582a087219577f2f7dbf9a29fcbc3b7`):
     brought `scripts/m3_trust_state.py:load_production_customer_trust()` to
     conformance-runner import-origin, `sys.modules`, unpinned `.pyc`, ancestor
     directory (`root_path.parents` up to `/` for `owner_uid=0`), and
     `O_NONBLOCK` parity; fixed `m3_trust_state_conformance.py` to test genuine
     backend CAS same-sequence/different-digest conflict; and added separated
     `residual-risk-approver` role validation in `scripts/m3_customer_trust.py`.
- **Wave-2 full integrated test receipt:** `docs/engineering/antigravity-integration-wave2-tests.txt`
  (`sha256=7f6e11f098d00ea409ee141f11be2811cb4ef8f72fc2291ef410710a1f8543df`):
  - `terraform fmt -check` + `terraform validate`: **PASS**
  - `bash scripts/test-offline-bundle-integrity.sh`: **PASS**
  - `integrations/ansible-ee` (with `ansible-core 2.17.3`): **58/58 PASS**
  - `tests/integration`: **101/101 PASS**
  - `make vet`: **PASS**
  - `KUBEBUILDER_ASSETS=.../1.37.0-linux-amd64 make test`: **PASS** (`405` infra + `32` newly wired M3 script tests + `11` SBOM + `3` base-lock + `9` release-workflow + `3` Kyverno = `463` Python + `45` Go packages + `3` bash suites; total **622 Python tests, 0 failures, 0 skips**)
  - `TestEnvtestJobDefaultsAndGeneratedLabels` (live kube-apiserver + etcd 1.37.0): **PASS** (5/5 mutation rejections)
- **Wave-3 Engineering Integration (integrated into `main` with 7 Antigravity independent-review fixes, verified and authorized for commit & push `2026-11-26`):**
  8. `M3-CTRL-AGENT-001` (tracked diff SHA-256 `f26177f794e2c49b57fb7a66645df17fb8039dd61c943c56886120ca7fddd723`):
     eliminated blind merge-patch initialization in `agent/internal/state/state.go`
     with `openat`/`O_NOFOLLOW`/`O_NONBLOCK` projected-file traversal, added
     `scripts/seed_agent_identity_secret.py` (resourceVersion CAS seed helper)
     plus offline staging & Helm/Kustomize integration, added bounded kubelet
     projected-Secret symlink resolution + `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` in
     `control-plane/internal/auditchain/private_key.go`, and narrowed
     `Succeeded -> RecoveryRequired` transactional reservation restoration in
     `control-plane/internal/store/{operations,lab_lifecycle}.go`.
  9. `M3-IAM-COST-001` (diff SHA-256 `6fbccc97b39800c77da47b50178e53195cb5d5d4fd443a7d80ae48907aa67e5f`):
     replaced invalid `cloudresourcemanager.*` permissions with
     `resourcemanager.projects.{get,list}` in BOTH `terraform-deployer-role.json`
     and `lab-inventory-role.json`, added `compute.snapshots.useReadOnly` and
     `compute.networks.updatePolicy` to `terraform-deployer-role.json`, fixed
     Secret Manager CEL condition in `docs/m3-persistent-lab-lifecycle.md` to
     use verified numeric `PROJECT_NUMBER`, and refined `scripts/m3_cost_model.py`
     + `scripts/self_managed_lab.py lab cost` for separate extra-host RHEL EUS
     PAYG hours and fail-closed BYOS rejection. Zero live GCP IAM mutations.
  10. `M3-EVIDENCE-CONTRACT-001` (diff SHA-256 `6cee17df099e3afb309543da8a68f7d952800c415755e939e141619fdb4ec704`):
      aligned `verify-host-upgrade-qualification.py`, `verify-m3-evidence-provenance.py`,
      `scripts/self_managed_lab.py`, and `tests/integration/self_managed_upgrade_smoke.py`
      on 9-key boot-disk license records, Debian `13.8` (`osMinor=""`, `osVersion="13"`),
      exact RHEL `9.<minor>` profiles, single-read signed corroboration timestamp
      verification (closing TOCTOU), all 16 `REQUIRED_ARTIFACTS` in
      `self_managed_lab.py`, empty Debian `qualification_os_minor` in
      `qualification_platform_binding()`, and API `RebootPolicy` enum (`Never`/`IfNeeded`/`Required`,
      rejecting unsupported `Always`).
  11. `M3-INFRA-BOOTSTRAP-001` (diff SHA-256 `cd320532134e544b825f53a0c1d00bb99a27603bcca3b89d8d78624b7729614b`):
      replaced worker `k3s.yaml` readiness loop with `systemctl is-active --quiet k3s-agent.service`,
      bound `secret_manager_bootstrap.py` publish/destroy to GCE metadata numeric
      project identity with `POST :destroy` + `b"{}"` JSON body and fail-closed 404,
      enforced exact Ubuntu/Debian OS version matching + `iptables` install +
      full-stream `rpm -qa` RHEL RHUI detection under `pipefail`, and added
      explicit DNS (`restricted_googleapis*`) and ingress/egress firewall
      `depends_on` edges to both `google_compute_instance.server` and `worker`
      in `main.tf` (completing Event 133).
- **Wave-3 full integrated test receipt:** `docs/engineering/antigravity-integration-wave3-tests.txt`
  (`sha256=738278d72645a6757ad2020dccf5a6eeef1518fb5c38b2bb40acad7ad8230f81`):
  - `git diff --check`: **PASS**
  - `python3 scripts/self_managed_lab.py validate` (`terraform fmt -check` on tracked sources + `terraform init -backend=false -lockfile=readonly` + `terraform validate`): **PASS**
  - `bash scripts/test-offline-bundle-integrity.sh` + `bash scripts/test-stage-offline-assets.sh`: **PASS**
  - `integrations/ansible-ee` (pinned `ansible-core 2.17.3`): **58/58 PASS**
  - `tests/integration`: **106/106 PASS**
  - `make vet`: **PASS**
  - Go `-race` on `agent/internal/state` & `control-plane/internal/auditchain`: **PASS**
  - `KUBEBUILDER_ASSETS=.../1.37.0-linux-amd64 make test`: **PASS** (`428` infra + `33` M3 script tests + `11` SBOM + `3` base-lock + `9` release-workflow + `3` Kyverno = `487` Python + `45` Go packages + `3` bash suites; total **651 Python tests, 0 failures, 0 skips**)
  - Explicit non-skipped `TestEnvtestJobDefaultsAndGeneratedLabels` (live `kube-apiserver` + `etcd` 1.37.0): **PASS** (5/5 mutation rejections)
  - Note: local Antigravity host did not have PostgreSQL server binaries installed, so live PostgreSQL `control-plane/internal/store` testing relies on Codex Events 114/116 plus Antigravity Go compilation/unit validation.
- **Wave-4 Engineering Integration (integrated into `main`, independently reviewed by Antigravity at Event 160):**
  12. `M3-TRUST-RECEIPT-CHALLENGE-001` (diff SHA-256 `fba9113b17f6e087382f2f4bb596567820b15c9b0f257d7e4006e79f0ab1c0e7`):
      upgraded customer trust-state transport & conformance protocol to v2
      (`kordex-m3-trust-state-v2` / `kordex-m3-trust-state-conformance-v2`),
      binding every `read_state` and `compare_and_swap` call to a fresh 256-bit
      `secrets.token_hex(32)` `requestId` echoed inside the Ed25519-signed
      receipt and audit events, added `schemas/m3-trust-state-conformance-run-report-v2.json`,
      and added replay/expiry rejection tests across fresh client instances.
- **Final Waves 1–4 pre-push verification receipt:** `docs/engineering/antigravity-integration-wave4-tests.txt`
  (`sha256=c7026955745d0289baeb979965f945d195a4d7f548748974ad9dae727a0578d4`):
  - `git diff --check`: **PASS**
  - `python3 scripts/self_managed_lab.py validate` (`terraform fmt -check` on tracked sources + `terraform init -backend=false -lockfile=readonly` + `terraform validate`): **PASS**
  - `bash scripts/test-offline-bundle-integrity.sh` + `bash scripts/test-stage-offline-assets.sh`: **PASS**
  - `integrations/ansible-ee` (pinned `ansible-core 2.17.3`): **58/58 PASS**
  - `tests/integration`: **106/106 PASS**
  - `make vet`: **PASS**
  - Go `-race` on `agent/internal/state` & `control-plane/internal/auditchain`: **PASS**
  - `KUBEBUILDER_ASSETS=.../1.37.0-linux-amd64 make test`: **PASS** (`430` infra + `33` M3 script tests + `11` SBOM + `3` base-lock + `9` release-workflow + `3` Kyverno = `489` Python + `45` Go packages + `3` bash suites; total **653 Python tests, 0 failures, 0 skips**)
  - Explicit non-skipped `TestEnvtestJobDefaultsAndGeneratedLabels` (live `kube-apiserver` + `etcd` 1.37.0): **PASS** (5/5 mutation rejections)
- **Wave-5 Offline Bundle Checksum Gate (`M3-BUNDLE-RCE-001` + `M3-OFFLINE-CHECKSUM-GATE-001`, Event 167):**
  13. `M3-OFFLINE-CHECKSUM-GATE-001` (combined offline-bundle diff SHA-256 `16065ca1f2b7ba06b17dbf4a2f9ac0a151815643429506af52ecc00c002ea5fe`, `scripts/verify-offline-checksums.sh` SHA-256 `17e29c96a9d5c39e85228002d9322b11e1323b5021b82fdd0805062d01240a09`):
      added trusted non-executing `scripts/verify-offline-checksums.sh` preflight
      (rejecting NUL bytes, empty manifests, trailing slashes, symlinks, traversal,
      duplicates, and hash mismatches before `check-offline-manifest.sh` parses
      deep bundle contents), wired into `sign-offline-bundle.sh`,
      `verify-offline-bundle.sh`, and `build-offline-bundle.sh`, alongside
      `M3-BUNDLE-RCE-001` trusted `$SCRIPT_DIR` helper execution and expanded
      ordering regressions in `test-offline-bundle-integrity.sh`. Independently
      verified via `bash -n`, `test-offline-bundle-integrity.sh`,
      `test-stage-offline-assets.sh`, `test-build-offline-bundle-platforms.sh`,
      and `test_m3_artifact_preflight` (28/28 PASS).
- **All 13/13 M3 engineering tasks integrated & pushed to `origin/main` (`In Progress: 0`):**
  - `M3-DEMO-001`, `M3-BUNDLE-RCE-001`, `M3-RECOVERY-FAULTS-001`, `M3-OPERATOR-EXEC-001`,
    `M3-CI-DEPLOY-001`, `M3-ANSIBLE-EE-001`, `M3-TRUST-LOADER-001`, `M3-CTRL-AGENT-001`,
    `M3-IAM-COST-001`, `M3-EVIDENCE-CONTRACT-001`, `M3-INFRA-BOOTSTRAP-001`,
    `M3-TRUST-RECEIPT-CHALLENGE-001`, and `M3-OFFLINE-CHECKSUM-GATE-001` (all
    awaiting Codex Step 6 confirmation on pushed `main` / authorized runtime environments).
- Host-upgrade and provider-upgrade default-off gates remain **OFF** and unmodified.
- Local tests, `envtest`, and `terraform console` do **not** constitute real-host qualification or M3 acceptance.

## Live GCP inspection (re-verified 2026-11-25 23:17 UTC)

Read-only verification against `kordex-fleet-platform-515416` (`209068399397`,
`ACTIVE`, label `kordex-disposable=qualification`, billing account
`0114E3-3DF354-050DF1` with `billingEnabled=true`):

- **Resources:** 0 Compute instances, 0 disks, 0 snapshots, 0 Artifact Registry
  repositories, 0 Cloud Storage buckets, 0 Secret Manager secrets, 0 Cloud DNS
  managed zones, 0 custom VPCs (only auto-mode `default` VPC with open
  `0.0.0.0/0` SSH/RDP firewalls — unsuitable for qualification), 0 Terraform
  state files (0 drift).
- **APIs & IAM:** 36 enabled APIs (`billingbudgets.googleapis.com` confirmed
  **NOT enabled**). IAM policy `etag: BwZhGh2EKzI=` unchanged: 0 custom roles;
  4 service accounts (`kordex-lab-tf`, `kordex-m3-lab-server`,
  `kordex-m3-lab-worker`, `209068399397-compute`). `kordex-lab-tf` still holds
  broad project-level roles; dedicated `kordex-m3-lab-terraform` and
  `kordex-m3-lab-lifecycle` accounts and custom roles are not yet deployed.
- **Quotas (newly verified global constraint):**
  - Global: **`CPUS_ALL_REGIONS = 0/12`**, `NETWORKS = 1/5`, `FIREWALLS = 4/100`, `IMAGES = 0/100`.
    A single 3-node `e2-medium` cluster uses 6 vCPUs (8 vCPUs peak with a 4th
    replacement/wrong-machine host), which fits `12` vCPUs **only when Debian
    and RHEL campaigns run sequentially** (concurrent campaigns would require
    12–16 vCPUs and exceed global quota).
  - `us-east1`: `CPUS 0/200`, `E2_CPUS 0/24`, `INSTANCES 0/24`, `DISKS_TOTAL_GB 0/2048`, `SSD_TOTAL_GB 0/250`, `SNAPSHOTS 0/1000`.
- **Public Images (re-verified 2026-11-25):**
  - Debian: newest public image is `projects/debian-cloud/global/images/debian-13-trixie-v20261116`
    (`ID: 5913446147369107523`, created `2026-11-16`). Does **not** establish
    exact guest point release `13.8`.
  - RHEL: genuine Google/Red Hat candidate `projects/rhel-cloud/global/images/rhel-9-8-eus-v20261113`
    (`ID: 1956089454365693535`, licenses `rhel-9-server`, `rhel-9-server-eus`).
    Requires independent image approval, RHEL repository/entitlement inputs, and
    billing confirmation for EUS/PAYG treatment.

## Recalculated missing customer inputs & dependencies

- **External delivery manifest (`docs/m3-external-delivery-manifest.json`):**
  **47/47 inputs `NOT PROVIDED`** (`/secure/m3`, `/approved-transfer`,
  `/independent-trust`, and `/etc/kordex/m3` do not exist).
- **Qualification dependencies (`docs/m3-qualification-dependencies.json`):**
  **25 total** (`2` marked `LOCALLY VERIFIED`: `M3-REPO-CONTROLLER`,
  `M3-LOCAL-SKOPEO`; **23 open** reported by `scripts/m3_qualification.py status`).
  On this workstation, live `m3_qualification.py inspect` also fails closed with
  `PinnedSkopeoEnvironmentUnsafe` because the pinned Rocky 10 `skopeo` RPM is
  not installed locally (effectively 24 live gates on this host).

| Blocker Category | Exact Missing Inputs / Dependencies | Responsible Owner | Qualification Gate Blocked | Engineering Unblocked? |
|---|---|---|---|---|
| **Billing & Budget Headroom** | Billing Overview remaining Free Trial credit & expiry + bounded sequential 2-OS cost worksheet (`M3-BILLING-COST`) | GCP Billing Owner / Budget Approver | `cloud-review`, `plan-review`, all GCP provisioning | Cost-model EUS refinement (`M3-IAM-COST-001`) can complete locally |
| **Root Trust, Identities & Durable Backends** | `/etc/kordex/m3/qualification-root.pub`, root-signed trust config, distinct reviewer/signer/verifier/approver/custodian keys, pinned customer trust-state CAS adapter & conformance report, durable replay registry (`M3-TRUST-ROOTS`, `M3-TRUST-STATE-BACKEND`, `M3-REPLAY-REGISTRY`, `M3-IDENTITIES`) | Customer Security Custodian, Platform Team & Independent Reviewer | `trust`, `evidence`, `plan-review`, all 22 rows | Production loader & verifier engineering (`M3-TRUST-LOADER-001`, `M3-EVIDENCE-CONTRACT-001`) can complete locally |
| **OS Images & Private Signed Package Mirrors** | Exact approved Debian 13.8 image or formal scope decision + private signed Debian mirrors; approved RHEL 9.8+ EUS image, private signed RPM repo, GPG key/fingerprint & pinned SELinux/kernel EVRAs (`M3-DEBIAN-IMAGE`, `M3-RHEL-IMAGE`, `M3-PACKAGE-ARTIFACTS`) | Debian/RHEL Image & Repository Owners, Independent Image Reviewers | `inputs`, `cloud-review`, `plan-review`, `qualification` | Bootstrap & Ansible fixes (`M3-INFRA-BOOTSTRAP-001`, `M3-ANSIBLE-EE-001`) can complete locally |
| **K3s & Signed 6-Image Kordex Release** | Pinned K3s binary + airgap image tarballs/locks/signatures; signed 6-image Kordex release bundle + SBOM/SLSA provenance + private OCI registry (`M3-K3S-ARTIFACTS`, `M3-KORDEX-ARTIFACTS`, `M3-PRIVATE-REGISTRY`) | K3s Approver, Kordex Release/Build Owners, Private Registry Admin | `inputs`, `qualification` | CI assembly & offline-bundle fixes (`M3-CI-DEPLOY-001`, `M3-BUNDLE-RCE-001`) can complete locally |
| **Private Network, PKI & Least-Privilege IAM** | Customer RFC1918 mirror & relay CIDRs/routes/PKI/mTLS relay, dedicated `kordex-m3-lab-terraform` & `kordex-m3-lab-lifecycle` SAs + custom IAM roles, separate plan/apply & risk approvals (`M3-LAB-DESIGN`, `M3-GCP-IDENTITY`, `M3-NETWORK-PKI`, `M3-PLAN-APPLY-AUTH`, `M3-IMAGE-RISK-ACCEPTANCE`) | Customer Network/PKI Admin, GCP IAM/Project Owners, Independent Approvers | `cloud-review`, `connectivity`, `plan-review`, `qualification` | IAM manifest/CEL fixes (`M3-IAM-COST-001`) can complete locally |

## Cost and budget gate

- **Incurred M3 spend:** **$0.00** (zero lab resources created).
- **Remaining Free Trial credit:** **UNKNOWN via CLI** (Billing Console export
  from billing owner required; `billingbudgets.googleapis.com` remains disabled).
- **Budget discipline:** Continuous 90-day 3-node RHEL `e2-medium` runtime
  models to ~$403.74 before disks/snapshots/DNS/logging/EUS add-on, exceeding
  `$300`. Sequential campaign execution (Debian 13.8 first, stop/destroy, then
  RHEL 9.8+ with idle VMs stopped) is mandatory for both the `$300` ceiling and
  the `CPUS_ALL_REGIONS = 12` quota. Exact EUS add-on pricing and stopped-VM
  license billing for `rhel-9-8-eus-v20261113` must be confirmed with the
  billing owner before any `terraform apply`.

## Qualification matrix status

- **Canonical Matrix SHA-256:** `ba25ba7224b193e4de3d048fae1d4f027c3cca5626bb1734bf3a426d7807c9ad`
- **Debian 13.8 (11 rows):** `0` accepted, `0` rejected, `11` `NOT RUN`
- **Genuine RHEL 9.8+ (11 rows):** `0` accepted, `0` rejected, `11` `NOT RUN`
- **Real-host identities observed:** `0` | **Evidence archives:** none | **Independent acceptances:** `0/22`
- **Final M3 status:** **INCOMPLETE** (do not start M4–M6 until 22/22 real-host rows are independently accepted or a formal scope change is approved).
