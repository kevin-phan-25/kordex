# Kordex Multi-Agent Task Board

The event journal `docs/engineering/multi-agent-events.jsonl` is authoritative
for all changes, reviews, handoffs, and decisions (current head: Event 167,
`8d4edcb6e0d16f46e141938cac6679c1b574af1ebbe6b1ec9505b81e71f3284c`, updated
`2026-11-26 01:54 UTC`). Machine-readable projection:
`python3 scripts/multi_agent_board.py get_tasks`.

Statuses: `Backlog`, `Proposed`, `Awaiting Codex Review`, `Approved`,
`In Progress`, `Awaiting Integration`, `Awaiting Independent Verification`,
`Blocked`, and `Complete`.

## Software implementation

| ID | Task | Owner | Reviewer | Priority | Status | Dependencies | Files / Verification / Blockers |
|---|---|---|---|---|---|---|---|
| COORD-BOARD-IMPL-001 | Implement & harden file-backed coordination board | Codex | Antigravity | P1 | **Complete** | None | `scripts/multi_agent_board.py`, `tests/infrastructure/test_multi_agent_board.py`. 20/20 tests PASS (`4e1608db...`); live Antigravity+Codex read/write verified ($0). Closed Event 31. |
| COORD-SETUP-001 | Verify Antigravity access and complete coordination demonstration | Antigravity | Codex | P0 | **Blocked** (stale initial status; demo wave integrated) | Step 6 Codex post-integration check on `M3-DEMO-001` | Antigravity `agy 1.5.16` read/write verified (Event 7); `M3-DEMO-001` completed proposal -> challenge -> response -> isolated worktree -> Antigravity integration (`4bc99955...`). Pending Codex Step 6 verification to close both. |
| COORD-MCP-001 | Stdlib stdio MCP server wrapper | Codex | Antigravity | P0 | **Blocked** (Deferred) | Project Owner | Explicitly deferred per user directive (`2026-11-25`, Event 32): shared file-backed board is already operational; focus 100% on M3 completion. |
| M3-DEMO-001 | Fix Terraform CIDR `split` args & defensive `try(tonumber(...))` | Codex | Antigravity | P0 | **Awaiting Independent Verification** | Integrated into `main` | Integrated Codex `.worktrees/wt-m3-demo-001` (`4bc99955...`): `main.tf`, `variables.tf`, `test_qualification_project_guard.py`, `test_self_managed_lab.py`. `terraform fmt/validate` + 80 tests + Wave-1 full `make test` PASS (`d1c0f09a...`). Awaiting Codex Step 6 verification. |
| M3-BUNDLE-RCE-001 | Eliminate untrusted bundle script execution before `SHA256SUMS` | Codex | Antigravity | P0 | **Awaiting Independent Verification** | Integrated into `main` | Integrated `.worktrees/wt-m3-bundle-rce-001` (`731b3aac...`): `check-offline-manifest.sh`, `sign-offline-bundle.sh`, `verify-offline-bundle.sh`, `test-offline-bundle-integrity.sh`. All offline bundle integrity + Wave-1 `make test` PASS (`d1c0f09a...`). Awaiting Codex Step 6 verification. |
| M3-RECOVERY-FAULTS-001 | Reconcile fault allowlist with 3 Terraform egress rules & principal binding | Codex | Antigravity | P0 | **Awaiting Independent Verification** | Integrated into `main` | Integrated `wt-m3-recovery-001` (`395fb9eb...`): `self_managed_lab.py`, `self_managed_lab_recovery.py`, `test_self_managed_lab_recovery.py`. Verified exact match against `main.tf:350-393`; 24/24 focused + Wave-1 full `make test` PASS (`d1c0f09a...`). Awaiting Codex Step 6 verification. |
| M3-OPERATOR-EXEC-001 | Fix operator EE Job API defaults, namespaced list, `Failed` checkpoint & RFC3339 precision | Codex | Antigravity | P0 | **Awaiting Independent Verification** | Integrated into `main` | Integrated `wt-m3-operator-exec-001` (`10f6d71a...`): `ansible_job.go`, `durable.go`, `recovery.go`, `upgrade_checkpoint.go`, `api/protocol/upgrade.go` + tests. Real `kubebuilder-envtest 1.37.0` + `-race` + `make vet` + Wave-1 full `make test` PASS (`d1c0f09a...`). Awaiting Codex Step 6 verification. |
| M3-CTRL-AGENT-001 | Fix control-plane projected Secret symlink, `Terminal->RecoveryRequired`, and agent `ProjectedSecretStore` CAS | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Event 149) | Integrated into `main` | Integrated Codex `wt-m3-ctrl-agent-001` (16 files including `seed_agent_identity_secret.py`, `test_agent_identity_secret_seed.py`, and `auditchain/private_key.go` bounded projected Secret symlink resolver) + Antigravity `O_NONBLOCK` hardening (`f26177f7...`). Go `-race`, `test-stage-offline-assets.sh`, Wave-3 full suite PASS (`738278d7...`). Awaiting Codex Step 6 check on `main` and authorized cluster runtime verification. |
| M3-CI-DEPLOY-001 | Fix CI 6+1 release evidence assembly, `control_plane_deploy.py`, and orphaned M3 tests | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Event 111 / Codex Event 142) | Integrated into `main` | Integrated Codex `wt-m3-ci-deploy-001` (`eb8109fe...`) + Antigravity Event 96 fix in `.github/workflows/ci.yaml:692-732` + inline assembly execution test (`4c892655...`). Codex verified 20/20 lock tests (Event 142); Wave-3 full suite PASS (`738278d7...`). |
| M3-ANSIBLE-EE-001 | Fix Ansible `set_fact` ordering & RHEL installonly RPM verification | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Event 112) | Integrated into `main` | Integrated Codex `wt-m3-ansible-001` (`0a77b784...`) + Antigravity Event 97 fix on `upgrade-rhel.yml:101,115` preflight `rpm -q` `\n` + baseline regression (`4124b12e...`). 58/58 Ansible EE tests (`ansible-core 2.17.3`) + Wave-3 full suite PASS (`738278d7...`). Awaiting Codex Step 6 check on `main`. |
| M3-TRUST-LOADER-001 | Harden production trust loader to conformance parity, backend CAS conflict test & `residual-risk-approver` | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Event 113 / Codex Event 134) | Integrated into `main` | Integrated Codex `wt-m3-trust-loader-001` (`d067c0d0...`) + Antigravity Event 98 `root_path.parents` ancestor protection & `O_NONBLOCK` fix (`f5f2bea2...`). Codex verified 34/34 focused trust tests on `main` (Event 134); Wave-3 full suite PASS (`738278d7...`). Kept open pending `M3-TRUST-RECEIPT-CHALLENGE-001` & external conformance. |
| M3-INFRA-BOOTSTRAP-001 | Fix worker `k3s.yaml` hang, Secret Manager numeric project & `POST :destroy`, Ubuntu/RHEL startup, and `main.tf` `depends_on` | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Event 152) | Integrated into `main` | Integrated Codex `.worktrees/wt-m3-infra-bootstrap-001` (`1889df41...`) + Antigravity fixes: `b"{}"` JSON body on `POST :destroy` in `secret_manager_bootstrap.py` and DNS + all ingress/egress firewall `depends_on` edges on `server`/`worker` in `main.tf` (`cd320532...`). `self_managed_lab.py validate` + Wave-3 full suite PASS (`738278d7...`). |
| M3-EVIDENCE-CONTRACT-001 | Reconcile Debian/RHEL evidence schema, 16-key preflight, 9-key boot-disk, corroboration TOCTOU & `RebootPolicy` `Required` | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Event 151) | Integrated into `main` | Integrated Codex `wt-m3-evidence-contract-001` (4 verifier/test files) + Antigravity fixes on `self_managed_lab.py` (16-key `REQUIRED_ARTIFACTS`, empty Debian `qualification_os_minor`) and `self_managed_upgrade_smoke.py`/`test_debian_upgrade_smoke.py` (`RebootPolicy` `Required`) (`6cee17df...`). Wave-3 full suite PASS (`738278d7...`). |
| M3-IAM-COST-001 | Fix `terraform-deployer-role.json` permissions, Secret Manager CEL numeric project number & EUS cost model | Codex | Antigravity | P1 | **Awaiting Independent Verification** (Event 150) | Integrated into `main` | Integrated Codex `wt-m3-iam-cost-001` (`2b8e125e...`) + Antigravity fixes: added `compute.networks.updatePolicy` to `terraform-deployer-role.json`, fixed `cloudresourcemanager.projects.get` -> `resourcemanager.projects.get` in `lab-inventory-role.json`, and fail-closed BYOS exit in `self_managed_lab.py lab cost` (`6fbccc97...`). Wave-3 full suite PASS (`738278d7...`). Zero live IAM mutations. |
| M3-TRUST-RECEIPT-CHALLENGE-001 | Bind trust-state read/CAS receipts to unique per-request `requestId` challenges to reject in-window replay | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Events 154–157, 160) | Integrated into `main` | Protocol v2 `secrets.token_hex(32)` `requestId` challenge binding on `read_state`/`compare_and_swap` + `schemas/m3-trust-state-conformance-run-report-v2.json` (`fba9113b...`). Independently audited line-by-line by Antigravity; Wave-4 full suite PASS (`c7026955...`, 653 Python + 45 Go + 5 bash + live `envtest 1.37.0`). External customer adapter conformance remains `NOT ESTABLISHED`. |
| M3-OFFLINE-CHECKSUM-GATE-001 | Add trusted non-executing safe-path `SHA256SUMS` preflight before deep manifest parsing in `sign`/`verify` entrypoints | Codex | Antigravity | P0 | **Awaiting Independent Verification** (Events 158–159, 161–167) | Integrated into `main` | Integrated Codex `verify-offline-checksums.sh` (including Event 166 NUL-byte rejection) + `M3-BUNDLE-RCE-001` with Antigravity review improvements (empty-manifest & trailing-slash pre-`sha256sum` rejection, `bash` invocation parity, stronger ordering regressions; diff `16065ca1...`). Verified via `test-offline-bundle-integrity.sh`, `test-stage-offline-assets.sh`, `test-build-offline-bundle-platforms.sh`, and `test_m3_artifact_preflight` (28/28 PASS); committed & pushed to `origin/main`. |
| M3-TRUST-SECURITY-001 | *(Parent tracker — split)* | Codex | Antigravity | P0 | **Proposed** (split) | Tracked by `M3-BUNDLE-RCE-001`, `M3-TRUST-LOADER-001`, `M3-EVIDENCE-CONTRACT-001` | Split per Codex Event 41 & Antigravity Event 51. |
| M3-RUNTIME-EE-001 | *(Parent tracker — split)* | Codex | Antigravity | P0 | **Proposed** (split) | Tracked by `M3-ANSIBLE-EE-001`, `M3-OPERATOR-EXEC-001`, `M3-CTRL-AGENT-001` | Split per Codex Event 42 & Antigravity Event 52. |

## Infrastructure execution

Live GCP inspection (`kordex-fleet-platform-515416` / `209068399397`, re-verified
`2026-11-25 23:17 UTC` in `docs/audits/m3-real-host-execution-report.md`):
- **State:** No Terraform state (`.tfstate`), 0 VMs, 0 disks, 0 snapshots, 0 custom VPCs, 0 DNS zones, 0 secrets, 0 GCS buckets, 0 Artifact Registry repos, 0 custom IAM roles, 36 enabled APIs (`billingbudgets.googleapis.com` NOT enabled).
- **Quotas:** Global `CPUS_ALL_REGIONS = 0/12` (forces sequential OS campaigns: 3× `e2-medium` = 6 vCPUs, 4-VM peak during `wrong-machine-id`/`node-replaced-during-recovery` = 8 vCPUs); `us-east1`: `CPUS 0/200`, `E2_CPUS 0/24`, `INSTANCES 0/24`, `DISKS_TOTAL_GB 0/2048`, `SSD_TOTAL_GB 0/250`, `SNAPSHOTS 0/1000`.
- **Gate:** Provisioning remains **BLOCKED** pending billing headroom confirmation, Debian 13.8 approved image/mirror, customer trust/adapter/replay/network/PKI inputs, and completion of active P0 bootstrap/runtime/verifier fixes.

## M3 scenario qualification

| OS campaign | Required topology | Accepted | Status |
|---|---|---:|---|
| Debian 13.8 | 1 K3s server + 2 workers | 0/11 | Blocked before deployment |
| Genuine RHEL 9.8+ | 1 K3s server + 2 workers | 0/11 | Blocked before deployment |

All 22 canonical scenario rows (matrix SHA-256 `ba25ba7224b193e4de3d048fae1d4f027c3cca5626bb1734bf3a426d7807c9ad`) remain `NOT RUN`: `clean-upgrade`, `cancel-during-executing`, `cancel-during-reboot`, `operator-restart-during-executing`, `ssh-loss-during-apply`, `partial-package-application`, `reboot-never-returns`, `ssh-loss-after-reboot-request`, `wrong-machine-id`, `node-replaced-during-recovery`, and `wrong-kernel-after-reboot`.

## Trust and evidence acceptance

- **External delivery inventory (`docs/m3-external-delivery-manifest.json`):** `47/47` inputs `NOT PROVIDED` (`/secure/m3`, `/approved-transfer`, `/independent-trust`, `/etc/kordex/m3` all absent).
- **Qualification dependencies (`docs/m3-qualification-dependencies.json`):** `25` total (`2` locally verified in repo metadata, `23` open in `m3_qualification.py status`; `M3-LOCAL-SKOPEO` also fails live `inspect` on this workstation with `PinnedSkopeoEnvironmentUnsafe`).
- **Real-host evidence & independent acceptance:** `0/22` collected, `0/22` verified, `0/22` independently accepted. Host-upgrade and provider-upgrade defaults remain OFF.

## Budget consumption

- **M3 resources created to date:** none.
- **Session & cumulative M3 spend:** `$0.00`.
- **Ceiling:** `$300 / 90 days` Free Trial credit (Billing Account `0114E3-3DF354-050DF1` attached; remaining dollar balance and expiry are not exposed via CLI and must be supplied by the billing owner before any cloud apply). `billingbudgets.googleapis.com` remains disabled.
