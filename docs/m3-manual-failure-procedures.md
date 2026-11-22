# M3 manual host-failure procedures

These procedures are for the disposable qualification lab only. They do not
authorize provisioning, a firewall change, package mutation, VM stop, Node
deletion, or host maintenance. Obtain separate approval for each lab run and
for every external control-plane action. The repository's fault helper covers
only bounded relay/API-path and private-mirror TCP faults; it does not implement
the seven host-level injections below. A customer lab operator must use an
approved, narrowly scoped mechanism and retain its independent audit record.
Do not create a generic production fault endpoint or use production hosts.

All seven scenarios are defined by
[`host_upgrade_failure_matrix.json`](../tests/integration/host_upgrade_failure_matrix.json).
Names, allowed outcomes, and acceptance criteria in that file remain
authoritative and unchanged. Run each scenario separately on an approved
Debian 13 Trixie image and an approved RHEL 9.8-or-later image, from a verified
baseline. Do not use Ubuntu results as Debian or RHEL evidence.

## Common entry gate

Before each case, the lab operator and independent reviewer must confirm all
of the following from independent project, VM, Kubernetes, and host records:

1. Project ID is `kordex-fleet-platform-515416`; project label is
   `kordex-disposable=qualification`; region/zone are `us-east1` / `us-east1-b`.
2. The lab identity, three expected VM names, instance IDs, selected OS
   profile, exact approved image self-link and unique image ID match the
   reviewed run plan. The target is one worker, never the server.
3. The target's pre-maintenance machine ID, boot ID, Kubernetes Node name and
   UID, internal IP, package baseline, kernel, operation ID, and plan digest
   have been captured. The other worker is Ready and remains an eligible peer.
4. The maintenance operation has reached the matrix-required phase; its
   durable journal, reservation, cordon owner, workload/PDB baseline, and
   current host state are captured immediately before injection.
5. Serial/IAP recovery has been tested for this exact disposable instance,
   the baseline snapshot/reset process is available, and the injection
   operator has a time-bounded restore procedure independent of the faulted
   SSH path.
6. The injection mechanism targets only the reviewed VM, package transaction,
   or Kubernetes object. Record the control-plane change ID and a stop time
   before applying it. Never broaden a firewall rule or affect other lab nodes.

Abort before injection if any identity is absent or conflicts, the peer is not
eligible, the baseline is unhealthy, unrelated workloads are present, the
operation phase is unexpected, serial recovery is unavailable, or the restore
mechanism cannot be independently confirmed. After injection, stop and keep
the operation fenced if observed state differs from the case contract. Never
resubmit a mutation, manually uncordon, release a reservation, or reset a host
to obtain a passing result.

## Per-scenario procedure

All seven procedures are **BLOCKED**. The repository has no approved, bounded
host-level injection controller or tested automatic restoration mechanism for
these cases. The scenario descriptions below are requirements for a future
customer-approved method, not authorization or executable instructions. Do not
use an unbounded VM stop, firewall edit, boot change, package hook, or Node
deletion as a substitute. The customer owner must document the control, exact
target scope, duration, independent restore, and audit source; an independent
reviewer must approve that run sheet before any fault is attempted.

| Canonical scenario | Exact disposable target and evidence checkpoint | Injection owner, bound, and current status | Expected state, restoration, evidence, and abort condition |
|---|---|---|---|
| `ssh-loss-during-apply` | One named Debian/RHEL worker in the approved three-node lab. Verify project, lab label, zone, instance ID, internal IP, machine ID, Node UID and operation ID from separate cloud, Kubernetes and host records. Capture healthy peer, package baseline, operation journal, reservation, cordon owner and durable `Executing`/apply intent immediately before fault. | Customer network administrator must approve a reversible TCP/22 path interruption limited to the execution-environment source and target `/32`. Maximum outage and automatic restore must be specified and tested by that owner; neither is established here. **BLOCKED.** | Expect `RecoveryRequired`, no replay, fence/reservation retained. Restore through the independent control plane, verify exact rule state, then run read-only recovery. Retain control-plane audit IDs/times, package state and operator evidence. Abort on any identity mismatch, unbounded rule, missing automatic restore, or ineligible peer. |
| `partial-package-application` | Same verified disposable worker; record signed package policy, source repository snapshot, package versions/digests, kernel and healthy baseline. Capture durable `Executing` plus package transaction intent. | Package custodian must approve a deterministic, one-transaction failure mechanism with a documented maximum scope; no such mechanism is implemented or approved. Do not improvise package hooks or corrupt package state. **BLOCKED.** | Expect `RecoveryRequired`, exact nonempty package delta, no replay and retained fence. Recovery/reset requires owner-approved steps and evidence export. Retain package logs, before/after inventory, exit code, operation and reservation state. Abort if a pinned package has not changed or the mechanism can affect another host. |
| `reboot-never-returns` | Verify the exact worker instance ID, machine ID, Node UID, authorized reboot intent and serial recovery path. Capture health, boot ID, disk/snapshot baseline, operation and reservation immediately before reboot. | GCP project owner must approve a timed, single-instance control-plane action with independently tested restoration. The matrix requires at least 120 seconds unavailable; restoration deadline and mechanism are not yet approved. **BLOCKED.** | Expect `RecoveryRequired`; cordon/reservation retained; no replay. Restore only the same verified instance, then revalidate machine and boot identity. Retain reboot intent, instance audit, serial output, exact unavailable interval and recovery result. Abort if target identity or timed restore is uncertain. |
| `ssh-loss-after-reboot-request` | Verify the worker and record machine ID, boot ID, Node UID, operation ID and durable reboot intent. Capture serial access and healthy peer before disrupting SSH. | Customer network administrator must approve a target-only TCP/22 interruption that leaves the VM running, with an explicit maximum outage and independently tested automatic restore. **BLOCKED.** | Expect `RecoveryRequired` while reboot/identity is ambiguous; never issue a second reboot because SSH response was lost. Restore the exact route, inspect boot/host identity, then use approved recovery. Retain route audit, before/after boot IDs and operation/fence evidence. Abort if reboot intent was not durable. |
| `wrong-machine-id` | Verify original worker instance ID, internal address, machine ID, Node UID and operation identity from independent records; capture `RecoveryRequired` state before testing identity rejection. | Customer host/recovery owner must provide an isolated disposable identity-substitution harness that cannot route to another host. No such mechanism is implemented or approved. **BLOCKED.** Do not alter the original host's machine ID or clone credentials. | Expect substitution rejected and original fence/reservation retained; replacement remains untouched. Restore original endpoint mapping and recover only the original host after identity verification. Retain both independently obtained identity records and operator decision. Abort if isolation cannot be proven. |
| `node-replaced-during-recovery` | Verify cluster identity, target node name and original UID; capture workloads, taints, readiness, operation, reservation and `RecoveryRequired` state from the isolated qualification cluster. | Customer Kubernetes owner must approve an isolated disposable-only Node replacement workflow, including exact object identity, restoration, and maximum duration. The repository provides no safe replacement harness. **BLOCKED.** | Expect new UID rejected and replacement left untouched; original reservation/fence retained. Restore baseline only after evidence export and separate approval. Retain Kubernetes audit records, both UIDs and workload state. Abort unless cluster identity and original UID match the reviewed run sheet. |
| `wrong-kernel-after-reboot` | Verify exact worker, approved image and package policy; capture machine ID, Node UID, boot ID, expected kernel, healthy peer, reboot intent and serial recovery availability. | Customer OS owner must approve a previously staged, signed alternate kernel and bounded boot-selection/rollback procedure. No approved alternate or tested rollback is supplied. **BLOCKED.** Do not edit boot configuration ad hoc or disable SELinux/Secure Boot. | Expect kernel mismatch rejected with `RecoveryRequired`, cordon and reservation retained. Restore only through the approved OS-owner rollback, then verify original identity and health. Retain expected/observed kernel, boot records, serial output and fence evidence. Abort if alternate kernel or rollback is unverified. |

## Evidence attachment

The runner creates the operation record. The existing recorder attaches an
external injection log, timestamps, operator identity, and the observations
required by the canonical case contract; it does not inject the fault. Check
the accepted CLI before use:

```sh
python3 tests/integration/record_host_upgrade_fault.py --help
```

For each completed case, copy the customer controller's raw, redacted audit
log to a protected evidence directory and use the exact scenario's required
observation keys from the canonical matrix. Example command shape (replace
placeholders with reviewed values; this is not an injection command):

```sh
python3 tests/integration/record_host_upgrade_fault.py \
  --evidence /secure/m3/evidence/<scenario>-<platform>.json \
  --method <approved-controller-and-change-id> \
  --started-at <RFC3339-UTC-start> \
  --ended-at <RFC3339-UTC-end> \
  --evidence-ref <independent-audit-record-reference> \
  --operator-identity <authorized-customer-operator-id> \
  --log /secure/m3/raw-logs/<scenario>-<platform>.log \
  --observations '<case-specific-JSON-required-by-host-upgrade-failure-matrix.json>'
```

The recorder copies the log, records its SHA-256, validates the timestamps
against the runner interval, and rejects missing case-specific observations.
It does not prove the external log's origin. Preserve the independent
controller audit record and host/cluster evidence for reviewer comparison.
After all 22 cases have actual evidence, prepare and verify the signed
evidence package using
[`m3-readiness-plan-binding.md`](m3-readiness-plan-binding.md#evidence-provenance-and-reviewer-acceptance).
Synthetic tests and fixture signatures must never be placed in the real-host
evidence directory.
