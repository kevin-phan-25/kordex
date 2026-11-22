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

| Canonical scenario | Disposable-only setup and approved injection | Expected operator behavior | Recovery, evidence, and abort conditions |
|---|---|---|---|
| `ssh-loss-during-apply` | Start the normal scenario and wait for durable `Executing` plus proof that the approved package apply began. Using the approved lab network controller, add a short-lived deny for TCP/22 from the exact execution-environment source to only the target worker's internal `/32`. Set and record automatic expiry before activating it. | `RecoveryRequired`; no package replay; operation reservation and node fence remain held. | Restore the rule through the independent control plane, verify the exact prior rule set and route, then perform approved read-only recovery. Capture deny/restore audit records and times, operation journal, host package state and fence/reservation state. Abort if the source/target tuple cannot be exact or auto-expiry is unavailable. |
| `partial-package-application` | Use only the signed package policy and package set approved for this platform. The package custodian must provide a reviewed disposable-only transaction-failure mechanism that deterministically fails after at least one pinned package changes. No such mechanism is provided by this repository; do not improvise with arbitrary scripts or corrupt the package database. | `RecoveryRequired`; evidence must show a real partial package change and that retry does not repeat the mutation. | Preserve package-manager logs, before/after package inventories, exit status, operation journal, reservation and cordon state. Recover only under an explicit reviewer-approved procedure, then reset from the verified baseline. Abort if no approved deterministic mechanism or package delta exists. |
| `reboot-never-returns` | Wait until durable reboot intent is observed for the exact worker. Through the separately approved project control plane, use a bounded action to prevent that VM from returning for at least the matrix's 120-second minimum. The operator must have an independent timed start/restore action and serial access. | `RecoveryRequired`; reservation and cordon remain held; timeout is not success and must not trigger automatic mutation replay. | Capture reboot intent, instance state/audit times, serial output, unavailable duration (at least 120 seconds), and operation/fence state. Restore only the same verified instance and revalidate its machine ID and boot identity. Abort if the action could affect another VM or the timed recovery path is not tested. |
| `ssh-loss-after-reboot-request` | After the reboot intent is durably recorded, use the approved lab network controller to deny only EE-to-target TCP/22, with a pre-recorded short expiry. Keep the host available to boot; this is an SSH-path fault, not a second reboot. | `RecoveryRequired` while identity/reboot completion is ambiguous; no second reboot merely because the response was lost. | Observe the new boot through serial/independent control plane, restore the exact SSH rule, capture before/after boot IDs and machine ID, and use the approved recovery workflow. Retain deny/restore records and operation/reservation evidence. Abort if reboot intent is not durable. |
| `wrong-machine-id` | During `RecoveryRequired`, configure the approved recovery test harness to present a separate disposable replacement host with a different machine ID at the expected recovery endpoint. Do not alter `/etc/machine-id` on the original host and do not clone credentials. Verify both host identities before connecting the harness. | Reject the substituted host; retain the original operation's fence and reservation; do not mutate or adopt the replacement. | Capture expected and observed machine IDs from independent host records, endpoint mapping, recovery logs, and retained fence state. Restore the original endpoint mapping and recover the original machine only after identity verification. Abort if the harness could route to a non-disposable host. |
| `node-replaced-during-recovery` | With the operation already `RecoveryRequired`, and only in the isolated qualification cluster, use the approved Kubernetes administrator workflow to replace the target Node object so that the same node name has a new UID. Capture original UID and workload state first. Do not delete or replace a Node in a shared cluster. | Reject the changed Node UID; leave the replacement object and its workloads untouched; retain the original reservation/fence. | Capture API audit log, original/replacement UIDs, Node readiness/taints, operation journal, and reservation. Restore the cluster to the reviewed baseline only after evidence is exported. Abort if the context, cluster UID, Node name, or original UID differs from the run sheet. |
| `wrong-kernel-after-reboot` | Before the run, the OS owner must approve a disposable-only boot selection that causes the target to return on a kernel different from the policy target. Use only an already-approved kernel artifact and the platform's documented serial-console recovery procedure; do not disable Secure Boot/SELinux or edit boot configuration ad hoc. | Reject the unexpected kernel; retain `RecoveryRequired`, cordon, and reservation; do not uncordon or claim health from SSH success. | Capture approved/observed kernel versions, boot ID, serial and bootloader records, machine ID, Node UID, health checks, and fence state. Restore the approved kernel selection through the OS owner's reviewed recovery steps, then verify the original host before any recovery transition. Abort if no alternate approved kernel or tested serial rollback exists. |

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
