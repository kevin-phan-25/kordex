# Kordex Ansible Execution Environment catalog

This first catalog is a fixed Debian-family package upgrade playbook. It is an execution artifact, not a general Ansible interface: the operator passes a bounded JSON plan, target IP, machine/node identity, and a signed plan digest. The image contains a fixed playbook and entrypoint; callers cannot provide playbook text, inventory, tags, or command arguments.

## Build an EE image

Choose and review an Ansible Execution Environment base image, then pin its OCI digest. The build verifies and embeds the base image reference, Ansible runtime version, playbook digest, and collections-lock digest in image labels and the fixed catalog. At runtime, the entrypoint rechecks the catalog files and installed Ansible version. Do not use a mutable tag for the base or publish the final image without pushing it to a registry and recording its resulting digest.

```bash
export KORDEX_ANSIBLE_EE_BASE='registry.example/ansible-ee-base@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_ANSIBLE_EE_TAG='registry.example/kordex/ansible-ee:build-1'
./integrations/ansible-ee/build-ee.sh
podman push "$KORDEX_ANSIBLE_EE_TAG"
podman image inspect "$KORDEX_ANSIBLE_EE_TAG" --format '{{.Digest}}'
```

Use the final registry reference with its `@sha256:` digest as `UpgradePolicy.executionEnvironment`; copy the script output into `playbookDigest` and `collectionsDigest`. The execution policy currently accepts `channel: stable`, OS family `debian`, and the `kordex.os-upgrade.debian.v2` catalog. Kernel package plans must pin `expectedKernelVersion` to the exact `uname -r` value expected after reboot; the EE receipt and operator verify it before recovery can uncordon the node. The CRD and API reject hooks, local retries, and RHEL plans until their implementations exist.

## Cluster-side prerequisites

The cluster operator creates one immutable request ConfigMap and one Kubernetes Job per operation phase. The Job uses an image digest that must be present in the operator's `KORDEX_UPGRADE_EE_ALLOWLIST`, then runs a fixed `/usr/local/bin/kordex-upgrade` entrypoint. Policy authors cannot select arbitrary images even when they provide a digest. The Job has no Kubernetes API token and no host mounts. It requires:

* A `kordex-upgrade-runner` ServiceAccount with token automount disabled and no RoleBindings.
* A fixed SSH Secret containing only `id_ed25519` and a fixed ConfigMap containing only `known_hosts`.
* The operator's preconfigured SSH user, not supplied by the campaign or policy.
* Optional `KORDEX_UPGRADE_IMAGE_PULL_SECRETS` names for namespace-local registry credentials when node-level image pull identity is unavailable. The referenced Secrets are used only by the Kubernetes image pull path; they are not mounted into the EE container.
* NetworkPolicy and routing that allow the Job pod to reach the selected node's internal IP on SSH.
* A node SSH account with the required narrowly controlled become privileges.

The runner enforces SSH host-key checking. Do not use an empty or wildcard `known_hosts` entry. On a signed cancellation, the operator first checks for an already persisted verified receipt. It accepts that receipt only to enter local recovery and never starts a later package/reboot phase. Otherwise cancellation writes an immutable operation/phase tombstone and requests Job deletion; retries cannot recreate that Job. Because Job deletion cannot prove a remote playbook stopped, the operator persists a separate read-only inspection Job to verify package pins and host identity before recovery. Missing or inconsistent inspection evidence keeps the reservation and cordon until intervention.

## Supported behavior and limits

The preflight phase reads distribution family, `/etc/machine-id`, and boot ID without changing packages. The apply phase installs exact package versions and verifies them without rebooting. `IfNeeded` considers both kernel packages and Debian's `/var/run/reboot-required` marker. The EE independently recomputes the canonical package-plan digest and rejects request tampering. If the apply receipt requires a reboot, the operator persists that evidence and sets an explicit reboot authorization in the immutable reboot request. The deterministic reboot Job revalidates the preflight machine/boot identity, reboots, verifies the same machine returns with a changed boot ID, and rechecks exact package versions. `Never` rejects kernel package plans. The playbook does not change apt repositories or run arbitrary hooks.

When an apply or reboot outcome is ambiguous and no verified execution receipt exists, the operator may run a separate fixed `inspect` phase. It is read-only: it checks the exact pinned versions, machine ID, and current boot ID, and reports whether a reboot remains required. The operator persists the deterministic inspection reference before starting it. A matching inspection allows only the existing node/workload recovery process to continue; it never retries package installation or reboot. Missing or mismatched package/identity evidence keeps the operation cordoned for intervention.

The adapter is wired into the maintenance controller behind `KORDEX_ENABLE_HOST_UPGRADES` (false by default). A verified EE receipt is copied to a deterministic immutable ConfigMap so status recovery does not depend on retaining the Job Pod logs. `IfNeeded` uses kernel package selection and the Debian `/var/run/reboot-required` marker to decide whether the operator records a separate reboot phase. The controller path has not completed disposable-VM upgrade, reboot, interruption, and recovery drills; keep the gate disabled outside that lab. The current GKE COS cluster is not supported by this package executor.
