# Kordex Ansible Execution Environment catalog

This first catalog is a fixed Debian-family package upgrade playbook. It is an execution artifact, not a general Ansible interface: the operator passes a bounded JSON plan, target IP, machine/node identity, and a signed plan digest. The image contains a fixed playbook and entrypoint; callers cannot provide playbook text, inventory, tags, or command arguments.

## Build an EE image

Choose and review an Ansible Execution Environment base image, then pin its OCI digest. The build verifies and embeds the playbook and collections-lock digests. Do not use a mutable tag for the base or publish the final image without pushing it to a registry and recording its resulting digest.

```bash
export KORDEX_ANSIBLE_EE_BASE='registry.example/ansible-ee-base@sha256:REPLACE_WITH_64_HEX_DIGEST'
export KORDEX_ANSIBLE_EE_TAG='registry.example/kordex/ansible-ee:build-1'
./integrations/ansible-ee/build-ee.sh
podman push "$KORDEX_ANSIBLE_EE_TAG"
podman image inspect "$KORDEX_ANSIBLE_EE_TAG" --format '{{.Digest}}'
```

Use the final registry reference with its `@sha256:` digest as `UpgradePolicy.executionEnvironment`; copy the script output into `playbookDigest` and `collectionsDigest`. The execution policy currently accepts `channel: stable`, OS family `debian`, and the `kordex.os-upgrade.debian.v1` catalog. The CRD and API reject hooks, local retries, and RHEL plans until their implementations exist.

## Cluster-side prerequisites

The cluster operator creates one immutable request ConfigMap and one Kubernetes Job per operation phase. The Job uses the policy's digest-pinned EE image and a fixed `/usr/local/bin/kordex-upgrade` entrypoint. It has no Kubernetes API token and no host mounts. It requires:

* A `kordex-upgrade-runner` ServiceAccount with token automount disabled and no RoleBindings.
* A fixed SSH Secret containing only `id_ed25519` and a fixed ConfigMap containing only `known_hosts`.
* The operator's preconfigured SSH user, not supplied by the campaign or policy.
* NetworkPolicy and routing that allow the Job pod to reach the selected node's internal IP on SSH.
* A node SSH account with the required narrowly controlled become privileges.

The runner enforces SSH host-key checking. Do not use an empty or wildcard `known_hosts` entry. Cancellation first writes an immutable operation/phase tombstone, then requests Job deletion. Retries see the tombstone and cannot recreate that Job. This still does not prove a remote playbook stopped; cancellation and any failed/expired Job require node and workload recovery verification.

## Supported behavior and limits

The preflight phase reads distribution family, `/etc/machine-id`, and boot ID without changing packages. The apply phase installs exact package versions with Ansible's APT module, verifies the installed versions and machine ID, and verifies boot-ID behavior. `Required` always reboots; `IfNeeded` conservatively reboots when the plan contains a kernel package; `Never` rejects kernel package plans. The playbook does not change apt repositories or run arbitrary hooks.

This artifact and Job adapter are **not wired into the maintenance controller**. The operator continues to reject upgrade permits before node reservation or cordon. Wiring remains gated on durable preflight/apply/recovery transitions and real disposable-VM reboot and failure drills.
