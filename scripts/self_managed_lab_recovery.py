#!/usr/bin/env python3
"""Fail-closed recovery and bounded fault tools for the disposable M3 lab.

This module is imported by self_managed_lab.py. Its cloud operations are only
reachable through explicit subcommands and require explicit project/lab
identity. Unit tests inject a command runner; no test contacts Google Cloud.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import time
from typing import Callable
import zlib


PROJECT_ID = "kordex-fleet-platform-515416"
LAB_ID = "kordex-lab"
PROJECT_LABEL = {"kordex-disposable": "qualification"}
NODE_ROLES = ("server", "worker-1", "worker-2")
SAFE_POINTS = {"fresh-baseline", "before-failure", "after-recovery"}
MAX_BASELINE_AGE_SECONDS = 2 * 60 * 60
FAULT_SCENARIOS = {"relay-connectivity": ("tcp", 18443),
                   "api-connectivity": ("tcp", 18443),
                   "private-mirror-connectivity": ("tcp", 443)}
MAX_FAULT_SECONDS = 900
LOCK_PREFIX = "kordex-m3-fault-lock:v1:"
DENY_PREFIX = "kordex-m3-fault:v1:"


class RecoveryError(RuntimeError):
    pass


Runner = Callable[..., str]


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def names_for(lab_id: str) -> dict[str, str]:
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,19}", lab_id):
        raise RecoveryError("lab identity must be a 3-20 character lowercase resource prefix")
    return {"server": f"{lab_id}-server", "worker-1": f"{lab_id}-worker", "worker-2": f"{lab_id}-worker-2"}


def validate_target(project_id: str, lab_id: str, zone: str, instances: dict[str, str]) -> dict[str, str]:
    if project_id != PROJECT_ID:
        raise RecoveryError(f"refusing recovery operation outside the approved lab project {PROJECT_ID}")
    if zone != "us-east1-b":
        raise RecoveryError("refusing recovery operation outside approved zone us-east1-b")
    if lab_id != LAB_ID:
        raise RecoveryError(f"lab identity must match the Terraform-designated disposable lab {LAB_ID}")
    expected = names_for(lab_id)
    if instances != expected:
        raise RecoveryError("explicit instances must exactly match the lab server and both Ubuntu worker names")
    return expected


def command(args: list[str], *, run: Runner, capture: bool = True, timeout: int = 120) -> str:
    try:
        return run(args, capture=capture, timeout=timeout)
    except RecoveryError:
        raise
    except Exception as error:
        # Cloud CLI output can contain diagnostic data. Do not echo it here.
        raise RecoveryError(f"cloud command failed: {args[0]} (exit status unavailable)") from error


def gcloud_prefix(project_id: str) -> list[str]:
    return [os.environ.get("GCLOUD", "gcloud"), "--project", project_id]


def json_command(args: list[str], *, run: Runner) -> dict:
    output = command(args, run=run)
    try:
        value = json.loads(output, object_pairs_hook=unique_object)
    except (TypeError, json.JSONDecodeError, RecoveryError) as error:
        raise RecoveryError("cloud command returned invalid or ambiguous JSON") from error
    if not isinstance(value, dict):
        raise RecoveryError("cloud command returned an unexpected JSON resource")
    return value


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError("duplicate JSON key in recovery input")
        result[key] = value
    return result


def verify_project(project_id: str, *, run: Runner) -> dict:
    if project_id != PROJECT_ID:
        raise RecoveryError(f"project must be exactly {PROJECT_ID}")
    project = json_command(gcloud_prefix(project_id) + ["projects", "describe", project_id, "--format=json"], run=run)
    if (project.get("projectId") != project_id or project.get("lifecycleState") != "ACTIVE"
            or (project.get("labels") or {}).get("kordex-disposable") != "qualification"):
        raise RecoveryError("project is not active and explicitly labeled kordex-disposable=qualification")
    return {"projectId": project_id, "projectNumber": str(project.get("projectNumber", "")),
            "labels": PROJECT_LABEL, "lifecycleState": "ACTIVE"}


def instance_resource(project_id: str, zone: str, name: str, *, run: Runner) -> dict:
    return json_command(gcloud_prefix(project_id) + ["compute", "instances", "describe", name,
                        f"--zone={zone}", "--format=json"], run=run)


def disk_resource(project_id: str, zone: str, disk: str, *, run: Runner) -> dict:
    return json_command(gcloud_prefix(project_id) + ["compute", "disks", "describe", disk,
                        f"--zone={zone}", "--format=json"], run=run)


def _suffix(value: object) -> str:
    return str(value or "").rstrip("/").split("/")[-1]


def verify_instance(project_id: str, lab_id: str, zone: str, role: str, name: str,
                    *, run: Runner, allowed_status: set[str]) -> dict:
    expected = names_for(lab_id)
    if role not in expected or expected[role] != name:
        raise RecoveryError("instance name does not match its explicit lab node role")
    resource = instance_resource(project_id, zone, name, run=run)
    labels = resource.get("labels") or {}
    required_labels = {"application": "kordex", "purpose": "disposable-qualification",
                       "managed-by": "terraform", "lab-id": lab_id, "node-role": role}
    if (resource.get("name") != name or resource.get("status") not in allowed_status
            or _suffix(resource.get("zone")) != zone
            or any(labels.get(key) != value for key, value in required_labels.items())):
        raise RecoveryError(f"instance {name} is not a verified member of lab {lab_id}")
    interfaces = resource.get("networkInterfaces") or []
    if len(interfaces) != 1 or not interfaces[0].get("networkIP") or interfaces[0].get("accessConfigs"):
        raise RecoveryError(f"instance {name} does not have the expected private-only network interface")
    if _suffix(interfaces[0].get("network")) != f"{lab_id}-network":
        raise RecoveryError(f"instance {name} is attached to an unexpected VPC")
    tags = set((resource.get("tags") or {}).get("items") or [])
    required_tags = {f"{lab_id}-server"} if role == "server" else {f"{lab_id}-worker", f"{lab_id}-{role}"}
    if not required_tags.issubset(tags):
        raise RecoveryError(f"instance {name} lacks its unique lab firewall identity tags")
    disks = [disk for disk in resource.get("disks") or [] if disk.get("boot") is True]
    if len(disks) != 1:
        raise RecoveryError(f"instance {name} must have exactly one boot disk")
    disk_name = _suffix(disks[0].get("source"))
    if not disk_name.startswith(f"{lab_id}-"):
        raise RecoveryError(f"instance {name} boot disk is outside the lab identity")
    disk = disk_resource(project_id, zone, disk_name, run=run)
    instance_self_link = str(resource.get("selfLink", ""))
    users = disk.get("users") or []
    if (disk.get("name") != disk_name or disk.get("status") != "READY"
            or _suffix(disk.get("zone")) != zone
            or not any(user == instance_self_link or _suffix(user) == name for user in users)):
        raise RecoveryError(f"boot disk {disk_name} is not attached to the verified instance")
    metadata = {item.get("key"): item.get("value") for item in (resource.get("metadata") or {}).get("items", [])}
    return {"role": role, "name": name, "instanceId": str(resource.get("id", "")),
            "status": resource.get("status"), "zone": zone, "disk": disk_name,
            "internalIp": interfaces[0]["networkIP"], "machineType": _suffix(resource.get("machineType")),
            "network": _suffix(interfaces[0].get("network")), "tags": sorted(tags),
            "labels": required_labels, "serialPortEnabled": metadata.get("serial-port-enable") == "TRUE",
            "resource": resource, "diskResource": disk}


def kubernetes_baseline(kube_context: str, names: dict[str, str], *, run: Runner,
                        kubectl: str = "kubectl") -> dict:
    if not kube_context or kube_context.startswith("-"):
        raise RecoveryError("an explicit disposable Kubernetes context is required")
    nodes = json_command([kubectl, "--context", kube_context, "get", "nodes", "-o", "json"], run=run)
    items = nodes.get("items")
    if not isinstance(items, list) or {item.get("metadata", {}).get("name") for item in items} != set(names.values()):
        raise RecoveryError("Kubernetes node set does not match the verified three-node lab topology")
    node_records = []
    for item in items:
        status = item.get("status") or {}
        ready = next((condition.get("status") for condition in status.get("conditions", [])
                      if condition.get("type") == "Ready"), "")
        if ready != "True":
            raise RecoveryError("all three Kubernetes nodes must be Ready before capturing a recovery baseline")
        node_records.append({"name": item["metadata"]["name"], "uid": item["metadata"].get("uid", ""),
                             "kubeletVersion": (item.get("status") or {}).get("nodeInfo", {}).get("kubeletVersion", "")})
    workloads = json_command([kubectl, "--context", kube_context, "get",
                              "deployments,statefulsets,daemonsets", "--all-namespaces", "-o", "json"], run=run)
    workload_items = workloads.get("items")
    if not isinstance(workload_items, list):
        raise RecoveryError("Kubernetes returned an invalid workload baseline")
    workload_records = []
    for item in workload_items:
        metadata, spec, status = item.get("metadata") or {}, item.get("spec") or {}, item.get("status") or {}
        if item.get("kind") == "DaemonSet":
            desired = int(status.get("desiredNumberScheduled", 0))
            ready = int(status.get("numberReady", 0))
        else:
            desired = int(spec.get("replicas", 1))
            ready = int(status.get("readyReplicas", 0))
        if desired > 0 and ready < desired:
            raise RecoveryError("workload baseline is not healthy; snapshot creation is blocked")
        workload_records.append({"kind": item.get("kind", ""), "namespace": metadata.get("namespace", ""),
                                 "name": metadata.get("name", ""), "uid": metadata.get("uid", ""),
                                 "desired": desired, "ready": ready})
    if not any(item["desired"] > 0 for item in workload_records):
        raise RecoveryError("at least one workload with desired replicas is required for a recovery baseline")
    return {"context": kube_context, "nodes": sorted(node_records, key=lambda item: item["name"]),
            "workloads": sorted(workload_records, key=lambda item: (item["namespace"], item["kind"], item["name"]))}


def remote_host_identity(project_id: str, zone: str, instance: str, *, run: Runner) -> dict:
    script = "printf '%s\\n%s\\n' \"$(cat /etc/machine-id)\" \"$(cat /proc/sys/kernel/random/boot_id)\""
    output = command(gcloud_prefix(project_id) + ["compute", "ssh", instance, f"--zone={zone}",
                    "--tunnel-through-iap", f"--command={script}", "--quiet"], run=run, timeout=60)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 2 or not re.fullmatch(r"[a-f0-9]{32}", lines[0]) or not re.fullmatch(
        r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", lines[1]
    ):
        raise RecoveryError(f"host identity read through IAP failed for {instance}")
    return {"machineId": lines[0], "bootId": lines[1]}


def remote_tcp_probe(project_id: str, zone: str, instance: str, destination: str, port: int,
                     *, run: Runner) -> bool:
    address = ipaddress.ip_address(destination)
    if not address.is_private or type(port) is not int or not 1 <= port <= 65535:
        raise RecoveryError("connectivity probe destination is not an approved private address and TCP port")
    # Distinguish a refused/timed-out destination socket from an unavailable
    # VM or broken IAP/SSH path. Treating every SSH error as an unreachable
    # destination would let an infrastructure failure falsely prove that a
    # network fault was injected.
    script = ("python3 -c 'import socket; s=socket.socket(); s.settimeout(3); "
              "result=s.connect_ex((\"" + str(address) + "\"," + str(port) + ")); "
              "print(\"reachable\" if result == 0 else \"unreachable\"); s.close()'")
    output = command(gcloud_prefix(project_id) + ["compute", "ssh", instance, f"--zone={zone}",
                     "--tunnel-through-iap", f"--command={script}", "--quiet"], run=run, timeout=30)
    results = [line.strip() for line in output.splitlines() if line.strip()]
    if not results or results[-1] not in {"reachable", "unreachable"}:
        raise RecoveryError("connectivity probe returned no valid result; fault state is unknown")
    return results[-1] == "reachable"


def _read_json(path: Path, limit: int = 128 * 1024) -> tuple[dict, bytes]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise RecoveryError("recovery manifest is unavailable or is a symlink") from error
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
            raise RecoveryError("recovery manifest must be a bounded regular file")
        raw = file.read(limit + 1)
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (TypeError, json.JSONDecodeError, RecoveryError) as error:
        raise RecoveryError("recovery manifest JSON is invalid or ambiguous") from error
    if not isinstance(value, dict):
        raise RecoveryError("recovery manifest must contain one object")
    return value, raw


def write_new_json(path: Path, value: dict) -> str:
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise RecoveryError("recovery evidence directory must be a real directory")
    if path.exists() or path.is_symlink():
        raise RecoveryError(f"refusing to overwrite existing recovery evidence: {path.name}")
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    temp_fd, temp_name = tempfile.mkstemp(prefix=".kordex-recovery-", dir=path.parent)
    try:
        os.fchmod(temp_fd, 0o600)
        with os.fdopen(temp_fd, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        os.link(temp_name, path, follow_symlinks=False)
    except OSError as error:
        raise RecoveryError("could not atomically create recovery evidence") from error
    finally:
        Path(temp_name).unlink(missing_ok=True)
    return hashlib.sha256(payload).hexdigest()


def append_audit(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise RecoveryError("could not securely open recovery audit file") from error
    with os.fdopen(fd, "ab") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise RecoveryError("recovery audit file must be regular and mode 0600")
        file.write((json.dumps(record, sort_keys=True) + "\n").encode())
        file.flush()
        os.fsync(file.fileno())


def require_confirmation(actual: str, expected: str) -> None:
    if actual != expected:
        raise RecoveryError(f"destructive confirmation must exactly equal {expected!r}")


def require_distinct_outputs(evidence_path: Path, audit_path: Path) -> None:
    if evidence_path.resolve(strict=False) == audit_path.resolve(strict=False):
        raise RecoveryError("evidence and audit outputs must be different files")


def capture_baseline(project_id: str, lab_id: str, zone: str, instances: dict[str, str],
                     kube_context: str, idle_attestation: str, output: Path, audit_path: Path,
                     *, run: Runner, now: Callable[[], str] = now_utc) -> tuple[dict, str]:
    names = validate_target(project_id, lab_id, zone, instances)
    require_distinct_outputs(output, audit_path)
    if idle_attestation != "NO_ACTIVE_MAINTENANCE":
        raise RecoveryError("type NO_ACTIVE_MAINTENANCE only after independently confirming no active or ambiguous operation")
    project = verify_project(project_id, run=run)
    k8s = kubernetes_baseline(kube_context, names, run=run)
    nodes = {}
    for role in NODE_ROLES:
        node = verify_instance(project_id, lab_id, zone, role, names[role], run=run, allowed_status={"RUNNING"})
        host = remote_host_identity(project_id, zone, names[role], run=run)
        nodes[role] = {key: value for key, value in node.items() if key not in {"resource", "diskResource"}}
        nodes[role].update(host)
    record = {"schema": "kordex-m3-recovery-baseline-v1", "project": project,
              "labId": lab_id, "zone": zone, "capturedAt": now(), "kubernetes": k8s,
              "idleAttestation": idle_attestation, "nodes": nodes,
              "recoverySetId": secrets.token_hex(6)}
    digest = write_new_json(output, record)
    append_audit(audit_path, {"event": "recovery-baseline-captured", "time": record["capturedAt"],
                  "projectId": project_id, "labId": lab_id, "zone": zone,
                  "recoverySetId": record["recoverySetId"], "evidenceFile": output.name,
                  "evidenceSHA256": digest, "nodeCount": len(nodes),
                  "workloadCount": len(k8s["workloads"])})
    return record, digest


def verify_baseline_record(path: Path, project_id: str, lab_id: str, zone: str,
                           instances: dict[str, str]) -> tuple[dict, str]:
    data, raw = _read_json(path)
    expected = validate_target(project_id, lab_id, zone, instances)
    if (data.get("schema") != "kordex-m3-recovery-baseline-v1"
            or (data.get("project") or {}).get("projectId") != project_id
            or data.get("labId") != lab_id or data.get("zone") != zone
            or data.get("idleAttestation") != "NO_ACTIVE_MAINTENANCE"
            or not re.fullmatch(r"[a-f0-9]{12}", str(data.get("recoverySetId", "")))):
        raise RecoveryError("baseline record does not match the requested project, lab, zone, or idle assertion")
    try:
        captured = dt.datetime.fromisoformat(data["capturedAt"].replace("Z", "+00:00"))
    except (ValueError, KeyError, AttributeError) as error:
        raise RecoveryError("baseline timestamp is missing or invalid") from error
    if captured.tzinfo is None or captured > dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60):
        raise RecoveryError("baseline timestamp must be timezone-aware and cannot be in the future")
    nodes = data.get("nodes")
    if not isinstance(nodes, dict) or set(nodes) != set(NODE_ROLES):
        raise RecoveryError("baseline record does not contain the complete three-node identity set")
    for role, name in expected.items():
        node = nodes[role]
        if not isinstance(node, dict):
            raise RecoveryError(f"baseline record has invalid identity for {role}")
        try:
            private_ip = ipaddress.ip_address(node.get("internalIp", "0.0.0.0")).is_private
        except ValueError as error:
            raise RecoveryError(f"baseline record has invalid identity for {role}") from error
        if (node.get("name") != name or not re.fullmatch(r"[0-9]{1,24}", str(node.get("instanceId", "")))
                or not re.fullmatch(r"[a-f0-9]{32}", str(node.get("machineId", "")))
                or not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", str(node.get("bootId", "")))
                or not private_ip):
            raise RecoveryError(f"baseline record has invalid identity for {role}")
    return data, hashlib.sha256(raw).hexdigest()


def create_snapshot_set(project_id: str, lab_id: str, zone: str, instances: dict[str, str],
                        baseline_path: Path, scenario: str, idle_attestation: str, confirmation: str,
                        output: Path, audit_path: Path, *, run: Runner,
                        now: Callable[[], str] = now_utc) -> tuple[dict, str]:
    names = validate_target(project_id, lab_id, zone, instances)
    require_distinct_outputs(output, audit_path)
    if output.exists() or output.is_symlink():
        raise RecoveryError("snapshot-set evidence path already exists; no snapshots were created")
    if scenario not in SAFE_POINTS:
        raise RecoveryError("snapshot safe point must be fresh-baseline, before-failure, or after-recovery")
    baseline, baseline_hash = verify_baseline_record(baseline_path, project_id, lab_id, zone, names)
    if idle_attestation != "NO_ACTIVE_MAINTENANCE":
        raise RecoveryError("type NO_ACTIVE_MAINTENANCE only after confirming no active or ambiguous Kordex operation")
    try:
        captured = dt.datetime.fromisoformat(baseline["capturedAt"].replace("Z", "+00:00"))
    except (ValueError, KeyError, AttributeError) as error:
        raise RecoveryError("baseline timestamp is missing or invalid") from error
    if captured.tzinfo is None:
        raise RecoveryError("baseline timestamp must be timezone-aware and cannot be in the future")
    baseline_age = (dt.datetime.now(dt.timezone.utc) - captured).total_seconds()
    if baseline_age < -60 or baseline_age > MAX_BASELINE_AGE_SECONDS:
        raise RecoveryError("baseline is over two hours old; recapture a healthy idle baseline before snapshotting")
    require_confirmation(confirmation, f"SNAPSHOT {project_id}/{lab_id}/{baseline['recoverySetId']}")
    verify_project(project_id, run=run)
    resources = {}
    for role, name in names.items():
        current = verify_instance(project_id, lab_id, zone, role, name, run=run, allowed_status={"TERMINATED"})
        prior = baseline["nodes"][role]
        if (current["instanceId"] != prior["instanceId"] or current["disk"] != prior["disk"]
                or current["internalIp"] != prior["internalIp"]):
            raise RecoveryError(f"lab instance {name} no longer matches the captured baseline identity")
        resources[role] = current
    snapshot_nodes: dict[str, dict] = {}
    for role, name in names.items():
        disk = resources[role]["disk"]
        snapshot_name = f"{lab_id}-{role}-snap-{baseline['recoverySetId']}"
        labels = {"application": "kordex", "purpose": "disposable-qualification",
                  "lab-id": lab_id, "node-role": role, "recovery-set": baseline["recoverySetId"],
                  "safe-point": scenario}
        args = gcloud_prefix(project_id) + ["compute", "snapshots", "create", snapshot_name,
                f"--source-disk={disk}", f"--source-disk-zone={zone}", "--storage-location=us-east1",
                "--labels=" + ",".join(f"{key}={value}" for key, value in labels.items()),
                f"--description=Kordex M3 {scenario} recovery set {baseline['recoverySetId']}"]
        try:
            command(args, run=run, timeout=900)
            snapshot = json_command(gcloud_prefix(project_id) + ["compute", "snapshots", "describe", snapshot_name,
                                  "--format=json"], run=run)
            expected_source_suffix = f"/zones/{zone}/disks/{disk}"
            actual_source = str(snapshot.get("sourceDisk", ""))
            actual_labels = snapshot.get("labels") or {}
            if (snapshot.get("name") != snapshot_name or snapshot.get("status") != "READY"
                    or not actual_source.endswith(expected_source_suffix)
                    or any(actual_labels.get(key) != value for key, value in labels.items())):
                raise RecoveryError(f"snapshot {snapshot_name} failed source, label, or READY verification")
            snapshot_nodes[role] = {"name": snapshot_name, "sourceDisk": disk,
                                    "sourceDiskUrl": actual_source, "status": "READY", "labels": labels}
            append_audit(audit_path, {"event": "snapshot-created", "time": now(), "projectId": project_id,
                          "labId": lab_id, "zone": zone, "recoverySetId": baseline["recoverySetId"],
                          "role": role, "snapshot": snapshot_name, "sourceDisk": disk, "status": "READY"})
        except BaseException:
            append_audit(audit_path, {"event": "snapshot-set-incomplete", "time": now(), "projectId": project_id,
                          "labId": lab_id, "zone": zone, "recoverySetId": baseline["recoverySetId"],
                          "completedRoles": sorted(snapshot_nodes), "failedRole": role,
                          "action": "preserve completed snapshots; do not use this set for restore"})
            raise
    manifest = {"schema": "kordex-m3-recovery-snapshot-set-v1", "projectId": project_id,
                "labId": lab_id, "zone": zone, "scenario": scenario, "createdAt": now(),
                "recoverySetId": baseline["recoverySetId"], "baselineSHA256": baseline_hash,
                "kubernetes": baseline["kubernetes"], "nodes": {
                    role: {"instanceName": baseline["nodes"][role]["name"],
                           "instanceId": baseline["nodes"][role]["instanceId"],
                           "machineId": baseline["nodes"][role]["machineId"],
                           "bootId": baseline["nodes"][role]["bootId"],
                           "internalIp": baseline["nodes"][role]["internalIp"],
                           "sourceDisk": snapshot_nodes[role]["sourceDisk"],
                           "snapshot": snapshot_nodes[role]["name"],
                           "sourceDiskUrl": snapshot_nodes[role]["sourceDiskUrl"]}
                    for role in NODE_ROLES},
                "snapshotOutcome": "READY_ALL_THREE"}
    digest = write_new_json(output, manifest)
    append_audit(audit_path, {"event": "snapshot-set-ready", "time": now(), "projectId": project_id,
                  "labId": lab_id, "zone": zone, "recoverySetId": manifest["recoverySetId"],
                  "manifest": str(output), "manifestSHA256": digest, "status": manifest["snapshotOutcome"]})
    return manifest, digest


def verify_snapshot_set(path: Path, project_id: str, lab_id: str, zone: str,
                        instances: dict[str, str], *, run: Runner) -> tuple[dict, str]:
    expected = validate_target(project_id, lab_id, zone, instances)
    verify_project(project_id, run=run)
    manifest, raw = _read_json(path)
    if (manifest.get("schema") != "kordex-m3-recovery-snapshot-set-v1"
            or manifest.get("projectId") != project_id or manifest.get("labId") != lab_id
            or manifest.get("zone") != zone or manifest.get("snapshotOutcome") != "READY_ALL_THREE"
            or manifest.get("scenario") not in SAFE_POINTS
            or not re.fullmatch(r"[a-f0-9]{12}", str(manifest.get("recoverySetId", "")))):
        raise RecoveryError("snapshot set manifest is incomplete or does not match the requested lab")
    nodes = manifest.get("nodes")
    if not isinstance(nodes, dict) or set(nodes) != set(NODE_ROLES):
        raise RecoveryError("snapshot set must contain all three lab node roles")
    for role, name in expected.items():
        record = nodes[role]
        expected_snapshot = f"{lab_id}-{role}-snap-{manifest['recoverySetId']}"
        source_disk = record.get("sourceDisk")
        source_disk_url = record.get("sourceDiskUrl")
        labels = {"application": "kordex", "purpose": "disposable-qualification", "lab-id": lab_id,
                  "node-role": role, "recovery-set": manifest["recoverySetId"], "safe-point": manifest["scenario"]}
        if (record.get("instanceName") != name or record.get("snapshot") != expected_snapshot
                or not isinstance(source_disk, str) or not source_disk.startswith(f"{lab_id}-")
                or _suffix(source_disk_url) != source_disk
                or source_disk_url != f"https://www.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/disks/{source_disk}"
                or not re.fullmatch(r"[0-9]{1,24}", str(record.get("instanceId", "")))
                or not re.fullmatch(r"[a-f0-9]{32}", str(record.get("machineId", "")))
                or not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", str(record.get("bootId", "")))
                or not ipaddress.ip_address(record.get("internalIp", "0.0.0.0")).is_private):
            raise RecoveryError(f"snapshot set identity is invalid for {role}")
        snapshot = json_command(gcloud_prefix(project_id) + ["compute", "snapshots", "describe", expected_snapshot,
                              "--format=json"], run=run)
        if (snapshot.get("status") != "READY" or snapshot.get("name") != expected_snapshot
                or snapshot.get("sourceDisk") != source_disk_url
                or not str(snapshot.get("sourceDisk", "")).endswith(f"/zones/{zone}/disks/{source_disk}")
                or any((snapshot.get("labels") or {}).get(key) != value for key, value in labels.items())):
            raise RecoveryError(f"snapshot {expected_snapshot} is not a verified snapshot of this lab's {role} disk")
    return manifest, hashlib.sha256(raw).hexdigest()


def delete_snapshot_set(project_id: str, lab_id: str, zone: str, instances: dict[str, str],
                        manifest_path: Path, confirmation: str, output: Path, audit_path: Path, *, run: Runner,
                        now: Callable[[], str] = now_utc) -> dict:
    require_distinct_outputs(output, audit_path)
    if output.exists() or output.is_symlink():
        raise RecoveryError("snapshot cleanup evidence path already exists")
    manifest, manifest_hash = verify_snapshot_set(manifest_path, project_id, lab_id, zone, instances, run=run)
    require_confirmation(confirmation, f"DELETE-SNAPSHOTS {project_id}/{lab_id}/{manifest['recoverySetId']}")
    outcomes = {}
    for role in NODE_ROLES:
        snapshot_name = manifest["nodes"][role]["snapshot"]
        try:
            command(gcloud_prefix(project_id) + ["compute", "snapshots", "delete", snapshot_name, "--quiet"], run=run)
            listing = command(gcloud_prefix(project_id) + ["compute", "snapshots", "list",
                              f"--filter=name={snapshot_name}", "--format=json"], run=run)
            try:
                remaining = json.loads(listing)
            except (TypeError, json.JSONDecodeError) as error:
                raise RecoveryError("snapshot deletion verification returned invalid JSON") from error
            if not isinstance(remaining, list) or any(item.get("name") == snapshot_name
                                                       for item in remaining if isinstance(item, dict)):
                raise RecoveryError(f"snapshot {snapshot_name} remains after deletion; preserve all other resources")
            outcomes[role] = {"snapshot": snapshot_name, "outcome": "DELETED_AND_ABSENT"}
            append_audit(audit_path, {"event": "snapshot-deleted", "time": now(), "projectId": project_id,
                          "labId": lab_id, "zone": zone, "recoverySetId": manifest["recoverySetId"],
                          "role": role, "snapshot": snapshot_name, "outcome": "DELETED_AND_ABSENT"})
        except BaseException as error:
            append_audit(audit_path, {"event": "snapshot-set-delete-incomplete", "time": now(),
                          "projectId": project_id, "labId": lab_id, "zone": zone,
                          "recoverySetId": manifest["recoverySetId"], "completedRoles": sorted(outcomes),
                          "failedRole": role, "failureClass": type(error).__name__,
                          "action": "preserve remaining verified snapshots and retry only by manifest"})
            raise
    record = {"schema": "kordex-m3-snapshot-cleanup-v1", "projectId": project_id,
            "labId": lab_id, "zone": zone, "recoverySetId": manifest["recoverySetId"],
            "snapshotManifestSHA256": manifest_hash, "deleted": outcomes, "completedAt": now()}
    digest = write_new_json(output, record)
    append_audit(audit_path, {"event": "snapshot-set-deleted", "time": record["completedAt"],
                  "projectId": project_id, "labId": lab_id, "zone": zone,
                  "recoverySetId": manifest["recoverySetId"], "evidenceFile": output.name,
                  "evidenceSHA256": digest, "outcome": "ALL_THREE_ABSENT"})
    return record


def restore_snapshot_set(project_id: str, lab_id: str, zone: str, instances: dict[str, str],
                         roles: list[str], snapshot_manifest: Path, kube_context: str,
                         confirmation: str, output: Path, audit_path: Path,
                         apply_restore: Callable[[dict[str, str], dict[str, str], str], None],
                         *, run: Runner, now: Callable[[], str] = now_utc) -> dict:
    """Restore one coherent three-node baseline; never restore a single K3s node.

    ``apply_restore`` must create/show a saved Terraform plan and require its
    own exact project/lab/operation confirmation before applying it. This
    function is not called by tests against a real cloud.
    """
    names = validate_target(project_id, lab_id, zone, instances)
    if roles != list(NODE_ROLES):
        raise RecoveryError("K3s reset requires explicit selection of all three roles in server, worker-1, worker-2 order")
    require_distinct_outputs(output, audit_path)
    if output.exists() or output.is_symlink():
        raise RecoveryError("restore evidence path already exists")
    verify_project(project_id, run=run)
    manifest, manifest_hash = verify_snapshot_set(snapshot_manifest, project_id, lab_id, zone, names, run=run)
    operation_id = secrets.token_hex(6)

    # A coherent K3s datastore snapshot must replace the whole topology. Require
    # every current VM to be stopped, lab-owned and attached to a lab disk; do
    # not address a resource selected only by a caller-provided name.
    for role, name in names.items():
        current = verify_instance(project_id, lab_id, zone, role, name, run=run, allowed_status={"TERMINATED"})
        saved = manifest["nodes"][role]
        if current["internalIp"] != saved["internalIp"]:
            raise RecoveryError(f"current {role} address differs from the verified snapshot baseline")
    require_confirmation(confirmation, f"RESTORE {project_id}/{lab_id}/{manifest['recoverySetId']}")

    snapshot_ids = {role: manifest["nodes"][role]["snapshot"] for role in NODE_ROLES}
    internal_ips = {role: manifest["nodes"][role]["internalIp"] for role in NODE_ROLES}
    record = {"schema": "kordex-m3-lab-restore-v1", "projectId": project_id, "labId": lab_id,
              "zone": zone, "operationId": operation_id, "snapshotSetId": manifest["recoverySetId"],
              "snapshotManifestSHA256": manifest_hash, "startedAt": now(), "roles": list(NODE_ROLES),
              "before": {role: {"instance": names[role], "status": "TERMINATED"} for role in NODE_ROLES},
              "outcome": "PENDING"}
    error: BaseException | None = None
    try:
        apply_restore(snapshot_ids, internal_ips, operation_id)
        verify_project(project_id, run=run)
        restored_nodes = {}
        for role, name in names.items():
            node = verify_instance(project_id, lab_id, zone, role, name, run=run, allowed_status={"RUNNING"})
            host = remote_host_identity(project_id, zone, name, run=run)
            saved = manifest["nodes"][role]
            if host["machineId"] != saved["machineId"] or host["bootId"] == saved.get("bootId"):
                raise RecoveryError(f"restored {role} host identity does not prove the saved machine booted again")
            restored_nodes[role] = {"instanceId": node["instanceId"], "machineId": host["machineId"],
                                    "bootId": host["bootId"], "internalIp": node["internalIp"],
                                    "bootDisk": node["disk"], "status": node["status"]}
        current_kubernetes = kubernetes_baseline(kube_context, names, run=run)
        if current_kubernetes != manifest.get("kubernetes"):
            raise RecoveryError("restored K3s node or workload baseline differs from the captured snapshot")
        record.update({"restoredNodes": restored_nodes, "kubernetes": current_kubernetes,
                       "finishedAt": now(), "outcome": "RESTORED_AND_HEALTHY"})
    except BaseException as caught:
        error = caught
        record.update({"finishedAt": now(), "outcome": "RESTORE_FAILED_OR_UNVERIFIED",
                       "failureClass": type(caught).__name__,
                       "manualRecovery": "Preserve all disks and snapshots. Use instance-level serial diagnostics and inspect the saved Terraform plan/state before retrying."})
    digest = write_new_json(output, record)
    append_audit(audit_path, {"event": "snapshot-set-restore", "time": record["finishedAt"],
                  "projectId": project_id, "labId": lab_id, "zone": zone,
                  "operationId": operation_id, "snapshotSetId": manifest["recoverySetId"],
                  "outcome": record["outcome"], "evidenceFile": output.name, "evidenceSHA256": digest})
    if error:
        raise RecoveryError(f"restore did not complete and verify; preserve resources and review {output.name}") from error
    return record


def _metadata_items(resource: dict) -> dict[str, str]:
    return {item.get("key", ""): item.get("value", "") for item in (resource.get("metadata") or {}).get("items", [])}


def serial_diagnostics(project_id: str, lab_id: str, zone: str, role: str, instance: str,
                      reason: str, output: Path, audit_path: Path, *, run: Runner,
                      now: Callable[[], str] = now_utc) -> dict:
    names = names_for(lab_id)
    validate_target(project_id, lab_id, zone, names)
    require_distinct_outputs(output, audit_path)
    if role not in NODE_ROLES or names[role] != instance or reason not in {"boot-failure", "ssh-loss", "host-unavailable"}:
        raise RecoveryError("serial diagnostics require an exact lab instance and supported recovery reason")
    verify_project(project_id, run=run)
    verified = verify_instance(project_id, lab_id, zone, role, instance, run=run,
                               allowed_status={"RUNNING", "TERMINATED", "STAGING", "STOPPING"})
    if not verified["serialPortEnabled"]:
        raise RecoveryError("instance-level serial-port-enable=TRUE is missing; project-wide enablement is not used")
    result = command(gcloud_prefix(project_id) + ["compute", "instances", "get-serial-port-output", instance,
                    "--port=1", f"--zone={zone}"], run=run, timeout=60)
    if not result:
        raise RecoveryError("serial-port output was empty; preserve the instance and use the manual recovery procedure")
    sanitized = redact_serial_output(result)
    digest = write_new_bytes(output, sanitized.encode())
    record = {"schema": "kordex-m3-serial-recovery-v1", "time": now(), "projectId": project_id,
              "labId": lab_id, "zone": zone, "role": role, "instance": instance,
              "instanceId": verified["instanceId"], "reason": reason, "port": 1,
              "outputFile": output.name, "outputSHA256": digest,
              "status": "SERIAL_OUTPUT_RETRIEVED"}
    append_audit(audit_path, record)
    return record


def redact_serial_output(value: str) -> str:
    # Serial output is evidence, but may contain incidental service diagnostics.
    # Store bounded redacted output and never write credentials/private keys.
    if len(value) > 1024 * 1024:
        value = value[-(1024 * 1024):]
    value = re.sub(r"(?im)(authorization\s*[:=]\s*bearer\s+)\S+", r"\1<redacted>", value)
    value = re.sub(r"(?im)((?:password|passwd|token|secret|api[_-]?key|client[_-]?secret|private[_-]?key)\s*[:=]\s*)[^\s,;]+",
                   r"\1<redacted>", value)
    value = re.sub(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
                   "<redacted-private-key>", value)
    return value


def write_new_bytes(path: Path, content: bytes) -> str:
    if not content or path.exists() or path.is_symlink():
        raise RecoveryError("refusing empty output or overwrite of existing recovery output")
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise RecoveryError("recovery output directory must be a real directory")
    fd, name = tempfile.mkstemp(prefix=".kordex-recovery-", dir=path.parent)
    digest = hashlib.sha256(content).hexdigest()
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.link(name, path, follow_symlinks=False)
    except OSError as error:
        raise RecoveryError("could not securely write recovery output") from error
    finally:
        Path(name).unlink(missing_ok=True)
    return digest


def _decode_description(value: str, prefix: str) -> dict:
    if not value.startswith(prefix):
        raise RecoveryError("firewall resource does not have the expected Kordex recovery identity")
    try:
        packed = base64.urlsafe_b64decode(value[len(prefix):] + "=" * (-len(value[len(prefix):]) % 4))
        decoder = zlib.decompressobj()
        raw = decoder.decompress(packed, 16 * 1024 + 1)
        if len(raw) > 16 * 1024 or decoder.unconsumed_tail or not decoder.eof:
            raise RecoveryError("firewall recovery identity exceeds the supported size")
        obj = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, zlib.error, json.JSONDecodeError, RecoveryError) as error:
        raise RecoveryError("firewall recovery identity is malformed") from error
    if not isinstance(obj, dict):
        raise RecoveryError("firewall recovery identity is malformed")
    return obj


def _encoded_description(prefix: str, record: dict) -> str:
    encoded = prefix + base64.urlsafe_b64encode(zlib.compress(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode(), level=9)).decode().rstrip("=")
    if len(encoded) > 1024:
        raise RecoveryError("recovery firewall identity exceeds the provider description limit")
    return encoded


def _firewall(project_id: str, name: str, *, run: Runner) -> dict | None:
    # Listing allows a successful empty result to be distinguished from API,
    # permission, and transport failures. Those failures must not be treated as
    # evidence that a temporary deny rule is absent.
    output = command(gcloud_prefix(project_id) + ["compute", "firewall-rules", "list",
                    f"--filter=name={name}", "--format=json"], run=run)
    try:
        resources = json.loads(output, object_pairs_hook=unique_object)
    except (TypeError, json.JSONDecodeError, RecoveryError) as error:
        raise RecoveryError("firewall lookup returned invalid or ambiguous JSON") from error
    if not isinstance(resources, list):
        raise RecoveryError("firewall lookup returned an unexpected result")
    matches = [resource for resource in resources if isinstance(resource, dict) and resource.get("name") == name]
    if len(matches) > 1:
        raise RecoveryError("firewall lookup returned duplicate resource names")
    return matches[0] if matches else None


def _verify_fault_allowlist(project_id: str, lab_id: str, target: dict, scenario: str,
                            destination_cidr: str, *, run: Runner) -> tuple[int, str]:
    if scenario not in FAULT_SCENARIOS:
        raise RecoveryError("unsupported network fault scenario")
    _, port = FAULT_SCENARIOS[scenario]
    try:
        network = ipaddress.ip_network(destination_cidr, strict=True)
    except ValueError as error:
        raise RecoveryError("fault destination must be a canonical IPv4 /32") from error
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32 or not network.network_address.is_private:
        raise RecoveryError("fault destination must be one private RFC1918 IPv4 host address")
    allow = json_command(gcloud_prefix(project_id) + ["compute", "firewall-rules", "describe",
                           f"{lab_id}-egress-private-services", "--format=json"], run=run)
    if (_suffix(allow.get("network")) != f"{lab_id}-network" or allow.get("direction") != "EGRESS"
            or target["tag"] not in (allow.get("targetTags") or [])):
        raise RecoveryError("approved private egress firewall rule does not include this exact lab target")
    ranges = allow.get("destinationRanges") or []
    try:
        range_networks = [ipaddress.ip_network(value, strict=False) for value in ranges]
    except (ValueError, TypeError) as error:
        raise RecoveryError("approved egress rule contains an invalid destination range") from error
    if not any(network.network_address in value for value in range_networks):
        raise RecoveryError("fault destination is not within the reviewed private egress CIDR allowlist")
    allowed = allow.get("allowed") or []
    if not any(item.get("IPProtocol") in {"tcp", "all"} and ("all" in (item.get("ports") or []) or
               any(_port_contains(p, port) for p in (item.get("ports") or []))) for item in allowed):
        raise RecoveryError("scenario TCP port is not allowed by the baseline private egress rule")
    try:
        allow_priority = int(allow.get("priority", 1000))
    except (TypeError, ValueError) as error:
        raise RecoveryError("approved egress rule priority is malformed") from error
    if allow_priority <= 700:
        raise RecoveryError("fault rule priority would not precede the baseline allow")
    fingerprint = hashlib.sha256(json.dumps(allow, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return port, _suffix(allow.get("network")), fingerprint


def _port_contains(value: str, port: int) -> bool:
    try:
        if "-" in value:
            low, high = value.split("-", 1)
            return int(low) <= port <= int(high)
        return int(value) == port
    except (ValueError, TypeError):
        return False


def _create_inert_lock(project_id: str, lab_id: str, network: str, record: dict, *, run: Runner) -> None:
    lock_name = f"{lab_id}-fault-lock"
    command(gcloud_prefix(project_id) + ["compute", "firewall-rules", "create", lock_name,
            f"--network={network}", "--direction=EGRESS", "--priority=799", "--action=DENY",
            "--rules=tcp:9", "--destination-ranges=0.0.0.0/0", "--target-tags=kordex-m3-lock-unused",
            f"--description={_encoded_description(LOCK_PREFIX, record)}"], run=run)
    lock = _firewall(project_id, lock_name, run=run)
    if (lock is None or not _is_inert_lock(lock, network)
            or _decode_description(str(lock.get("description", "")), LOCK_PREFIX) != record):
        raise RecoveryError("fault lock rule did not match the exact inert lab reservation")


def _is_inert_lock(resource: dict, network: str) -> bool:
    return (_suffix(resource.get("network")) == network and resource.get("direction") == "EGRESS"
            and resource.get("priority") == 799
            and resource.get("targetTags") == ["kordex-m3-lock-unused"]
            and resource.get("destinationRanges") == ["0.0.0.0/0"]
            and resource.get("denied") == [{"IPProtocol": "tcp", "ports": ["9"]}]
            and not resource.get("allowed"))


def _is_exact_fault_rule(resource: dict, record: dict, tag: str, network: str) -> bool:
    return (_suffix(resource.get("network")) == network and resource.get("direction") == "EGRESS"
            and resource.get("priority") == 700 and resource.get("targetTags") == [tag]
            and resource.get("destinationRanges") == [record.get("destinationCIDR")]
            and resource.get("denied") == [{"IPProtocol": "tcp", "ports": [str(record.get("port"))]}]
            and not resource.get("allowed"))


def _delete_firewall(project_id: str, name: str, *, run: Runner) -> None:
    command(gcloud_prefix(project_id) + ["compute", "firewall-rules", "delete", name, "--quiet"], run=run)
    if _firewall(project_id, name, run=run) is not None:
        raise RecoveryError(f"firewall rule {name} still exists after delete; manual recovery is required")


def inject_network_fault(project_id: str, lab_id: str, zone: str, role: str, instance: str,
                         scenario: str, destination_cidr: str, duration: int,
                         confirmation: str, evidence_path: Path, audit_path: Path, *,
                         run: Runner, sleep: Callable[[int], None] = time.sleep,
                         probe: Callable[[str, str, str, str, int], bool] | None = None,
                         operation_id: str | None = None,
                         now: Callable[[], str] = now_utc) -> dict:
    names = names_for(lab_id)
    validate_target(project_id, lab_id, zone, names)
    if role not in NODE_ROLES or names[role] != instance:
        raise RecoveryError("fault target must be one explicitly identified lab instance")
    if type(duration) is not int or not 1 <= duration <= MAX_FAULT_SECONDS:
        raise RecoveryError(f"fault duration must be between 1 and {MAX_FAULT_SECONDS} seconds")
    require_distinct_outputs(evidence_path, audit_path)
    if evidence_path.exists() or evidence_path.is_symlink():
        raise RecoveryError("fault evidence path already exists")
    verify_project(project_id, run=run)
    current = verify_instance(project_id, lab_id, zone, role, instance, run=run, allowed_status={"RUNNING"})
    tag = f"{lab_id}-server" if role == "server" else f"{lab_id}-{role}"
    allow_tag = f"{lab_id}-server" if role == "server" else f"{lab_id}-worker"
    port, network, allow_fingerprint = _verify_fault_allowlist(project_id, lab_id,
                    {"tag": allow_tag}, scenario, destination_cidr, run=run)
    operation_id = operation_id or secrets.token_hex(6)
    if not re.fullmatch(r"[a-f0-9]{12}", operation_id):
        raise RecoveryError("fault operation ID must be 12 lowercase hexadecimal characters")
    lock_name = f"{lab_id}-fault-lock"
    if _firewall(project_id, lock_name, run=run) is not None:
        raise RecoveryError("another fault operation owns the lab lock; run the explicit recovery command")
    deny_name = f"{lab_id}-fi-{operation_id}-deny"
    if _firewall(project_id, deny_name, run=run) is not None:
        raise RecoveryError("generated fault rule name is already in use; no network change was made")
    probe = probe or (lambda project, selected_zone, host, address, selected_port:
                      remote_tcp_probe(project, selected_zone, host, address, selected_port, run=run))
    if not probe(project_id, zone, instance, str(ipaddress.ip_network(destination_cidr).network_address), port):
        raise RecoveryError("private endpoint must be reachable before fault injection; no firewall change was made")
    record = {"schema": "kordex-m3-network-fault-v1", "operationId": operation_id,
              "scenarioId": f"M3-NET-{scenario.upper().replace('-', '-')}", "faultType": scenario,
              "projectId": project_id, "labId": lab_id, "zone": zone, "targetRole": role,
              "targetInstance": instance, "targetInstanceId": current["instanceId"],
              "destinationCIDR": destination_cidr, "protocol": "tcp", "port": port,
              "durationSeconds": duration, "lockRule": lock_name, "denyRule": deny_name,
              "network": network, "allowRuleSHA256": allow_fingerprint, "startedAt": now(), "endedAt": None,
              "before": {"temporaryDenyRule": "ABSENT", "allowRule": f"{lab_id}-egress-private-services",
                         "endpointReachable": True},
              "after": None, "restoreOutcome": "PENDING", "faultObserved": False}
    require_confirmation(confirmation, f"INJECT {project_id}/{lab_id}/{operation_id}")
    rule_identity = json.loads(json.dumps(record))
    _create_inert_lock(project_id, lab_id, network, record, run=run)
    deny_description = _encoded_description(DENY_PREFIX, record)
    failure = None
    try:
        command(gcloud_prefix(project_id) + ["compute", "firewall-rules", "create", deny_name,
                f"--network={network}", "--direction=EGRESS", "--priority=700", "--action=DENY",
                f"--rules=tcp:{port}", f"--destination-ranges={destination_cidr}",
                f"--target-tags={tag}", f"--description={deny_description}"], run=run)
        applied = _firewall(project_id, deny_name, run=run)
        if (applied is None or not _is_exact_fault_rule(applied, record, tag, network)
                or _decode_description(str(applied.get("description", "")), DENY_PREFIX) != record):
            raise RecoveryError("created network fault rule could not be verified")
        if probe(project_id, zone, instance, str(ipaddress.ip_network(destination_cidr).network_address), port):
            raise RecoveryError("endpoint remained reachable; injected fault was not observed")
        record["faultObserved"] = True
        sleep(duration)
    except BaseException as error:
        failure = error
    finally:
        try:
            deny = _firewall(project_id, deny_name, run=run)
            if deny is not None:
                details = _decode_description(str(deny.get("description", "")), DENY_PREFIX)
                if details != rule_identity or not _is_exact_fault_rule(deny, rule_identity, tag, network):
                    raise RecoveryError("temporary deny rule identity differs; manual recovery required")
                _delete_firewall(project_id, deny_name, run=run)
            if not probe(project_id, zone, instance, str(ipaddress.ip_network(destination_cidr).network_address), port):
                raise RecoveryError("endpoint did not recover after removing the temporary deny rule")
            _delete_firewall(project_id, lock_name, run=run)
            record["endedAt"] = now()
            record["after"] = {"temporaryDenyRule": "ABSENT", "lockRule": "ABSENT", "endpointReachable": True}
            record["restoreOutcome"] = "AUTOMATIC_RESTORE_VERIFIED"
        except BaseException as restore_error:
            record["endedAt"] = now()
            record["restoreOutcome"] = "RESTORE_FAILED_LOCK_RETAINED"
            record["restoreErrorClass"] = type(restore_error).__name__
            record["manualRecovery"] = f"Run fault recover for {project_id}/{lab_id}; do not start an overlapping fault."
            failure = restore_error
        record["executionOutcome"] = "FAILED" if failure else "COMPLETED"
        write_new_json(evidence_path, record)
        append_audit(audit_path, {"event": "network-fault-finished", "time": record["endedAt"],
                      "projectId": project_id, "labId": lab_id, "operationId": operation_id,
                      "scenarioId": record["scenarioId"], "restoreOutcome": record["restoreOutcome"],
                      "evidenceFile": evidence_path.name, "evidenceSHA256": hashlib.sha256(evidence_path.read_bytes()).hexdigest()})
    if failure:
        raise RecoveryError("fault operation failed; inspect the mode-0600 evidence and use fault recover if the lock remains") from failure
    return record


def recover_network_fault(project_id: str, lab_id: str, zone: str, operation_id: str,
                          confirmation: str, evidence_path: Path, audit_path: Path, *,
                          run: Runner, now: Callable[[], str] = now_utc) -> dict:
    validate_target(project_id, lab_id, zone, names_for(lab_id))
    require_distinct_outputs(evidence_path, audit_path)
    if not re.fullmatch(r"[a-f0-9]{12}", operation_id):
        raise RecoveryError("fault recovery requires the approved project, zone, lab ID, and 12-hex operation ID")
    if evidence_path.exists() or evidence_path.is_symlink():
        raise RecoveryError("fault recovery evidence path already exists; no firewall rule was changed")
    verify_project(project_id, run=run)
    lock_name = f"{lab_id}-fault-lock"
    lock = _firewall(project_id, lock_name, run=run)
    if lock is None:
        raise RecoveryError("there is no recoverable lab fault lock")
    record = _decode_description(str(lock.get("description", "")), LOCK_PREFIX)
    if (record.get("projectId") != project_id or record.get("labId") != lab_id
            or record.get("zone") != zone or record.get("operationId") != operation_id):
        raise RecoveryError("fault lock identity does not match the explicitly selected lab operation")
    if not _is_inert_lock(lock, f"{lab_id}-network"):
        raise RecoveryError("fault lock firewall properties do not match the inert recovery lock")
    require_confirmation(confirmation, f"RESTORE-FAULT {project_id}/{lab_id}/{operation_id}")
    deny_name = record.get("denyRule")
    if not isinstance(deny_name, str) or deny_name != f"{lab_id}-fi-{operation_id}-deny":
        raise RecoveryError("fault lock has an invalid deny-rule name")
    target_role = record.get("targetRole")
    target_instance = record.get("targetInstance")
    if target_role not in NODE_ROLES or names_for(lab_id)[target_role] != target_instance:
        raise RecoveryError("fault lock target is not one of the exact lab instances")
    target = verify_instance(project_id, lab_id, zone, target_role, target_instance, run=run,
                             allowed_status={"RUNNING"})
    if target["instanceId"] != record.get("targetInstanceId"):
        raise RecoveryError("fault recovery target instance identity changed; preserve the rule and review manually")
    scenario = record.get("faultType")
    if scenario not in FAULT_SCENARIOS or record.get("protocol") != "tcp" or record.get("port") != FAULT_SCENARIOS[scenario][1]:
        raise RecoveryError("fault lock has an unsupported scenario, protocol, or port")
    try:
        destination_network = ipaddress.ip_network(record.get("destinationCIDR", "0.0.0.0/32"), strict=True)
    except ValueError as error:
        raise RecoveryError("fault lock destination is malformed") from error
    if destination_network.prefixlen != 32 or not destination_network.network_address.is_private:
        raise RecoveryError("fault lock destination is outside the supported private /32 scope")
    destination = str(destination_network.network_address)
    port = record.get("port")
    deny = _firewall(project_id, deny_name, run=run)
    fault_observed = False
    if deny is not None:
        details = _decode_description(str(deny.get("description", "")), DENY_PREFIX)
        expected_tag = f"{lab_id}-server" if target_role == "server" else f"{lab_id}-{target_role}"
        if details != record or not _is_exact_fault_rule(deny, record, expected_tag, f"{lab_id}-network"):
            raise RecoveryError("fault deny rule conflicts with its lock; refusing to delete an unverified rule")
        if remote_tcp_probe(project_id, zone, target_instance, destination, port, run=run):
            raise RecoveryError("endpoint is still reachable; retain both rules and investigate before recovery")
        fault_observed = True
        _delete_firewall(project_id, deny_name, run=run)
    if not remote_tcp_probe(project_id, zone, target_instance, destination, port, run=run):
        raise RecoveryError("endpoint did not recover; fault lock is retained for investigation")
    _delete_firewall(project_id, lock_name, run=run)
    recovered = dict(record)
    recovered.update({"endedAt": now(), "restoreOutcome": "MANUAL_RESTORE_VERIFIED",
                      "after": {"temporaryDenyRule": "ABSENT", "lockRule": "ABSENT", "endpointReachable": True},
                      "faultObserved": fault_observed,
                      "executionOutcome": "RECOVERED_AFTER_INTERRUPTION" if fault_observed else
                                          "RECOVERED_WITHOUT_FAULT_PROOF"})
    write_new_json(evidence_path, recovered)
    append_audit(audit_path, {"event": "network-fault-manual-recovery", "time": recovered["endedAt"],
                  "projectId": project_id, "labId": lab_id, "operationId": operation_id,
                  "scenarioId": recovered["scenarioId"], "restoreOutcome": recovered["restoreOutcome"],
                  "evidenceFile": evidence_path.name, "evidenceSHA256": hashlib.sha256(evidence_path.read_bytes()).hexdigest()})
    return recovered


def verify_recovery_evidence(path: Path, expected_sha256: str) -> dict:
    record, raw = _read_json(path)
    actual_hash = hashlib.sha256(raw).hexdigest()
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or actual_hash != expected_sha256:
        raise RecoveryError("recovery evidence does not match the independently retained SHA-256")
    schema = record.get("schema")
    if schema == "kordex-m3-network-fault-v1":
        if record.get("restoreOutcome") not in {"AUTOMATIC_RESTORE_VERIFIED", "MANUAL_RESTORE_VERIFIED"}:
            raise RecoveryError("fault evidence does not prove that connectivity restoration was verified")
        if record.get("faultObserved") is not True:
            raise RecoveryError("fault evidence does not prove the connectivity interruption was observed")
        after = record.get("after")
        if (not isinstance(after, dict) or after.get("temporaryDenyRule") != "ABSENT"
                or after.get("lockRule") != "ABSENT" or after.get("endpointReachable") is not True):
            raise RecoveryError("fault evidence does not prove endpoint recovery and removal of temporary rules")
        try:
            started = dt.datetime.fromisoformat(record["startedAt"].replace("Z", "+00:00"))
            ended = dt.datetime.fromisoformat(record["endedAt"].replace("Z", "+00:00"))
        except (ValueError, KeyError, AttributeError) as error:
            raise RecoveryError("fault evidence timestamps are missing or malformed") from error
        if started.tzinfo is None or ended.tzinfo is None:
            raise RecoveryError("fault evidence timestamps must include a timezone")
        if ended < started or int((ended - started).total_seconds()) > MAX_FAULT_SECONDS + 300:
            raise RecoveryError("fault evidence time interval is invalid")
    elif schema == "kordex-m3-recovery-baseline-v1":
        if record.get("idleAttestation") != "NO_ACTIVE_MAINTENANCE" or set(record.get("nodes", {})) != set(NODE_ROLES):
            raise RecoveryError("baseline evidence is missing the idle attestation or complete node identity set")
    elif schema == "kordex-m3-recovery-snapshot-set-v1":
        if record.get("snapshotOutcome") != "READY_ALL_THREE" or set(record.get("nodes", {})) != set(NODE_ROLES):
            raise RecoveryError("snapshot evidence does not contain a verified complete three-node set")
    elif schema == "kordex-m3-lab-restore-v1":
        if record.get("roles") != list(NODE_ROLES) or record.get("outcome") not in {
                "RESTORED_AND_HEALTHY", "RESTORE_FAILED_OR_UNVERIFIED"}:
            raise RecoveryError("restore evidence is incomplete or has an unsupported outcome")
    elif schema == "kordex-m3-snapshot-cleanup-v1":
        deleted = record.get("deleted")
        if not isinstance(deleted, dict) or set(deleted) != set(NODE_ROLES) or any(
                item.get("outcome") != "DELETED_AND_ABSENT" for item in deleted.values()):
            raise RecoveryError("snapshot cleanup evidence does not prove all three named snapshots are absent")
    elif schema == "kordex-m3-serial-recovery-v1":
        if record.get("status") != "SERIAL_OUTPUT_RETRIEVED":
            raise RecoveryError("serial recovery evidence status is unsupported")
        output = path.parent / str(record.get("outputFile", ""))
        if output.parent != path.parent or output.is_symlink() or not output.is_file():
            raise RecoveryError("serial output evidence is missing or unsafe")
        if hashlib.sha256(output.read_bytes()).hexdigest() != record.get("outputSHA256"):
            raise RecoveryError("serial output evidence checksum does not match")
    else:
        raise RecoveryError("unsupported lab recovery evidence schema")
    return {"record": record, "sha256": actual_hash}
