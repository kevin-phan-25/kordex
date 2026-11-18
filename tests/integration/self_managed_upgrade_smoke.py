#!/usr/bin/env python3
"""Guarded provider-neutral Debian/RHEL host-upgrade qualification drill.

The default mode only checks identity, freshness, policy and executor readiness.
Execution submits one approved UpgradePackages operation and requires an exact
disposable-target confirmation. This script never provisions infrastructure.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class DrillError(RuntimeError):
    pass


PAGE_SIZE = 500
CANCELLATION_CASES = {
    "Draining": "cancel-before-apply",
    "Executing": "cancel-during-executing",
    "Rebooting": "cancel-during-reboot",
    "VerifyingWorkloads": "cancel-during-recovery",
}
SUPPLEMENTAL_CASES = {"cancel-before-apply", "cancel-during-recovery"}


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise DrillError(f"required environment variable is missing: {name}")
    return value


def run_json(args: list[str]) -> dict:
    try:
        output = subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=30)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        details = getattr(error, "output", b"") or b""
        if isinstance(details, bytes):
            details = details.decode(errors="replace")
        raise DrillError(f"command failed ({args[0]}): {str(details)[-1500:]}") from error
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise DrillError(f"command returned invalid JSON ({args[0]})") from error
    if not isinstance(value, dict):
        raise DrillError(f"command returned unexpected JSON ({args[0]})")
    return value


def ready_operator_pod_uids(kubectl: str, namespace: str) -> list[str]:
    pods = run_json([kubectl, "-n", namespace, "get", "pods",
                     "-l", "app.kubernetes.io/name=kordex-operator", "-o", "json"])
    items = pods.get("items")
    if not isinstance(items, list):
        raise DrillError("Kubernetes returned an invalid operator pod list")
    ready = []
    for pod in items:
        metadata = pod.get("metadata") or {}
        status = pod.get("status") or {}
        containers = status.get("containerStatuses") or []
        uid = metadata.get("uid")
        try:
            valid_uid = isinstance(uid, str) and str(uuid.UUID(uid)) == uid
        except ValueError:
            valid_uid = False
        if (valid_uid and status.get("phase") == "Running" and containers
                and all(item.get("ready") is True for item in containers)):
            ready.append(uid)
    return sorted(ready)


def restart_operator(kubectl: str, namespace: str, timeout_seconds: int = 180) -> dict:
    before = ready_operator_pod_uids(kubectl, namespace)
    if not before:
        raise DrillError("no Ready Kordex operator pod exists before restart")
    requested_at = dt.datetime.now(dt.timezone.utc).isoformat()
    commands = (
        [kubectl, "-n", namespace, "rollout", "restart", "deployment/kordex-operator"],
        [kubectl, "-n", namespace, "rollout", "status", "deployment/kordex-operator",
         f"--timeout={timeout_seconds}s"],
    )
    for command in commands:
        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout_seconds + 15)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            details = getattr(error, "stdout", "") or getattr(error, "output", "") or ""
            raise DrillError(f"operator rollout command failed: {str(details)[-1000:]}") from error
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        new_uids = [uid for uid in ready_operator_pod_uids(kubectl, namespace) if uid not in before]
        if new_uids:
            return {
                "namespace": namespace,
                "deployment": "kordex-operator",
                "oldPodUID": before[0],
                "newPodUID": new_uids[0],
                "phaseAtRestart": "Executing",
                "requestedAt": requested_at,
                "readyAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
        time.sleep(1)
    raise DrillError("operator deployment did not produce a new Ready pod UID")


def parse_time(value: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise DrillError("management plane returned an invalid observation timestamp")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise DrillError("management plane returned an invalid observation timestamp") from error
    if result.tzinfo is None:
        raise DrillError("management plane returned a timestamp without timezone")
    return result.astimezone(dt.timezone.utc)


def api_path(org_id: str, suffix: str) -> str:
    return f"/v1/organizations/{urllib.parse.quote(org_id, safe='')}/{suffix}"


class Hub:
    def __init__(self, origin: str, token: str):
        parsed = urllib.parse.urlparse(origin)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
            raise DrillError("KORDEX_API must use HTTPS, except for loopback development")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise DrillError("KORDEX_API must be an origin")
        self.origin = origin.rstrip("/")
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(self.origin + path, method=method, data=data, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                value = json.loads(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode(errors="replace")
            raise DrillError(f"Kordex API returned HTTP {error.code}: {detail}") from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise DrillError(f"Kordex API request failed: {error}") from error
        if not isinstance(value, dict):
            raise DrillError("Kordex API returned unexpected JSON")
        return value


def list_all(hub: Hub, path: str) -> list[dict]:
    items: list[dict] = []
    offset = 0
    while True:
        page = hub.request("GET", f"{path}?limit={PAGE_SIZE}&offset={offset}")
        batch = page.get("items")
        if not isinstance(batch, list) or page.get("limit") != PAGE_SIZE or page.get("offset") != offset:
            raise DrillError("management plane returned invalid pagination metadata")
        items.extend(batch)
        if len(batch) < PAGE_SIZE:
            return items
        offset += len(batch)
        if offset > 100_000:
            raise DrillError("inventory exceeds qualification pagination limit")


def validate_execution_confirmation(target: str, confirmation: str) -> None:
    if confirmation != target:
        raise DrillError("--execute requires KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM to equal the exact cluster/node/UID target")


def detect_os_family(os_image: str) -> str:
    image = os_image.casefold()
    if "coreos" in image or "immutable" in image:
        raise DrillError(f"immutable node OS image is not supported by the host package executor: {os_image!r}")
    if "debian" in image or "ubuntu" in image:
        return "debian"
    rhel_markers = ("red hat", "rhel", "rocky", "alma linux", "almalinux", "oracle linux", "centos")
    if any(marker in image for marker in rhel_markers):
        return "rhel"
    raise DrillError(f"unsupported host OS image for fixed Ansible catalogs: {os_image!r}")


def check_node(node: dict, require_ready: bool = True, require_schedulable: bool = True,
               expected_os_family: str | None = None) -> dict:
    if not isinstance(node, dict):
        raise DrillError("Kubernetes returned an invalid Node object")
    metadata = node.get("metadata", {})
    status = node.get("status", {})
    spec = node.get("spec", {})
    if not isinstance(metadata, dict) or not isinstance(status, dict) or not isinstance(spec, dict):
        raise DrillError("Kubernetes returned malformed Node identity or status")
    raw_conditions = status.get("conditions", [])
    if not isinstance(raw_conditions, list) or any(not isinstance(item, dict) for item in raw_conditions):
        raise DrillError("Kubernetes returned malformed Node conditions")
    conditions = {item.get("type"): item.get("status") for item in raw_conditions}
    ready = conditions.get("Ready") == "True"
    unschedulable = spec.get("unschedulable", False)
    if not isinstance(unschedulable, bool):
        raise DrillError("Kubernetes returned an invalid Node scheduling state")
    if require_ready and not ready or require_schedulable and unschedulable:
        raise DrillError("target node must be Ready and schedulable before qualification")
    node_info = status.get("nodeInfo", {})
    if not isinstance(node_info, dict):
        raise DrillError("Kubernetes returned malformed Node system information")
    os_image = node_info.get("osImage", "")
    if not isinstance(os_image, str):
        raise DrillError("Kubernetes returned an invalid Node OS image")
    os_family = detect_os_family(os_image) if os_image else ""
    if expected_os_family and os_family != expected_os_family:
        raise DrillError(f"target OS family {os_family!r} does not match policy family {expected_os_family!r}")
    uid = metadata.get("uid", "")
    name = metadata.get("name", "")
    if not isinstance(uid, str) or not uid or not isinstance(name, str) or not name:
        raise DrillError("target node has no Kubernetes identity")
    kernel_version = node_info.get("kernelVersion", "")
    kubelet_version = node_info.get("kubeletVersion", "")
    if not isinstance(kernel_version, str) or not isinstance(kubelet_version, str):
        raise DrillError("Kubernetes returned invalid Node version evidence")
    return {
        "name": name,
        "uid": uid,
        "osImage": os_image,
        "osFamily": os_family,
        "kernelVersion": kernel_version,
        "kubeletVersion": kubelet_version,
        "ready": ready,
        "unschedulable": unschedulable,
    }


def fresh(observed: str, max_age: int, name: str) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    at = parse_time(observed)
    if (now - at).total_seconds() > max_age or at > now + dt.timedelta(minutes=2):
        raise DrillError(f"{name} is stale or from the future")


def validate_policy_entry(entry: dict, digest: str) -> dict:
    if not isinstance(entry, dict) or not isinstance(entry.get("upgrade"), dict):
        raise DrillError("local operator policy catalog has no valid upgrade plan")
    plan = entry.get("upgrade") or {}
    if entry.get("suspended") or entry.get("upgradePlanInvalid") or entry.get("upgradePlanDigest") != digest:
        raise DrillError("host-upgrade policy is suspended, invalid, or has a different plan digest")
    family_catalogs = {"debian": "kordex.os-upgrade.debian.v2", "rhel": "kordex.os-upgrade.rhel.v1"}
    family = plan.get("osFamily")
    if not isinstance(family, str) or family not in family_catalogs or plan.get("playbookCatalogId") != family_catalogs[family] or plan.get("executionBackend") != "ansible-ee":
        raise DrillError("policy is not for a supported fixed Debian/RHEL Ansible EE catalog")
    if plan.get("actionMarkerVersion") != 1:
        raise DrillError("host-upgrade policy must require actionMarkerVersion 1")
    packages = plan.get("packages")
    if not isinstance(packages, list) or not packages:
        raise DrillError("policy contains no exact package pins")
    names: set[str] = set()
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str) or not package["name"] or not package["version"]:
            raise DrillError("policy contains an invalid exact package pin")
        if package["name"] in names:
            raise DrillError("policy contains a duplicate package pin")
        names.add(package["name"])
    return entry


def check_policy(hub: Hub, org: str, cluster_id: str, policy_name: str, digest: str) -> dict:
    path = api_path(org, f"clusters/{urllib.parse.quote(cluster_id, safe='')}/maintenance-policies")
    catalog = hub.request("GET", path)
    if not isinstance(catalog.get("items"), list) or not isinstance(catalog.get("capabilities") or {}, dict):
        raise DrillError("management plane returned an invalid maintenance-policy catalog")
    fresh(catalog.get("observedAt", ""), 45, "operator maintenance-policy catalog")
    capabilities = catalog.get("capabilities") or {}
    observed = capabilities.get("observedAt")
    if not capabilities.get("hostUpgrades") or not observed:
        raise DrillError("local operator does not report host upgrades available")
    fresh(observed, 45, "operator host-upgrade capability")
    matches = [item for item in catalog["items"] if isinstance(item, dict)
               and isinstance(item.get("policy"), dict) and item["policy"].get("name") == policy_name]
    if len(matches) != 1:
        raise DrillError("local operator policy catalog does not contain exactly one named policy")
    return validate_policy_entry(matches[0], digest)


def redacted_operation(operation: dict) -> dict:
    return {key: value for key, value in operation.items() if key not in {"command", "authorization", "signature"}}


def verify_action_marker(marker: dict, operation_id: str, plan_digest: str, node_uid: str,
                         machine_id: str, boot_id: str, phase: str, sequence: int) -> None:
    if not isinstance(marker, dict) or not marker:
        raise DrillError(f"host receipt lacks the exact {phase} action marker")
    try:
        uuid.UUID(str(marker.get("operationId")))
        uuid.UUID(str(marker.get("bootId")))
    except (ValueError, AttributeError):
        raise DrillError("action marker has an invalid operation or boot identity")
    if (marker.get("version") != 1 or marker.get("operationId") != operation_id
            or marker.get("actionDigest") != plan_digest or marker.get("nodeUid") != node_uid
            or marker.get("machineId") != machine_id or marker.get("bootId") != boot_id
            or marker.get("phase") != phase or marker.get("sequence") != sequence
            or not isinstance(marker.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", marker["sha256"])):
        raise DrillError(f"host receipt lacks the exact {phase} action marker")


def verify_completed_operation(operation: dict, plan_digest: str, node_uid: str, plan: dict) -> dict:
    if not isinstance(operation, dict) or not isinstance(plan, dict):
        raise DrillError("operation or upgrade plan evidence is malformed")
    status = operation.get("status") or {}
    if not isinstance(status, dict):
        raise DrillError("operation status evidence is malformed")
    checkpoint = status.get("upgradeCheckpoint") or {}
    if not isinstance(checkpoint, dict):
        raise DrillError("operation upgrade checkpoint is malformed")
    operation_id = operation.get("id")
    if (not isinstance(operation_id, str) or not operation_id
            or checkpoint.get("phase") != "Succeeded" or checkpoint.get("planDigest") != plan_digest
            or checkpoint.get("nodeUid") != node_uid):
        raise DrillError("operation lacks a successful checkpoint bound to the requested plan and node")
    raw_receipts = checkpoint.get("receipts", [])
    if not isinstance(raw_receipts, list) or any(not isinstance(receipt, dict) for receipt in raw_receipts):
        raise DrillError("operation checkpoint receipt history is malformed")
    receipts = {}
    for receipt in raw_receipts:
        phase = receipt.get("phase")
        if not isinstance(phase, str) or not phase or phase in receipts:
            raise DrillError("operation checkpoint receipt phases are missing or duplicated")
        receipts[phase] = receipt
    raw_packages = plan.get("packages")
    if (not isinstance(raw_packages, list) or not raw_packages
            or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                   or not item.get("name") or not isinstance(item.get("version"), str)
                   or not item.get("version") for item in raw_packages)):
        raise DrillError("upgrade plan package pins are malformed")
    expected_packages = {item["name"]: item["version"] for item in raw_packages}
    if len(expected_packages) != len(raw_packages):
        raise DrillError("upgrade plan contains duplicate package pins")
    preflight = receipts.get("preflight")
    machine_id = preflight.get("machineId") if preflight else None
    boot_id = preflight.get("bootIdBefore") if preflight else None
    try:
        valid_boot_id = isinstance(boot_id, str) and str(uuid.UUID(boot_id)) == boot_id
    except (ValueError, AttributeError):
        valid_boot_id = False
    if (not isinstance(machine_id, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", machine_id)
            or not valid_boot_id or preflight.get("bootIdAfter") != boot_id):
        raise DrillError("successful checkpoint has no verified host identity/package preflight receipt")
    apply = receipts.get("apply")
    if not apply or apply.get("packages") != expected_packages:
        raise DrillError("successful checkpoint does not prove every exact package pin")
    if (type(apply.get("rebootRequired")) is not bool
            or apply.get("machineId") != machine_id
            or apply.get("bootIdBefore") != boot_id
            or apply.get("bootIdAfter") != apply.get("bootIdBefore")):
        raise DrillError("apply receipt changed machine or boot identity unexpectedly")
    verify_action_marker(apply.get("actionMarker") or {}, operation_id, plan_digest, node_uid,
                         apply["machineId"], apply["bootIdAfter"], "packages-verified", 2)
    reboot = receipts.get("reboot")
    if plan.get("reboot") == "Never" and (apply["rebootRequired"] or reboot is not None):
        raise DrillError("Never reboot policy cannot succeed with a reboot or an outstanding reboot requirement")
    if (apply["rebootRequired"] or plan.get("reboot") == "Always") and (
            reboot is None or reboot.get("rebooted") is not True):
        raise DrillError("package receipt required reboot but no verified reboot receipt exists")
    if reboot is not None and not apply["rebootRequired"]:
        raise DrillError("reboot receipt contradicts the apply receipt's reboot requirement")
    if reboot is not None and (reboot.get("rebooted") is not True or reboot.get("bootIdBefore") == reboot.get("bootIdAfter")):
        raise DrillError("reboot receipt does not prove a changed boot ID")
    if reboot is not None:
        if reboot.get("rebootRequired") is not True:
            raise DrillError("reboot receipt does not confirm the apply reboot requirement")
        if reboot.get("packages") != expected_packages:
            raise DrillError("reboot receipt does not prove every exact package pin")
        try:
            valid_post_boot_id = isinstance(reboot.get("bootIdAfter"), str) and str(uuid.UUID(reboot["bootIdAfter"])) == reboot["bootIdAfter"]
        except (ValueError, AttributeError):
            valid_post_boot_id = False
        if (reboot.get("machineId") != machine_id or reboot.get("bootIdBefore") != apply.get("bootIdAfter")
                or not valid_post_boot_id):
            raise DrillError("reboot receipt changed machine identity or started from an unexpected boot")
        verify_action_marker(reboot.get("actionMarker") or {}, operation_id, plan_digest, node_uid,
                             reboot["machineId"], reboot["bootIdAfter"], "reboot-verified", 4)
    expected_kernel = plan.get("expectedKernelVersion")
    final_receipt = reboot or apply
    if expected_kernel is not None and not isinstance(expected_kernel, str):
        raise DrillError("upgrade plan expected kernel version is malformed")
    if expected_kernel and final_receipt.get("kernelVersion") != expected_kernel:
        raise DrillError("final host kernel does not match the exact policy version")
    return checkpoint


def upgrade_phase(operation: dict) -> str:
    return ((operation.get("status") or {}).get("upgradeCheckpoint") or {}).get("phase", "")


def cancel_operation(hub: Hub, org: str, cluster_id: str, operation_id: str) -> dict:
    suffix = (f"clusters/{urllib.parse.quote(cluster_id, safe='')}/operations/"
              f"{urllib.parse.quote(operation_id, safe='')}/cancel")
    return hub.request("POST", api_path(org, suffix), {})


def request_phase_cancellation(hub: Hub, org: str, cluster_id: str, operation: dict,
                               phase: str, evidence: dict, path: Path) -> None:
    if operation.get("phase") in {"Succeeded", "Failed", "Cancelled", "RecoveryRequired"}:
        raise DrillError("cannot inject a phase cancellation into a terminal operation")
    if upgrade_phase(operation) != phase or operation.get("id") != evidence.get("operationId"):
        raise DrillError("cancellation target does not match the saved operation and requested phase")
    evidence.update({"cancellationPhase": phase,
                     "cancellationObservedOperation": redacted_operation(operation),
                     "cancellationRequestedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                     "cancellationSubmission": "SubmissionUnknown"})
    write_evidence(path, evidence)
    response = cancel_operation(hub, org, cluster_id, evidence["operationId"])
    if response.get("status") != "cancellation_requested":
        raise DrillError("management API did not acknowledge the cancellation request")
    evidence.update({"cancellationSubmission": "Accepted", "cancellationResponse": response})
    write_evidence(path, evidence)


def verify_cancellation_case(operation: dict, requested_phase: str, requested: bool,
                             evidence: dict) -> None:
    if not requested:
        evidence["outcome"] = "CancellationPhaseNotObserved"
        raise DrillError("requested cancellation phase was not observed; this is not cancellation evidence")
    if operation.get("phase") not in {"Cancelled", "RecoveryRequired"}:
        evidence["outcome"] = "CancellationNotVerified"
        raise DrillError("cancellation did not reach Cancelled or fenced RecoveryRequired")
    if requested_phase == "Draining":
        status = operation.get("status") or {}
        events = status.get("events")
        receipts = (status.get("upgradeCheckpoint") or {}).get("receipts", [])
        if (not isinstance(events, list) or not events
                or any(not isinstance(event, dict) for event in events)
                or not isinstance(receipts, list) or any(not isinstance(receipt, dict) for receipt in receipts)):
            raise DrillError("pre-apply cancellation lacks valid durable phase/receipt history")
        if (any(event.get("phase") in {"Executing", "Rebooting"} for event in events)
                or any(receipt.get("phase") in {"apply", "reboot", "inspect"} for receipt in receipts)):
            evidence["outcome"] = "CancellationArrivedAfterApply"
            raise DrillError("pre-apply cancellation raced with host execution; record it as a missed injection")


def verify_cancellation_fence(operation: dict, node: dict, original_uid: str) -> str:
    phase = operation.get("phase")
    checkpoint = upgrade_phase(operation)
    if phase == "Cancelled" and checkpoint == "Cancelled":
        if node["uid"] != original_uid or not node.get("ready") or node["unschedulable"]:
            raise DrillError("cancelled operation did not recover the original node to Ready and schedulable state")
        return "CancellationRecovered"
    if phase == "RecoveryRequired" and checkpoint == "RecoveryRequired":
        if node["uid"] != original_uid or not node["unschedulable"]:
            raise DrillError("recovery-required operation did not keep the original node fenced")
        return "CancellationFenced"
    raise DrillError("cancellation did not end in a verified Cancelled or fenced RecoveryRequired state")


def verify_maintenance_reservation(kubectl: str, operation_id: str, namespace: str) -> dict:
    maintenance = run_json([kubectl, "get", "nodemaintenance", f"op-{operation_id}", "-n", namespace, "-o", "json"])
    owner_uid = maintenance.get("metadata", {}).get("uid")
    if not owner_uid:
        raise DrillError("NodeMaintenance has no Kubernetes UID for reservation verification")
    lease = run_json([kubectl, "get", "lease", "kordex-maintenance-cluster-slot", "-n",
                      "kordex-operations-ledger", "-o", "json"])
    holder = (lease.get("spec") or {}).get("holderIdentity")
    if holder != owner_uid:
        raise DrillError("maintenance reservation is not held by the RecoveryRequired operation")
    return {"held": True, "reference": f"kordex-operations-ledger/kordex-maintenance-cluster-slot",
            "holderIdentity": holder, "operationResourceVersion": maintenance.get("metadata", {}).get("resourceVersion")}


def write_evidence(path: Path, evidence: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def submit_operation(hub: Hub, path: str, request: dict, evidence: dict, evidence_path: Path) -> dict:
    # Persist the chosen identity before the first request can reach the hub.
    # A lost response must never lead the observer to submit another operation.
    evidence.update({"operationId": request["operationId"], "submission": "IntentPersisted",
                     "outcome": "SubmissionUnknown"})
    write_evidence(evidence_path, evidence)
    latest = hub.request("POST", path, request)
    evidence.update({"submission": "ResponseReceived", "outcome": "InProgress",
                     "lastOperation": redacted_operation(latest)})
    write_evidence(evidence_path, evidence)
    return latest


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise DrillError(f"duplicate evidence field: {key}")
        value[key] = item
    return value


def observe_existing_operation(source_path: Path, evidence: dict, evidence_path: Path,
                               timeout_seconds: int, poll_seconds: float) -> None:
    """Observe a saved operation using only hub GETs and Kubernetes reads.

    The separate report is supplemental evidence, never a replacement for the
    original execution record or proof that a missed fault injection happened.
    """
    raw = source_path.read_bytes()
    source = json.loads(raw, object_pairs_hook=unique_object)
    if (not isinstance(source, dict) or source.get("drill") != "self-managed-linux-upgrade"
            or source.get("mode") != "execute" or source.get("admissionChecksPassed") is not True):
        raise DrillError("observation requires an execution record with passed admission checks")
    operation_id = source.get("operationId")
    try:
        valid_id = isinstance(operation_id, str) and str(uuid.UUID(operation_id)) == operation_id
    except ValueError:
        valid_id = False
    if not valid_id:
        raise DrillError("saved operation ID is missing or invalid; do not resubmit execution")
    hub = Hub(required("KORDEX_API"), required("KORDEX_ADMIN_TOKEN"))
    org, cluster_id = required("KORDEX_ORG_ID"), required("KORDEX_CLUSTER_ID")
    context = required("KORDEX_EXPECTED_CONTEXT")
    if (source.get("organization") != org or source.get("cluster") != cluster_id
            or source.get("apiOrigin") != hub.origin or source.get("context") != context):
        raise DrillError("saved management origin, organization, cluster, or context differs from environment")
    node = source.get("node")
    policy = source.get("policyIdentity")
    digest = source.get("planDigest")
    if (not isinstance(node, dict) or not isinstance(node.get("name"), str) or not node["name"]
            or not isinstance(node.get("uid"), str) or not node["uid"]
            or not isinstance(policy, dict) or not isinstance(policy.get("name"), str) or not policy["name"]
            or not isinstance(policy.get("uid"), str) or not policy["uid"]
            or type(policy.get("generation")) is not int or policy["generation"] < 1
            or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
        raise DrillError("saved node, policy, or plan identity is malformed")
    validate_policy_entry({"upgrade": source.get("upgradePlan"), "upgradePlanDigest": digest}, digest)
    kubectl = os.environ.get("KUBECTL", "kubectl")
    actual_context = subprocess.check_output([kubectl, "config", "current-context"], text=True, timeout=30).strip()
    if actual_context != context:
        raise DrillError("kubectl context differs from saved observation target")
    cluster_uid = run_json([kubectl, "get", "namespace", "kube-system", "-o", "json"]).get("metadata", {}).get("uid")
    if not cluster_uid or cluster_uid != source.get("clusterUid"):
        raise DrillError("live Kubernetes cluster UID differs from saved observation target")
    evidence.update({"sourceEvidenceSHA256": hashlib.sha256(raw).hexdigest(),
                     "operationId": operation_id, "organization": org, "cluster": cluster_id,
                     "clusterUid": cluster_uid, "context": context, "node": node,
                     "planDigest": digest, "outcome": "ObservationInProgress"})
    write_evidence(evidence_path, evidence)
    path = api_path(org, f"clusters/{urllib.parse.quote(cluster_id, safe='')}/operations")
    expected_request = {"operationId": operation_id, "nodeName": node["name"], "nodeUid": node["uid"],
                        "policy": policy, "action": "UpgradePackages", "planDigest": digest}
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        matches = [item for item in list_all(hub, path) if isinstance(item, dict) and item.get("id") == operation_id]
        if len(matches) != 1:
            evidence["outcome"] = "OperationNotFoundUnknown"
            raise DrillError("saved operation is not uniquely visible; do not resubmit execution")
        latest = matches[0]
        if (latest.get("organizationId") != org or latest.get("clusterId") != cluster_id
                or latest.get("request") != expected_request):
            raise DrillError("live operation does not match saved organization, target, policy, and plan")
        evidence["lastOperation"] = redacted_operation(latest)
        write_evidence(evidence_path, evidence)
        phase = latest.get("phase")
        if phase in {"Succeeded", "Cancelled", "RecoveryRequired", "Failed"}:
            observed_node = check_node(run_json([kubectl, "get", "node", node["name"], "-o", "json"]),
                                       require_ready=phase in {"Succeeded", "Cancelled"},
                                       require_schedulable=phase in {"Succeeded", "Cancelled"})
            evidence["nodeAfter"] = observed_node
            if observed_node["uid"] != node["uid"]:
                raise DrillError("node UID changed; observation cannot verify original host recovery")
            if phase == "Succeeded":
                evidence["checkpoint"] = verify_completed_operation(latest, digest, node["uid"], source["upgradePlan"])
            elif phase in {"Cancelled", "RecoveryRequired"}:
                verify_cancellation_fence(latest, observed_node, node["uid"])
                if phase == "RecoveryRequired":
                    evidence["reservationEvidence"] = verify_maintenance_reservation(
                        kubectl, operation_id, os.environ.get("KORDEX_NAMESPACE", "kordex-system"))
            else:
                evidence["outcome"] = "ObservedFailed"
                raise DrillError("operation failed; observation does not establish safe recovery")
            evidence["outcome"] = f"Observed{phase}"
            return
        time.sleep(max(0.25, min(poll_seconds, 60.0)))
    evidence["outcome"] = "TimedOutUnknown"
    raise DrillError("observation timed out; operation may still be active; do not resubmit execution")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="submit one signed UpgradePackages operation")
    mode.add_argument("--observe-evidence", type=Path,
                      help="read-only observation of the existing operation in a saved execution record")
    parser.add_argument("--cancel-on-phase", choices=tuple(CANCELLATION_CASES),
                        help="request signed cancellation once the local upgrade checkpoint reaches this phase")
    parser.add_argument("--qualification-case", choices=(
        "clean-upgrade", *CANCELLATION_CASES.values(),
        "operator-restart-during-executing", "ssh-loss-during-apply", "partial-package-application",
        "reboot-never-returns", "ssh-loss-after-reboot-request", "wrong-machine-id",
        "node-replaced-during-recovery", "wrong-kernel-after-reboot",
    ),
                        help="stable case identifier for the qualification evidence matrix")
    parser.add_argument("--evidence", type=Path, help="write redacted drill evidence JSON")
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    parser.add_argument("--poll-seconds", type=float, default=10)
    args = parser.parse_args()
    if (args.execute or args.observe_evidence) and not args.evidence:
        parser.error("--execute and --observe-evidence require a new --evidence output path")
    if args.observe_evidence and (args.cancel_on_phase or args.qualification_case):
        parser.error("read-only observation cannot request cancellation or a qualification case")
    if args.evidence and (args.evidence.exists() or args.evidence.is_symlink()):
        parser.error("refusing to overwrite existing evidence; use a new output path")
    case_id = args.qualification_case or CANCELLATION_CASES.get(args.cancel_on_phase, "clean-upgrade")
    expected_cancel_phase = next((phase for phase, case in CANCELLATION_CASES.items() if case == case_id), None)
    if args.cancel_on_phase and expected_cancel_phase != args.cancel_on_phase:
        parser.error("--qualification-case conflicts with --cancel-on-phase")
    if expected_cancel_phase and not args.cancel_on_phase:
        parser.error("cancellation qualification cases require --cancel-on-phase")
    if case_id == "clean-upgrade" and args.cancel_on_phase:
        parser.error("clean-upgrade cannot request cancellation")
    evidence: dict = {"drill": "self-managed-linux-upgrade", "mode": "execute" if args.execute else "preflight",
                      "qualificationCase": case_id, "startedAt": dt.datetime.now(dt.timezone.utc).isoformat()}
    if case_id in SUPPLEMENTAL_CASES:
        evidence["qualificationScope"] = "supplemental"
    if args.observe_evidence:
        evidence.update({"drill": "self-managed-linux-upgrade-observation", "mode": "observe"})
        evidence.pop("qualificationCase")
    evidence_owned = False
    result = 1
    try:
        if args.evidence:
            args.evidence.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(args.evidence, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            evidence_owned = True
            write_evidence(args.evidence, evidence)
        if args.timeout_seconds < 1 or args.poll_seconds <= 0:
            raise DrillError("timeout and polling interval must be positive")
        if args.observe_evidence:
            observe_existing_operation(args.observe_evidence, evidence, args.evidence,
                                       args.timeout_seconds, args.poll_seconds)
            return 0
        if args.cancel_on_phase and not args.execute:
            raise DrillError("--cancel-on-phase requires --execute")
        hub = Hub(required("KORDEX_API"), required("KORDEX_ADMIN_TOKEN"))
        org, cluster_id = required("KORDEX_ORG_ID"), required("KORDEX_CLUSTER_ID")
        node_name, policy_name = required("KORDEX_NODE_NAME"), required("KORDEX_HOST_POLICY")
        digest, expected_context = required("KORDEX_HOST_PLAN_DIGEST"), required("KORDEX_EXPECTED_CONTEXT")
        kubectl = os.environ.get("KUBECTL", "kubectl")
        context = subprocess.check_output([kubectl, "config", "current-context"], text=True, timeout=30).strip()
        if context != expected_context:
            raise DrillError(f"kubectl context mismatch: expected {expected_context!r}, got {context!r}")
        cluster = next((item for item in list_all(hub, api_path(org, "clusters")) if item.get("id") == cluster_id), None)
        if cluster is None or cluster.get("provider") != "self-managed" or not cluster.get("connected"):
            raise DrillError("registered cluster must be connected and provider self-managed")
        fresh(cluster.get("observedAt", ""), 90, "cluster inventory")
        fresh(cluster.get("lastHeartbeatAt", ""), 90, "cluster heartbeat")
        cluster_uid = run_json([kubectl, "get", "namespace", "kube-system", "-o", "json"]).get("metadata", {}).get("uid")
        if not cluster_uid or cluster_uid != cluster.get("clusterUid"):
            raise DrillError("live Kubernetes cluster UID differs from registered cluster identity")
        node_object = run_json([kubectl, "get", "node", node_name, "-o", "json"])
        node = check_node(node_object)
        inventory = list_all(hub, api_path(org, f"clusters/{urllib.parse.quote(cluster_id, safe='')}/nodes"))
        matching = [item for item in inventory if item.get("uid") == node["uid"] and item.get("name") == node_name]
        if (len(matching) != 1 or not matching[0].get("ready") or matching[0].get("unschedulable")
                or matching[0].get("osImage") != node["osImage"]):
            raise DrillError("central node inventory is missing, stale, or differs from live Kubernetes")
        entry = check_policy(hub, org, cluster_id, policy_name, digest)
        node = check_node(node_object, expected_os_family=entry["upgrade"]["osFamily"])
        target = f"{cluster_id}/{node_name}/{node['uid']}"
        evidence.update({"organization": org, "apiOrigin": hub.origin,
                         "cluster": cluster_id, "clusterUid": cluster_uid, "context": context,
                         "node": node, "osFamily": node["osFamily"], "policyIdentity": entry.get("policy"), "planDigest": digest,
                         "upgradePlan": entry["upgrade"],
                         "admissionChecksPassed": True, "targetConfirmation": target})
        result = 0
        if args.execute:
            validate_execution_confirmation(target, os.environ.get("KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM", ""))
            operation_id = str(uuid.uuid4())
            suffix = f"clusters/{urllib.parse.quote(cluster_id, safe='')}/operations"
            request = {"operationId": operation_id, "nodeName": node_name, "nodeUid": node["uid"],
                       "policy": entry["policy"], "action": "UpgradePackages", "planDigest": digest}
            latest = submit_operation(hub, api_path(org, suffix), request, evidence, args.evidence)
            deadline = time.monotonic() + args.timeout_seconds
            terminal = {"Succeeded", "Failed", "Cancelled", "RecoveryRequired"}
            cancel_requested = False
            operator_restart_requested = False
            while time.monotonic() < deadline:
                operations = list_all(hub, api_path(org, suffix))
                latest = next((item for item in operations if item.get("id") == operation_id), latest)
                evidence["lastOperation"] = redacted_operation(latest)
                write_evidence(args.evidence, evidence)
                if (args.cancel_on_phase and not cancel_requested and latest.get("phase") not in terminal
                        and upgrade_phase(latest) == args.cancel_on_phase):
                    cancel_requested = True
                    request_phase_cancellation(hub, org, cluster_id, latest, args.cancel_on_phase,
                                              evidence, args.evidence)
                if (case_id == "operator-restart-during-executing" and not operator_restart_requested
                        and upgrade_phase(latest) == "Executing"):
                    operator_restart_requested = True
                    try:
                        evidence["operatorRestart"] = restart_operator(
                            kubectl, os.environ.get("KORDEX_NAMESPACE", "kordex-system"))
                    except DrillError as error:
                        evidence["operatorRestart"] = {
                            "phaseAtRestart": "Executing",
                            "error": str(error),
                            "requestedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
                        }
                    write_evidence(args.evidence, evidence)
                if latest.get("phase") in terminal:
                    break
                poll_seconds = min(args.poll_seconds, 1.0) if (args.cancel_on_phase or case_id == "operator-restart-during-executing") else args.poll_seconds
                time.sleep(max(0.25, min(poll_seconds, 60.0)))
            else:
                evidence["outcome"] = "TimedOutUnknown"
                raise DrillError("operation timed out and may still be active; inspect Kordex before any intervention")
            if args.cancel_on_phase:
                verify_cancellation_case(latest, args.cancel_on_phase, cancel_requested, evidence)
            if case_id == "operator-restart-during-executing":
                restart = evidence.get("operatorRestart") or {}
                if not restart.get("oldPodUID") or not restart.get("newPodUID"):
                    evidence["outcome"] = "OperatorRestartNotVerified"
                    raise DrillError("operator Deployment restart and new Ready pod identity were not verified")
            if latest.get("phase") != "Succeeded":
                terminal_checkpoint = ((latest.get("status") or {}).get("upgradeCheckpoint") or {})
                if latest.get("phase") == "Failed":
                    evidence["mutationStarted"] = any(
                        receipt.get("phase") in {"apply", "reboot"}
                        for receipt in terminal_checkpoint.get("receipts", [])
                    )
                preflight_receipt = next((item for item in terminal_checkpoint.get("receipts", [])
                                          if item.get("phase") == "preflight"), None)
                if preflight_receipt:
                    evidence["hostPreflightReceipt"] = preflight_receipt
                if cancel_requested:
                    recovered_node = check_node(run_json([kubectl, "get", "node", node_name, "-o", "json"]),
                                                require_ready=latest.get("phase") == "Cancelled",
                                                require_schedulable=latest.get("phase") == "Cancelled")
                    evidence["cancellationOutcome"] = verify_cancellation_fence(latest, recovered_node, node["uid"])
                    evidence["nodeAfter"] = recovered_node
                    if evidence["cancellationOutcome"] == "CancellationFenced":
                        evidence["reservationEvidence"] = verify_maintenance_reservation(
                            kubectl, operation_id, os.environ.get("KORDEX_NAMESPACE", "kordex-system"))
                    evidence["outcome"] = evidence["cancellationOutcome"]
                    result = 0
                elif latest.get("phase") == "RecoveryRequired":
                    observed_node = check_node(run_json([kubectl, "get", "node", node_name, "-o", "json"]),
                                               require_ready=False, require_schedulable=False)
                    if case_id == "node-replaced-during-recovery":
                        if observed_node["uid"] == node["uid"] or observed_node["unschedulable"]:
                            raise DrillError("replacement drill did not prove a new, untouched Node identity")
                    elif observed_node["uid"] != node["uid"] or not observed_node["unschedulable"]:
                        raise DrillError("RecoveryRequired operation did not retain the original node cordon")
                    evidence["nodeAfter"] = observed_node
                    evidence["reservationEvidence"] = verify_maintenance_reservation(
                        kubectl, operation_id, os.environ.get("KORDEX_NAMESPACE", "kordex-system"))
                    evidence["outcome"] = "RecoveryRequired"
                    result = 0
                else:
                    evidence["outcome"] = latest.get("phase", "Unknown")
                    raise DrillError(f"operation ended in {latest.get('phase')}: {(latest.get('status') or {}).get('reason', 'unknown')}")
            else:
                checkpoint = verify_completed_operation(latest, digest, node["uid"], entry["upgrade"])
                preflight_receipt = next((item for item in checkpoint.get("receipts", [])
                                          if item.get("phase") == "preflight"), None)
                if preflight_receipt:
                    evidence["hostPreflightReceipt"] = preflight_receipt
                recovered = check_node(run_json([kubectl, "get", "node", node_name, "-o", "json"]))
                if recovered["uid"] != node["uid"]:
                    raise DrillError("node UID changed during host upgrade")
                evidence.update({"checkpoint": checkpoint, "nodeAfter": recovered, "outcome": "Succeeded"})
    except (DrillError, KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        evidence["outcome"] = evidence.get("outcome", "Failed")
        evidence["error"] = str(error)
        result = 1
    finally:
        evidence["finishedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
        if args.evidence and evidence_owned:
            write_evidence(args.evidence, evidence)
        print(json.dumps(evidence, indent=2, sort_keys=True))
    return result


if __name__ == "__main__":
    sys.exit(main())
