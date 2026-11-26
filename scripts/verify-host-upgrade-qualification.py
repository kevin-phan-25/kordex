#!/usr/bin/env python3
"""Validate that every required disposable-host upgrade drill has evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid


class EvidenceError(ValueError):
    pass


RHEL_PAYG_LICENSES = {
    "https://www.googleapis.com/compute/v1/projects/rhel-cloud/global/licenses/rhel-9-server",
    "https://www.googleapis.com/compute/v1/projects/rhel-cloud/global/licenses/rhel-9-server-eus",
}


FAILURE_MATRIX_SHA256 = "ba25ba7224b193e4de3d048fae1d4f027c3cca5626bb1734bf3a426d7807c9ad"


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate JSON keys instead of silently trusting the last value."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json_object(path: Path, description: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"{description}: invalid JSON") from error
    require(isinstance(value, dict), f"{description}: expected one JSON object")
    return value


def timestamp(value: object, field: str) -> dt.datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{field} must be an RFC3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(f"{field} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise EvidenceError(f"{field} must include a timezone")
    return parsed


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def verify_action_marker(marker: object, evidence: dict, machine_id: str, boot_id: str,
                         phase: str, sequence: int, case_id: str) -> None:
    require(isinstance(marker, dict), f"{case_id}: {phase} action marker missing")
    try:
        uuid.UUID(str(marker.get("operationId")))
        uuid.UUID(str(marker.get("bootId")))
    except (ValueError, AttributeError) as error:
        raise EvidenceError(f"{case_id}: action marker operation or boot identity invalid") from error
    require(type(marker.get("version")) is int and marker.get("version") == 1
            and marker.get("operationId") == evidence.get("operationId")
            and marker.get("actionDigest") == evidence.get("planDigest")
            and marker.get("nodeUid") == (evidence.get("node") or {}).get("uid")
            and marker.get("machineId") == machine_id
            and marker.get("bootId") == boot_id
            and marker.get("phase") == phase
            and type(marker.get("sequence")) is int and marker.get("sequence") == sequence
            and re.fullmatch(r"[a-f0-9]{64}", str(marker.get("sha256", ""))) is not None,
            f"{case_id}: {phase} action marker does not match operation, plan, node, machine, or boot")


def verify_injection_artifact(injection: dict, evidence_dir: Path, case_id: str) -> None:
    relative_name = injection.get("evidenceFile")
    expected_digest = injection.get("evidenceSHA256")
    require(isinstance(relative_name, str) and relative_name,
            f"{case_id}: copied fault-injection evidence file is missing")
    require(re.fullmatch(r"[a-f0-9]{64}", str(expected_digest or "")) is not None,
            f"{case_id}: fault-injection evidence SHA-256 is missing or invalid")
    relative = Path(relative_name)
    require(relative.parts and not relative.is_absolute()
            and all(part not in {"", ".", ".."} for part in relative.parts),
            f"{case_id}: fault-injection evidence path must be a safe relative path")
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and os.open in os.supports_dir_fd,
            f"{case_id}: platform cannot safely open fault-injection evidence without following links")
    descriptors: list[int] = []
    try:
        directory_fd = os.open(evidence_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(directory_fd)
        for part in relative.parts[:-1]:
            directory_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            descriptors.append(directory_fd)
        file_fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        descriptors.append(file_fd)
        require(stat.S_ISREG(os.fstat(file_fd).st_mode),
                f"{case_id}: fault-injection evidence is not a regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        actual_digest = digest.hexdigest()
    except OSError as error:
        raise EvidenceError(f"{case_id}: fault-injection evidence path is unavailable or contains a symlink") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    require(actual_digest == expected_digest, f"{case_id}: fault-injection evidence SHA-256 mismatch")


def verify_fault_observations(requirement: dict, injection: dict, evidence: dict, case_id: str) -> None:
    fault_type = requirement.get("faultType")
    require(isinstance(fault_type, str) and injection.get("faultType") == fault_type,
            f"{case_id}: specific injected fault type is missing or mismatched")
    observations = injection.get("observations")
    required_fields = requirement.get("required")
    require(isinstance(observations, dict) and isinstance(required_fields, list) and required_fields,
            f"{case_id}: structured fault observations are missing")
    for field in required_fields:
        require(field in observations and observations[field] is not None,
                f"{case_id}: required fault observation {field} is missing")
    if "phase" in requirement:
        require(observations.get("phase") == requirement["phase"],
                f"{case_id}: injected fault was not observed during {requirement['phase']}")
        operation = evidence.get("lastOperation") or {}
        status = operation.get("status") or {}
        events = status.get("events")
        require(isinstance(events, list) and bool(events),
                f"{case_id}: durable operation phase history is missing")
        previous_sequence = 0
        for event in events:
            require(isinstance(event, dict) and type(event.get("sequence")) is int
                    and event["sequence"] == previous_sequence + 1
                    and isinstance(event.get("phase"), str)
                    and isinstance(event.get("reason"), str),
                    f"{case_id}: durable operation phase history is malformed")
            timestamp(event.get("time"), f"{case_id}: operation event time")
            previous_sequence = event["sequence"]
        require(status.get("phase") == operation.get("phase")
                and status.get("sequence") == previous_sequence
                and events[-1].get("phase") == operation.get("phase")
                and any(event.get("phase") == requirement["phase"] for event in events),
                f"{case_id}: durable operation history does not prove the expected and terminal phases")
    if fault_type == "operator-restart":
        require(observations["oldPodUID"] != observations["newPodUID"],
                f"{case_id}: operator pod identity did not change")
    elif fault_type == "ssh-loss":
        require(observations["blockedObserved"] is True and observations["restoredObserved"] is True,
                f"{case_id}: SSH loss and restoration were not both observed")
    elif fault_type == "package-manager-failure":
        require(isinstance(observations["changedPackageNames"], list)
                and bool(observations["changedPackageNames"])
                and all(isinstance(name, str) and name for name in observations["changedPackageNames"])
                and type(observations["exitCode"]) is int and observations["exitCode"] != 0,
                f"{case_id}: package change and nonzero package-manager exit were not both observed")
    elif fault_type == "host-no-return":
        minimum = requirement.get("minimumUnavailableSeconds")
        duration = observations["unavailableDurationSeconds"]
        require(observations["rebootIntentObserved"] is True
                and type(minimum) is int and type(duration) is int and duration >= minimum,
                f"{case_id}: reboot intent or minimum host outage was not observed")
    elif fault_type == "ssh-loss-after-reboot-intent":
        require(observations["rebootIntentObserved"] is True
                and observations["blockedObserved"] is True
                and observations["restoredObserved"] is True,
                f"{case_id}: reboot intent, SSH loss, and restoration were not all observed")
    elif fault_type == "machine-id-mismatch":
        require(isinstance(observations["expectedMachineId"], str)
                and isinstance(observations["observedMachineId"], str)
                and observations["expectedMachineId"] != observations["observedMachineId"],
                f"{case_id}: observed machine ID did not differ from the expected identity")
    elif fault_type == "node-replacement":
        require(observations["originalNodeUID"] == (evidence.get("node") or {}).get("uid")
                and observations["replacementNodeUID"] == (evidence.get("nodeAfter") or {}).get("uid")
                and observations["replacementNodeUID"] != observations["originalNodeUID"],
                f"{case_id}: observed replacement Node UID does not match the original and post-recovery nodes")
    elif fault_type == "kernel-mismatch":
        expected = ((evidence.get("upgradePlan") or {}).get("expectedKernelVersion"))
        require(isinstance(expected, str) and expected
                and observations["expectedKernel"] == expected
                and isinstance(observations["observedKernel"], str)
                and observations["observedKernel"] != expected,
                f"{case_id}: observed kernel did not differ from the exact planned kernel")


def verify_workload_snapshot(snapshot: object) -> dict:
    require(isinstance(snapshot, dict) and isinstance(snapshot.get("items"), list)
            and snapshot["items"], "workload recovery snapshot missing")
    identities = {}
    for item in snapshot["items"]:
        require(isinstance(item, dict), "workload recovery entry malformed")
        require(item.get("kind") in {"Deployment", "StatefulSet", "DaemonSet"}, "workload kind unsupported")
        require(all(isinstance(item.get(key), str) and item[key] for key in ("namespace", "name", "uid")),
                "workload recovery identity missing")
        require(all(type(item.get(key)) is int and item[key] >= 0
                    for key in ("generation", "observedGeneration", "desired", "ready", "updated", "available")),
                "workload recovery counts missing or invalid")
        require(item["generation"] > 0 and item["observedGeneration"] >= item["generation"]
                and all(item[key] >= item["desired"] for key in ("ready", "updated", "available")),
                "workload recovery stale or unhealthy")
        key = (item["kind"], item["namespace"], item["name"])
        require(key not in identities, "workload recovery identities duplicated")
        identities[key] = (item["uid"], item["generation"], item["desired"])
    require(any(item["desired"] > 0 for item in snapshot["items"]), "no running qualification workload")
    return identities


def verify_recovery_release(evidence: dict) -> None:
    recovery = evidence.get("recoveryEvidence")
    require(isinstance(recovery, dict), "independent recovery/release evidence missing")
    require(recovery.get("operationId") == evidence["operationId"] and isinstance(recovery.get("maintenanceUid"), str)
            and recovery["maintenanceUid"], "recovery operation identity missing or mismatched")
    node = recovery.get("nodeAfter")
    require(isinstance(node, dict) and node.get("uid") == evidence["node"]["uid"]
            and node.get("ready") is True and node.get("unschedulable") is False
            and node.get("cordonOwner") == "" and (evidence.get("nodeAfter") or {}).get("cordonOwner") == "",
            "owned cordon removal was not independently verified")
    reservation = recovery.get("reservation")
    require(recovery.get("reservationReleased") is True and isinstance(reservation, dict)
            and reservation.get("reference") == "kordex-operations-ledger/kordex-maintenance-cluster-slot"
            and isinstance(reservation.get("holderIdentity"), str)
            and reservation["holderIdentity"] != recovery["maintenanceUid"]
            and isinstance(reservation.get("resourceVersion"), str) and reservation["resourceVersion"],
            "maintenance reservation release evidence missing or still held")
    before, after = evidence.get("workloadsBefore"), recovery.get("workloadsAfter")
    require(verify_workload_snapshot(before) == verify_workload_snapshot(after),
            "workload identities, generations, or replica targets changed")
    start, finish = timestamp(evidence["startedAt"], "startedAt"), timestamp(evidence["finishedAt"], "finishedAt")
    require(start <= timestamp(before.get("observedAt"), "workloadsBefore.observedAt")
            <= timestamp(after.get("observedAt"), "workloadsAfter.observedAt")
            <= timestamp(recovery.get("observedAt"), "recovery.observedAt") <= finish,
            "recovery/release observations are outside the drill interval")


def verify_baseline_packages(evidence: dict, preflight: dict) -> None:
    artifact = evidence.get("baselinePackageEvidence")
    require(isinstance(artifact, dict), "baseline package evidence missing")
    raw = artifact.get("receiptJSON")
    require(isinstance(raw, str) and artifact.get("reference") == preflight.get("reference")
            and artifact.get("digest") == preflight.get("digest")
            and hashlib.sha256(raw.encode()).hexdigest() == preflight.get("digest"),
            "baseline package receipt digest or reference mismatch")
    try:
        receipt = json.loads(raw, object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        raise EvidenceError("baseline package receipt contains invalid JSON") from error
    require(isinstance(receipt, dict) and receipt.get("operationId") == evidence["operationId"]
            and receipt.get("planDigest") == evidence["planDigest"] and receipt.get("nodeUid") == evidence["node"]["uid"]
            and all(receipt.get(key) == preflight.get(key) for key in ("machineId", "bootIdBefore", "bootIdAfter")),
            "baseline package receipt identity mismatch")
    packages = receipt.get("baselinePackages")
    names = {pin["name"] for pin in evidence["upgradePlan"]["packages"]}
    require(isinstance(packages, dict) and set(packages) == names and packages == evidence.get("baselinePackages")
            and all(isinstance(value, str) and len(value) <= 256 for value in packages.values()),
            "baseline package versions missing or inconsistent")
    if evidence.get("qualificationCase") == "clean-upgrade" and evidence.get("outcome") == "Succeeded":
        require(any(packages[pin["name"]] != pin["version"] for pin in evidence["upgradePlan"]["packages"]),
                "clean upgrade did not change any requested package version")


def verify_platform_evidence(evidence: dict, os_family: str, preflight: dict) -> None:
    platform = evidence.get("platformEvidence")
    require(isinstance(platform, dict) and platform.get("schemaVersion") == 1,
            f"{evidence.get('qualificationCase')}: platform, image, and artifact evidence missing")
    for field in ("profile", "qualificationOSProfile", "osId", "osMajor", "osMinor", "imageID", "imageUniqueID", "imageProject",
                  "imageFamilyOrName", "architecture", "artifactPreflightReportSHA256", "packagePolicySHA256",
                  "packageArchiveSHA256", "packageRepositorySnapshotID", "imageApprovalReference",
                  "imageApprovalSHA256", "osImage", "osVersion", "osPointRelease",
                  "kernelVersionBefore", "kernelVersionAfter"):
        require(isinstance(platform.get(field), str), f"{evidence['qualificationCase']}: platform evidence {field} missing")
    boot_check = platform.get("bootDiskImageVerification")
    require(isinstance(boot_check, dict)
            and set(boot_check) == {"schemaVersion", "method", "verifiedAt", "projectId", "zone", "labId",
                                   "imageSelfLink", "imageUniqueId", "instances"}
            and boot_check.get("schemaVersion") == 1
            and boot_check.get("method") == "gcloud-compute-instance-and-disk-source-image"
            and boot_check.get("imageSelfLink") == platform.get("imageID")
            and boot_check.get("imageUniqueId") == platform.get("imageUniqueID")
            and isinstance(boot_check.get("projectId"), str) and boot_check["projectId"]
            and isinstance(boot_check.get("zone"), str) and boot_check["zone"]
            and isinstance(boot_check.get("labId"), str) and boot_check["labId"],
            f"{evidence['qualificationCase']}: actual boot-disk image verification is missing or mismatched")
    try:
        checked_at = timestamp(boot_check.get("verifiedAt"), "bootDiskImageVerification.verifiedAt")
        operation_start = timestamp(evidence.get("startedAt"), "startedAt")
        operation_finish = timestamp(evidence.get("finishedAt"), "finishedAt")
    except EvidenceError:
        raise
    require(checked_at <= operation_start and operation_start - checked_at <= dt.timedelta(minutes=5),
            f"{evidence['qualificationCase']}: actual boot-disk image check must be fresh and precede execution")
    expected_disks = {
        (f"{boot_check['labId']}-server", "server"),
        (f"{boot_check['labId']}-worker", "worker-1"),
        (f"{boot_check['labId']}-worker-2", "worker-2"),
    }
    instances = boot_check.get("instances")
    require(isinstance(instances, list) and len(instances) == 3,
            f"{evidence['qualificationCase']}: boot-disk image check must cover exactly the three lab nodes")
    observed_disks = set()
    disk_resource_prefix = (
        f"https://www.googleapis.com/compute/v1/projects/{boot_check['projectId']}/"
        f"zones/{boot_check['zone']}/disks/"
    )
    for item in instances:
        require(isinstance(item, dict) and set(item) == {
            "name", "role", "instanceId", "bootDiskName", "bootDiskId", "bootDiskSelfLink",
            "sourceImage", "sourceImageId", "licenses",
        }, f"{evidence['qualificationCase']}: boot-disk identity/license record is malformed")
        licenses = item.get("licenses")
        require(isinstance(licenses, list) and all(isinstance(value, str) and value for value in licenses)
                and len(licenses) == len(set(licenses)),
                f"{evidence['qualificationCase']}: boot-disk license identity is malformed")
        if os_family == "debian":
            require(not licenses,
                    f"{evidence['qualificationCase']}: Debian boot disk unexpectedly carries licensed-image terms")
        else:
            require(RHEL_PAYG_LICENSES.issubset(set(licenses)),
                    f"{evidence['qualificationCase']}: RHEL boot disk lacks the approved PAYG/EUS license identities")
        pair = (item.get("name"), item.get("role"))
        require(pair in expected_disks and pair not in observed_disks
                and re.fullmatch(r"[1-9][0-9]{0,19}", str(item.get("instanceId", "")))
                and isinstance(item.get("bootDiskName"), str)
                and re.fullmatch(r"[a-z][a-z0-9-]{0,62}", item.get("bootDiskName", ""))
                and re.fullmatch(r"[1-9][0-9]{0,19}", str(item.get("bootDiskId", "")))
                and item.get("bootDiskSelfLink") == disk_resource_prefix + item.get("bootDiskName", "")
                and item.get("sourceImage") == platform.get("imageID")
                and str(item.get("sourceImageId", "")) == platform.get("imageUniqueID"),
                f"{evidence['qualificationCase']}: boot disk is not bound to the approved image")
        observed_disks.add(pair)
    require(observed_disks == expected_disks,
            f"{evidence['qualificationCase']}: boot-disk identity check omitted a required lab node")
    for field in ("artifactPreflightReportSHA256", "packagePolicySHA256", "packageArchiveSHA256", "imageApprovalSHA256"):
        require(re.fullmatch(r"[a-f0-9]{64}", platform[field]) is not None,
                f"{evidence['qualificationCase']}: platform evidence {field} is invalid")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", platform["imageApprovalReference"]) is not None,
            f"{evidence['qualificationCase']}: image owner approval reference is invalid")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", platform["packageRepositorySnapshotID"]) is not None,
            f"{evidence['qualificationCase']}: package repository snapshot identity is invalid")
    require(platform["architecture"] == "linux/amd64"
            and re.fullmatch(r"https://www\.googleapis\.com/compute/v1/projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,62}", platform["imageID"]) is not None,
            f"{evidence['qualificationCase']}: selected image or architecture is not pinned")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", platform["imageUniqueID"]) is not None,
            f"{evidence['qualificationCase']}: server-assigned image identity is missing or malformed")
    require(platform["imageProject"] == platform["imageID"].split("/")[6]
            and platform["imageFamilyOrName"] == platform["imageID"].rsplit("/", 1)[-1],
            f"{evidence['qualificationCase']}: image source metadata does not match the selected image self-link")
    require(platform["artifactPreflightReportSHA256"] and platform["profile"].startswith("m3-")
            and platform["profile"] == evidence.get("artifactPreflightProfile", platform["profile"]),
            f"{evidence['qualificationCase']}: artifact profile binding is malformed")
    node = evidence["node"]
    require(platform["osImage"] == node.get("osImage")
            and platform["kernelVersionBefore"] == preflight.get("kernelVersion") == node.get("kernelVersion")
            and platform["kernelVersionAfter"] != "",
            f"{evidence['qualificationCase']}: host OS or initial kernel evidence conflicts with the selected node")
    node_after = evidence.get("nodeAfter")
    if isinstance(node_after, dict) and node_after.get("uid") == node.get("uid") and node_after.get("kernelVersion"):
        require(platform["kernelVersionAfter"] == node_after["kernelVersion"],
                f"{evidence['qualificationCase']}: final kernel evidence differs from the original host's Node record")
    require(preflight.get("osId") == platform["osId"] and preflight.get("osVersion") == platform["osVersion"]
            and preflight.get("osPointRelease") == platform["osPointRelease"]
            and preflight.get("architecture") == "amd64",
            f"{evidence['qualificationCase']}: host preflight OS identity differs from platform evidence")
    package_baseline = platform.get("baselinePackages")
    require(isinstance(package_baseline, dict) and package_baseline == evidence.get("baselinePackages"),
            f"{evidence['qualificationCase']}: platform package baseline is missing or inconsistent")
    if os_family == "debian":
        require(platform["osId"] == "debian" and platform["osMajor"] == "13" and platform["osMinor"] == ""
                and platform["qualificationOSProfile"] == "debian-13"
                and platform["imageProject"] == "debian-cloud"
                and platform["imageFamilyOrName"] == platform["imageID"].rsplit("/", 1)[-1]
                and platform["imageFamilyOrName"].startswith("debian-13")
                and platform["osPointRelease"] == "13.8"
                and platform["osVersion"] == "13"
                and re.fullmatch(r"m3-debian-13-k3s-[A-Za-z0-9.+-]+-linux-amd64", platform["profile"]) is not None
                and (node.get("osId"), node.get("osMajor"), node.get("osMinor")) == ("debian", "13", ""),
                f"{evidence['qualificationCase']}: evidence is not from a Debian 13 Trixie host")
    else:
        version = platform["osVersion"].split(".")
        require(platform["osId"] == "rhel" and platform["osMajor"] == "9" and platform["osMinor"].isdigit()
                and int(platform["osMinor"]) >= 8 and platform["qualificationOSProfile"] == "rhel-9"
                and len(version) >= 2 and version[0] == "9" and version[1] == platform["osMinor"]
                and platform["osVersion"] == f"9.{platform['osMinor']}"
                and re.fullmatch(
                    rf"m3-rhel-9\.{re.escape(platform['osMinor'])}-k3s-[A-Za-z0-9.+-]+-linux-amd64",
                    platform["profile"],
                ) is not None
                and platform["osPointRelease"] == platform["osVersion"]
                and (node.get("osId"), node.get("osMajor"), node.get("osMinor")) == ("rhel", "9", platform["osMinor"]),
                f"{evidence['qualificationCase']}: evidence is not from a supported RHEL 9.8-or-later host")


def verify_cancellation_request(evidence: dict) -> None:
    phases = {"cancel-during-executing": "Executing", "cancel-during-reboot": "Rebooting"}
    phase = phases.get(evidence.get("qualificationCase"))
    require(phase is not None and evidence.get("cancellationPhase") == phase
            and evidence.get("cancellationSubmission") == "Accepted"
            and (evidence.get("cancellationResponse") or {}).get("status") == "cancellation_requested",
            "cancellation phase/request acknowledgement evidence missing")
    observed = evidence.get("cancellationObservedOperation")
    require(isinstance(observed, dict) and observed.get("id") == evidence["operationId"]
            and observed.get("phase") == phase
            and (((observed.get("status") or {}).get("upgradeCheckpoint") or {}).get("phase")) == phase,
            "cancellation phase snapshot does not match the requested operation/phase")
    request = observed.get("request")
    require(isinstance(request, dict) and isinstance(evidence.get("policyIdentity"), dict)
            and request == {"operationId": evidence["operationId"], "nodeName": evidence["node"]["name"],
                            "nodeUid": evidence["node"]["uid"], "policy": evidence["policyIdentity"],
                            "action": "UpgradePackages", "planDigest": evidence["planDigest"]},
            "cancellation request does not match the original host target, policy and plan")
    requested = timestamp(evidence.get("cancellationRequestedAt"), "cancellationRequestedAt")
    operation = evidence["lastOperation"]
    accepted = timestamp(operation.get("cancelRequestedAt"), "operation.cancelRequestedAt")
    start, finish = timestamp(evidence["startedAt"], "startedAt"), timestamp(evidence["finishedAt"], "finishedAt")
    require(start <= requested <= finish and start <= accepted <= finish,
            "cancellation request timestamps are outside the drill interval")
    events = (operation.get("status") or {}).get("events", [])
    require(any(isinstance(event, dict) and event.get("phase") == phase
                and timestamp(event.get("time"), "cancellation phase event") <= requested for event in events),
            "durable history does not show the requested phase before cancellation")


def verify_case(case: dict, evidence: dict, os_family: str = "debian",
                evidence_dir: Path | None = None) -> None:
    case_id = case["id"]
    require(evidence.get("qualificationCase") == case_id, f"{case_id}: qualificationCase mismatch")
    require(evidence.get("qualificationScope") != "supplemental",
            f"{case_id}: supplemental evidence cannot satisfy a pinned matrix case")
    require(evidence.get("drill") == "self-managed-linux-upgrade", f"{case_id}: unexpected drill type")
    require(evidence.get("osFamily") == os_family, f"{case_id}: evidence does not match required OS family {os_family}")
    require(evidence.get("admissionChecksPassed") is True, f"{case_id}: admission checks did not pass")
    require(re.fullmatch(r"[a-f0-9]{64}", str(evidence.get("planDigest", ""))) is not None,
            f"{case_id}: plan digest missing or invalid")
    for field in ("cluster", "clusterUid", "context"):
        require(isinstance(evidence.get(field), str) and evidence[field], f"{case_id}: {field} missing")
    node = evidence.get("node")
    require(isinstance(node, dict) and node.get("name") and node.get("uid"), f"{case_id}: original node identity missing")
    start = timestamp(evidence.get("startedAt"), "startedAt")
    finish = timestamp(evidence.get("finishedAt"), "finishedAt")
    require(finish >= start, f"{case_id}: finish timestamp precedes start")
    operation_id = evidence.get("operationId")
    try:
        uuid.UUID(str(operation_id))
    except (ValueError, AttributeError) as error:
        raise EvidenceError(f"{case_id}: operation ID missing or invalid") from error
    outcome = evidence.get("outcome")
    require(outcome in case["allowedOutcomes"], f"{case_id}: outcome {outcome!r} is not accepted")
    operation = evidence.get("lastOperation")
    require(isinstance(operation, dict), f"{case_id}: redacted terminal operation evidence missing")
    checkpoint = ((operation.get("status") or {}).get("upgradeCheckpoint") or {})
    require(checkpoint.get("planDigest") == evidence["planDigest"] and checkpoint.get("nodeUid") == node["uid"],
            f"{case_id}: terminal checkpoint is not bound to the requested node and plan")
    if case_id == "operator-restart-during-executing":
        restart = evidence.get("operatorRestart")
        require(isinstance(restart, dict) and restart.get("deployment") == "kordex-operator"
                and isinstance(restart.get("namespace"), str) and restart["namespace"],
                f"{case_id}: operator Deployment restart evidence is missing")
        try:
            old_uid = str(uuid.UUID(str(restart.get("oldPodUID"))))
            new_uid = str(uuid.UUID(str(restart.get("newPodUID"))))
        except (ValueError, AttributeError) as error:
            raise EvidenceError(f"{case_id}: operator pod UID evidence is invalid") from error
        require(old_uid != new_uid and restart.get("phaseAtRestart") == "Executing",
                f"{case_id}: operator restart did not replace a pod during Executing")
        requested_at = timestamp(restart.get("requestedAt"), "operatorRestart.requestedAt")
        ready_at = timestamp(restart.get("readyAt"), "operatorRestart.readyAt")
        require(start <= requested_at <= ready_at <= finish,
                f"{case_id}: operator restart timestamps are outside the drill interval")
        events = ((operation.get("status") or {}).get("events") or [])
        executing_events = [event for event in events if isinstance(event, dict) and event.get("phase") == "Executing"]
        require(any(timestamp(event.get("time"), f"{case_id}: Executing event time") <= requested_at
                    for event in executing_events),
                f"{case_id}: durable operation history does not show Executing before operator restart")
    preflight = evidence.get("hostPreflightReceipt")
    require(isinstance(preflight, dict) and preflight.get("phase") == "preflight",
            f"{case_id}: host package-resolution and identity preflight receipt missing")
    require(preflight.get("machineId") and preflight.get("bootIdBefore")
            and preflight.get("bootIdBefore") == preflight.get("bootIdAfter"),
            f"{case_id}: host preflight did not prove stable machine and boot identity")
    require(re.fullmatch(r"[a-f0-9]{64}", str(preflight.get("digest", ""))) is not None
            and isinstance(preflight.get("reference"), str) and preflight["reference"],
            f"{case_id}: host preflight receipt is not immutable and referenced")
    timestamp(preflight.get("completedAt"), "hostPreflightReceipt.completedAt")
    checkpoint_receipts = checkpoint.get("receipts", [])
    require(isinstance(checkpoint_receipts, list)
            and all(isinstance(item, dict) and isinstance(item.get("phase"), str)
                    and item["phase"] for item in checkpoint_receipts),
            f"{case_id}: checkpoint receipt history is malformed")
    require(len({item["phase"] for item in checkpoint_receipts}) == len(checkpoint_receipts),
            f"{case_id}: checkpoint receipt phases are duplicated")
    require(any(item.get("phase") == "preflight" and item.get("reference") == preflight.get("reference")
                and item.get("digest") == preflight.get("digest") for item in checkpoint_receipts),
            f"{case_id}: host preflight evidence is not in the operation checkpoint")
    verify_platform_evidence(evidence, os_family, preflight)
    verify_baseline_packages(evidence, preflight)
    node_after = evidence.get("nodeAfter")

    if outcome == "Succeeded":
        require(operation.get("phase") == "Succeeded" and checkpoint.get("phase") == "Succeeded",
                f"{case_id}: operation/checkpoint did not succeed")
        require(checkpoint.get("planDigest") == evidence["planDigest"] and checkpoint.get("nodeUid") == node["uid"],
                f"{case_id}: successful checkpoint identity mismatch")
        require(isinstance(node_after, dict) and node_after.get("uid") == node["uid"]
                and node_after.get("ready") is True
                and node_after.get("unschedulable") is False,
                f"{case_id}: original node was not verified Ready and schedulable after success")
        plan = evidence.get("upgradePlan")
        require(isinstance(plan, dict) and type(plan.get("actionMarkerVersion")) is int
                and plan.get("actionMarkerVersion") == 1,
                f"{case_id}: signed upgrade plan does not require action marker version 1")
        receipts = {item.get("phase"): item for item in checkpoint_receipts if isinstance(item, dict)}
        apply = receipts.get("apply")
        expected_packages = {item.get("name"): item.get("version") for item in plan.get("packages", [])
                             if isinstance(item, dict)}
        require(isinstance(apply, dict) and expected_packages and apply.get("packages") == expected_packages,
                f"{case_id}: apply receipt does not prove exact package pins")
        require(apply.get("machineId") == preflight["machineId"]
                and apply.get("bootIdBefore") == preflight.get("bootIdAfter")
                and apply.get("bootIdBefore") == apply.get("bootIdAfter"),
                f"{case_id}: apply receipt changed machine or boot identity unexpectedly")
        verify_action_marker(apply.get("actionMarker"), evidence, apply["machineId"],
                             apply["bootIdAfter"], "packages-verified", 2, case_id)
        reboot = receipts.get("reboot")
        reboot_required = apply.get("rebootRequired", False)
        reboot_policy = plan.get("reboot")
        require(type(reboot_required) is bool, f"{case_id}: apply reboot requirement is not a boolean")
        require(reboot_policy in {"Never", "IfNeeded", "Required"},
                f"{case_id}: signed plan has an unsupported reboot policy")
        require(reboot_policy != "Never" or (not reboot_required and reboot is None),
                f"{case_id}: Never reboot policy has a reboot or outstanding reboot requirement")
        policy_requires_reboot = reboot_policy == "Required"
        if reboot_required or policy_requires_reboot:
            require(isinstance(reboot, dict) and reboot.get("rebooted") is True,
                    f"{case_id}: required reboot receipt is absent or unverified")
        if reboot is not None:
            require(reboot_required or policy_requires_reboot,
                    f"{case_id}: reboot receipt contradicts the apply and signed reboot policy")
            require(isinstance(reboot, dict) and reboot.get("rebooted") is True
                    and reboot.get("rebootRequired") is True
                    and reboot.get("bootIdBefore") != reboot.get("bootIdAfter")
                    and reboot.get("machineId") == preflight["machineId"]
                    and reboot.get("bootIdBefore") == apply.get("bootIdAfter"),
                    f"{case_id}: required reboot receipt is absent or has unchanged boot identity")
            require(reboot.get("packages") == expected_packages,
                    f"{case_id}: reboot receipt does not prove exact package pins")
            verify_action_marker(reboot.get("actionMarker"), evidence, reboot["machineId"],
                                 reboot["bootIdAfter"], "reboot-verified", 4, case_id)
        expected_kernel = plan.get("expectedKernelVersion")
        if expected_kernel:
            final_receipt = reboot or apply
            require(final_receipt.get("kernelVersion") == expected_kernel,
                    f"{case_id}: final running kernel differs from the exact signed plan")
    elif outcome == "CancellationRecovered":
        require(operation.get("phase") == "Cancelled" and checkpoint.get("phase") == "Cancelled",
                f"{case_id}: cancellation terminal states disagree")
        require(isinstance(node_after, dict) and node_after.get("uid") == node["uid"]
                and node_after.get("ready") is True
                and node_after.get("unschedulable") is False,
                f"{case_id}: cancelled node was not verified Ready and uncordoned")
    elif outcome in {"CancellationFenced", "RecoveryRequired"}:
        require(operation.get("phase") == "RecoveryRequired" and checkpoint.get("phase") == "RecoveryRequired",
                f"{case_id}: operation is not explicitly RecoveryRequired")
        require(isinstance(node_after, dict), f"{case_id}: post-failure node observation missing")
        if case.get("recoveryNodeExpectation") == "replacement-untouched":
            require(node_after.get("uid") != node["uid"] and node_after.get("unschedulable") is False,
                    f"{case_id}: replacement node was altered or original node was not replaced")
        else:
            require(node_after.get("uid") == node["uid"] and node_after.get("unschedulable") is True,
                    f"{case_id}: original node is not still fenced")
        reservation = evidence.get("reservationEvidence")
        require(isinstance(reservation, dict) and reservation.get("held") is True
                and isinstance(reservation.get("reference"), str) and reservation["reference"],
                f"{case_id}: no evidence that the maintenance reservation remains held")
    elif outcome == "Failed":
        require(operation.get("phase") == "Failed", f"{case_id}: operation did not report Failed")
        require(evidence.get("mutationStarted") is False,
                f"{case_id}: Failed is acceptable only when host mutation never started")

    if outcome in {"Succeeded", "CancellationRecovered"}:
        verify_recovery_release(evidence)
    if outcome in {"CancellationRecovered", "CancellationFenced"}:
        verify_cancellation_request(evidence)

    if case["execution"] == "manual-injection":
        injection = evidence.get("injection")
        require(isinstance(injection, dict), f"{case_id}: fault injection record missing")
        require(isinstance(injection.get("method"), str) and injection["method"],
                f"{case_id}: injection method missing")
        injected_at = timestamp(injection.get("startedAt"), "injection.startedAt")
        restored_at = timestamp(injection.get("endedAt"), "injection.endedAt")
        require(start <= injected_at <= restored_at <= finish, f"{case_id}: injection times are outside the drill interval")
        require(isinstance(injection.get("evidenceRef"), str) and injection["evidenceRef"],
                f"{case_id}: external fault-injection evidence reference missing")
        if "faultEvidence" in case:
            verify_fault_observations(case["faultEvidence"], injection, evidence, case_id)
        require(evidence_dir is not None, f"{case_id}: evidence directory is unavailable")
        verify_injection_artifact(injection, evidence_dir, case_id)


def verify_directory(matrix_path: Path, evidence_dir: Path) -> list[str]:
    matrix = load_json_object(matrix_path, "failure matrix")
    require(matrix.get("schemaVersion") == 1, "unsupported failure-matrix schema")
    cases = matrix.get("cases")
    require(isinstance(cases, list) and cases and all(isinstance(case, dict) for case in cases),
            "failure matrix has no valid cases")
    families = matrix.get("osFamilies", ["debian"])
    require(isinstance(families, list) and families and all(item in {"debian", "rhel"} for item in families),
            "failure matrix has invalid OS families")
    require(len(set(families)) == len(families), "failure matrix repeats an OS family")
    completed: list[str] = []
    seen_case_ids: set[str] = set()
    for case in cases:
        case_id = case.get("id", "")
        require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", case_id) is not None, "invalid case ID in failure matrix")
        require(case_id not in seen_case_ids, f"duplicate case ID in failure matrix: {case_id}")
        seen_case_ids.add(case_id)
        require(case.get("execution") in {"runner", "manual-injection"},
                f"{case_id}: unsupported execution mode")
        outcomes = case.get("allowedOutcomes")
        require(isinstance(outcomes, list) and outcomes and all(isinstance(value, str) for value in outcomes),
                f"{case_id}: allowed outcomes are missing or invalid")
        require(len(set(outcomes)) == len(outcomes), f"{case_id}: duplicate allowed outcome")
    for case in cases:
        case_id = case["id"]
        for family in families:
            evidence_name = f"{case_id}-{family}.json" if "osFamilies" in matrix else f"{case_id}.json"
            path = evidence_dir / evidence_name
            require(path.is_file() and not path.is_symlink(), f"missing evidence file: {path.name}")
            evidence = load_json_object(path, path.name)
            verify_case(case, evidence, family, evidence_dir)
            completed.append(f"{case_id}-{family}" if "osFamilies" in matrix else case_id)
    return completed


def default_matrix_path(script_path: Path) -> Path:
    script_dir = script_path.resolve().parent
    candidates = (
        script_dir.parent / "tests/integration/host_upgrade_failure_matrix.json",
        script_dir / "host_upgrade_failure_matrix.json",
    )
    return next((path for path in candidates if path.is_file()), candidates[0])


def verify_pinned_matrix(path: Path) -> None:
    require(path.is_file() and not path.is_symlink(), "pinned failure matrix is missing or is a symlink")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    require(actual == FAILURE_MATRIX_SHA256,
            "failure matrix digest differs from the reviewed qualification case set")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_directory", type=Path)
    args = parser.parse_args()
    try:
        matrix_path = default_matrix_path(Path(__file__))
        verify_pinned_matrix(matrix_path)
        cases = verify_directory(matrix_path, args.evidence_directory)
    except (EvidenceError, OSError, KeyError, TypeError) as error:
        print(f"qualification evidence rejected: {error}", file=sys.stderr)
        return 1
    print(f"qualification evidence complete: {len(cases)} cases: {', '.join(cases)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
