#!/usr/bin/env python3
"""Guarded helpers for disposable self-managed host-upgrade qualification.

This command never provisions or destroys anything without displaying a fresh
Terraform plan and requiring an exact interactive project-bound confirmation.
It never tears down infrastructure automatically after a failed drill.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Callable

import self_managed_lab_recovery as recovery
import m3_terraform_context as terraform_context
import m3_gcloud_context as gcloud_context
import m3_lab_lifecycle as lifecycle
import m3_artifact_preflight as artifact_preflight
import m3_readiness_binding as readiness_binding


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infrastructure/terraform/gcp/self-managed-lab"
RUNNER = ROOT / "tests/integration/self_managed_upgrade_smoke.py"
VERIFIER = ROOT / "scripts/verify-host-upgrade-qualification.py"
PRODUCT_PROJECT = "kordex-fleet-platform"
RHEL_PAYG_LICENSES = (
    "https://www.googleapis.com/compute/v1/projects/rhel-cloud/global/licenses/rhel-9-server",
    "https://www.googleapis.com/compute/v1/projects/rhel-cloud/global/licenses/rhel-9-server-eus",
)
CASES = (
    "clean-upgrade",
    "cancel-before-apply",
    "cancel-during-executing",
    "cancel-during-reboot",
    "cancel-during-recovery",
    "operator-restart-during-executing",
    "ssh-loss-during-apply",
    "partial-package-application",
    "reboot-never-returns",
    "ssh-loss-after-reboot-request",
    "wrong-machine-id",
    "node-replaced-during-recovery",
    "wrong-kernel-after-reboot",
)
PHASES = ("Draining", "Executing", "Rebooting", "VerifyingWorkloads")
CANCELLATION_CASE_PHASES = {
    "cancel-before-apply": "Draining",
    "cancel-during-executing": "Executing",
    "cancel-during-reboot": "Rebooting",
    "cancel-during-recovery": "VerifyingWorkloads",
}
LOG_REDACTIONS = (
    (re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+"), r"\1<redacted>"),
    (re.compile(r"(?im)((?:[\"']?\b(?:password|passwd|token|secret|api[_-]?key|client[_-]?secret|private[_-]?key)\b[\"']?)\s*[:=]\s*[\"']?)([^\"'\s,;}\]]+)"), r"\1<redacted>"),
    (re.compile(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"), "<redacted-private-key>"),
)
FORBIDDEN_ARCHIVE_NAMES = (".tfstate", ".tfvars", ".tfplan", "kubeconfig", "known_hosts", "enrollment-token", "identity-secret")


class LabError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_private_json(path: Path, *, limit: int = 256 * 1024) -> tuple[dict, bytes]:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size <= 0
                    or info.st_size > limit):
                raise LabError("lifecycle identity evidence must be a bounded private regular file")
            raw = source.read(limit + 1)
        value = json.loads(raw)
    except LabError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LabError("lifecycle identity evidence is missing, unsafe, or invalid JSON") from error
    if not isinstance(value, dict):
        raise LabError("lifecycle identity evidence must be one JSON object")
    return value, raw


def secure_plan_sha256(path: Path) -> str:
    """Hash a private saved plan from a stable no-follow file descriptor."""
    if path.is_symlink():
        raise LabError("saved Terraform plan was replaced by a symlink")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise LabError("saved Terraform plan is unavailable") from error
    if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise LabError("saved Terraform plan is unsafe or changed while being verified")
    return digest.hexdigest()


def _bound_operation_context(principal: str) -> tuple[dict, str]:
    try:
        context = terraform_context.describe(principal, module=MODULE)
        source = readiness_binding.source_fingerprint(MODULE, run_command)
    except (terraform_context.ContextError, readiness_binding.BindingError, LabError) as error:
        raise LabError("Terraform operation context or source could not be bound") from error
    return context, source


def _require_operation_context(expected_context: dict, expected_source: str, principal: str) -> None:
    current_context, current_source = _bound_operation_context(principal)
    if current_context != expected_context or current_source != expected_source:
        raise LabError("Terraform operation context or source changed after plan review")


def terraform_principal_from_tfvars(raw: str) -> str:
    rows = re.findall(r"(?m)^\s*terraform_principal_email\s*=\s*\"([^\"\r\n]+)\"\s*(?:#.*)?$", raw)
    if len(rows) != 1 or not terraform_context.PRINCIPAL.fullmatch(rows[0]):
        raise LabError("terraform.tfvars must identify exactly one approved provider impersonation target")
    return rows[0]


def verify_live_image_identity(values: dict, approval: dict, *, run: Callable | None = None) -> None:
    """Re-resolve the exact approved Compute image immediately before plan/apply."""
    run = run or run_command
    profile = values["qualification_os_profile"]
    link = (values.get("debian_image_self_link") if profile == "debian-13"
            else values.get("rhel_image_self_link") if profile == "rhel-9" else "")
    if profile not in {"debian-13", "rhel-9"} or not isinstance(link, str):
        raise LabError("supplemental or unsupported image cannot enter canonical qualification")
    match = re.fullmatch(r"https://www\.googleapis\.com/compute/v1/projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/global/images/([a-z][a-z0-9-]{0,62})", link)
    if not match:
        raise LabError("approved image self-link is malformed")
    project, name = match.groups()
    principal = values["terraform_principal_email"]
    command, cloud_env, _cloud_context = gcloud_context.command(
        ["compute", "images", "describe", name, f"--project={project}",
         f"--impersonate-service-account={principal}", "--format=json(name,selfLink,id,architecture,licenses)"])
    try:
        output = run(command, cwd=ROOT, capture=True, timeout=30,
                     env=cloud_env)
        observed = json.loads(output)
    except (LabError, OSError, json.JSONDecodeError, TypeError) as error:
        raise LabError("approved Compute image could not be independently re-resolved") from error
    if (not isinstance(observed, dict) or observed.get("name") != name or observed.get("selfLink") != link
            or str(observed.get("id")) != str(approval.get("imageUniqueId"))
            or str(observed.get("id")) != str(values.get("qualification_image_unique_id"))
            or str(observed.get("architecture", "")).upper() not in {"X86_64", "AMD64"}
            or approval.get("projectId") != values.get("project_id")):
        raise LabError("approved Compute image identity or architecture changed after review")
    if profile == "rhel-9":
        licenses = observed.get("licenses")
        if (not isinstance(licenses, list) or any(not isinstance(item, str) for item in licenses)
                or not set(RHEL_PAYG_LICENSES).issubset(set(licenses))):
            raise LabError("approved RHEL image does not carry the expected Compute Engine PAYG/EUS licenses")


def verify_created_boot_disk_images(project_id: str, zone: str, lab_id: str, principal: str,
                                   image_self_link: str, image_unique_id: str, *,
                                   require_rhel_payg: bool = False,
                                   run: Callable | None = None) -> dict:
    """Verify all live lab boot disks came from the exact approved image.

    GCE creates a boot disk from an image name/self-link, not an immutable image
    ID. This post-creation check compares the disk's server-reported
    ``sourceImage`` and ``sourceImageId`` before qualification is allowed.
    It detects substitution; it does not eliminate the create-time race.
    """
    run = run or run_command
    validate_project_id(project_id)
    if (lab_id != recovery.LAB_ID
            or not re.fullmatch(r"[a-z]+-[a-z0-9]+-[a-z]", zone)
            or not terraform_context.PRINCIPAL.fullmatch(principal)
            or not re.fullmatch(r"[1-9][0-9]{0,19}", image_unique_id)):
        raise LabError("boot-disk verification context is malformed")
    image_match = re.fullmatch(
        r"https://www\.googleapis\.com/compute/v1/projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/global/images/([a-z][a-z0-9-]{0,62})",
        image_self_link if isinstance(image_self_link, str) else "",
    )
    if not image_match:
        raise LabError("approved boot image self-link is malformed")
    image_project, image_name = image_match.groups()
    roles = ((f"{lab_id}-server", "server"), (f"{lab_id}-worker", "worker-1"),
             (f"{lab_id}-worker-2", "worker-2"))

    def read_cloud_json(arguments: list[str], subject: str) -> dict:
        try:
            command, env, _context = gcloud_context.command(arguments)
            output = run(command, cwd=ROOT, capture=True, timeout=30, env=env)
            result = json.loads(output)
        except (LabError, OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError,
                gcloud_context.GCloudContextError) as error:
            raise LabError(f"live {subject} identity could not be verified; qualification is blocked") from error
        if not isinstance(result, dict):
            raise LabError(f"live {subject} identity response is malformed; qualification is blocked")
        return result

    verified_instances = []
    for instance_name, role in roles:
        instance = read_cloud_json(
            ["compute", "instances", "describe", instance_name, f"--project={project_id}",
             f"--zone={zone}", f"--impersonate-service-account={principal}",
             "--format=json(name,id,zone,status,labels,disks(boot,source))"],
            f"instance {instance_name}",
        )
        labels = instance.get("labels")
        zone_ref = instance.get("zone")
        if isinstance(zone_ref, str) and zone_ref.startswith("https://www.googleapis.com/compute/v1/"):
            zone_ref = zone_ref.removeprefix("https://www.googleapis.com/compute/v1/")
        if (instance.get("name") != instance_name or instance.get("status") != "RUNNING"
                or not isinstance(instance.get("id"), (str, int))
                or not re.fullmatch(r"[1-9][0-9]{0,19}", str(instance.get("id")))
                or zone_ref != f"projects/{project_id}/zones/{zone}"
                or not isinstance(labels, dict)
                or labels.get("application") != "kordex"
                or labels.get("purpose") != "disposable-qualification"
                or labels.get("managed-by") != "terraform"
                or labels.get("lab-id") != lab_id or labels.get("node-role") != role):
            raise LabError(f"live instance {instance_name} does not match the approved disposable lab identity")
        disks = instance.get("disks")
        boot = [disk for disk in disks if isinstance(disk, dict) and disk.get("boot") is True] if isinstance(disks, list) else []
        if len(boot) != 1 or not isinstance(boot[0].get("source"), str):
            raise LabError(f"live instance {instance_name} does not have exactly one verifiable boot disk")
        disk_match = re.fullmatch(
            rf"https://www\.googleapis\.com/compute/v1/projects/{re.escape(project_id)}/zones/{re.escape(zone)}/disks/([a-z][a-z0-9-]{{0,62}})",
            boot[0]["source"],
        )
        if not disk_match:
            raise LabError(f"live instance {instance_name} boot disk belongs to an unexpected project or zone")
        disk_name = disk_match.group(1)
        disk = read_cloud_json(
            ["compute", "disks", "describe", disk_name, f"--project={project_id}",
             f"--zone={zone}", f"--impersonate-service-account={principal}",
             "--format=json(name,id,selfLink,sourceImage,sourceImageId,licenses)"],
            f"boot disk {disk_name}",
        )
        expected_image_path = f"projects/{image_project}/global/images/{image_name}"
        source_image = disk.get("sourceImage")
        if isinstance(source_image, str) and source_image.startswith("https://www.googleapis.com/compute/v1/"):
            source_image = source_image.removeprefix("https://www.googleapis.com/compute/v1/")
        if (disk.get("name") != disk_name or not re.fullmatch(r"[1-9][0-9]{0,19}", str(disk.get("id", "")))
                or source_image != expected_image_path
                or str(disk.get("sourceImageId", "")) != image_unique_id
                or disk.get("selfLink") != boot[0]["source"]):
            raise LabError(f"live boot disk {disk_name} does not identify the approved image and image ID")
        disk_licenses = disk.get("licenses", [])
        if require_rhel_payg and (
            not isinstance(disk_licenses, list)
            or any(not isinstance(item, str) for item in disk_licenses)
            or not set(RHEL_PAYG_LICENSES).issubset(set(disk_licenses))
        ):
            raise LabError(f"live boot disk {disk_name} does not carry the approved RHEL PAYG/EUS licenses")
        verified_instances.append({
            "name": instance_name, "role": role, "instanceId": str(instance["id"]),
            "bootDiskName": disk_name, "bootDiskId": str(disk["id"]),
            "bootDiskSelfLink": disk.get("selfLink", ""),
            "sourceImage": image_self_link, "sourceImageId": image_unique_id,
            "licenses": disk_licenses,
        })

    return {
        "schemaVersion": 1,
        "method": "gcloud-compute-instance-and-disk-source-image",
        "verifiedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "projectId": project_id, "zone": zone, "labId": lab_id,
        "imageSelfLink": image_self_link, "imageUniqueId": image_unique_id,
        "instances": verified_instances,
    }


def run_command(args: list[str], *, cwd: Path | None = None, capture: bool = False,
                timeout: int | None = None, env: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        output = getattr(error, "stdout", "") or ""
        reason = "timed out" if isinstance(error, subprocess.TimeoutExpired) else "failed"
        raise LabError(f"command {reason}: {args[0]} ({str(output)[-2000:]})") from error
    return result.stdout or ""


def validate_project_id(project_id: str) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id):
        raise LabError("project ID must be a valid 6–30 character GCP project ID")
    if project_id == PRODUCT_PROJECT:
        raise LabError(f"{PRODUCT_PROJECT} is permanently prohibited as a disposable lab project")


def private_tfvars_config(project_id: str) -> tuple[Path, str]:
    path = MODULE / "terraform.tfvars"
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError as error:
        raise LabError("create terraform.tfvars from the example and set the reviewed disposable project values") from error
    except OSError as error:
        raise LabError("terraform.tfvars must be a regular file with no group/other permissions") from error
    with os.fdopen(descriptor, "r") as tfvars:
        info = os.fstat(tfvars.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise LabError("terraform.tfvars must be a regular file with no group/other permissions")
        raw = tfvars.read()

    def value(name: str) -> str:
        assignment = re.compile(rf"(?m)^\s*{re.escape(name)}\s*=")
        lines = [line for line in raw.splitlines() if assignment.match(line)]
        if len(lines) != 1:
            raise LabError(f"terraform.tfvars must set {name} exactly once")
        match = re.fullmatch(rf"\s*{re.escape(name)}\s*=\s*\"([^\"\r\n]+)\"\s*(?:#.*)?", lines[0])
        if not match:
            raise LabError(f"terraform.tfvars must set {name} as one quoted string")
        return match.group(1)

    configured_project = value("project_id")
    if configured_project != project_id:
        raise LabError("--project-id must exactly match project_id in terraform.tfvars")
    if value("project_id_confirmation") != project_id:
        raise LabError("project_id_confirmation in terraform.tfvars must exactly match the reviewed project")
    allowlist_assignments = re.findall(r"(?m)^\s*allowed_project_ids\s*=", raw)
    allowlist = re.search(r"(?ms)^\s*allowed_project_ids\s*=\s*\[(.*?)\]", raw)
    allowed_ids = re.findall(r'"([^"\n]+)"', allowlist.group(1)) if allowlist else []
    if len(allowlist_assignments) != 1 or allowed_ids != [project_id]:
        raise LabError("allowed_project_ids in terraform.tfvars must contain exactly the reviewed target project")
    return path, raw


def private_tfvars(project_id: str) -> Path:
    return private_tfvars_config(project_id)[0]


def terraform_artifact_values(raw: str) -> tuple[str, str]:
    def value(name: str) -> str:
        assignment = re.compile(rf"(?m)^\s*{re.escape(name)}\s*=")
        lines = [line for line in raw.splitlines() if assignment.match(line)]
        if len(lines) != 1:
            raise LabError(f"terraform.tfvars must set {name} exactly once")
        match = re.fullmatch(rf"\s*{re.escape(name)}\s*=\s*\"([^\"\r\n]+)\"\s*(?:#.*)?", lines[0])
        if not match:
            raise LabError(f"terraform.tfvars must set {name} as one quoted string")
        return match.group(1)

    digest = value("k3s_binary_sha256")
    mirror = value("k3s_binary_mirror_url")
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise LabError("terraform.tfvars k3s_binary_sha256 is malformed")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::443)?(?:/[A-Za-z0-9._~%+@:-]+)+", mirror):
        raise LabError("terraform.tfvars k3s_binary_mirror_url is malformed")
    return digest, mirror


def reject_auto_tfvars() -> None:
    for path in MODULE.iterdir():
        if path.name == "terraform.tfvars":
            continue
        if path.name == "terraform.tfvars.json" or path.name.endswith(".auto.tfvars") or path.name.endswith(".auto.tfvars.json"):
            raise LabError(f"unexpected automatic Terraform variable file is not allowed: {path.name}")


def sanitized_terraform_env(principal_email: str | None = None) -> dict[str, str]:
    """Return the strict Terraform environment allowlist; never inherit user CLI knobs."""
    executable = shutil.which("terraform")
    if not executable:
        raise LabError("Terraform executable is unavailable")
    principal = principal_email or os.environ.get("KORDEX_TERRAFORM_PRINCIPAL", "")
    try:
        if principal:
            env, _context = terraform_context.execution_environment(principal, module=MODULE, binary=executable)
        else:
            env = terraform_context.tool_environment(module=MODULE, binary=executable)
    except terraform_context.ContextError as error:
        raise LabError(str(error)) from error
    return env


def _read_bounded_json(path: Path, maximum: int = 2 * 1024 * 1024) -> tuple[dict, bytes]:
    if path.is_symlink():
        raise LabError("readiness and plan input files must not be symlinks")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or not raw or len(raw) > maximum or len(raw) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise LabError("readiness or plan input file is unsafe, oversized, or changed while reading")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise LabError("readiness or plan input file contains duplicate JSON keys")
                result[key] = value
            return result

        value = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise LabError("readiness or plan input file must be a JSON object")
        return value, raw
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LabError("readiness or plan input file is unavailable or malformed") from error


def verify_readiness_plan_binding(*, project_id: str, readiness_report: Path,
                                  terraform_inputs: Path, network_inputs: Path,
                                  artifact_inputs: Path, artifact_report: Path,
                                  principal_attestation: Path | None = None,
                                  image_approval_path: Path) -> tuple[dict, str]:
    """Revalidate every non-secret document used to authorize one Terraform plan."""
    readiness, readiness_raw = _read_bounded_json(readiness_report, 1024 * 1024)
    plan_values, _ = _read_bounded_json(terraform_inputs, 1024 * 1024)
    network, _ = _read_bounded_json(network_inputs, 1024 * 1024)
    artifact_config, _ = _read_bounded_json(artifact_inputs, 1024 * 1024)
    artifact_result, _ = _read_bounded_json(artifact_report, 1024 * 1024)
    _image_approval, _ = _read_bounded_json(image_approval_path, 64 * 1024)
    binding = readiness.get("planBinding")
    if principal_attestation is None:
        attestation_name = binding.get("terraformPrincipalAttestationFile") if isinstance(binding, dict) else None
        if not isinstance(attestation_name, str) or Path(attestation_name).name != attestation_name:
            raise LabError("readiness does not bind a safe Terraform provider identity attestation filename")
        principal_attestation = readiness_report.with_name(attestation_name)
    checks = readiness.get("checks")
    if (readiness.get("schemaVersion") != 2 or not isinstance(binding, dict)
            or not isinstance(checks, dict)
            or checks.get("planInputBinding", {}).get("result") != "PASS"
            or checks.get("artifactPreflight", {}).get("result") != "PASS"
            or checks.get("trackedTerraformProfile", {}).get("result") != "PASS"
            or checks.get("designatedProject", {}).get("result") != "PASS"
            or checks.get("actualTerraformInputs", {}).get("result") != "PROVIDED"
            or checks.get("customerNetworkInputs", {}).get("result") != "PROVIDED"
            or checks.get("selectedLabOSProfile", {}).get("result") != "PROVIDED"
            or readiness.get("overallStatus") not in {"PASS", "PROVIDED"}):
        raise LabError("M3 readiness report does not authorize a bound Terraform plan")
    try:
        readiness_binding.validate_readiness_results(readiness)
    except readiness_binding.BindingError as error:
        raise LabError("M3 readiness contains an unapproved or non-passing requirement state") from error
    try:
        readiness_binding.validate_readiness_approval(readiness_report, readiness, readiness_raw)
    except readiness_binding.BindingError as error:
        raise LabError("customer-signed readiness authorization is unavailable or invalid") from error
    for required_check in ("artifactTrustCustody", "imageOwnerApproval", "imageIdentityHumanReview",
                           "liveProjectLabelAndLifecycle", "requiredAPIsAndIAM", "billingBudget",
                           "privateRouteDNSFirewallAndPKI", "terraformExecutionContext",
                           "terraformAuthenticatedPrincipal"):
        if checks.get(required_check, {}).get("result") != "PASS":
            raise LabError(f"M3 readiness prerequisite is not independently verified: {required_check}")
    try:
        generated = dt.datetime.fromisoformat(str(readiness.get("generatedAt", "")).replace("Z", "+00:00"))
    except ValueError as error:
        raise LabError("M3 readiness report timestamp is invalid") from error
    now = dt.datetime.now(dt.timezone.utc)
    if (generated.tzinfo is None or generated > now + dt.timedelta(minutes=5)
            or now - generated > dt.timedelta(hours=4)):
        raise LabError("M3 readiness report is stale or has a future timestamp")
    if (artifact_result.get("schemaVersion") != 1 or artifact_result.get("overallStatus") != "PASS"
            or not isinstance(artifact_result.get("artifacts"), dict)
            or any(artifact_result["artifacts"].get(name, {}).get("status") != "PASS"
                   for name in artifact_preflight.REQUIRED_ARTIFACTS)):
        raise LabError("current M3 artifact preflight is incomplete or not PASS")
    if project_id != recovery.PROJECT_ID or plan_values.get("project_id") != project_id:
        raise LabError("readiness-bound Terraform project does not match the explicit project ID")
    if readiness_binding.canonical_sha256(readiness_binding.canonical_network_inputs(network)) != binding.get("networkInputsSha256"):
        raise LabError("network inputs changed after readiness; regenerate readiness report")
    if readiness_binding.canonical_sha256(artifact_config) != binding.get("artifactInputsSha256"):
        raise LabError("artifact inputs changed after readiness; regenerate readiness report")
    if readiness_binding.canonical_sha256(artifact_result) != binding.get("artifactReportSha256"):
        raise LabError("artifact preflight report changed after readiness; regenerate readiness report")
    source_hash = readiness_binding.source_fingerprint(MODULE, run_command)
    if source_hash != binding.get("terraformSourceSha256"):
        raise LabError("Terraform source changed after readiness; regenerate readiness report")
    normalized, effective_hash = readiness_binding.validate_plan_inputs(
        terraform_inputs, reader=artifact_preflight.read_json,
        terraform_source=(MODULE / "variables.tf").read_text(encoding="utf-8"),
        network=network, artifact_report=artifact_result,
        expected_project=recovery.PROJECT_ID, expected_region="us-east1", expected_zone="us-east1-b",
        expected_lab_id=recovery.LAB_ID)
    if effective_hash != binding.get("terraformInputsSha256"):
        raise LabError("effective Terraform inputs changed after readiness; regenerate readiness report")
    try:
        execution_context = terraform_context.describe(normalized["terraform_principal_email"], module=MODULE)
    except terraform_context.ContextError as error:
        raise LabError("Terraform execution context is unavailable or changed") from error
    if (binding.get("executionContext") != execution_context
            or binding.get("executionContextSha256") != terraform_context.canonical_sha256(execution_context)):
        raise LabError("Terraform execution context changed after readiness; regenerate and review the report")
    try:
        _principal_attestation, principal_attestation_digest = terraform_context.verify_provider_identity_attestation(
            principal_attestation, project_id=project_id,
            target_principal=normalized["terraform_principal_email"], context=execution_context)
    except terraform_context.ContextError as error:
        raise LabError("independent Terraform provider principal attestation is unavailable or invalid") from error
    if (binding.get("terraformPrincipalAttestationSha256") != principal_attestation_digest
            or binding.get("terraformPrincipalAttestationFile") != principal_attestation.name):
        raise LabError("Terraform provider principal attestation changed after readiness")
    expected_bound_values = {
        "schemaVersion": 1,
        "k3sVersion": normalized["k3s_version"],
        "k3sBinarySha256": normalized["k3s_binary_sha256"],
        "k3sSystemImagesBundleSha256": normalized["k3s_system_images_bundle_sha256"],
        "packagePolicySha256": artifact_result["artifacts"]["hostPackageArtifacts"]["policySha256"],
        "imageApprovalRequiresIndependentReview": True,
    }
    if any(binding.get(key) != value for key, value in expected_bound_values.items()):
        raise LabError("readiness report is missing or mismatches a required artifact or policy binding")
    _approval, approval_hash = readiness_binding.validate_image_approval(
        image_approval_path, terraform_values=normalized,
        artifact_report=artifact_result)
    if normalized.get("qualification_image_approval_sha256") != approval_hash:
        raise LabError("Terraform image-approval digest does not match its input record")
    if approval_hash != binding.get("imageApprovalSha256"):
        raise LabError("image owner approval changed after readiness; regenerate readiness report")
    selected_image = (normalized.get("debian_image_self_link") if normalized["qualification_os_profile"] == "debian-13"
                      else normalized.get("rhel_image_self_link") if normalized["qualification_os_profile"] == "rhel-9"
                      else "supplemental-image-family")
    if (binding.get("profile") != normalized["qualification_os_profile"]
            or binding.get("imageSelfLink") != selected_image
            or binding.get("imageUniqueId") != (normalized.get("qualification_image_unique_id") or "supplemental-image-family")
            or binding.get("imageApprovalReference") != normalized["qualification_image_approval_reference"]):
        raise LabError("selected image or image-owner approval reference differs from readiness")
    return normalized, effective_hash


def secure_plan_var_file(values: dict) -> Path:
    old_umask = os.umask(0o077)
    try:
        fd, name = tempfile.mkstemp(prefix=".kordex-readiness-inputs-", suffix=".tfvars.json", dir=MODULE)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(values, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        return Path(name)
    finally:
        os.umask(old_umask)


def offline_go_env() -> dict[str, str]:
    env = sanitized_terraform_env()
    env.update(GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local")
    return env


def artifact_approval_fingerprints(lock_path: Path, signature_path: Path, trust_path: Path) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    for label, path, limit in (
        ("lock", lock_path, 16 << 10),
        ("signature", signature_path, 4096),
        ("trust", trust_path, 16 << 10),
    ):
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise LabError(f"customer artifact {label} input is unavailable or unsafe") from error
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > limit:
                raise LabError(f"customer artifact {label} input must be a bounded regular file")
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(64 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(source.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise LabError(f"customer artifact {label} input changed while being checked")
            fingerprints[label] = digest.hexdigest()
    return fingerprints


def verify_customer_artifact(binary_path: Path, lock_path: Path, signature_path: Path, trust_path: Path,
                             expected_digest: str, expected_mirror: str,
                             run: Callable = run_command) -> dict[str, str]:
    before = artifact_approval_fingerprints(lock_path, signature_path, trust_path)
    # Verify private snapshots rather than reopening caller-controlled paths.
    # This prevents a lock/trust file swap-and-restore race while the Go
    # verifier reads the files. The snapshots contain public approval data,
    # but are still private temporary files and are removed on every exit.
    with tempfile.TemporaryDirectory(prefix="kordex-artifact-approval-") as temporary:
        snapshot_dir = Path(temporary)
        os.chmod(snapshot_dir, 0o700)
        snapshot_paths: dict[str, Path] = {}
        for label, source_path, limit in (
            ("lock", lock_path, 16 << 10),
            ("signature", signature_path, 4096),
            ("trust", trust_path, 16 << 10),
        ):
            try:
                descriptor = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError as error:
                raise LabError(f"customer artifact {label} input is unavailable or unsafe") from error
            with os.fdopen(descriptor, "rb") as source:
                initial = os.fstat(source.fileno())
                if not stat.S_ISREG(initial.st_mode) or initial.st_size <= 0 or initial.st_size > limit:
                    raise LabError(f"customer artifact {label} input must be a bounded regular file")
                content = source.read(limit + 1)
                final = os.fstat(source.fileno())
                if len(content) != initial.st_size or len(content) > limit or (
                    initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns
                ) != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns):
                    raise LabError(f"customer artifact {label} input changed while being checked")
            if hashlib.sha256(content).hexdigest() != before[label]:
                raise LabError(f"customer artifact {label} input changed while being snapshotted")
            snapshot_path = snapshot_dir / label
            snapshot_fd = os.open(snapshot_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(snapshot_fd, "wb") as snapshot:
                snapshot.write(content)
                snapshot.flush()
                os.fsync(snapshot.fileno())
            snapshot_paths[label] = snapshot_path

        command = [
            "go", "run", "./cmd/kordex-artifact-lock", "verify",
            "--binary", os.path.abspath(binary_path),
            "--lock", str(snapshot_paths["lock"]),
            "--signature", str(snapshot_paths["signature"]),
            "--trust-bundle", str(snapshot_paths["trust"]),
            "--expected-digest", expected_digest,
            "--expected-mirror-url", expected_mirror,
        ]
        run(command, cwd=ROOT / "api", capture=True, timeout=600, env=offline_go_env())
    after = artifact_approval_fingerprints(lock_path, signature_path, trust_path)
    if before != after:
        raise LabError("customer artifact lock, signature, or trust bundle changed during verification")
    return before


def system_images_approval_fingerprints(bundle_path: Path, lock_path: Path, signature_path: Path,
                                       trust_path: Path) -> dict[str, str]:
    fingerprints: dict[str, str] = {}
    for label, path, limit in (
        ("bundle", bundle_path, 512 << 20),
        ("lock", lock_path, 64 << 10),
        ("signature", signature_path, 4096),
        ("trust", trust_path, 16 << 10),
    ):
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise LabError(f"customer system-image {label} input is unavailable or unsafe") from error
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > limit:
                raise LabError(f"customer system-image {label} input must be a bounded regular file")
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(source.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise LabError(f"customer system-image {label} input changed while being checked")
            fingerprints[label] = digest.hexdigest()
    return fingerprints


def verify_customer_system_images(bundle_path: Path, lock_path: Path, signature_path: Path,
                                  trust_path: Path, run: Callable = run_command) -> tuple[dict[str, str], dict[str, str]]:
    before = system_images_approval_fingerprints(bundle_path, lock_path, signature_path, trust_path)
    # Verify snapshots so a caller cannot swap an archive or lock while the Go
    # verifier is reading it. The archive is streamed, not loaded into memory.
    with tempfile.TemporaryDirectory(prefix="kordex-system-image-approval-") as temporary:
        snapshot_dir = Path(temporary)
        os.chmod(snapshot_dir, 0o700)
        paths: dict[str, Path] = {}
        for label, source_path, limit in (
            ("bundle", bundle_path, 512 << 20), ("lock", lock_path, 64 << 10),
            ("signature", signature_path, 4096), ("trust", trust_path, 16 << 10),
        ):
            try:
                descriptor = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError as error:
                raise LabError(f"customer system-image {label} input is unavailable or unsafe") from error
            snapshot = snapshot_dir / label
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb") as source:
                initial = os.fstat(source.fileno())
                if not stat.S_ISREG(initial.st_mode) or initial.st_size <= 0 or initial.st_size > limit:
                    raise LabError(f"customer system-image {label} input must be a bounded regular file")
                snapshot_fd = os.open(snapshot, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(snapshot_fd, "wb") as destination:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                        destination.write(chunk)
                    destination.flush()
                    os.fsync(destination.fileno())
                final = os.fstat(source.fileno())
                if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (
                    final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns
                ) or digest.hexdigest() != before[label]:
                    raise LabError(f"customer system-image {label} input changed while being snapshotted")
            paths[label] = snapshot
        output = run([
            "go", "run", "./cmd/kordex-artifact-lock", "system-images", "verify",
            "--bundle", str(paths["bundle"]), "--lock", str(paths["lock"]),
            "--signature", str(paths["signature"]), "--trust-bundle", str(paths["trust"]), "--json",
        ], cwd=ROOT / "api", capture=True, timeout=900, env=offline_go_env())
    try:
        verified = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise LabError("customer system-image verifier returned invalid structured output") from error
    required = {"manifestVersion", "k3sVersion", "architecture", "bundleSha256", "bundleMirrorReference", "mirrorHost", "signerKeyId", "approvedAt", "images"}
    if not isinstance(verified, dict) or set(verified) != required:
        raise LabError("customer system-image verifier returned an incomplete result")
    if verified["manifestVersion"] != "1" or verified["k3sVersion"] != "v1.36.6+k3s1" or verified["architecture"] != "linux/amd64":
        raise LabError("verified K3s system-image manifest version, K3s version, or architecture is unsupported")
    if not re.fullmatch(r"[a-f0-9]{64}", str(verified["bundleSha256"])):
        raise LabError("verified K3s system-image bundle digest is malformed")
    if not isinstance(verified["bundleMirrorReference"], str) or not re.fullmatch(
        r"https://[A-Za-z0-9.-]+(?::443)?(?:/[A-Za-z0-9._~%+@:-]+)+", verified["bundleMirrorReference"]
    ):
        raise LabError("verified K3s system-image bundle URL is not an approved path-only HTTPS URL")
    bundle_suffixes = (
        f"/k3s/{verified['k3sVersion']}/linux-amd64/{verified['bundleSha256']}/k3s-airgap-images-amd64.tar",
        f"/k3s/v1.36.6%2Bk3s1/linux-amd64/{verified['bundleSha256']}/k3s-airgap-images-amd64.tar",
    )
    if not any(verified["bundleMirrorReference"].endswith(suffix) for suffix in bundle_suffixes):
        raise LabError("verified K3s system-image bundle URL is not bound to its content-addressed stage path")
    if not isinstance(verified["mirrorHost"], str) or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::443)?", verified["mirrorHost"]
    ):
        raise LabError("verified K3s private image mirror host is malformed")
    if verified["mirrorHost"].lower().removesuffix(":443") in {
        "docker.io", "registry-1.docker.io", "ghcr.io", "quay.io",
    }:
        raise LabError("verified K3s image mirror host is a public registry")
    if not re.fullmatch(r"[a-f0-9]{64}", str(verified["signerKeyId"])):
        raise LabError("verified K3s system-image signer ID is malformed")
    if not isinstance(verified["approvedAt"], str) or not verified["approvedAt"].endswith("Z"):
        raise LabError("customer system-image approval time must be UTC")
    try:
        approved_at = dt.datetime.fromisoformat(verified["approvedAt"].replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise LabError("customer system-image approval time is malformed") from error
    if approved_at.utcoffset() != dt.timedelta(0):
        raise LabError("customer system-image approval time must be UTC")
    images = verified["images"]
    if not isinstance(images, list) or len(images) != 8:
        raise LabError("verified K3s system-image lock did not return the exact eight-image inventory")
    seen_sources: set[str] = set()
    for image in images:
        if not isinstance(image, dict) or set(image) != {"SourceReference", "MirrorReference", "Digest"}:
            raise LabError("verified K3s system-image inventory is malformed")
        source, reference, digest_value = image["SourceReference"], image["MirrorReference"], image["Digest"]
        if (not isinstance(source, str) or source in seen_sources
                or not isinstance(reference, str) or not reference.startswith(verified["mirrorHost"].rstrip("/") + "/")
                or not isinstance(digest_value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest_value)):
            raise LabError("verified K3s image mapping is duplicate, malformed, or outside the signed private mirror")
        seen_sources.add(source)
    after = system_images_approval_fingerprints(bundle_path, lock_path, signature_path, trust_path)
    if before != after:
        raise LabError("customer system-image bundle, lock, signature, or trust changed during verification")
    return verified, before


def require_system_images_approval_unchanged(bundle_path: Path, lock_path: Path, signature_path: Path,
                                             trust_path: Path, fingerprints: dict[str, str]) -> None:
    if system_images_approval_fingerprints(bundle_path, lock_path, signature_path, trust_path) != fingerprints:
        raise LabError("customer system-image approval inputs changed after preflight; rerun verification")


def require_approval_unchanged(lock_path: Path, signature_path: Path, trust_path: Path,
                               verified: dict[str, str]) -> None:
    if artifact_approval_fingerprints(lock_path, signature_path, trust_path) != verified:
        raise LabError("customer artifact approval inputs changed after preflight; rerun verification")


def terraform_init(run: Callable = run_command, *, principal_email: str | None = None) -> None:
    run(["terraform", "init", "-backend=false", "-input=false", "-lockfile=readonly"],
        cwd=MODULE, env=sanitized_terraform_env(principal_email))


def terraform_source_files(run: Callable = run_command) -> list[str]:
    """Return checkout Terraform sources without asking Terraform to recurse.

    In particular, ignored local terraform.tfvars is not a source file and must
    never be passed to `terraform fmt`. Include tracked and ordinary untracked
    .tf files so newly added source cannot be silently skipped.
    """
    try:
        module_relative = MODULE.relative_to(ROOT)
    except ValueError as error:
        raise LabError("Terraform module must be inside the repository checkout") from error
    output = run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--",
         module_relative.as_posix()],
        cwd=ROOT,
        capture=True,
    )
    sources: list[str] = []
    for entry in output.splitlines():
        try:
            relative = Path(entry).relative_to(module_relative)
        except ValueError:
            continue
        if relative.suffix == ".tf":
            sources.append(relative.as_posix())
    sources = sorted(set(sources))
    if not sources:
        raise LabError(f"no tracked or non-ignored Terraform source files found under {module_relative}")
    return sources


def terraform_validate(run: Callable = run_command) -> None:
    sources = terraform_source_files(run)
    try:
        run(["terraform", "fmt", "-check", *sources], cwd=MODULE, env=sanitized_terraform_env())
    except LabError as error:
        raise LabError(f"Terraform source formatting check failed: {error}") from error
    terraform_init(run)
    run(["terraform", "validate"], cwd=MODULE, env=sanitized_terraform_env())


def run_m3_artifact_preflight(inputs: Path, report: Path, *, run: Callable = run_command) -> str:
    if inputs.is_symlink() or report.is_symlink() or inputs.resolve() == report.resolve():
        raise LabError("M3 artifact input and report paths must be regular, distinct paths")
    output = run(["python3", str(ROOT / "scripts/m3_artifact_preflight.py"), "--inputs", str(inputs), "--report", str(report)],
                 cwd=ROOT, capture=True, timeout=1800)
    match = re.search(r"(?:^|\n)M3 artifact preflight: PASS; report-sha256=([a-f0-9]{64})\s*$", output)
    if match is None:
        raise LabError("M3 artifact preflight did not report a verified PASS report digest")
    expected_report_hash = match.group(1)
    try:
        descriptor = os.open(report, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 1024 * 1024:
                raise LabError("M3 artifact preflight report is not a bounded regular file")
            raw = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
            if len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise LabError("M3 artifact preflight report changed while being read")
        if hashlib.sha256(raw).hexdigest() != expected_report_hash:
            raise LabError("M3 artifact preflight report digest does not match verifier output")
        result = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise LabError("M3 artifact preflight did not produce a valid report") from error
    if not isinstance(result, dict) or result.get("schemaVersion") != 1 or result.get("overallStatus") != "PASS":
        raise LabError("M3 artifact preflight is not PASS; guarded lab operation was not started")
    artifacts = result.get("artifacts")
    required = {"maintenancePublicTrust", "artifactApprovalTrust", "releasePublicTrust", "toolProvenancePublicTrust",
                "signedReleaseBundle", "signedImageDigestLock", "k3sBinaryApproval", "k3sSystemImageApproval",
                "privateRegistryImages", "hostPackageArtifacts", "helmSignerAllowlist", "requiredKordexImages"}
    if not isinstance(artifacts, dict) or set(artifacts) != required or any(
            not isinstance(artifacts[name], dict) or artifacts[name].get("status") != "PASS" for name in required):
        raise LabError("M3 artifact preflight report has incomplete or non-PASS artifact rows")
    package_row = artifacts["hostPackageArtifacts"]
    profile_bindings = {
        "m3-ubuntu-24.04-k3s-v1.36.6+k3s1-linux-amd64":
            ("debian", "ubuntu", "24", "04"),
        "m3-debian-13-k3s-v1.36.6+k3s1-linux-amd64":
            ("debian", "debian", "13", ""),
    }
    profile = result.get("profile")
    binding = profile_bindings.get(profile) if isinstance(profile, str) else None
    if (isinstance(package_row, dict) and package_row.get("osId") == "rhel"
            and package_row.get("osMajor") == "9" and str(package_row.get("osMinor", "")).isdigit()
            and int(package_row["osMinor"]) >= 8):
        binding = ("rhel", "rhel", "9", str(package_row["osMinor"]))
    if binding is None:
        raise LabError("artifact preflight does not select an implemented Ubuntu 24.04 supplemental, Debian 13, or RHEL 9.8+ lab profile")
    os_family, os_id, os_major, os_minor = binding
    if (package_row.get("profile") != profile or package_row.get("osFamily") != os_family
            or package_row.get("osId") != os_id or package_row.get("osMajor") != os_major
            or package_row.get("osMinor") != os_minor):
        raise LabError("artifact package OS identity does not match its exact approved profile")
    return hashlib.sha256(raw).hexdigest()


def qualification_os_profile(report_path: Path, expected_report_sha256: str) -> str:
    """Read the OS profile only from the exact report bytes accepted by preflight."""
    try:
        descriptor = os.open(report_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 1024 * 1024:
                raise LabError("M3 artifact preflight report is not a bounded regular file")
            raw = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
            if len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise LabError("M3 artifact preflight report changed while being read")
        if hashlib.sha256(raw).hexdigest() != expected_report_sha256:
            raise LabError("M3 artifact preflight report changed after verification")
        result = json.loads(raw)
        profile = result["artifacts"]["hostPackageArtifacts"]["profile"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise LabError("M3 artifact preflight report has no bound host profile") from error
    mapping = {
        "m3-ubuntu-24.04-k3s-v1.36.6+k3s1-linux-amd64": "ubuntu-24.04",
        "m3-debian-13-k3s-v1.36.6+k3s1-linux-amd64": "debian-13",
    }
    if isinstance(profile, str) and profile in mapping and result.get("profile") == profile:
        return mapping[profile]
    package = result.get("artifacts", {}).get("hostPackageArtifacts", {})
    if (isinstance(package, dict) and package.get("profile") == profile == result.get("profile")
            and package.get("osId") == "rhel" and package.get("osMajor") == "9"
            and str(package.get("osMinor", "")).isdigit() and int(package["osMinor"]) >= 8):
        return "rhel-9"
    raise LabError("M3 artifact profile is not available in the guarded lab")


def qualification_os_minor(report_path: Path, expected_report_sha256: str) -> str:
    """Return the exact RHEL minor bound by the verified artifact report."""
    try:
        descriptor = os.open(report_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            raw = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or len(raw) != info.st_size or info.st_size > 1024 * 1024
                or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or hashlib.sha256(raw).hexdigest() != expected_report_sha256):
            raise LabError("M3 artifact preflight report changed after verification")
        result = json.loads(raw)
        package = result["artifacts"]["hostPackageArtifacts"]
        if result.get("profile", "").startswith("m3-rhel-9."):
            minor = str(package["osMinor"])
            if package.get("osId") == "rhel" and package.get("osMajor") == "9" and minor.isdigit() and int(minor) >= 8:
                return minor
        if package.get("osId") == "rhel":
            raise LabError("RHEL artifact profile is below the supported minor release floor")
        return ""
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise LabError("M3 artifact preflight report has no bound OS minor release") from error


def qualification_os_point_release(report_path: Path, expected_report_sha256: str) -> str:
    """Return the exact Debian stable point or RHEL minor bound by package approval."""
    try:
        descriptor = os.open(report_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            raw = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or len(raw) != info.st_size or info.st_size > 1024 * 1024
                or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or hashlib.sha256(raw).hexdigest() != expected_report_sha256):
            raise LabError("M3 artifact preflight report changed after verification")
        result = json.loads(raw)
        package = result["artifacts"]["hostPackageArtifacts"]
        point = package["osPointRelease"]
        if package.get("osId") == "debian" and package.get("osMajor") == "13":
            if point != artifact_preflight.M3_DEBIAN_POINT_RELEASE:
                raise LabError("M3 artifact report does not bind approved Debian 13.8")
            return point
        if package.get("osId") == "rhel" and package.get("osMajor") == "9":
            if point != f"9.{package.get('osMinor')}":
                raise LabError("approved RHEL point release does not match the selected minor")
            return point
        if point:
            raise LabError("unexpected OS point release in the selected package profile")
        return ""
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise LabError("M3 artifact preflight report has no bound OS point release") from error


def qualification_platform_binding(report_path: Path, expected_report_sha256: str,
                                  *, run: Callable = run_command) -> dict:
    """Bind qualification evidence to artifact policy and the selected image in saved state."""
    try:
        descriptor = os.open(report_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            raw = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or len(raw) != info.st_size or info.st_size > 1024 * 1024
                or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or hashlib.sha256(raw).hexdigest() != expected_report_sha256):
            raise LabError("M3 artifact preflight report changed before platform evidence binding")
        report = json.loads(raw)
        package = report["artifacts"]["hostPackageArtifacts"]
        profile = qualification_os_profile(report_path, expected_report_sha256)
        minor = qualification_os_minor(report_path, expected_report_sha256)
        point_release = qualification_os_point_release(report_path, expected_report_sha256)
        expected_report_profile = report["profile"]
        identity = (package.get("osId"), package.get("osMajor"), package.get("osMinor"))
        if (package.get("profile") != expected_report_profile or
                package.get("architecture") != "linux/amd64" or
                not isinstance(package.get("policySha256"), str) or
                not re.fullmatch(r"[a-f0-9]{64}", package["policySha256"]) or
                not isinstance(package.get("packageArchiveSha256"), str) or
                not re.fullmatch(r"[a-f0-9]{64}", package["packageArchiveSha256"]) or
                not isinstance(package.get("repositorySnapshotID"), str) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", package["repositorySnapshotID"])):
            raise LabError("M3 artifact report lacks package-policy, architecture, or repository snapshot binding")
        state_values = {}
        for output_name in ("project_id", "lab_id", "zone", "terraform_principal_email",
                            "qualification_os_profile", "qualification_os_minor", "qualification_os_point_release",
                            "qualification_image_approval_reference", "qualification_image_approval_sha256",
                            "qualification_image_unique_id", "boot_image_id", "boot_image_unique_id",
                            "boot_image_project", "boot_image_family", "boot_architecture"):
            value = run(["terraform", "output", "-raw", output_name], cwd=MODULE, capture=True,
                        env=sanitized_terraform_env()).strip()
            if not value or "\n" in value or "\r" in value:
                raise LabError("saved Terraform platform outputs are incomplete")
            state_values[output_name] = value
        if (state_values["qualification_os_profile"] != profile or state_values["qualification_os_minor"] != minor
                or state_values["qualification_os_point_release"] != point_release
                or state_values["boot_architecture"] != "linux/amd64"
                or not re.fullmatch(r"https://www\.googleapis\.com/compute/v1/projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,62}", state_values["boot_image_id"])):
            raise LabError("saved Terraform image identity does not match the verified artifact OS profile")
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", state_values["qualification_image_approval_reference"])
                or not re.fullmatch(r"[a-f0-9]{64}", state_values["qualification_image_approval_sha256"])):
            raise LabError("saved Terraform state does not bind the image-owner approval record")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", state_values["boot_image_unique_id"]):
            raise LabError("saved Terraform state does not identify the exact server-assigned boot image ID")
        if profile in {"debian-13", "rhel-9"} and state_values["qualification_image_unique_id"] != state_values["boot_image_unique_id"]:
            raise LabError("saved Terraform image unique ID differs from the independently approved image record")
        if identity == ("debian", "13", "") and (state_values["boot_image_project"] != "debian-cloud"
                                                       or state_values["boot_image_family"] != state_values["boot_image_id"].rsplit("/", 1)[-1]
                                                       or not state_values["boot_image_family"].startswith("debian-13")):
            raise LabError("saved Terraform image is not the exact approved Debian 13 image")
        if identity[0] == "rhel" and (state_values["boot_image_project"] != state_values["boot_image_id"].split("/")[6]
                                       or state_values["boot_image_family"] != state_values["boot_image_id"].rsplit("/", 1)[-1]):
            raise LabError("saved Terraform image does not match the exact customer-approved RHEL image")
        if state_values["project_id"] != recovery.PROJECT_ID:
            raise LabError("saved Terraform state does not belong to the designated qualification project")
        if profile in {"debian-13", "rhel-9"}:
            verify_disposable_project(state_values["project_id"], run=run,
                                      principal_email=state_values["terraform_principal_email"])
            image_values = {
                "project_id": state_values["project_id"],
                "qualification_os_profile": profile,
                "qualification_image_unique_id": state_values["qualification_image_unique_id"],
                "debian_image_self_link": state_values["boot_image_id"] if profile == "debian-13" else "",
                "rhel_image_self_link": state_values["boot_image_id"] if profile == "rhel-9" else "",
                "terraform_principal_email": state_values["terraform_principal_email"],
            }
            image_approval = {"projectId": state_values["project_id"],
                              "imageUniqueId": state_values["qualification_image_unique_id"]}
            verify_live_image_identity(image_values, image_approval, run=run)
            boot_disk_verification = verify_created_boot_disk_images(
                state_values["project_id"], state_values["zone"], state_values["lab_id"],
                state_values["terraform_principal_email"], state_values["boot_image_id"],
                state_values["boot_image_unique_id"], require_rhel_payg=profile == "rhel-9", run=run,
            )
        else:
            boot_disk_verification = None
        return {"schemaVersion": 1, "profile": expected_report_profile,
                "qualificationOSProfile": profile, "osId": identity[0], "osMajor": identity[1],
                "osMinor": identity[2], "osPointRelease": point_release, "imageID": state_values["boot_image_id"],
                "imageUniqueID": state_values["boot_image_unique_id"],
                "imageProject": state_values["boot_image_project"], "imageFamilyOrName": state_values["boot_image_family"],
                "imageApprovalReference": state_values["qualification_image_approval_reference"],
                "imageApprovalSHA256": state_values["qualification_image_approval_sha256"],
                "bootDiskImageVerification": boot_disk_verification,
                "architecture": state_values["boot_architecture"],
                "artifactPreflightReportSHA256": expected_report_sha256,
                "packagePolicySHA256": package["policySha256"],
                "packageArchiveSHA256": package["packageArchiveSha256"],
                "packageRepositorySnapshotID": package["repositorySnapshotID"]}
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise LabError("could not bind the selected OS and artifact policy to qualification evidence") from error


def require_preflight_binds_k3s(report_path: Path, *, artifact_binary: Path, artifact_lock: Path,
                                artifact_signature: Path, artifact_trust: Path,
                                system_images_bundle: Path, system_images_lock: Path,
                                system_images_signature: Path, system_images_trust: Path,
                                expected_report_sha256: str | None = None) -> None:
    try:
        descriptor = os.open(report_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 1024 * 1024:
                raise LabError("M3 artifact preflight report is not a bounded regular file")
            raw = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
            if len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise LabError("M3 artifact preflight report changed while being read")
        if expected_report_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_report_sha256:
            raise LabError("M3 artifact preflight report changed after verification")
        result = json.loads(raw)
        bindings = result["inputSha256"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise LabError("M3 artifact preflight report is malformed") from error
    expected_paths = {
        "k3sBinary.binary": artifact_binary, "k3sBinary.lock": artifact_lock,
        "k3sBinary.signature": artifact_signature, "k3sBinary.trustBundle": artifact_trust,
        "k3sSystemImages.bundle": system_images_bundle, "k3sSystemImages.lock": system_images_lock,
        "k3sSystemImages.signature": system_images_signature, "k3sSystemImages.trustBundle": system_images_trust,
    }
    if not isinstance(bindings, dict):
        raise LabError("M3 artifact preflight report has no input bindings")
    for name, path in expected_paths.items():
        try:
            actual = sha256_file(path)
        except OSError as error:
            raise LabError("K3s artifact input is unavailable after preflight") from error
        if bindings.get(name) != actual:
            raise LabError("lab K3s inputs do not match the consolidated artifact preflight")


def ask_confirmation(expected: str, *, input_fn: Callable[[str], str] | None = None) -> None:
    if not sys.stdin.isatty():
        raise LabError("mutation confirmation requires an interactive terminal")
    input_fn = input if input_fn is None else input_fn
    entered = input_fn(f"Type exactly {expected!r} to continue: ")
    if entered != expected:
        raise LabError("confirmation did not match; no Terraform apply was run")


def terraform_plan(project_id: str, *, artifact_binary: Path, artifact_lock: Path,
                   artifact_signature: Path, artifact_trust: Path,
                   system_images_bundle: Path, system_images_lock: Path,
                   system_images_signature: Path, system_images_trust: Path,
                   os_profile: str,
                   os_minor: str = "",
                   os_point_release: str = "",
                   readiness_report_path: Path | None = None,
                   terraform_inputs_path: Path | None = None,
                   network_inputs_path: Path | None = None,
                   artifact_inputs_path: Path | None = None,
                   artifact_report_path: Path | None = None,
                   principal_attestation_path: Path | None = None,
                   image_approval_path: Path | None = None,
                   recheck_artifact_preflight: Callable[[], None] | None = None,
                   run: Callable = run_command) -> None:
    validate_project_id(project_id)
    if recheck_artifact_preflight is None:
        raise LabError("consolidated M3 artifact preflight is required before Terraform plan")
    if any(path is None for path in (readiness_report_path, terraform_inputs_path, network_inputs_path,
                                     artifact_inputs_path, artifact_report_path, principal_attestation_path,
                                     image_approval_path)):
        raise LabError("readiness report and complete effective Terraform inputs are required before plan")
    reject_auto_tfvars()
    if recovery_vars_file().exists() or recovery_vars_file().is_symlink():
        raise LabError("normal qualification plan refuses active restore-only Terraform inputs")
    recheck_artifact_preflight()
    values, _ = verify_readiness_plan_binding(project_id=project_id, readiness_report=readiness_report_path,
        terraform_inputs=terraform_inputs_path, network_inputs=network_inputs_path,
        artifact_inputs=artifact_inputs_path, artifact_report=artifact_report_path,
        principal_attestation=principal_attestation_path, image_approval_path=image_approval_path)
    image_approval, _image_digest = readiness_binding.validate_image_approval(
        image_approval_path, terraform_values=values,
        artifact_report=artifact_preflight.read_json(artifact_report_path))
    verify_live_image_identity(values, image_approval, run=run)
    digest, mirror = values["k3s_binary_sha256"], values["k3s_binary_mirror_url"]
    approval = verify_customer_artifact(artifact_binary, artifact_lock, artifact_signature,
                                        artifact_trust, digest, mirror, run=run)
    images, images_fingerprints = verify_customer_system_images(
        system_images_bundle, system_images_lock, system_images_signature, system_images_trust, run=run)
    require_artifact_overrides_bound(values, digest, mirror, images, os_profile, os_minor, os_point_release)
    terraform_init(run, principal_email=values["terraform_principal_email"])
    require_approval_unchanged(artifact_lock, artifact_signature, artifact_trust, approval)
    require_system_images_approval_unchanged(system_images_bundle, system_images_lock,
                                             system_images_signature, system_images_trust,
                                             images_fingerprints)
    recheck_artifact_preflight()
    current_values, current_hash = verify_readiness_plan_binding(project_id=project_id,
        readiness_report=readiness_report_path, terraform_inputs=terraform_inputs_path,
        network_inputs=network_inputs_path, artifact_inputs=artifact_inputs_path,
        artifact_report=artifact_report_path, principal_attestation=principal_attestation_path,
        image_approval_path=image_approval_path)
    if current_hash != readiness_binding.canonical_sha256(values) or current_values != values:
        raise LabError("effective Terraform inputs changed during plan preflight")
    var_file = secure_plan_var_file(values)
    try:
        run(["terraform", "plan", "-input=false", f"-var-file={var_file}"] + recovery_var_args() +
            terraform_artifact_vars(digest, mirror, images, os_profile, os_minor, os_point_release),
            cwd=MODULE, env=sanitized_terraform_env(values["terraform_principal_email"]))
    finally:
        var_file.unlink(missing_ok=True)


def verify_disposable_project(project_id: str, run: Callable = run_command,
                              principal_email: str | None = None) -> None:
    validate_project_id(project_id)
    principal = principal_email or os.environ.get("KORDEX_TERRAFORM_PRINCIPAL", "")
    if not terraform_context.PRINCIPAL.fullmatch(principal):
        raise LabError("approved Terraform provider principal is required for live project verification")
    command, cloud_env, _cloud_context = gcloud_context.command(
        ["projects", "describe", project_id,
         f"--project={project_id}",
         f"--impersonate-service-account={principal}",
         "--format=json(projectId,projectNumber,lifecycleState,labels)"])
    output = run(command, cwd=ROOT, capture=True, timeout=30, env=cloud_env)
    try:
        project = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise LabError("live project designation response is invalid") from error
    if not isinstance(project, dict) or project.get("projectId") != project_id:
        raise LabError("live project identity does not match the reviewed project ID")
    if not re.fullmatch(r"[0-9]+", str(project.get("projectNumber", ""))):
        raise LabError("live project number is missing or invalid")
    if project.get("lifecycleState") != "ACTIVE":
        raise LabError("live project is not ACTIVE")
    labels = project.get("labels")
    if not isinstance(labels, dict) or labels.get("kordex-disposable") != "qualification":
        raise LabError("live project is missing label kordex-disposable=qualification")


def terraform_apply(project_id: str, *, artifact_binary: Path, artifact_lock: Path,
                    artifact_signature: Path, artifact_trust: Path,
                    system_images_bundle: Path, system_images_lock: Path,
                    system_images_signature: Path, system_images_trust: Path,
                    os_profile: str,
                    os_minor: str = "",
                    os_point_release: str = "",
                    readiness_report_path: Path | None = None,
                    terraform_inputs_path: Path | None = None,
                    network_inputs_path: Path | None = None,
                    artifact_inputs_path: Path | None = None,
                    artifact_report_path: Path | None = None,
                    principal_attestation_path: Path | None = None,
                    image_approval_path: Path | None = None,
                    recheck_artifact_preflight: Callable[[], None] | None = None,
                    run: Callable = run_command, confirm: Callable = ask_confirmation,
                    verify_project: Callable = verify_disposable_project) -> None:
    validate_project_id(project_id)
    if recheck_artifact_preflight is None:
        raise LabError("consolidated M3 artifact preflight is required before Terraform apply")
    if any(path is None for path in (readiness_report_path, terraform_inputs_path, network_inputs_path,
                                     artifact_inputs_path, artifact_report_path, principal_attestation_path,
                                     image_approval_path)):
        raise LabError("readiness report and complete effective Terraform inputs are required before apply")
    reject_auto_tfvars()
    if recovery_vars_file().exists() or recovery_vars_file().is_symlink():
        raise LabError("normal qualification apply refuses active restore-only Terraform inputs")
    recheck_artifact_preflight()
    values, _ = verify_readiness_plan_binding(project_id=project_id, readiness_report=readiness_report_path,
        terraform_inputs=terraform_inputs_path, network_inputs=network_inputs_path,
        artifact_inputs=artifact_inputs_path, artifact_report=artifact_report_path,
        principal_attestation=principal_attestation_path, image_approval_path=image_approval_path)
    digest, mirror = values["k3s_binary_sha256"], values["k3s_binary_mirror_url"]
    approval = verify_customer_artifact(artifact_binary, artifact_lock, artifact_signature,
                                        artifact_trust, digest, mirror, run=run)
    images, images_fingerprints = verify_customer_system_images(
        system_images_bundle, system_images_lock, system_images_signature, system_images_trust, run=run)
    require_artifact_overrides_bound(values, digest, mirror, images, os_profile, os_minor, os_point_release)
    terraform_init(run, principal_email=values["terraform_principal_email"])
    require_approval_unchanged(artifact_lock, artifact_signature, artifact_trust, approval)
    require_system_images_approval_unchanged(system_images_bundle, system_images_lock,
                                             system_images_signature, system_images_trust,
                                             images_fingerprints)
    old_umask = os.umask(0o077)
    plan_name = ""
    plan_digest = ""
    var_file = secure_plan_var_file(values)
    try:
        fd, plan_name = tempfile.mkstemp(prefix=".kordex-lab-apply-", suffix=".tfplan", dir=MODULE)
        os.close(fd)
        run(["terraform", "plan", "-input=false", f"-var-file={var_file}"] + recovery_var_args() +
            terraform_artifact_vars(digest, mirror, images, os_profile, os_minor, os_point_release) + [f"-out={plan_name}"],
            cwd=MODULE, env=sanitized_terraform_env(values["terraform_principal_email"]))
        plan_digest = secure_plan_sha256(Path(plan_name))
        run(["terraform", "show", plan_name], cwd=MODULE,
            env=sanitized_terraform_env(values["terraform_principal_email"]))
        confirm(f"APPLY {project_id} PLAN-SHA256 {plan_digest}")
        verify_project(project_id, run=run, principal_email=values["terraform_principal_email"])
        recheck_artifact_preflight()
        require_approval_unchanged(artifact_lock, artifact_signature, artifact_trust, approval)
        require_system_images_approval_unchanged(system_images_bundle, system_images_lock,
                                                 system_images_signature, system_images_trust,
                                                 images_fingerprints)
        current_values, current_hash = verify_readiness_plan_binding(project_id=project_id,
            readiness_report=readiness_report_path, terraform_inputs=terraform_inputs_path,
            network_inputs=network_inputs_path, artifact_inputs=artifact_inputs_path,
            artifact_report=artifact_report_path, principal_attestation=principal_attestation_path,
            image_approval_path=image_approval_path)
        if current_values != values or current_hash != readiness_binding.canonical_sha256(values):
            raise LabError("effective Terraform inputs changed after plan review; no apply was run")
        current_approval, _image_digest = readiness_binding.validate_image_approval(
            image_approval_path, terraform_values=current_values,
            artifact_report=artifact_preflight.read_json(artifact_report_path))
        verify_live_image_identity(current_values, current_approval, run=run)
        if secure_plan_sha256(Path(plan_name)) != plan_digest:
            raise LabError("saved Terraform plan changed after review; no apply was run")
        run(["terraform", "apply", "-input=false", plan_name], cwd=MODULE,
            env=sanitized_terraform_env(values["terraform_principal_email"]))
        # Terraform/GCE accepts an image self-link at create time, so verify
        # the actual boot disks after creation as well as re-resolving the
        # image immediately before apply. A failure leaves the resources for
        # explicit review; it never authorizes host qualification.
        if os_profile in {"debian-13", "rhel-9"}:
            verify_disposable_project(project_id, run=run, principal_email=values["terraform_principal_email"])
            verify_live_image_identity(current_values, current_approval, run=run)
            image_self_link = (current_values.get("debian_image_self_link")
                               if os_profile == "debian-13" else current_values.get("rhel_image_self_link"))
            verify_created_boot_disk_images(
                project_id, current_values["zone"], current_values["name_prefix"],
                current_values["terraform_principal_email"], image_self_link,
                current_values["qualification_image_unique_id"], run=run,
            )
    finally:
        os.umask(old_umask)
        if plan_name:
            Path(plan_name).unlink(missing_ok=True)
        var_file.unlink(missing_ok=True)


def terraform_destroy(project_id: str, run: Callable = run_command, confirm: Callable = ask_confirmation,
                      verify_project: Callable = verify_disposable_project) -> None:
    validate_project_id(project_id)
    reject_auto_tfvars()
    _, raw_tfvars = private_tfvars_config(project_id)
    principal = terraform_principal_from_tfvars(raw_tfvars)
    terraform_init(run, principal_email=principal)
    state_project = run(["terraform", "output", "-raw", "project_id"], cwd=MODULE, capture=True,
                        env=sanitized_terraform_env(principal)).strip()
    if state_project != project_id:
        raise LabError("refusing destroy: Terraform state project_id does not match the confirmed disposable project")
    state_image_values: dict[str, str] = {}
    for output_name in (
        "k3s_system_images_manifest_version", "k3s_system_images_k3s_version",
        "k3s_system_images_architecture", "k3s_system_images_bundle_sha256",
        "k3s_system_images_bundle_mirror_url", "k3s_system_images_mirror_host",
    ):
        value = run(["terraform", "output", "-raw", output_name], cwd=MODULE, capture=True,
                    env=sanitized_terraform_env(principal)).strip()
        if not value or "\n" in value or "\r" in value:
            raise LabError("refusing destroy: saved K3s system-image configuration output is missing or malformed")
        state_image_values[output_name] = value
    destroy_vars = recovery_var_args() + [f"-var={name}={value}" for name, value in state_image_values.items()]
    operation_context, source_fingerprint = _bound_operation_context(principal)
    old_umask = os.umask(0o077)
    plan_name = ""
    try:
        fd, plan_name = tempfile.mkstemp(prefix=".kordex-lab-destroy-", suffix=".tfplan", dir=MODULE)
        os.close(fd)
        run(["terraform", "plan", "-destroy", "-input=false"] + destroy_vars + [f"-out={plan_name}"],
            cwd=MODULE, env=sanitized_terraform_env(principal))
        reviewed_digest = secure_plan_sha256(Path(plan_name))
        run(["terraform", "show", plan_name], cwd=MODULE, env=sanitized_terraform_env(principal))
        if secure_plan_sha256(Path(plan_name)) != reviewed_digest:
            raise LabError("destroy plan changed while being displayed")
        confirm(f"DESTROY {project_id} PLAN-SHA256 {reviewed_digest}")
        verify_project(project_id, run=run, principal_email=principal)
        _require_operation_context(operation_context, source_fingerprint, principal)
        if secure_plan_sha256(Path(plan_name)) != reviewed_digest:
            raise LabError("destroy plan changed after review; no apply was run")
        run(["terraform", "apply", "-input=false", plan_name], cwd=MODULE,
            env=sanitized_terraform_env(principal))
    finally:
        os.umask(old_umask)
        if plan_name:
            Path(plan_name).unlink(missing_ok=True)


def runner_command(execute: bool, evidence: Path, case: str | None = None, timeout: int = 14400,
                   cancel_phase: str | None = None, target_confirmation: str | None = None,
                   run: Callable = run_command, project_id: str | None = None,
                   confirm_project: Callable = ask_confirmation,
                   verify_project: Callable = verify_disposable_project,
                   recheck_artifact_preflight: Callable[[], None] | None = None,
                   platform_binding: dict | None = None) -> None:
    command = [sys.executable, str(RUNNER)]
    if execute:
        if recheck_artifact_preflight is None:
            raise LabError("execute requires a passing consolidated M3 artifact preflight")
        if case not in CASES:
            raise LabError("execute requires an explicit supported --qualification-case")
        if timeout < 1:
            raise LabError("--timeout-seconds must be positive")
        expected_phase = CANCELLATION_CASE_PHASES.get(case)
        if cancel_phase != expected_phase:
            raise LabError(f"qualification case {case} requires --cancel-on-phase {expected_phase}" if expected_phase
                           else f"qualification case {case} does not accept --cancel-on-phase")
        actual = os.environ.get("KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM", "")
        if not target_confirmation or target_confirmation != actual:
            raise LabError("--target-confirmation must exactly equal KORDEX_SELF_MANAGED_DISPOSABLE_CONFIRM")
        if not project_id:
            raise LabError("execute requires the reviewed --project-id")
        if not isinstance(platform_binding, dict) or platform_binding.get("schemaVersion") != 1:
            raise LabError("execute requires a verified image and artifact platform evidence binding")
        verify_project(project_id, run=run)
        confirm_project(f"EXECUTE IN DISPOSABLE PROJECT {project_id}")
        recheck_artifact_preflight()
        command.extend(["--execute", "--qualification-case", case, "--timeout-seconds", str(timeout)])
        if cancel_phase:
            if cancel_phase not in PHASES:
                raise LabError("unsupported cancellation phase")
            command.extend(["--cancel-on-phase", cancel_phase])
    command.extend(["--evidence", str(evidence)])
    environment = os.environ.copy()
    if execute:
        environment["KORDEX_M3_PLATFORM_BINDING"] = json.dumps(platform_binding, sort_keys=True, separators=(",", ":"))
    run(command, cwd=ROOT, env=environment)


def collect_diagnostics(output_dir: Path, namespace: str = "kordex-system", run: Callable = run_command) -> Path:
    kubectl = os.environ.get("KUBECTL", "kubectl")
    expected_context = os.environ.get("KORDEX_EXPECTED_CONTEXT", "").strip()
    if not expected_context:
        raise LabError("set KORDEX_EXPECTED_CONTEXT to the exact disposable lab context")
    current = run([kubectl, "config", "current-context"], cwd=ROOT, capture=True, timeout=20).strip()
    if current != expected_context:
        raise LabError(f"kubectl context mismatch: expected {expected_context!r}, got {current!r}")
    if output_dir.exists() or output_dir.is_symlink():
        raise LabError("diagnostics output directory already exists")
    output_dir.mkdir(parents=True, mode=0o700)
    os.chmod(output_dir, 0o700)
    commands = [
        ("nodes.txt", [kubectl, "get", "nodes", "-o", "wide"]),
        ("pods.txt", [kubectl, "get", "pods", "-A", "-o", "wide"]),
        ("pdbs.txt", [kubectl, "get", "pdb", "-A"]),
        ("events.txt", [kubectl, "get", "events", "-A", "--sort-by=.lastTimestamp"]),
        ("maintenance-resources.yaml", [kubectl, "-n", namespace, "get", "maintenancepolicies,nodemaintenances,maintenancecampaigns", "-o", "yaml"]),
        ("operator.log", [kubectl, "-n", namespace, "logs", "-l", "app.kubernetes.io/name=kordex-operator", "--all-containers=true", "--prefix", "--since=24h"]),
        ("agent.log", [kubectl, "-n", namespace, "logs", "-l", "app.kubernetes.io/name=kordex-agent", "--all-containers=true", "--prefix", "--since=24h"]),
    ]
    manifest = {"context": current, "namespace": namespace, "collectedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "artifacts": []}
    for filename, command in commands:
        started = dt.datetime.now(dt.timezone.utc).isoformat()
        try:
            output = run(command, cwd=ROOT, capture=True, timeout=60)
            exit_code = 0
        except LabError as error:
            output = str(error)
            exit_code = 1
        for pattern, replacement in LOG_REDACTIONS:
            output = pattern.sub(replacement, output)
        artifact = output_dir / filename
        artifact.write_text(output)
        os.chmod(artifact, 0o600)
        manifest["artifacts"].append({
            "file": filename,
            "command": command,
            "startedAt": started,
            "finishedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "exitCode": exit_code,
            "sha256": hashlib.sha256(output.encode()).hexdigest(),
        })
        (output_dir / "collection-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        os.chmod(output_dir / "collection-manifest.json", 0o600)
        if exit_code:
            raise LabError(f"diagnostic command failed; partial evidence was kept in {output_dir}")
    return output_dir


def archive_evidence(source: Path, destination: Path) -> tuple[Path, Path, Path]:
    if source.is_symlink():
        raise LabError("evidence source must not be a symlink")
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise LabError("evidence source must be a real directory")
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = destination.parent.resolve(strict=True) / destination.name
    if source == destination.parent or source in destination.parents:
        raise LabError("archive destination must be outside the evidence source directory")
    checksum_path = Path(str(destination) + ".sha256")
    manifest_path = Path(str(destination) + ".manifest.json")
    for candidate in (destination, checksum_path, manifest_path):
        if candidate.exists() or candidate.is_symlink():
            raise LabError(f"refusing to overwrite existing archive artifact: {candidate}")
    files: list[Path] = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise LabError(f"refusing to archive symlink: {path.relative_to(source)}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise LabError(f"refusing to archive non-regular evidence: {path.relative_to(source)}")
        lowered = path.name.lower()
        if (any(name in lowered for name in FORBIDDEN_ARCHIVE_NAMES)
                or path.suffix.lower() in {".pem", ".key", ".env"}
                or lowered in {"state.json", "credentials.json"}):
            raise LabError(f"refusing to archive secret-bearing artifact name: {path.relative_to(source)}")
        files.append(path)
    if not files:
        raise LabError("evidence directory is empty")
    manifest = {
        "format": "kordex-qualification-archive-v1",
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "files": [{"path": str(path.relative_to(source)), "sha256": sha256_file(path)} for path in files],
    }
    temp_dir = Path(tempfile.mkdtemp(prefix=".kordex-archive-", dir=destination.parent))
    os.chmod(temp_dir, 0o700)
    staged = temp_dir / destination.name
    published: list[Path] = []
    try:
        internal_manifest = temp_dir / "qualification-manifest.json"
        internal_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        with tarfile.open(staged, "w:gz") as archive:
            for path in files:
                archive.add(path, arcname=str(path.relative_to(source)), recursive=False)
            archive.add(internal_manifest, arcname="qualification-manifest.json", recursive=False)
        os.chmod(staged, 0o600)
        for path, item in zip(files, manifest["files"]):
            if sha256_file(path) != item["sha256"]:
                raise LabError(f"evidence changed while it was being archived: {path.relative_to(source)}")
        archive_hash = sha256_file(staged)
        checksum_temp = temp_dir / "archive.sha256"
        checksum_temp.write_text(f"{archive_hash}  {destination.name}\n")
        manifest["archive"] = destination.name
        manifest["archiveSHA256"] = archive_hash
        manifest_temp = temp_dir / "archive.manifest.json"
        manifest_temp.write_text(json.dumps(manifest, indent=2) + "\n")
        for path in (checksum_temp, manifest_temp):
            os.chmod(path, 0o600)
        for source_path, target_path in ((staged, destination), (checksum_temp, checksum_path), (manifest_temp, manifest_path)):
            os.link(source_path, target_path)
            published.append(target_path)
    except Exception:
        for path in published:
            path.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    return destination, checksum_path, manifest_path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="Terraform fmt/init/validate; no cloud plan")
    plan = commands.add_parser("plan", help="show a read-only Terraform plan")
    plan.add_argument("--project-id", required=True)
    add_artifact_approval_args(plan)
    add_m3_artifact_preflight_args(plan)
    add_readiness_binding_args(plan)
    apply = commands.add_parser("apply", help="review a fresh plan, then require typed project confirmation")
    apply.add_argument("--project-id", required=True)
    add_artifact_approval_args(apply)
    add_m3_artifact_preflight_args(apply)
    add_readiness_binding_args(apply)
    destroy = commands.add_parser("destroy", help="review a destroy plan and require typed project confirmation")
    destroy.add_argument("--project-id", required=True)
    preflight = commands.add_parser("preflight", help="run the existing read-only qualification preflight")
    preflight.add_argument("--evidence", type=Path, required=True)
    execute = commands.add_parser("execute", help="run one explicitly confirmed qualification case")
    execute.add_argument("--project-id", required=True)
    execute.add_argument("--target-confirmation", required=True)
    execute.add_argument("--qualification-case", choices=CASES, required=True)
    execute.add_argument("--evidence", type=Path, required=True)
    execute.add_argument("--timeout-seconds", type=int, default=14400)
    execute.add_argument("--cancel-on-phase", choices=PHASES)
    add_artifact_approval_args(execute)
    add_m3_artifact_preflight_args(execute)
    collect = commands.add_parser("collect", help="collect redacted Kubernetes and Kordex diagnostics")
    collect.add_argument("--output-dir", type=Path, required=True)
    collect.add_argument("--namespace", default=os.environ.get("KORDEX_NAMESPACE", "kordex-system"))
    verify = commands.add_parser("verify", help="validate qualification evidence against the full matrix")
    verify.add_argument("evidence_directory", type=Path)
    archive = commands.add_parser("archive", help="create a checksum-manifested local archive for off-cluster retention")
    archive.add_argument("--source", type=Path, required=True)
    archive.add_argument("--destination", type=Path, required=True)
    recovery_group = commands.add_parser("recovery", help="guarded snapshot, reset, serial diagnostics, and bounded fault tools")
    recovery_commands = recovery_group.add_subparsers(dest="recovery_command", required=True)

    lab_group = commands.add_parser("lab", help="operate the persistent lab with a durable maintenance-admission barrier")
    lab_commands = lab_group.add_subparsers(dest="lab_command", required=True)

    def add_lifecycle_context(command: argparse.ArgumentParser) -> None:
        command.add_argument("--project-id", default=lifecycle.PROJECT_ID)
        command.add_argument("--project-number", default=lifecycle.PROJECT_NUMBER)
        command.add_argument("--zone", default=lifecycle.ZONE)
        command.add_argument("--lab-id", required=True)
        command.add_argument("--terraform-principal-email", required=True)
        command.add_argument("--lifecycle-principal-email", required=True)
        command.add_argument("--organization-id", required=True)
        command.add_argument("--cluster-id", required=True)
        command.add_argument("--control-plane-url", required=True)
        command.add_argument("--control-plane-cert-sha256", required=True)
        command.add_argument("--token-file", type=Path, required=True)
        command.add_argument("--identity-evidence", type=Path, required=True)
        command.add_argument("--identity-sha256", required=True, help="out-of-band retained digest for post-create image/VM identity evidence")
        command.add_argument("--recovery-baseline", type=Path, required=True)
        command.add_argument("--baseline-sha256", required=True, help="out-of-band retained digest for the recovery baseline")
        command.add_argument("--os-id", choices=("debian", "rhel"), required=True)
        command.add_argument("--os-release", required=True, help="exact approved point/minor release")
        command.add_argument("--kube-context", required=True)
        command.add_argument("--timeout-seconds", type=int, default=900)

    for name, help_text in (("status", "read lifecycle state and exact VM inventory"),
                            ("start", "start only the verified persistent lab VMs"),
                            ("stop", "fence maintenance, drain durable operations, then stop VMs"),
                            ("restart", "perform the guarded stop and start sequence")):
        sub = lab_commands.add_parser(name, help=help_text)
        add_lifecycle_context(sub)
    cost = lab_commands.add_parser("cost", help="show the 90-day estimate; actual billing requires owner evidence")
    cost.add_argument("--machine-type", required=True,
                      help="exact selected Terraform machine type (for example e2-medium)")
    cost.add_argument("--boot-disk-size-gib", type=float, required=True)
    cost.add_argument("--debian-scenario-hours-per-vm", type=float, required=True)
    cost.add_argument("--debian-cleanup-restore-hours-per-vm", type=float, required=True)
    cost.add_argument("--rhel-scenario-hours-per-vm", type=float, required=True)
    cost.add_argument("--rhel-cleanup-restore-hours-per-vm", type=float, required=True)
    cost.add_argument("--wrong-machine-id-extra-host-hours-per-os", type=float, required=True)
    cost.add_argument("--rhel-license-mode", choices=("payg", "byos"), required=True)
    cost.add_argument("--rhel-license-hours-per-vm", type=float, required=True,
                      help="billable license hours per RHEL VM, including stopped time if applicable")
    cost.add_argument("--debian-boot-disk-gib-hours", type=float, required=True)
    cost.add_argument("--rhel-boot-disk-gib-hours", type=float, required=True)
    cost.add_argument("--wrong-machine-id-extra-host-disk-gib-hours-per-os", type=float, required=True)
    cost.add_argument("--snapshot-stored-gib-hours", type=float, required=True)
    cost.add_argument("--private-dns-query-bound", type=float, required=True)
    cost.add_argument("--monthly-logging-gib", type=float, nargs=3, required=True)
    cost.add_argument("--logging-retention-cost-bound-usd", type=float, required=True)
    cost.add_argument("--network-bound-usd", type=float, required=True)
    cost.add_argument("--artifact-storage-bound-usd", type=float, required=True)
    cost.add_argument("--registry-storage-bound-usd", type=float, required=True)
    cost.add_argument("--rhel-subscription-bound-usd", type=float, required=True)
    cost.add_argument("--other-bound-usd", type=float, required=True)

    def add_lab_identity(command: argparse.ArgumentParser, *, role: bool = False) -> None:
        command.add_argument("--project-id", required=True)
        command.add_argument("--lab-id", required=True)
        command.add_argument("--zone", required=True)
        command.add_argument("--server", required=True)
        command.add_argument("--worker-1", required=True)
        command.add_argument("--worker-2", required=True)
        if role:
            command.add_argument("--role", choices=recovery.NODE_ROLES, required=True)

    baseline = recovery_commands.add_parser("baseline", help="verify healthy idle lab and capture node/workload baseline")
    add_lab_identity(baseline)
    baseline.add_argument("--context", required=True)
    baseline.add_argument("--idle-attestation", required=True)
    baseline.add_argument("--output", type=Path, required=True)
    baseline.add_argument("--audit", type=Path, required=True)

    snapshot = recovery_commands.add_parser("snapshot", help="snapshot all stopped lab nodes from a verified baseline")
    add_lab_identity(snapshot)
    snapshot.add_argument("--baseline", type=Path, required=True)
    snapshot.add_argument("--safe-point", choices=sorted(recovery.SAFE_POINTS), required=True)
    snapshot.add_argument("--idle-attestation", required=True)
    snapshot.add_argument("--output", type=Path, required=True)
    snapshot.add_argument("--audit", type=Path, required=True)

    snapshot_verify = recovery_commands.add_parser("snapshot-verify", help="verify a complete live snapshot set")
    add_lab_identity(snapshot_verify)
    snapshot_verify.add_argument("--manifest", type=Path, required=True)

    snapshot_delete = recovery_commands.add_parser("snapshot-delete", help="delete only snapshots in a verified complete lab set")
    add_lab_identity(snapshot_delete)
    snapshot_delete.add_argument("--manifest", type=Path, required=True)
    snapshot_delete.add_argument("--output", type=Path, required=True)
    snapshot_delete.add_argument("--audit", type=Path, required=True)

    restore = recovery_commands.add_parser("restore", help="review and restore the complete three-node Terraform lab baseline")
    add_lab_identity(restore)
    restore.add_argument("--context", required=True)
    restore.add_argument("--manifest", type=Path, required=True)
    restore.add_argument("--roles", nargs=3, choices=recovery.NODE_ROLES, required=True)
    restore.add_argument("--output", type=Path, required=True)
    restore.add_argument("--audit", type=Path, required=True)

    serial = recovery_commands.add_parser("serial", help="capture bounded, redacted instance serial diagnostics")
    add_lab_identity(serial, role=True)
    serial.add_argument("--reason", choices=("boot-failure", "ssh-loss", "host-unavailable"), required=True)
    serial.add_argument("--output", type=Path, required=True)
    serial.add_argument("--audit", type=Path, required=True)

    fault = recovery_commands.add_parser("fault", help="temporarily deny one approved private TCP endpoint")
    add_lab_identity(fault, role=True)
    fault.add_argument("--scenario", choices=sorted(recovery.FAULT_SCENARIOS), required=True)
    fault.add_argument("--destination-cidr", required=True, help="exact private endpoint IPv4 /32 from the approved egress range")
    fault.add_argument("--duration-seconds", type=int, required=True)
    fault.add_argument("--output", type=Path, required=True)
    fault.add_argument("--audit", type=Path, required=True)

    fault_recover = recovery_commands.add_parser("fault-recover", help="remove and verify the exact interrupted lab fault")
    fault_recover.add_argument("--project-id", required=True)
    fault_recover.add_argument("--lab-id", required=True)
    fault_recover.add_argument("--zone", required=True)
    fault_recover.add_argument("--operation-id", required=True)
    fault_recover.add_argument("--output", type=Path, required=True)
    fault_recover.add_argument("--audit", type=Path, required=True)

    evidence = recovery_commands.add_parser("verify-evidence", help="validate recovery evidence against an independently retained SHA-256")
    evidence.add_argument("--file", type=Path, required=True)
    evidence.add_argument("--sha256", required=True)
    return result


def recovery_run(args: list[str], *, capture: bool = True, timeout: int = 120,
                 env: dict[str, str] | None = None) -> str:
    try:
        return run_command(args, cwd=ROOT, capture=capture, timeout=timeout, env=env)
    except LabError as error:
        raise recovery.RecoveryError("cloud or Kubernetes recovery command failed; protected output was not printed") from error


def recovery_confirmation(expected: str) -> str:
    if not sys.stdin.isatty():
        raise LabError("recovery mutation confirmation requires an interactive terminal")
    return input(f"Type exactly {expected!r} to continue: ")


def selected_nodes(args: argparse.Namespace) -> dict[str, str]:
    return {"server": args.server, "worker-1": args.worker_1, "worker-2": args.worker_2}


def run_recovery_command(args: argparse.Namespace) -> None:
    run = recovery_run
    if args.recovery_command == "baseline":
        _, digest = recovery.capture_baseline(args.project_id, args.lab_id, args.zone, selected_nodes(args),
                     args.context, args.idle_attestation, args.output, args.audit, run=run)
        print(f"Recovery baseline captured: {args.output} SHA-256 {digest}")
    elif args.recovery_command == "snapshot":
        baseline, _ = recovery.verify_baseline_record(args.baseline, args.project_id, args.lab_id,
                                                       args.zone, selected_nodes(args))
        confirmation = recovery_confirmation(f"SNAPSHOT {args.project_id}/{args.lab_id}/{baseline['recoverySetId']}")
        _, digest = recovery.create_snapshot_set(args.project_id, args.lab_id, args.zone,
                       selected_nodes(args), args.baseline, args.safe_point, args.idle_attestation, confirmation,
                       args.output, args.audit, run=run)
        print(f"Complete snapshot set created: {args.output} SHA-256 {digest}")
    elif args.recovery_command == "snapshot-verify":
        manifest, digest = recovery.verify_snapshot_set(args.manifest, args.project_id, args.lab_id,
                            args.zone, selected_nodes(args), run=run)
        print(f"Snapshot set {manifest['recoverySetId']} verified; SHA-256 {digest}")
    elif args.recovery_command == "snapshot-delete":
        preview, _ = recovery.verify_snapshot_set(args.manifest, args.project_id, args.lab_id,
                            args.zone, selected_nodes(args), run=run)
        confirmation = recovery_confirmation(
            f"DELETE-SNAPSHOTS {args.project_id}/{args.lab_id}/{preview['recoverySetId']}")
        result = recovery.delete_snapshot_set(args.project_id, args.lab_id, args.zone,
                    selected_nodes(args), args.manifest, confirmation, args.output, args.audit, run=run)
        print(f"Snapshot cleanup verified: {json.dumps(result, sort_keys=True)}")
    elif args.recovery_command == "restore":
        preview, _ = recovery.verify_snapshot_set(args.manifest, args.project_id, args.lab_id,
                            args.zone, selected_nodes(args), run=run)
        confirmation = recovery_confirmation(f"RESTORE {args.project_id}/{args.lab_id}/{preview['recoverySetId']}")
        record = recovery.restore_snapshot_set(args.project_id, args.lab_id, args.zone,
                    selected_nodes(args), args.roles, args.manifest, args.context, confirmation,
                    args.output, args.audit,
                    lambda snapshots, ips, operation: terraform_restore_apply(
                        args.project_id, args.lab_id, args.zone, snapshots, ips, operation), run=run)
        print(f"Lab restore {record['outcome']}: {args.output}")
    elif args.recovery_command == "serial":
        name = selected_nodes(args)[args.role]
        record = recovery.serial_diagnostics(args.project_id, args.lab_id, args.zone, args.role,
                    name, args.reason, args.output, args.audit, run=run)
        print(f"Serial diagnostics saved (redacted): {args.output}; SHA-256 {record['outputSHA256']}")
    elif args.recovery_command == "fault":
        name = selected_nodes(args)[args.role]
        operation = os.urandom(6).hex()
        expected = f"INJECT {args.project_id}/{args.lab_id}/{operation}"
        confirmation = recovery_confirmation(expected)
        record = recovery.inject_network_fault(args.project_id, args.lab_id, args.zone, args.role, name,
                    args.scenario, args.destination_cidr, args.duration_seconds, confirmation,
                    args.output, args.audit, run=run, operation_id=operation)
        print(f"Fault {record['executionOutcome']}; restoration {record['restoreOutcome']}; evidence {args.output}")
    elif args.recovery_command == "fault-recover":
        confirmation = recovery_confirmation(f"RESTORE-FAULT {args.project_id}/{args.lab_id}/{args.operation_id}")
        record = recovery.recover_network_fault(args.project_id, args.lab_id, args.zone,
                    args.operation_id, confirmation, args.output, args.audit, run=run)
        print(f"Manual fault recovery {record['restoreOutcome']}; evidence {args.output}")
    elif args.recovery_command == "verify-evidence":
        result = recovery.verify_recovery_evidence(args.file, args.sha256)
        print(f"Recovery evidence verified: {args.file} SHA-256 {result['sha256']}")


def add_artifact_approval_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--k3s-binary", type=Path, required=True,
                         help="local copy of the exact binary from the approved internal mirror")
    command.add_argument("--k3s-artifact-lock", type=Path, required=True,
                         help="customer-signed K3s artifact lock")
    command.add_argument("--k3s-artifact-signature", type=Path, required=True,
                         help="detached customer artifact-lock signature")
    command.add_argument("--k3s-artifact-trust", type=Path, required=True,
                         help="public trust bundle received through the independent customer channel")
    command.add_argument("--k3s-system-images-bundle", type=Path, required=True,
                         help="local customer-approved K3s airgap OCI archive")
    command.add_argument("--k3s-system-images-lock", type=Path, required=True,
                         help="customer-signed K3s system-image manifest")
    command.add_argument("--k3s-system-images-signature", type=Path, required=True,
                         help="detached K3s system-image manifest signature")
    command.add_argument("--k3s-system-images-trust", type=Path, required=True,
                         help="independently provisioned customer artifact trust bundle")


def add_m3_artifact_preflight_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--m3-artifact-inputs", type=Path, required=True,
                         help="customer-local JSON path map for all independently verified M3 inputs")
    command.add_argument("--m3-artifact-report", type=Path, required=True,
                         help="new or replaceable deterministic consolidated artifact report")


def add_readiness_binding_args(command: argparse.ArgumentParser) -> None:
    command.add_argument("--readiness-report", type=Path, required=True,
                         help="fresh readiness report binding all non-secret plan inputs")
    command.add_argument("--terraform-inputs", type=Path, required=True,
                         help="complete non-secret Terraform JSON variable file bound by readiness")
    command.add_argument("--network-inputs", type=Path, required=True,
                         help="customer network input document bound by readiness")
    command.add_argument("--terraform-principal-attestation", type=Path, required=True,
                         help="customer-rooted evidence of the identity observed through the Terraform provider")
    command.add_argument("--image-approval", type=Path, required=True,
                         help="customer image-owner record bound by readiness")


def terraform_artifact_vars(binary_digest: str, binary_mirror: str, images: dict[str, str],
                            os_profile: str, os_minor: str = "", os_point_release: str = "") -> list[str]:
    if os_profile not in {"ubuntu-24.04", "debian-13", "rhel-9"}:
        raise LabError("Terraform OS profile is unsupported or blocked")
    os_family = "rhel" if os_profile == "rhel-9" else "debian"
    if (os_profile == "rhel-9" and (not os_minor.isdigit() or int(os_minor) < 8)
            or os_profile != "rhel-9" and os_minor):
        raise LabError("Terraform OS minor release does not match the selected approved profile")
    if (os_profile == "debian-13" and os_point_release != artifact_preflight.M3_DEBIAN_POINT_RELEASE
            or os_profile == "rhel-9" and os_point_release != f"9.{os_minor}"
            or os_profile == "ubuntu-24.04" and os_point_release):
        raise LabError("Terraform OS point release does not match the selected approved profile")
    return [
        f"-var=qualification_os_profile={os_profile}",
        f"-var=qualification_os_minor={os_minor}",
        f"-var=qualification_os_point_release={os_point_release}",
        f"-var=os_family={os_family}",
        f"-var=k3s_binary_sha256={binary_digest}",
        f"-var=k3s_binary_mirror_url={binary_mirror}",
        f"-var=k3s_system_images_manifest_version={images['manifestVersion']}",
        f"-var=k3s_system_images_k3s_version={images['k3sVersion']}",
        f"-var=k3s_system_images_architecture={images['architecture']}",
        f"-var=k3s_system_images_bundle_sha256={images['bundleSha256']}",
        f"-var=k3s_system_images_bundle_mirror_url={images['bundleMirrorReference']}",
        f"-var=k3s_system_images_mirror_host={images['mirrorHost']}",
    ]


def require_artifact_overrides_bound(values: dict, binary_digest: str, binary_mirror: str,
                                    images: dict[str, str], os_profile: str, os_minor: str,
                                    os_point_release: str) -> None:
    """Ensure CLI -var overrides cannot diverge from reviewed JSON inputs.

    Terraform CLI variables outrank the explicit -var-file. These values are
    therefore checked against the canonical, readiness-bound variable map
    before the command is constructed.
    """
    os_family = "rhel" if os_profile == "rhel-9" else "debian"
    expected = {
        "qualification_os_profile": os_profile,
        "qualification_os_minor": os_minor,
        "qualification_os_point_release": os_point_release,
        "os_family": os_family,
        "k3s_binary_sha256": binary_digest,
        "k3s_binary_mirror_url": binary_mirror,
        "k3s_system_images_manifest_version": images.get("manifestVersion"),
        "k3s_system_images_k3s_version": images.get("k3sVersion"),
        "k3s_system_images_architecture": images.get("architecture"),
        "k3s_system_images_bundle_sha256": images.get("bundleSha256"),
        "k3s_system_images_bundle_mirror_url": images.get("bundleMirrorReference"),
        "k3s_system_images_mirror_host": images.get("mirrorHost"),
    }
    if any(values.get(name) != value for name, value in expected.items()):
        raise LabError("Terraform CLI artifact overrides differ from readiness-bound inputs")


def recovery_vars_file() -> Path:
    """Persistent non-secret Terraform inputs for a snapshot-restored baseline."""
    return MODULE / ".kordex-recovery-state.tfvars.json"


def read_recovery_vars(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise LabError("recovery Terraform inputs are unavailable or are a symlink") from error
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise LabError("recovery Terraform inputs must be a mode-0600 regular file")
        try:
            values = json.load(stream, object_pairs_hook=recovery.unique_object)
        except (OSError, json.JSONDecodeError, recovery.RecoveryError) as error:
            raise LabError("recovery Terraform inputs are invalid or ambiguous") from error
    if (not isinstance(values, dict) or set(values) != {
            "recovery_snapshot_ids", "recovery_internal_ips", "recovery_operation_id",
            "recovery_project_id", "recovery_lab_id", "recovery_zone"}):
        raise LabError("recovery Terraform inputs do not contain the exact supported variables")
    snapshots, addresses, operation = (values["recovery_snapshot_ids"], values["recovery_internal_ips"],
                                       values["recovery_operation_id"])
    if (not isinstance(snapshots, dict) or set(snapshots) != set(recovery.NODE_ROLES)
            or not isinstance(addresses, dict) or set(addresses) != set(recovery.NODE_ROLES)
            or not all(isinstance(value, str) for value in [*snapshots.values(), *addresses.values()])
            or not re.fullmatch(r"[a-f0-9]{12}", str(operation))
            or not all(isinstance(values[key], str) and values[key] for key in
                       ("recovery_project_id", "recovery_lab_id", "recovery_zone"))
            or values["recovery_project_id"] != recovery.PROJECT_ID
            or values["recovery_lab_id"] != recovery.LAB_ID
            or values["recovery_zone"] != "us-east1-b"
            or any(not re.fullmatch(rf"{re.escape(recovery.LAB_ID)}-{re.escape(role)}-snap-[a-f0-9]{{12}}", snapshots[role])
                   for role in recovery.NODE_ROLES)
            or len(set(addresses.values())) != 3
            or any(not re.fullmatch(r"10\.76\.0\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])", addresses[role])
                   for role in recovery.NODE_ROLES)):
        raise LabError("recovery Terraform inputs fail closed validation")
    return values


def recovery_var_args() -> list[str]:
    path = recovery_vars_file()
    if not path.exists() and not path.is_symlink():
        return []
    read_recovery_vars(path)
    return [f"-var-file={path}"]


def write_recovery_vars(path: Path, project_id: str, lab_id: str, zone: str,
                        snapshots: dict[str, str], addresses: dict[str, str], operation: str,
                        *, replace_existing: bool = False) -> None:
    if (set(snapshots) != set(recovery.NODE_ROLES) or set(addresses) != set(recovery.NODE_ROLES)
            or project_id != recovery.PROJECT_ID or lab_id != recovery.LAB_ID or zone != "us-east1-b"
            or any(not isinstance(snapshots[role], str) or
                   not re.fullmatch(rf"{re.escape(lab_id)}-{re.escape(role)}-snap-[a-f0-9]{{12}}", snapshots[role])
                   for role in recovery.NODE_ROLES)
            or any(not isinstance(addresses[role], str) or not re.fullmatch(
                r"10\.76\.0\.(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])", addresses[role])
                for role in recovery.NODE_ROLES)
            or len(set(addresses.values())) != 3 or not re.fullmatch(r"[a-f0-9]{12}", operation)):
        raise LabError("restore inputs must cover the exact three-node lab and operation ID")
    payload = (json.dumps({"recovery_snapshot_ids": snapshots, "recovery_internal_ips": addresses,
                           "recovery_operation_id": operation, "recovery_project_id": project_id,
                           "recovery_lab_id": lab_id, "recovery_zone": zone}, sort_keys=True, indent=2) + "\n").encode()
    if path.exists() or path.is_symlink():
        if not replace_existing:
            raise LabError("refusing to overwrite an existing recovery Terraform input file")
        previous = read_recovery_vars(path)
        if (previous["recovery_project_id"] != project_id or previous["recovery_lab_id"] != lab_id
                or previous["recovery_zone"] != zone):
            raise LabError("existing recovery Terraform input belongs to another project, lab, or zone")
    fd, name = tempfile.mkstemp(prefix=".kordex-recovery-inputs-", suffix=".tfvars.json", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    except OSError as error:
        raise LabError("could not securely persist the approved snapshot restore inputs") from error
    finally:
        Path(name).unlink(missing_ok=True)


def terraform_restore_apply(project_id: str, lab_id: str, zone: str,
                            snapshots: dict[str, str], addresses: dict[str, str], operation: str,
                            *, run: Callable = run_command, confirm: Callable = ask_confirmation,
                            verify_project: Callable = verify_disposable_project) -> None:
    """Create and apply a reviewed full-lab restore plan; never invoked by validation."""
    recovery.validate_target(project_id, lab_id, zone, recovery.names_for(lab_id))
    _, raw = private_tfvars_config(project_id)
    principal = terraform_principal_from_tfvars(raw)
    reject_auto_tfvars()
    digest, mirror = terraform_artifact_values(raw)
    terraform_init(run, principal_email=principal)
    for output_name, expected in (("project_id", project_id), ("lab_id", lab_id), ("zone", zone)):
        observed = run(["terraform", "output", "-raw", output_name], cwd=MODULE, capture=True,
                       env=sanitized_terraform_env(principal)).strip()
        if observed != expected:
            raise LabError(f"Terraform state {output_name} does not match the explicitly selected lab")
    image_outputs = {
        "osProfile": "qualification_os_profile",
        "manifestVersion": "k3s_system_images_manifest_version",
        "k3sVersion": "k3s_system_images_k3s_version",
        "architecture": "k3s_system_images_architecture",
        "bundleSha256": "k3s_system_images_bundle_sha256",
        "bundleMirrorReference": "k3s_system_images_bundle_mirror_url",
        "mirrorHost": "k3s_system_images_mirror_host",
    }
    images = {}
    for key, output_name in image_outputs.items():
        images[key] = run(["terraform", "output", "-raw", output_name], cwd=MODULE, capture=True,
                          env=sanitized_terraform_env(principal)).strip()
        if not images[key] or "\n" in images[key] or "\r" in images[key]:
            raise LabError("saved K3s system-image configuration is missing or malformed")
    temp_dir = Path(tempfile.mkdtemp(prefix=".kordex-restore-", dir=MODULE))
    os.chmod(temp_dir, 0o700)
    pending = temp_dir / "restore.tfvars.json"
    write_recovery_vars(pending, project_id, lab_id, zone, snapshots, addresses, operation)
    old_umask = os.umask(0o077)
    plan_name = ""
    operation_context, source_fingerprint = _bound_operation_context(principal)
    try:
        fd, plan_name = tempfile.mkstemp(prefix=".kordex-lab-restore-", suffix=".tfplan", dir=MODULE)
        os.close(fd)
        args = ["terraform", "plan", "-input=false"] + recovery_var_args()
        profile = images["osProfile"]
        if profile not in {"ubuntu-24.04", "debian-13", "rhel-9"}:
            raise LabError("saved Terraform state uses an unsupported or blocked OS profile")
        os_minor = run(["terraform", "output", "-raw", "qualification_os_minor"], cwd=MODULE,
                       capture=True, env=sanitized_terraform_env(principal)).strip()
        os_point_release = run(["terraform", "output", "-raw", "qualification_os_point_release"], cwd=MODULE,
                               capture=True, env=sanitized_terraform_env(principal)).strip()
        if profile == "rhel-9" and (not os_minor.isdigit() or int(os_minor) < 8):
            raise LabError("saved Terraform state does not bind a supported RHEL minor release")
        if profile != "rhel-9" and os_minor:
            raise LabError("saved Terraform state has an unexpected OS minor release")
        if profile == "debian-13" and os_point_release != artifact_preflight.M3_DEBIAN_POINT_RELEASE:
            raise LabError("saved Terraform state does not bind a Debian 13 stable point release")
        if profile == "rhel-9" and os_point_release != f"9.{os_minor}":
            raise LabError("saved Terraform state does not bind the selected RHEL 9 minor release")
        if profile == "ubuntu-24.04" and os_point_release:
            raise LabError("saved Terraform state has an unexpected supplemental Ubuntu point release")
        args += [f"-var-file={pending}"] + terraform_artifact_vars(digest, mirror, images, profile, os_minor,
                                                                       os_point_release) + [f"-out={plan_name}"]
        run(args, cwd=MODULE, env=sanitized_terraform_env(principal))
        reviewed_digest = secure_plan_sha256(Path(plan_name))
        run(["terraform", "show", plan_name], cwd=MODULE, env=sanitized_terraform_env(principal))
        if secure_plan_sha256(Path(plan_name)) != reviewed_digest:
            raise LabError("restore plan changed while being displayed")
        confirm(f"RESTORE-APPLY {project_id}/{lab_id}/{operation} PLAN-SHA256 {reviewed_digest}")
        verify_project(project_id, run=run, principal_email=principal)
        active = recovery_vars_file()
        # Persist the selected snapshot set before apply: after an interrupted
        # apply, subsequent normal plans must continue to reference these disks.
        write_recovery_vars(active, project_id, lab_id, zone, snapshots, addresses, operation,
                            replace_existing=active.exists() or active.is_symlink())
        _require_operation_context(operation_context, source_fingerprint, principal)
        if secure_plan_sha256(Path(plan_name)) != reviewed_digest:
            raise LabError("restore plan changed after review; no apply was run")
        run(["terraform", "apply", "-input=false", plan_name], cwd=MODULE,
            env=sanitized_terraform_env(principal))
    finally:
        os.umask(old_umask)
        if plan_name:
            Path(plan_name).unlink(missing_ok=True)
        shutil.rmtree(temp_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            terraform_validate()
        elif args.command == "plan":
            preflight_hash = run_m3_artifact_preflight(args.m3_artifact_inputs, args.m3_artifact_report)
            os_profile = qualification_os_profile(args.m3_artifact_report, preflight_hash)
            os_minor = qualification_os_minor(args.m3_artifact_report, preflight_hash)
            os_point_release = qualification_os_point_release(args.m3_artifact_report, preflight_hash)
            require_preflight_binds_k3s(args.m3_artifact_report, artifact_binary=args.k3s_binary,
                artifact_lock=args.k3s_artifact_lock, artifact_signature=args.k3s_artifact_signature,
                artifact_trust=args.k3s_artifact_trust, system_images_bundle=args.k3s_system_images_bundle,
                system_images_lock=args.k3s_system_images_lock, system_images_signature=args.k3s_system_images_signature,
                system_images_trust=args.k3s_system_images_trust, expected_report_sha256=preflight_hash)
            def recheck_plan_preflight() -> None:
                current_hash = run_m3_artifact_preflight(args.m3_artifact_inputs, args.m3_artifact_report)
                if current_hash != preflight_hash:
                    raise LabError("consolidated M3 artifact preflight changed before Terraform plan")
                require_preflight_binds_k3s(args.m3_artifact_report, artifact_binary=args.k3s_binary,
                    artifact_lock=args.k3s_artifact_lock, artifact_signature=args.k3s_artifact_signature,
                    artifact_trust=args.k3s_artifact_trust, system_images_bundle=args.k3s_system_images_bundle,
                    system_images_lock=args.k3s_system_images_lock, system_images_signature=args.k3s_system_images_signature,
                    system_images_trust=args.k3s_system_images_trust, expected_report_sha256=current_hash)
            terraform_plan(args.project_id, artifact_binary=args.k3s_binary, artifact_lock=args.k3s_artifact_lock,
                           artifact_signature=args.k3s_artifact_signature, artifact_trust=args.k3s_artifact_trust,
                           system_images_bundle=args.k3s_system_images_bundle,
                           system_images_lock=args.k3s_system_images_lock,
                           system_images_signature=args.k3s_system_images_signature,
                           system_images_trust=args.k3s_system_images_trust,
                           os_profile=os_profile,
                           os_minor=os_minor,
                           os_point_release=os_point_release,
                           readiness_report_path=args.readiness_report,
                           terraform_inputs_path=args.terraform_inputs,
                           network_inputs_path=args.network_inputs,
                           artifact_inputs_path=args.m3_artifact_inputs,
                           artifact_report_path=args.m3_artifact_report,
                           principal_attestation_path=args.terraform_principal_attestation,
                           image_approval_path=args.image_approval,
                           recheck_artifact_preflight=recheck_plan_preflight)
        elif args.command == "apply":
            preflight_hash = run_m3_artifact_preflight(args.m3_artifact_inputs, args.m3_artifact_report)
            os_profile = qualification_os_profile(args.m3_artifact_report, preflight_hash)
            os_minor = qualification_os_minor(args.m3_artifact_report, preflight_hash)
            os_point_release = qualification_os_point_release(args.m3_artifact_report, preflight_hash)
            require_preflight_binds_k3s(args.m3_artifact_report, artifact_binary=args.k3s_binary,
                artifact_lock=args.k3s_artifact_lock, artifact_signature=args.k3s_artifact_signature,
                artifact_trust=args.k3s_artifact_trust, system_images_bundle=args.k3s_system_images_bundle,
                system_images_lock=args.k3s_system_images_lock, system_images_signature=args.k3s_system_images_signature,
                system_images_trust=args.k3s_system_images_trust, expected_report_sha256=preflight_hash)
            def recheck_preflight() -> None:
                current_hash = run_m3_artifact_preflight(args.m3_artifact_inputs, args.m3_artifact_report)
                if current_hash != preflight_hash:
                    raise LabError("consolidated M3 artifact preflight changed after plan review; no apply was run")
                require_preflight_binds_k3s(args.m3_artifact_report, artifact_binary=args.k3s_binary,
                    artifact_lock=args.k3s_artifact_lock, artifact_signature=args.k3s_artifact_signature,
                    artifact_trust=args.k3s_artifact_trust, system_images_bundle=args.k3s_system_images_bundle,
                    system_images_lock=args.k3s_system_images_lock, system_images_signature=args.k3s_system_images_signature,
                    system_images_trust=args.k3s_system_images_trust, expected_report_sha256=current_hash)
            terraform_apply(args.project_id, artifact_binary=args.k3s_binary, artifact_lock=args.k3s_artifact_lock,
                            artifact_signature=args.k3s_artifact_signature, artifact_trust=args.k3s_artifact_trust,
                            system_images_bundle=args.k3s_system_images_bundle,
                            system_images_lock=args.k3s_system_images_lock,
                            system_images_signature=args.k3s_system_images_signature,
                            system_images_trust=args.k3s_system_images_trust,
                            os_profile=os_profile,
                            os_minor=os_minor,
                            os_point_release=os_point_release,
                            readiness_report_path=args.readiness_report,
                            terraform_inputs_path=args.terraform_inputs,
                            network_inputs_path=args.network_inputs,
                            artifact_inputs_path=args.m3_artifact_inputs,
                            artifact_report_path=args.m3_artifact_report,
                            principal_attestation_path=args.terraform_principal_attestation,
                            image_approval_path=args.image_approval,
                            recheck_artifact_preflight=recheck_preflight)
        elif args.command == "destroy":
            terraform_destroy(args.project_id)
        elif args.command == "preflight":
            runner_command(False, args.evidence)
        elif args.command == "execute":
            preflight_hash = run_m3_artifact_preflight(args.m3_artifact_inputs, args.m3_artifact_report)
            def recheck_execute_preflight() -> None:
                current_hash = run_m3_artifact_preflight(args.m3_artifact_inputs, args.m3_artifact_report)
                if current_hash != preflight_hash:
                    raise LabError("consolidated M3 artifact preflight changed before qualification execution")
                require_preflight_binds_k3s(args.m3_artifact_report, artifact_binary=args.k3s_binary,
                    artifact_lock=args.k3s_artifact_lock, artifact_signature=args.k3s_artifact_signature,
                    artifact_trust=args.k3s_artifact_trust, system_images_bundle=args.k3s_system_images_bundle,
                    system_images_lock=args.k3s_system_images_lock,
                    system_images_signature=args.k3s_system_images_signature,
                    system_images_trust=args.k3s_system_images_trust, expected_report_sha256=current_hash)
            require_preflight_binds_k3s(args.m3_artifact_report, artifact_binary=args.k3s_binary,
                artifact_lock=args.k3s_artifact_lock, artifact_signature=args.k3s_artifact_signature,
                artifact_trust=args.k3s_artifact_trust, system_images_bundle=args.k3s_system_images_bundle,
                system_images_lock=args.k3s_system_images_lock,
                system_images_signature=args.k3s_system_images_signature,
                system_images_trust=args.k3s_system_images_trust, expected_report_sha256=preflight_hash)
            platform_binding = qualification_platform_binding(args.m3_artifact_report, preflight_hash)
            runner_command(True, args.evidence, args.qualification_case, args.timeout_seconds,
                           args.cancel_on_phase, args.target_confirmation, project_id=args.project_id,
                           recheck_artifact_preflight=recheck_execute_preflight,
                           platform_binding=platform_binding)
        elif args.command == "collect":
            print(f"Diagnostics retained at {collect_diagnostics(args.output_dir, args.namespace)}")
        elif args.command == "verify":
            run_command([sys.executable, str(VERIFIER), str(args.evidence_directory)], cwd=ROOT)
        elif args.command == "archive":
            paths = archive_evidence(args.source, args.destination)
            print("Evidence archive written:", *paths)
        elif args.command == "recovery":
            run_recovery_command(args)
        elif args.command == "lab":
            if args.lab_command == "cost":
                import m3_cost_model

                try:
                    report = m3_cost_model.estimate(
                        machine_type=args.machine_type,
                        boot_disk_size_gib=args.boot_disk_size_gib,
                        debian_scenario_hours_per_vm=args.debian_scenario_hours_per_vm,
                        debian_cleanup_restore_hours_per_vm=args.debian_cleanup_restore_hours_per_vm,
                        rhel_scenario_hours_per_vm=args.rhel_scenario_hours_per_vm,
                        rhel_cleanup_restore_hours_per_vm=args.rhel_cleanup_restore_hours_per_vm,
                        wrong_machine_id_extra_host_hours_per_os=args.wrong_machine_id_extra_host_hours_per_os,
                        rhel_license_mode=args.rhel_license_mode,
                        rhel_license_hours_per_vm=args.rhel_license_hours_per_vm,
                        debian_boot_disk_gib_hours=args.debian_boot_disk_gib_hours,
                        rhel_boot_disk_gib_hours=args.rhel_boot_disk_gib_hours,
                        wrong_machine_id_extra_host_disk_gib_hours_per_os=args.wrong_machine_id_extra_host_disk_gib_hours_per_os,
                        snapshot_stored_gib_hours=args.snapshot_stored_gib_hours,
                        private_dns_queries=args.private_dns_query_bound,
                        monthly_logging_gib=args.monthly_logging_gib,
                        logging_retention_cost_bound_usd=args.logging_retention_cost_bound_usd,
                        network_cost_bound_usd=args.network_bound_usd,
                        artifact_storage_cost_bound_usd=args.artifact_storage_bound_usd,
                        registry_storage_cost_bound_usd=args.registry_storage_bound_usd,
                        rhel_subscription_cost_bound_usd=args.rhel_subscription_bound_usd,
                        other_cost_bound_usd=args.other_bound_usd,
                    )
                except m3_cost_model.CostModelError as error:
                    raise LabError(f"invalid cost estimate inputs: {error}") from error
                print(json.dumps({**report, "billingEvidence": "NOT_PROVIDED", "availableBudgetUsd": None,
                                  "note": "This is an estimate only; it does not establish actual spending or headroom."}, indent=2))
                if report["status"] == "BLOCKED_WORST_CASE_EXCEEDS_POLICY_CEILING":
                    raise LabError("conservative modeled high-water cost exceeds the $300 policy ceiling")
            else:
                lifecycle_config = {
                    "projectId": args.project_id, "projectNumber": args.project_number, "zone": args.zone,
                    "labId": args.lab_id, "terraformPrincipalEmail": args.terraform_principal_email,
                    "lifecyclePrincipalEmail": args.lifecycle_principal_email,
                    "organizationId": args.organization_id, "clusterId": args.cluster_id,
                    "osIdentity": {"osId": args.os_id, "versionId": args.os_release, "architecture": "amd64"},
                    "kubeContext": args.kube_context,
                }
                lifecycle.validate_config(lifecycle_config)
                identity, identity_bytes = _read_private_json(args.identity_evidence)
                baseline, baseline_bytes = _read_private_json(args.recovery_baseline)
                if (not re.fullmatch(r"[a-f0-9]{64}", args.identity_sha256)
                        or hashlib.sha256(identity_bytes).hexdigest() != args.identity_sha256
                        or not re.fullmatch(r"[a-f0-9]{64}", args.baseline_sha256)
                        or hashlib.sha256(baseline_bytes).hexdigest() != args.baseline_sha256):
                    raise LabError("lab identity/baseline evidence digest does not match the independently retained values")
                baseline, _ = recovery.verify_baseline_record(args.recovery_baseline, args.project_id, args.lab_id,
                                                              args.zone, recovery.names_for(args.lab_id))
                cloud = lifecycle.GCloudLab(lifecycle_config, identity, baseline, run_command)
                api = lifecycle.ControlPlaneClient(args.control_plane_url, args.organization_id, args.cluster_id,
                                                   lifecycle.safe_token_path(str(args.token_file)),
                                                   args.control_plane_cert_sha256)
                controller = lifecycle.LabLifecycleController(api, cloud, wait_seconds=args.timeout_seconds)
                if args.lab_command == "status":
                    value = controller.status()
                elif args.lab_command == "start":
                    ask_confirmation(f"START {lifecycle.PROJECT_ID} {args.lab_id}")
                    value = controller.start()
                elif args.lab_command == "stop":
                    ask_confirmation(f"STOP {lifecycle.PROJECT_ID} {args.lab_id}")
                    value = controller.stop()
                else:
                    ask_confirmation(f"RESTART {lifecycle.PROJECT_ID} {args.lab_id}")
                    value = controller.restart()
                print(json.dumps(value, indent=2, sort_keys=True))
        return 0
    except LabError as error:
        print(f"qualification lab error: {error}", file=sys.stderr)
        return 1
    except lifecycle.LifecycleError as error:
        print(f"qualification lab lifecycle error: {error}", file=sys.stderr)
        return 1
    except recovery.RecoveryError as error:
        print(f"qualification lab recovery error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
