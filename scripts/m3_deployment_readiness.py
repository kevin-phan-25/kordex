#!/usr/bin/env python3
"""Read-only local readiness gate for the disposable M3 GCP lab.

This command performs no cloud calls, network lookups, Terraform commands, or
registry operations. It checks the tracked lab profile, a non-secret customer
network-input document, and an existing artifact-preflight report. The guarded
lab plan command remains authoritative: it re-runs artifact verification,
binds the exact K3s inputs, checks the live project designation, and validates
the actual ignored Terraform input file without printing it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

try:
    import m3_artifact_preflight as artifact_preflight
except ModuleNotFoundError:  # allow focused tests to load this file by path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import m3_artifact_preflight as artifact_preflight

try:
    import m3_readiness_binding as readiness_binding
except ModuleNotFoundError:  # allow focused tests to load this file by path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import m3_readiness_binding as readiness_binding

try:
    import m3_terraform_context as terraform_context
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import m3_terraform_context as terraform_context

try:
    import m3_skopeo_tool
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import m3_skopeo_tool


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infrastructure/terraform/gcp/self-managed-lab"
EXPECTED_PROJECT = "kordex-fleet-platform-515416"
EXPECTED_REGION = "us-east1"
EXPECTED_ZONE = "us-east1-b"
EXPECTED_LAB_ID = "kordex-lab"
EXPECTED_SUBNET = "10.76.0.0/24"
EXPECTED_GOOGLE_APIS_CIDR = "199.36.153.4/30"
EXPECTED_RELAY_PORT = 18443
EXPECTED_MIRROR_PORT = 443
EXPECTED_NODE_ROLES = ["server", "worker-1", "worker-2"]
SUPPORTED_NETWORK_PROFILES = {"ubuntu-24.04", "debian-13", "rhel-9"}
MAX_PREFLIGHT_AGE = dt.timedelta(hours=4)
DNS_NAME = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
RFC1918 = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class ReadinessError(ValueError):
    pass


VALID_STATUSES = {"PASS", "PROVIDED", "NOT PROVIDED", "BLOCKED", "FAIL"}


def _status(status: str, code: str, **details) -> dict:
    if status not in VALID_STATUSES:
        raise ReadinessError("internal readiness status is invalid")
    return {"status": status, "code": code, **details}


def _safe_json(path: Path, limit: int = 2 * 1024 * 1024) -> dict:
    """Use the artifact preflight's bounded, no-follow, duplicate-safe reader."""
    return artifact_preflight.read_json(path, limit)


def validate_project(project_id: str) -> dict[str, str]:
    return (_status("PASS", "DesignatedProjectId") if project_id == EXPECTED_PROJECT
            else _status("FAIL", "UnexpectedProjectId"))


def _network(value: object) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise ReadinessError("CIDR must be a string")
    try:
        parsed = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ReadinessError("CIDR is malformed or not canonical") from error
    if not isinstance(parsed, ipaddress.IPv4Network):
        raise ReadinessError("only IPv4 CIDRs are supported")
    if parsed.prefixlen < 24 or not any(parsed.subnet_of(allowed) for allowed in RFC1918):
        raise ReadinessError("mirror and relay CIDRs must be RFC1918 and no broader than /24")
    return parsed


def validate_network_inputs(config: dict) -> None:
    allowed = {
        "schemaVersion", "projectId", "region", "zone", "labId", "osFamily", "nodeRoles",
        "subnetCIDR", "labSourceCIDR", "approvedPrivateMirrorCIDRs", "approvedPrivateRelayCIDRs",
        "restrictedGoogleApisCIDR", "mirrorPort", "relayPort", "noVMExternalIPs", "noCloudNAT",
        "relayDNSName", "mirrorDNSNames",
    }
    if set(config) != allowed or type(config.get("schemaVersion")) is not int or config["schemaVersion"] != 1:
        raise ReadinessError("network input schema is incomplete or contains unsupported fields")
    expected = {
        "projectId": EXPECTED_PROJECT, "region": EXPECTED_REGION, "zone": EXPECTED_ZONE,
        "labId": EXPECTED_LAB_ID, "nodeRoles": EXPECTED_NODE_ROLES,
        "subnetCIDR": EXPECTED_SUBNET, "labSourceCIDR": EXPECTED_SUBNET,
        "restrictedGoogleApisCIDR": EXPECTED_GOOGLE_APIS_CIDR,
        "mirrorPort": EXPECTED_MIRROR_PORT, "relayPort": EXPECTED_RELAY_PORT,
        "noVMExternalIPs": True, "noCloudNAT": True,
    }
    if any(config.get(key) != value for key, value in expected.items()):
        raise ReadinessError("network inputs do not match the designated project, three-node profile, or fixed ports")
    if config.get("osFamily") not in SUPPORTED_NETWORK_PROFILES:
        raise ReadinessError("osFamily must name an exact supported M3 lab profile")

    mirror_values = config.get("approvedPrivateMirrorCIDRs")
    relay_values = config.get("approvedPrivateRelayCIDRs")
    if (not isinstance(mirror_values, list) or not mirror_values
            or not isinstance(relay_values, list) or not relay_values):
        raise ReadinessError("private mirror and relay CIDRs are required")
    mirror = [_network(value) for value in mirror_values]
    relay = [_network(value) for value in relay_values]
    reserved = [ipaddress.ip_network(EXPECTED_SUBNET), ipaddress.ip_network(EXPECTED_GOOGLE_APIS_CIDR)]
    all_remote = mirror + relay
    if len(set(all_remote)) != len(all_remote):
        raise ReadinessError("private mirror and relay CIDRs must be unique and disjoint")
    if any(item.overlaps(other) for item in all_remote for other in reserved):
        raise ReadinessError("private mirror and relay CIDRs overlap the lab subnet or Google APIs VIP")
    if any(left.overlaps(right) for index, left in enumerate(all_remote) for right in all_remote[index + 1:]):
        raise ReadinessError("private mirror and relay CIDR ranges must be mutually disjoint")

    relay_name = config.get("relayDNSName")
    mirror_names = config.get("mirrorDNSNames")
    if not isinstance(relay_name, str) or not DNS_NAME.fullmatch(relay_name):
        raise ReadinessError("relayDNSName must be a customer-owned private DNS name")
    if (not isinstance(mirror_names, list) or not mirror_names
            or any(not isinstance(name, str) or not DNS_NAME.fullmatch(name) for name in mirror_names)
            or len(set(mirror_names)) != len(mirror_names)):
        raise ReadinessError("mirrorDNSNames must contain unique, customer-owned DNS names")


def _static_profile() -> None:
    """Check the tracked Terraform profile only; never open ignored tfvars."""
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    variables = (MODULE / "variables.tf").read_text(encoding="utf-8")
    versions = (MODULE / "versions.tf").read_text(encoding="utf-8")
    outputs = (MODULE / "outputs.tf").read_text(encoding="utf-8")
    example = (MODULE / "terraform.tfvars.example").read_text(encoding="utf-8")
    server_template = (MODULE / "server-startup.sh.tftpl").read_text(encoding="utf-8")
    worker_template = (MODULE / "worker-startup.sh.tftpl").read_text(encoding="utf-8")
    required_fragments = (
        'subnet_cidr                = "10.76.0.0/24"',
        'restricted_googleapis_cidr = "199.36.153.4/30"',
        'resource "google_compute_instance" "server"',
        'resource "google_compute_instance" "worker"',
        'for_each                  = local.worker_vm_names',
        'worker-1 = "${var.name_prefix}-worker"',
        'worker-2 = "${var.name_prefix}-worker-2"',
        'resource "google_compute_firewall" "egress_private_mirrors"',
        'resource "google_compute_firewall" "egress_private_relay"',
        'resource "google_compute_firewall" "egress_deny_other"',
        'resource "google_compute_firewall" "egress_restricted_googleapis"',
        'auto_create_subnetworks = false',
        'network                  = google_compute_network.lab.id',
        'protocol = "tcp"\n    ports    = ["443"]',
        'protocol = "tcp"\n    ports    = ["18443"]',
        'deny {\n    protocol = "all"',
        'value       = [for suffix in ["worker-1", "worker-2"]',
        f'project_id = "{EXPECTED_PROJECT}"',
        f'allowed_project_ids = ["{EXPECTED_PROJECT}"]',
        f'project_id_confirmation = "{EXPECTED_PROJECT}"',
        'os_family               = "debian"',
        'data "google_compute_image" "debian_13"',
        'project = "debian-cloud"',
        'name    = basename(var.debian_image_self_link)',
        'data.google_compute_image.debian_13[0].image_id == var.qualification_image_unique_id',
        'data "google_compute_image" "rhel_9"',
        'name    = basename(var.rhel_image_self_link)',
        'data.google_compute_image.rhel_9[0].image_id == var.qualification_image_unique_id',
        'qualification_image_approval_reference',
        'qualification_image_unique_id',
        'output "boot_architecture"',
        'variable "qualification_os_profile"',
        'impersonate_service_account = var.terraform_principal_email',
        'DEBIAN_ARCHIVE_MIRROR_URL',
        'DEBIAN_SECURITY_MIRROR_URL',
    )
    combined = main + "\n" + variables + "\n" + versions + "\n" + outputs + "\n" + example + "\n" + server_template + "\n" + worker_template
    if any(fragment not in combined for fragment in required_fragments):
        raise ReadinessError("tracked Terraform profile no longer matches M3 project, topology, or network contract")
    for template in (server_template, worker_template):
        if any(fragment not in template for fragment in (
                "OS_PROFILE='${qualification_os_profile}'", "EXPECTED_OS_ID=debian", "EXPECTED_OS_VERSION=13",
                "EXPECTED_OS_ID=ubuntu", "EXPECTED_OS_VERSION=24.04", "trixie trixie-updates",
                "trixie-security", "debian-archive-keyring.gpg", "Host machine identity is unavailable",
                'dpkg --print-architecture)" != amd64', "repo_gpgcheck=1", "gpgcheck=1")):
            raise ReadinessError("tracked startup template does not enforce Debian/Ubuntu identity and bootstrap policy")
    if ('data "google_compute_image" "rocky"' in main or
            'var.qualification_os_profile == "rhel-9" ? data.google_compute_image.rhel_9[0].self_link' not in main or
            'var.qualification_os_minor' not in main):
        raise ReadinessError("tracked lab must resolve the exact approved RHEL 9 image and minor release")

    def resource_body(resource_type: str, name: str) -> str:
        marker = f'resource "{resource_type}" "{name}"'
        start = main.find(marker)
        if start < 0:
            raise ReadinessError("required Terraform resource is absent")
        following = main.find("\nresource ", start + len(marker))
        return main[start:] if following < 0 else main[start:following]

    resource_contracts = {
        ("google_compute_firewall", "admin"): (
            'source_ranges = [local.iap_tcp_cidr]', 'ports    = ["22"]',
        ),
        ("google_compute_firewall", "egress_private_mirrors"): (
            'destination_ranges = tolist(var.approved_private_mirror_cidrs)', 'ports    = ["443"]',
        ),
        ("google_compute_firewall", "egress_private_relay"): (
            'destination_ranges = tolist(var.approved_private_relay_cidrs)', 'ports    = ["18443"]',
        ),
        ("google_compute_firewall", "egress_restricted_googleapis"): (
            'destination_ranges = [local.restricted_googleapis_cidr]', 'ports    = ["443"]',
        ),
        ("google_compute_firewall", "egress_deny_other"): (
            'destination_ranges = ["0.0.0.0/0"]', 'deny {', 'protocol = "all"',
        ),
    }
    if any(any(field not in resource_body(resource_type, name) for field in fields)
           for (resource_type, name), fields in resource_contracts.items()):
        raise ReadinessError("tracked Terraform firewall rules no longer match the private egress contract")
    if re.search(r'resource\s+"google_compute_(?:router|router_nat|address)"', main):
        raise ReadinessError("tracked lab unexpectedly defines NAT or public address resources")
    if "access_config {" in main:
        raise ReadinessError("tracked lab unexpectedly assigns VM external IP addresses")


def check_static_profile() -> dict[str, str]:
    try:
        _static_profile()
        return _status("PASS", "TrackedLabProfileValidated")
    except (OSError, UnicodeError, ReadinessError):
        return _status("FAIL", "TrackedLabProfileInvalid")


def check_selected_lab_os_profile(profile: str | None) -> dict[str, str]:
    """Do not let a valid policy profile imply the Terraform lab can boot it."""
    if profile is None:
        return _status("NOT PROVIDED", "LabOSProfileNotSelected")
    if profile == "ubuntu-24.04":
        return _status("PROVIDED", "UbuntuProfileSelectedSupplementalOnly")
    if profile == "debian-13":
        return _status("PROVIDED", "Debian13ProfileSelectedImageOwnerEvidenceRequired")
    if profile == "rhel-9":
        return _status("PROVIDED", "RHEL9ProfileSelectedImageAndEntitlementEvidenceRequired")
    return _status("FAIL", "UnsupportedLabOSProfile")


def check_local_tools() -> dict[str, str]:
    required = ("bash", "go", "gcloud", "kubectl", "openssl", "python3", "sha256sum", "terraform")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        # Names are executable identifiers, never credential or path values.
        return _status("NOT PROVIDED", "LocalToolsMissing:" + ",".join(missing))
    try:
        m3_skopeo_tool.verify_runtime()
    except m3_skopeo_tool.SkopeoMissing:
        return _status("NOT PROVIDED", "PinnedSkopeoMissing")
    except m3_skopeo_tool.SkopeoError as error:
        reason = str(error)
        if "only on Rocky Linux" in reason or "not pinned for this CPU architecture" in reason:
            return _status("BLOCKED", "PinnedSkopeoPlatformUnsupported")
        return _status("FAIL", "PinnedSkopeoVerificationFailed")
    return _status("PASS", "LocalToolsPresentAndPinnedSkopeoVerified")


def _hash_mapped_inputs(config: dict, report: dict) -> None:
    bindings = report.get("inputSha256")
    if not isinstance(bindings, dict):
        raise ReadinessError("artifact report has no input digest bindings")
    expected: dict[str, str] = {}

    def add(name: str, section: str, field: str) -> None:
        section_value = config.get(section)
        if isinstance(section_value, dict) and isinstance(section_value.get(field), str):
            expected[name] = artifact_preflight.hash_file(Path(section_value[field]))

    add("maintenancePublicTrust", "trust", "maintenanceBundle")
    add("artifactApprovalTrust", "trust", "artifactApprovalBundle")
    add("releasePublicTrust", "trust", "releasePublicKey")
    add("toolProvenancePublicTrust", "trust", "toolProvenancePublicKey")
    add("helmSignerAllowlist", "trust", "helmSignerAllowlist")
    release_dir = config.get("release", {}).get("bundleDirectory") if isinstance(config.get("release"), dict) else None
    if isinstance(release_dir, str):
        expected["signedReleaseBundle"] = artifact_preflight.hash_release_bundle(Path(release_dir))
    add("signedImageDigestLock", "release", "imageDigestLock")
    add("signedImageDigestSignature", "release", "imageDigestSignature")
    for key in ("binary", "lock", "signature", "trustBundle"):
        add(f"k3sBinary.{key}", "k3sBinary", key)
    for key in ("bundle", "lock", "signature", "trustBundle"):
        add(f"k3sSystemImages.{key}", "k3sSystemImages", key)
    add("packagePolicy", "packageArtifacts", "policy")
    add("packageArchive", "packageArtifacts", "archive")

    # Registry verification is a fresh online read performed by artifact
    # preflight and its temporary report is deliberately not retained. The
    # guarded plan re-runs it; do not treat its prior digest as current proof.
    allowed_bindings = set(expected) | {"privateRegistryVerification"}
    if set(bindings) != allowed_bindings:
        raise ReadinessError("artifact report bindings are incomplete or unsupported")
    if any(not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
           for digest in bindings.values()):
        raise ReadinessError("artifact report contains malformed digest bindings")
    if any(bindings.get(name) != digest for name, digest in expected.items()):
        raise ReadinessError("current local artifacts do not match the artifact report bindings")


def check_artifact_preflight(inputs_path: Path | None, report_path: Path | None,
                             *, now: dt.datetime | None = None) -> dict[str, str]:
    if inputs_path is None or report_path is None:
        return _status("NOT PROVIDED", "ArtifactInputsOrReportMissing")
    try:
        if inputs_path.is_symlink() or report_path.is_symlink():
            raise ReadinessError("artifact input or report path is a symlink")
        config = _safe_json(inputs_path)
        artifact_preflight.validate_input_schema(config)
        if config.get("schemaVersion") != 1:
            raise ReadinessError("unsupported artifact input schema")
        report_before = report_path.stat(follow_symlinks=False)
        if not stat.S_ISREG(report_before.st_mode):
            raise ReadinessError("artifact report is not a regular file")
        report = _safe_json(report_path, 1024 * 1024)
        if report.get("schemaVersion") != 1 or report.get("overallStatus") != "PASS":
            raise ReadinessError("artifact preflight is absent, malformed, or not PASS")
        rows = report.get("artifacts")
        if (not isinstance(rows, dict) or set(rows) != set(artifact_preflight.REQUIRED_ARTIFACTS)
                or any(not isinstance(rows.get(name), dict) or rows[name].get("status") != "PASS"
                       for name in artifact_preflight.REQUIRED_ARTIFACTS)):
            raise ReadinessError("artifact preflight has missing or non-PASS required rows")
        package_row = rows["hostPackageArtifacts"]
        package_profile = package_row.get("profile")
        package_identity = (package_row.get("osId"), package_row.get("osMajor"), package_row.get("osMinor"))
        supported_family = artifact_preflight.supported_package_os(*package_identity) if all(
            isinstance(value, str) for value in package_identity) else None
        expected_package_profile = (f"m3-{package_row.get('osId')}-{package_row.get('osMajor')}"
                                    + (f".{package_row.get('osMinor')}" if package_row.get("osMinor") else "")
                                    + f"-k3s-{artifact_preflight.EXPECTED_K3S}-linux-amd64")
        point_release = package_row.get("osPointRelease")
        point_release_valid = (
            isinstance(point_release, str) and (
                (package_row.get("osId") == "debian" and package_row.get("osMajor") == "13"
                 and re.fullmatch(r"13\.[0-9]+", point_release) is not None)
                or (package_row.get("osId") == "rhel" and package_row.get("osMajor") == "9"
                    and point_release == f"9.{package_row.get('osMinor')}" and
                    str(package_row.get("osMinor", "")).isdigit() and int(package_row["osMinor"]) >= 8)
                or (package_row.get("osId") == "ubuntu" and package_row.get("osMajor") == "24"
                    and package_row.get("osMinor") == "04" and point_release == "")
            )
        )
        if (not isinstance(package_profile, str) or not package_profile.startswith("m3-")
                or report.get("profile") != package_profile or package_profile != expected_package_profile
                or package_row.get("osFamily") != supported_family
                or package_row.get("architecture") != artifact_preflight.EXPECTED_ARCH
                or not point_release_valid
                or not isinstance(package_row.get("repositorySnapshotID"), str)
                or not package_row["repositorySnapshotID"]
                or not isinstance(package_row.get("policySha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", package_row["policySha256"])
                or not isinstance(package_row.get("packageArchiveSha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", package_row["packageArchiveSha256"])):
            raise ReadinessError("artifact preflight does not bind an exact host package profile")
        if (rows["k3sBinaryApproval"].get("version") != artifact_preflight.EXPECTED_K3S
                or rows["k3sBinaryApproval"].get("architecture") != artifact_preflight.EXPECTED_ARCH
                or rows["k3sSystemImageApproval"].get("version") != artifact_preflight.EXPECTED_K3S
                or rows["k3sSystemImageApproval"].get("architecture") != artifact_preflight.EXPECTED_ARCH
                or rows["k3sSystemImageApproval"].get("imageCount") != 8):
            raise ReadinessError("artifact report K3s version, architecture, or system-image count mismatches")
        _hash_mapped_inputs(config, report)

        report_after = report_path.stat(follow_symlinks=False)
        if ((report_before.st_dev, report_before.st_ino, report_before.st_size, report_before.st_mtime_ns)
                != (report_after.st_dev, report_after.st_ino, report_after.st_size, report_after.st_mtime_ns)
                or report_after.st_size <= 0):
            raise ReadinessError("artifact report changed while checking freshness and bindings")
        if _safe_json(inputs_path) != config:
            raise ReadinessError("artifact input map changed during readiness verification")
        checked_at = now or dt.datetime.now(dt.timezone.utc)
        age = checked_at.timestamp() - report_after.st_mtime
        if age < -300 or age > MAX_PREFLIGHT_AGE.total_seconds():
            raise ReadinessError("artifact preflight report is stale or has a future modification time")
        for name in ("k3sBinaryApproval", "k3sSystemImageApproval"):
            approval = rows[name]
            approved_at = dt.datetime.fromisoformat(str(approval.get("approvedAt", "")).replace("Z", "+00:00"))
            days = approval.get("approvalValidForDays")
            if (not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 365
                    or approved_at.tzinfo is None or approved_at > checked_at
                    or checked_at - approved_at > dt.timedelta(days=days)):
                raise ReadinessError("K3s artifact approval is expired or malformed")
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            artifact_preflight.PreflightError, ReadinessError):
        return _status("FAIL", "ArtifactPreflightInvalidStaleOrMismatched")
    return _status("PASS", "ArtifactReportFreshAndInputsBound")


def _requirements(checks: dict, *, checked_at: str) -> dict:
    result = {}
    for name, item in checks.items():
        schema = readiness_binding.READINESS_CHECK_SCHEMA[name]
        result[name] = {
            **item,
            "requirementId": schema["requirementId"],
            "platformApplicability": schema["platformApplicability"],
            "inputReference": schema["inputReference"],
            "verificationMethod": schema["verificationMethod"],
            "verificationTimestamp": checked_at if item["status"] in {"PASS", "FAIL", "PROVIDED"} else None,
            "result": item["status"],
            "reason": item["code"],
            "independentReviewRequired": schema["independentReviewRequired"],
        }
    return result


def check_plan_inputs(path: Path | None, image_approval_path: Path | None, network_path: Path | None, artifact_inputs_path: Path | None,
                      artifact_report_path: Path | None, principal_attestation_path: Path | None = None,
                      *, now: dt.datetime | None = None) -> tuple[dict, dict | None]:
    if any(value is None for value in (path, image_approval_path, network_path, artifact_inputs_path,
                                       artifact_report_path, principal_attestation_path)):
        return _status("BLOCKED", "SignedTerraformProviderIdentityAttestationRequired"), None
    try:
        network = _safe_json(network_path)
        artifact_config = _safe_json(artifact_inputs_path)
        artifact_report = _safe_json(artifact_report_path, 1024 * 1024)
        validate_network_inputs(network)
        variables_source = (MODULE / "variables.tf").read_text(encoding="utf-8")
        normalized, digest = readiness_binding.validate_plan_inputs(
            path, reader=_safe_json, terraform_source=variables_source, network=network,
            artifact_report=artifact_report, expected_project=EXPECTED_PROJECT,
            expected_region=EXPECTED_REGION, expected_zone=EXPECTED_ZONE,
            expected_lab_id=EXPECTED_LAB_ID)
        _approval, approval_digest = readiness_binding.validate_image_approval(
            image_approval_path, terraform_values=normalized,
            artifact_report=artifact_report)
        if normalized.get("qualification_image_approval_sha256") != approval_digest:
            raise readiness_binding.BindingError("Terraform image-approval digest does not match its input record")
        def git_run(command, *, cwd, capture):
            result = subprocess.run(command, cwd=cwd, check=True, text=True,
                                    stdout=subprocess.PIPE if capture else None,
                                    stderr=subprocess.PIPE)
            return result.stdout if capture else ""

        source_digest = readiness_binding.source_fingerprint(MODULE, git_run)
        execution_context = terraform_context.describe(normalized["terraform_principal_email"], module=MODULE)
        checked_at = now or dt.datetime.now(dt.timezone.utc)
        _identity_attestation, identity_attestation_digest = terraform_context.verify_provider_identity_attestation(
            principal_attestation_path, project_id=normalized["project_id"],
            target_principal=normalized["terraform_principal_email"], context=execution_context, now=checked_at)
        binding = {
            "schemaVersion": 1,
            "terraformInputsSha256": digest,
            "networkInputsSha256": readiness_binding.canonical_sha256(
                readiness_binding.canonical_network_inputs(network)),
            "artifactInputsSha256": readiness_binding.canonical_sha256(artifact_config),
            "artifactReportSha256": readiness_binding.canonical_sha256(artifact_report),
            "imageApprovalSha256": approval_digest,
            "terraformSourceSha256": source_digest,
            "executionContext": execution_context,
            "executionContextSha256": terraform_context.canonical_sha256(execution_context),
            "terraformPrincipalAttestationSha256": identity_attestation_digest,
            "terraformPrincipalAttestationFile": principal_attestation_path.name,
            "profile": normalized["qualification_os_profile"],
            "imageSelfLink": (normalized.get("debian_image_self_link") if normalized["qualification_os_profile"] == "debian-13"
                              else normalized.get("rhel_image_self_link") if normalized["qualification_os_profile"] == "rhel-9"
                              else "supplemental-image-family"),
            "imageApprovalReference": normalized["qualification_image_approval_reference"],
            "imageUniqueId": normalized["qualification_image_unique_id"] or "supplemental-image-family",
            "imageApprovalRequiresIndependentReview": True,
            "k3sVersion": normalized["k3s_version"],
            "k3sBinarySha256": normalized["k3s_binary_sha256"],
            "k3sSystemImagesBundleSha256": normalized["k3s_system_images_bundle_sha256"],
            "packagePolicySha256": artifact_report["artifacts"]["hostPackageArtifacts"].get("policySha256"),
            "boundAt": checked_at.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        # References and metadata only. Never copy variable values into a report.
        return _status("PASS", "CompleteTerraformInputsCanonicallyBound"), binding
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            artifact_preflight.PreflightError, ReadinessError, readiness_binding.BindingError,
            terraform_context.ContextError):
        return _status("FAIL", "TerraformInputsMissingStaleOrMismatched"), None


def report(project_id: str, network_path: Path | None, inputs_path: Path | None,
           artifact_report_path: Path | None, terraform_inputs_path: Path | None = None,
           image_approval_path: Path | None = None, principal_attestation_path: Path | None = None,
           *, now: dt.datetime | None = None) -> dict:
    selected_os_profile = None
    if network_path is not None:
        try:
            network_document = _safe_json(network_path)
            candidate = network_document.get("osFamily")
            selected_os_profile = candidate if isinstance(candidate, str) else None
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, ReadinessError):
            pass
    checks = {
        "designatedProject": validate_project(project_id),
        "trackedTerraformProfile": check_static_profile(),
        "selectedLabOSProfile": check_selected_lab_os_profile(selected_os_profile),
        "localTools": check_local_tools(),
        "customerNetworkInputs": _status("NOT PROVIDED", "CustomerNetworkInputsMissing"),
        "artifactPreflight": check_artifact_preflight(inputs_path, artifact_report_path, now=now),
        "artifactTrustCustody": _status("BLOCKED", "IndependentTrustCustodyReviewRequired"),
        "imageOwnerApproval": _status("NOT PROVIDED", "ImageOwnerApprovalRecordMissing"),
        "imageIdentityHumanReview": _status("BLOCKED", "ImageOwnerEvidenceMustBeIndependentlyReviewed"),
        "liveProjectLabelAndLifecycle": _status("BLOCKED", "CloudReadOnlyVerificationRequired"),
        "requiredAPIsAndIAM": _status("BLOCKED", "CloudOwnerReviewRequired"),
        "billingBudget": _status("BLOCKED", "BillingOwnerReviewRequired"),
        "privateRouteDNSFirewallAndPKI": _status("BLOCKED", "CustomerNetworkAndPKIEvidenceRequired"),
        "actualTerraformInputs": _status("NOT PROVIDED", "CompleteTerraformInputDocumentMissing"),
        "planInputBinding": _status("NOT PROVIDED", "PlanInputsNotBound"),
        "terraformExecutionContext": _status("BLOCKED", "TerraformExecutionContextNotBound"),
        "terraformAuthenticatedPrincipal": _status("BLOCKED", "EffectiveTerraformPrincipalNotIndependentlyVerified"),
    }
    if network_path is not None:
        try:
            network_config = _safe_json(network_path)
            validate_network_inputs(network_config)
            checks["customerNetworkInputs"] = _status("PROVIDED", "CustomerInputsStructurallyValidLiveNetworkNotVerified")
            if artifact_report_path is not None and artifact_report_path.is_file():
                artifact_report = _safe_json(artifact_report_path, 1024 * 1024)
                package = artifact_report.get("artifacts", {}).get("hostPackageArtifacts", {})
                package_os = (package.get("osId"), package.get("osMajor"), package.get("osMinor"))
                expected_family = artifact_preflight.supported_package_os(*package_os) if all(
                    isinstance(value, str) for value in package_os) else None
                profile_matches = (
                    network_config["osFamily"] == "ubuntu-24.04" and package_os == ("ubuntu", "24", "04") or
                    network_config["osFamily"] == "debian-13" and package_os == ("debian", "13", "") or
                    network_config["osFamily"] == "rhel-9" and package_os[0:2] == ("rhel", "9")
                    and expected_family == "rhel"
                )
                if not profile_matches or package.get("profile") != artifact_report.get("profile"):
                    checks["customerNetworkInputs"] = _status("FAIL", "NetworkAndArtifactOSProfileMismatch")
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, ReadinessError,
                artifact_preflight.PreflightError):
            checks["customerNetworkInputs"] = _status("FAIL", "NetworkInputsInvalid")
    plan_status, binding = check_plan_inputs(terraform_inputs_path, image_approval_path, network_path, inputs_path,
                                             artifact_report_path, principal_attestation_path, now=now)
    checks["planInputBinding"] = plan_status
    if binding is not None:
        checks["actualTerraformInputs"] = _status("PROVIDED", "CompleteNonSecretTerraformInputsBound")
        checks["imageOwnerApproval"] = _status("PASS", "CustomerSignedImageOwnerApprovalAndIndependentReviewVerified")
        checks["imageIdentityHumanReview"] = _status("PASS", "IndependentImageReleaseEvidenceReviewed")
        checks["artifactTrustCustody"] = _status("PASS", "RootAnchoredCustomerTrustConfigurationVerified")
        checks["terraformExecutionContext"] = _status("PASS", "TerraformExecutableWorkspaceProviderPrincipalAndEnvironmentBound")
        checks["terraformAuthenticatedPrincipal"] = _status("PASS", "SignedIndependentProviderIdentityAttestationVerified")
    statuses = [item["status"] for item in checks.values()]
    overall = ("FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses else
               "NOT PROVIDED" if "NOT PROVIDED" in statuses else "PROVIDED" if "PROVIDED" in statuses else "PASS")
    profile = {"ubuntu-24.04": "m3-ubuntu-24.04-k3s-v1.36.6+k3s1-linux-amd64",
               "debian-13": "m3-debian-13-k3s-v1.36.6+k3s1-linux-amd64",
               "rhel-9": "customer-selected-rhel-9.8-or-later"}.get(selected_os_profile, "unselected")
    checked_at = now or dt.datetime.now(dt.timezone.utc)
    detailed = _requirements(checks, checked_at=checked_at.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"))
    return {"schemaVersion": 2, "generatedAt": checked_at.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "profile": profile, "overallStatus": overall,
            "checks": detailed, "planBinding": binding}


def write_report(path: Path, result: dict) -> None:
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if path.exists() or path.is_symlink():
        raise ReadinessError("refusing to overwrite an existing readiness report")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--network-inputs", type=Path)
    parser.add_argument("--artifact-inputs", type=Path)
    parser.add_argument("--artifact-report", type=Path)
    parser.add_argument("--terraform-inputs", type=Path,
                        help="complete secret-free JSON Terraform variable file that the guarded plan will consume")
    parser.add_argument("--image-approval", type=Path,
                        help="customer image-owner record binding exact image self-link, OS release, and architecture")
    parser.add_argument("--terraform-principal-attestation", type=Path,
                        help="customer-rooted signed attestation of the identity observed through Terraform provider authentication")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = report(args.project_id, args.network_inputs, args.artifact_inputs, args.artifact_report,
                    args.terraform_inputs, args.image_approval, args.terraform_principal_attestation)
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output is not None:
        try:
            write_report(args.output, result)
        except (OSError, ReadinessError):
            print("M3 deployment readiness report could not be written", file=sys.stderr)
            return 2
    print(encoded, end="")
    return 0 if result["overallStatus"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
