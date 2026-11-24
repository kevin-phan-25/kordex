"""Canonical, secret-free bindings for the self-managed M3 Terraform plan."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import datetime as dt
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

try:
    import m3_terraform_context
    import m3_customer_trust
    import m3_artifact_preflight
except ImportError:  # loaded by tests/importlib from a repository-relative path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import m3_terraform_context
    import m3_customer_trust
    import m3_artifact_preflight


class BindingError(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    """Canonical JSON used for readiness fingerprints (UTF-8, sorted keys)."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise BindingError("input cannot be represented as canonical JSON") from error


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def terraform_variable_names(source: str) -> set[str]:
    names = set(re.findall(r'^variable\s+"([a-z][a-z0-9_]*)"\s*\{', source, flags=re.MULTILINE))
    if not names:
        raise BindingError("Terraform variable declarations could not be enumerated")
    return names


def _load(path: Path, reader) -> dict:
    if path.is_symlink():
        raise BindingError("Terraform input document must not be a symlink")
    try:
        value = reader(path, 1024 * 1024)
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise BindingError("Terraform input document is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise BindingError("Terraform input document must be one JSON object")
    return value


def source_fingerprint(module: Path, run) -> str:
    """Bind Terraform source, embedded files, and the local authorization gate."""
    repository = module.parents[3]
    module_relative = module.relative_to(repository)
    guard_paths = (
        "scripts/self_managed_lab.py", "scripts/self_managed_lab_recovery.py",
        "scripts/m3_deployment_readiness.py", "scripts/m3_readiness_binding.py",
        "scripts/m3_terraform_context.py", "scripts/m3_gcloud_context.py", "scripts/m3_customer_trust.py",
        "scripts/m3_artifact_preflight.py", "scripts/m3_artifact_review.py", "scripts/build-offline-package-artifacts.py",
        "scripts/m3_supply_chain_verify.py", "scripts/validate_image_sbom.py",
        "integrations/ansible-ee/upgrade.py", "api/go.mod", "api/go.sum",
    )
    listing = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "--",
                   module_relative.as_posix(), *guard_paths, "schemas/cyclonedx",
                   "schemas/m3-artifact-review-v1.json",
                   "api/artifactlock", "api/cmd/kordex-artifact-lock"],
                  cwd=repository, capture=True)
    # main.tf uses templatefile() and embeds secret_manager_bootstrap.py with
    # file(). Include the provider lock and all local authorization/artifact
    # verifier sources invoked by the guarded plan path. An ignored terraform.tfvars
    # is neither listed nor read.
    module_names = {name for name in listing.splitlines()
                    if name.startswith(module_relative.as_posix() + "/")
                    and name.endswith((".tf", ".tftpl", ".py", ".terraform.lock.hcl"))}
    names = sorted(module_names | {name for name in listing.splitlines()
                                   if name in guard_paths
                                   or name.startswith("schemas/cyclonedx/") and name.endswith(".json")
                                   or name == "schemas/m3-artifact-review-v1.json"
                                   or name.startswith(("api/artifactlock/", "api/cmd/kordex-artifact-lock/"))
                                   and name.endswith(".go")})
    if not names:
        raise BindingError("tracked Terraform source files are unavailable")
    parts = []
    for name in names:
        path = repository / name
        if path.is_symlink() or not path.is_file():
            raise BindingError("tracked Terraform source is unavailable or unsafe")
        data = path.read_bytes()
        relative = (Path(name).relative_to(module_relative).as_posix()
                    if name.startswith(module_relative.as_posix() + "/") else name)
        parts.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest()})
    return canonical_sha256(parts)


def _sorted_set(values: object, field: str) -> list[str]:
    if (not isinstance(values, list) or not values
            or any(not isinstance(item, str) or not item for item in values)
            or len(set(values)) != len(values)):
        raise BindingError(f"{field} must be a non-empty list of unique strings")
    return sorted(values)


def canonical_network_inputs(network: dict) -> dict:
    """Normalize order-insensitive network CIDR/name collections."""
    result = dict(network)
    for name in ("approvedPrivateMirrorCIDRs", "approvedPrivateRelayCIDRs", "mirrorDNSNames"):
        values = result.get(name)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise BindingError(f"{name} must be a list of strings")
        if len(values) != len(set(values)):
            raise BindingError(f"{name} must not contain duplicates")
        result[name] = sorted(values)
    return result


def validate_plan_inputs(path: Path, *, reader, terraform_source: str, network: dict,
                         artifact_report: dict, expected_project: str, expected_region: str,
                         expected_zone: str, expected_lab_id: str) -> tuple[dict, str]:
    """Validate a complete Terraform JSON variable file without logging values."""
    values = _load(path, reader)
    names = terraform_variable_names(terraform_source)
    if set(values) != names:
        missing = names - set(values)
        extra = set(values) - names
        raise BindingError(f"Terraform inputs are incomplete or unsupported (missing={len(missing)}, extra={len(extra)})")
    def bounded_json(value: object, depth: int = 0) -> bool:
        if depth > 3:
            return False
        if value is None:
            return False
        if type(value) in (str, bool, int, float):
            return not isinstance(value, float) or value == value and abs(value) != float("inf")
        if isinstance(value, list):
            return all(bounded_json(item, depth + 1) for item in value)
        if isinstance(value, dict):
            return all(isinstance(key, str) and bounded_json(item, depth + 1)
                       for key, item in value.items())
        return False

    if not all(bounded_json(value) for value in values.values()):
        raise BindingError("Terraform inputs contain unsupported JSON values")

    def require(condition: bool, reason: str) -> None:
        if not condition:
            raise BindingError(reason)

    require(values.get("project_id") == expected_project
            and values.get("project_id_confirmation") == expected_project
            and _sorted_set(values.get("allowed_project_ids"), "allowed_project_ids") == [expected_project],
            "Terraform project ID, allowlist, or confirmation does not match the designated project")
    require(isinstance(values.get("terraform_principal_email"), str)
            and m3_terraform_context.PRINCIPAL.fullmatch(values["terraform_principal_email"]) is not None,
            "a customer-approved Terraform service-account principal is required")
    require(values.get("region") == expected_region and values.get("zone") == expected_zone
            and values.get("name_prefix") == expected_lab_id,
            "Terraform region, zone, or lab identity differs from readiness inputs")
    require(values.get("server_service_account_id") == f"{expected_lab_id}-server"
            and values.get("worker_service_account_id") == f"{expected_lab_id}-worker",
            "Terraform server or worker service-account IDs differ from the approved lab identity")
    require(values.get("os_family") == ("rhel" if network["osFamily"] == "rhel-9" else "debian")
            and values.get("qualification_os_profile") == network["osFamily"],
            "Terraform OS profile differs from the selected customer package profile")
    require(values.get("k3s_version") == "v1.36.6+k3s1", "Terraform K3s version differs from the approved release")
    require(isinstance(values.get("machine_type"), str) and re.fullmatch(r"[a-z][a-z0-9-]{1,62}", values["machine_type"])
            and type(values.get("boot_disk_size_gb")) is int and 30 <= values["boot_disk_size_gb"] <= 200
            and isinstance(values.get("upgrade_ssh_user"), str)
            and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", values["upgrade_ssh_user"]),
            "Terraform machine, disk, or SSH principal input is malformed")

    expected_mirrors = sorted(network["approvedPrivateMirrorCIDRs"])
    expected_relays = sorted(network["approvedPrivateRelayCIDRs"])
    require(_sorted_set(values.get("approved_private_mirror_cidrs"), "approved_private_mirror_cidrs") == expected_mirrors
            and _sorted_set(values.get("approved_private_relay_cidrs"), "approved_private_relay_cidrs") == expected_relays,
            "Terraform mirror or relay CIDRs differ from the reviewed network input document")
    for cidr in expected_mirrors + expected_relays:
        ipaddress.ip_network(cidr, strict=True)

    mirror_names = network.get("mirrorDNSNames")
    require(isinstance(mirror_names, list) and mirror_names
            and all(isinstance(name, str) and name for name in mirror_names)
            and len(mirror_names) == len(set(mirror_names)),
            "network input must provide unique private mirror DNS identities")
    mirror_name_set = {name.lower() for name in mirror_names}

    def private_mirror_host(url: object, field: str) -> str:
        require(isinstance(url, str), f"{field} must be provided as a private HTTPS URL")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as error:
            raise BindingError(f"{field} URL is malformed") from error
        require(parsed.scheme == "https" and parsed.hostname is not None
                and parsed.username is None and parsed.password is None
                and port in (None, 443) and not parsed.query and not parsed.fragment,
                f"{field} must be a credential-free HTTPS URL without query or fragment")
        require(parsed.hostname.lower() in mirror_name_set,
                f"{field} host is not listed in the reviewed private mirror DNS inputs")
        decoded_path = unquote(parsed.path)
        require(re.search(r"%(?!2[Bb])", parsed.path) is None
                and ".." not in decoded_path.split("/") and "." not in decoded_path.split("/")
                and "\\" not in decoded_path and "//" not in decoded_path,
                f"{field} contains an unsafe path")
        return parsed.hostname.lower()

    package = artifact_report["artifacts"]["hostPackageArtifacts"]
    os_id, os_major, os_minor = package["osId"], package["osMajor"], package["osMinor"]
    point = package["osPointRelease"]
    require(isinstance(package.get("policySha256"), str)
            and re.fullmatch(r"[a-f0-9]{64}", package["policySha256"]) is not None
            and isinstance(package.get("packageArchiveSha256"), str)
            and re.fullmatch(r"[a-f0-9]{64}", package["packageArchiveSha256"]) is not None
            and isinstance(package.get("privateMirrorURLHost"), str),
            "verified package policy or archive digest is missing")
    profile = network["osFamily"]
    minor = os_minor if profile == "rhel-9" else ""
    require(values.get("qualification_os_minor") == minor
            and values.get("qualification_os_point_release") == point,
            "Terraform OS release does not match the verified package-policy profile")
    require((profile == "debian-13" and (os_id, os_major) == ("debian", "13")
             and point == m3_artifact_preflight.M3_DEBIAN_POINT_RELEASE)
            or (profile == "rhel-9" and os_id == "rhel" and os_major == "9"
                and minor.isdigit() and int(minor) >= 8 and point == f"9.{minor}")
            or (profile == "ubuntu-24.04" and (os_id, os_major, os_minor, point) == ("ubuntu", "24", "04", "")),
            "Terraform OS profile does not meet the selected platform minimum")

    binary = artifact_report["artifacts"]["k3sBinaryApproval"]
    system = artifact_report["artifacts"]["k3sSystemImageApproval"]
    require(values.get("k3s_binary_sha256") == binary.get("binarySha256")
            and values.get("k3s_binary_mirror_url") == binary.get("mirrorReference"),
            "Terraform K3s binary digest or mirror does not match the approved artifact report")
    private_mirror_host(values.get("k3s_binary_mirror_url"), "k3s_binary_mirror_url")
    require(values.get("k3s_system_images_manifest_version") == "1"
            and values.get("k3s_system_images_k3s_version") == system.get("version")
            and values.get("k3s_system_images_architecture") == system.get("architecture")
            and values.get("k3s_system_images_bundle_sha256") == system.get("bundleSha256")
            and values.get("k3s_system_images_bundle_mirror_url") == system.get("bundleMirrorReference")
            and values.get("k3s_system_images_mirror_host") == system.get("mirrorHost"),
            "Terraform K3s system-image inputs do not match the signed system-image report")
    private_mirror_host(values.get("k3s_system_images_bundle_mirror_url"),
                        "k3s_system_images_bundle_mirror_url")
    registry = artifact_report["artifacts"].get("privateRegistryImages", {})
    require(isinstance(values.get("k3s_system_images_mirror_host"), str)
            and registry.get("status") == "PASS" and isinstance(registry.get("registryHost"), str)
            and registry["registryHost"].lower() == values["k3s_system_images_mirror_host"].lower()
            and private_mirror_host(f"https://{registry['registryHost']}/", "registryHost") in mirror_name_set,
            "Terraform private registry host does not match the verified registry report and DNS allowlist")

    image_approval_ref = values.get("qualification_image_approval_reference")
    require(isinstance(image_approval_ref, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", image_approval_ref) is not None,
            "an exact image-owner approval reference is required")
    require(isinstance(values.get("qualification_image_approval_sha256"), str)
            and re.fullmatch(r"[a-f0-9]{64}", values["qualification_image_approval_sha256"]) is not None,
            "the canonical image-owner approval digest is required")
    image_unique_id = values.get("qualification_image_unique_id")
    if profile == "debian-13":
        image = values.get("debian_image_self_link")
        require(isinstance(image, str) and re.fullmatch(
            r"https://www\.googleapis\.com/compute/v1/projects/debian-cloud/global/images/[a-z][a-z0-9-]{0,62}", image) is not None,
            "Debian 13 requires an exact approved debian-cloud image self-link")
        require(values.get("rhel_image_self_link") == "", "Debian plan must not also select a RHEL image")
        require(values.get("ubuntu_apt_mirror_url") == "" and values.get("rhel_repository_baseurl") == ""
                and values.get("rhel_repository_gpg_key_path") == ""
                and values.get("rhel_repository_gpg_fingerprint") == "",
                "Debian plan contains conflicting Ubuntu or RHEL repository inputs")
        archive_host = private_mirror_host(values.get("debian_archive_mirror_url"), "debian_archive_mirror_url")
        security_host = private_mirror_host(values.get("debian_security_mirror_url"), "debian_security_mirror_url")
        require(package["privateMirrorURLHost"].lower() in {archive_host, security_host},
                "Debian package artifact mirror host differs from the selected private archive/security mirrors")
    elif profile == "rhel-9":
        image = values.get("rhel_image_self_link")
        require(isinstance(image, str) and re.fullmatch(
            r"https://www\.googleapis\.com/compute/v1/projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,62}", image) is not None,
            "RHEL 9 requires an exact customer-approved image self-link")
        require(values.get("debian_image_self_link") == "", "RHEL plan must not also select a Debian image")
        require(values.get("ubuntu_apt_mirror_url") == "" and values.get("debian_archive_mirror_url") == ""
                and values.get("debian_security_mirror_url") == "",
                "RHEL plan contains conflicting Ubuntu or Debian repository inputs")
        rhel_host = private_mirror_host(values.get("rhel_repository_baseurl"), "rhel_repository_baseurl")
        require(package["privateMirrorURLHost"].lower() == rhel_host,
                "RHEL package artifact mirror host differs from the selected private RPM repository")
        require(isinstance(values.get("rhel_repository_gpg_key_path"), str)
                and re.fullmatch(r"/etc/pki/rpm-gpg/[A-Za-z0-9._-]+", values["rhel_repository_gpg_key_path"])
                and isinstance(values.get("rhel_repository_gpg_fingerprint"), str)
                and re.fullmatch(r"[A-Fa-f0-9]{40}", values["rhel_repository_gpg_fingerprint"]),
                "RHEL plan requires the approved repository key path and fingerprint")
    else:
        image = ""
        require(values.get("debian_image_self_link") == "" and values.get("rhel_image_self_link") == "",
                "supplemental Ubuntu plan must not select a Debian or RHEL image")
        require(values.get("debian_archive_mirror_url") == "" and values.get("debian_security_mirror_url") == ""
                and values.get("rhel_repository_baseurl") == ""
                and values.get("rhel_repository_gpg_key_path") == ""
                and values.get("rhel_repository_gpg_fingerprint") == "",
                "supplemental Ubuntu plan contains conflicting Debian or RHEL repository inputs")
        ubuntu_host = private_mirror_host(values.get("ubuntu_apt_mirror_url"), "ubuntu_apt_mirror_url")
        require(package["privateMirrorURLHost"].lower() == ubuntu_host,
                "Ubuntu package artifact mirror host differs from the selected private APT mirror")
    if profile in {"debian-13", "rhel-9"}:
        require(isinstance(image_unique_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", image_unique_id),
                "an exact Compute Engine image unique ID is required")
    else:
        require(image_unique_id == "", "supplemental Ubuntu must not use a qualification image unique ID")

    # All six restore-only variables must be empty in a normal qualification plan.
    require(values.get("recovery_snapshot_ids") == {} and values.get("recovery_project_id") == ""
            and values.get("recovery_lab_id") == "" and values.get("recovery_zone") == ""
            and values.get("recovery_internal_ips") == {} and values.get("recovery_operation_id") == "",
            "restore-only inputs cannot be present in a normal qualification plan")

    # Canonical Terraform values use sorted representations for set-typed fields.
    normalized = dict(values)
    for name in ("allowed_project_ids", "approved_private_mirror_cidrs", "approved_private_relay_cidrs"):
        normalized[name] = _sorted_set(values[name], name)
    return normalized, canonical_sha256(normalized)


def validate_image_approval(path: Path, *, terraform_values: dict,
                            artifact_report: dict, trust_loader=None,
                            now: dt.datetime | None = None) -> tuple[dict, str]:
    """Verify independently signed image-owner approval and reviewer decision."""
    trust_loader = trust_loader or m3_customer_trust.load_trust
    trust_document, trust_sha = trust_loader()
    raw = m3_customer_trust.read_regular(path, 256 * 1024)
    try:
        approval = json.loads(raw, object_pairs_hook=m3_customer_trust.unique_object)
    except (json.JSONDecodeError, UnicodeError, m3_customer_trust.TrustError) as error:
        raise BindingError("image approval record is malformed") from error
    expected_keys = {"schemaVersion", "projectId", "approvalStatus", "approvalReference", "platformProfile",
                     "imageSelfLink", "imageUniqueId", "osId", "osVersion", "pointRelease", "architecture",
                     "packagePolicySha256", "imageOwner", "approverIdentity", "approvedAt", "expiresAt",
                     "evidenceReference", "rationale"}
    if (set(approval) != expected_keys or approval.get("schemaVersion") != 1
            or approval.get("approvalStatus") != "approved" or raw != m3_customer_trust.canonical_json(approval)):
        raise BindingError("image approval record is incomplete, noncanonical, or not approved")
    owner_public, owner_fp = m3_customer_trust.authorized_key(
        trust_document, approval.get("approverIdentity"), "image-approver", now=now)
    owner_sig = m3_customer_trust.read_regular(path.with_name(path.name + ".sig"), 4096)
    m3_customer_trust.verify_signature(raw, owner_sig, owner_public)
    profile = terraform_values["qualification_os_profile"]
    package = artifact_report["artifacts"]["hostPackageArtifacts"]
    image = (terraform_values.get("debian_image_self_link") if profile == "debian-13"
             else terraform_values.get("rhel_image_self_link") if profile == "rhel-9"
             else "")
    expected_os_version = ("13" if profile == "debian-13" else
                           f"9.{terraform_values['qualification_os_minor']}" if profile == "rhel-9" else "24.04")
    expected_os_id = "debian" if profile == "debian-13" else "rhel" if profile == "rhel-9" else "ubuntu"
    expected_point = package["osPointRelease"]
    if (approval.get("platformProfile") != profile
            or approval.get("imageSelfLink") != image
            or approval.get("imageUniqueId") != terraform_values.get("qualification_image_unique_id")
            or approval.get("osId") != expected_os_id
            or approval.get("osVersion") != expected_os_version
            or approval.get("pointRelease") != expected_point
            or approval.get("architecture") != "linux/amd64"
            or approval.get("approvalReference") != terraform_values["qualification_image_approval_reference"]):
        raise BindingError("image approval record does not bind the exact image, platform, point release, and architecture")
    for field in ("imageOwner", "evidenceReference"):
        if not isinstance(approval.get(field), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", approval[field]):
            raise BindingError(f"image approval {field} is malformed")
    if (not isinstance(approval.get("rationale"), str) or len(approval["rationale"].strip()) < 8
            or any(ord(char) < 32 for char in approval["rationale"])):
        raise BindingError("image approval rationale is malformed")
    if approval.get("projectId") != terraform_values["project_id"] or package.get("policySha256") != approval.get("packagePolicySha256"):
        raise BindingError("image approval project or package policy digest does not match the reviewed plan")
    try:
        approved_at = m3_customer_trust.parse_time(approval["approvedAt"], "approvedAt")
        approval_expires = m3_customer_trust.parse_time(approval["expiresAt"], "expiresAt")
        current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    except (KeyError, m3_customer_trust.TrustError) as error:
        raise BindingError("image approval validity timestamps are invalid") from error
    if (approved_at > current + dt.timedelta(minutes=2) or approved_at > current
            or approval_expires <= current or approval_expires <= approved_at
            or approval_expires - approved_at > dt.timedelta(days=30)):
        raise BindingError("image approval is not currently valid or exceeds the 30-day validity limit")
    review_path = path.with_name(path.stem + ".review.json")
    review_raw = m3_customer_trust.read_regular(review_path, 64 * 1024)
    try:
        review = json.loads(review_raw, object_pairs_hook=m3_customer_trust.unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise BindingError("image approval review record is malformed") from error
    required_review = {"schemaVersion", "approvalSha256", "reviewerIdentity", "decision", "reviewedAt", "rationale"}
    if (not isinstance(review, dict) or set(review) != required_review or review["schemaVersion"] != 1
            or review["approvalSha256"] != hashlib.sha256(raw).hexdigest()
            or review["decision"] != "accepted" or not isinstance(review["rationale"], str)
            or len(review["rationale"].strip()) < 8 or review_raw != m3_customer_trust.canonical_json(review)):
        raise BindingError("independent image approval review is missing, rejected, or not bound to the signed approval")
    reviewer_public, reviewer_fp = m3_customer_trust.authorized_key(
        trust_document, review["reviewerIdentity"], "reviewer", now=now)
    review_sig = m3_customer_trust.read_regular(review_path.with_name(review_path.name + ".sig"), 4096)
    m3_customer_trust.verify_signature(review_raw, review_sig, reviewer_public)
    reviewed_at = m3_customer_trust.parse_time(review["reviewedAt"], "reviewedAt")
    if (review["reviewerIdentity"] == approval["approverIdentity"] or reviewer_fp == owner_fp
            or reviewed_at < approved_at or reviewed_at > current + dt.timedelta(minutes=2)
            or reviewed_at > approval_expires):
        raise BindingError("image approval review is not independent, ordered, or current")
    approval_binding = {"approvalSha256": hashlib.sha256(raw).hexdigest(),
                        "approvalSignatureSha256": hashlib.sha256(owner_sig).hexdigest(),
                        "reviewSha256": hashlib.sha256(review_raw).hexdigest(),
                        "reviewSignatureSha256": hashlib.sha256(review_sig).hexdigest(),
                        "customerTrustSha256": trust_sha}
    return approval, canonical_sha256(approval_binding)


READINESS_APPROVAL_CHECKS = {
    "designatedProject", "trackedTerraformProfile", "localTools", "artifactPreflight", "planInputBinding",
    "artifactTrustCustody", "imageOwnerApproval", "imageIdentityHumanReview",
    "liveProjectLabelAndLifecycle", "requiredAPIsAndIAM", "billingBudget",
    "privateRouteDNSFirewallAndPKI", "terraformExecutionContext", "terraformAuthenticatedPrincipal",
}
READINESS_PROVIDED_INPUT_CHECKS = {
    "actualTerraformInputs", "customerNetworkInputs", "selectedLabOSProfile",
}

def _readiness_check(requirement_id: str, platforms: list[str], required_result: str,
                     input_reference: str, verification_method: str,
                     independent_review: bool) -> dict:
    return {
        "requirementId": requirement_id,
        "platformApplicability": platforms,
        "requiredResult": required_result,
        "inputReference": input_reference,
        "verificationMethod": verification_method,
        "independentReviewRequired": independent_review,
    }


READINESS_CHECK_SCHEMA = {
    "designatedProject": _readiness_check(
        "M3-CLOUD-PROJECT", ["debian-13", "rhel-9", "ubuntu-24.04-supplemental"], "PASS",
        "Explicit --project-id value", "Compare with designated project constant", False),
    "trackedTerraformProfile": _readiness_check(
        "M3-TERRAFORM-SAFETY", ["all"], "PASS", "Tracked Terraform source",
        "Static safety invariant inspection", False),
    "selectedLabOSProfile": _readiness_check(
        "M3-PLATFORM-PROFILE", ["debian-13", "rhel-9", "ubuntu-24.04-supplemental"], "PROVIDED",
        "Customer network input osFamily", "Compare profile with tracked profile", True),
    "localTools": _readiness_check(
        "M3-LOCAL-TOOLS", ["all"], "PASS", "Pinned local toolchain and Skopeo RPM provenance",
        "Verify supported OS and architecture, Rocky RPM signer fingerprint and package digest, installed NEVRA, executable path, SHA-256 and reported version",
        False),
    "customerNetworkInputs": _readiness_check(
        "M3-PRIVATE-NETWORK", ["debian-13", "rhel-9"], "PROVIDED",
        "Customer network input document", "Schema, topology, CIDR and port validation; no live route check", True),
    "artifactPreflight": _readiness_check(
        "M3-ARTIFACTS", ["debian-13", "rhel-9"], "PASS", "Customer artifact preflight report",
        "Cryptographic artifact checks and local digest binding", True),
    "artifactTrustCustody": _readiness_check(
        "M3-TRUST-CUSTODY", ["debian-13", "rhel-9"], "PASS", "Independent custodian confirmation",
        "Out-of-band key fingerprint and ownership review", True),
    "imageOwnerApproval": _readiness_check(
        "M3-IMAGE-IDENTITY", ["debian-13", "rhel-9"], "PASS",
        "Exact image self-link and approval reference in Terraform input document",
        "Validate owner record binding exact image, OS release and architecture", True),
    "imageIdentityHumanReview": _readiness_check(
        "M3-IMAGE-IDENTITY-REVIEW", ["debian-13", "rhel-9"], "PASS",
        "Independent image owner/reviewer evidence",
        "Confirm image metadata does not independently prove OS point release", True),
    "liveProjectLabelAndLifecycle": _readiness_check(
        "M3-CLOUD-PROJECT-LIVE", ["debian-13", "rhel-9"], "PASS", "Project owner evidence",
        "Read-only live project metadata check", True),
    "requiredAPIsAndIAM": _readiness_check(
        "M3-CLOUD-ACCESS", ["debian-13", "rhel-9"], "PASS", "Project owner API/IAM approval",
        "Independent cloud configuration review", True),
    "billingBudget": _readiness_check(
        "M3-COST-CONTROL", ["debian-13", "rhel-9"], "PASS", "Billing owner cost approval",
        "Current pricing and billing headroom review", True),
    "privateRouteDNSFirewallAndPKI": _readiness_check(
        "M3-PRIVATE-CONNECTIVITY", ["debian-13", "rhel-9"], "PASS",
        "Network and PKI owner evidence", "Live private-route, DNS, TLS and firewall acceptance", True),
    "actualTerraformInputs": _readiness_check(
        "M3-PLAN-INPUTS", ["debian-13", "rhel-9"], "PROVIDED",
        "Complete non-secret Terraform JSON variable file",
        "Exact variable set, project, topology and platform validation", True),
    "planInputBinding": _readiness_check(
        "M3-PLAN-BINDING", ["debian-13", "rhel-9"], "PASS", "Readiness-bound Terraform JSON inputs",
        "Canonical SHA-256 over effective values and tracked Terraform source", True),
    "terraformExecutionContext": _readiness_check(
        "M3-TERRAFORM-CONTEXT", ["debian-13", "rhel-9"], "PASS",
        "Explicit Terraform provider principal and binary identity",
        "Allowlisted environment, fixed workspace/configuration, executable digest and principal binding", True),
    "terraformAuthenticatedPrincipal": _readiness_check(
        "M3-TERRAFORM-PRINCIPAL", ["debian-13", "rhel-9"], "PASS",
        "Effective provider identity from an independently authenticated cloud check",
        "Must prove the impersonated service account used by the Google provider; an input value alone is not proof", True),
}
READINESS_CHECK_PLATFORMS = {name: schema["platformApplicability"] for name, schema in READINESS_CHECK_SCHEMA.items()}
READINESS_CHECK_RECORD_FIELDS = {
    "status", "code", "requirementId", "platformApplicability", "inputReference",
    "verificationMethod", "verificationTimestamp", "result", "reason", "independentReviewRequired",
}


def validate_readiness_results(report: dict) -> None:
    """Permit only explicitly supplied configuration inputs under signed review.

    PROVIDED remains a non-verified state. A separate customer signature over
    the exact readiness report and input binding is required by the caller.
    All operational and trust gates must independently be PASS.
    """
    checks = report.get("checks")
    if not isinstance(checks, dict):
        raise BindingError("readiness checks are missing")
    expected = set(READINESS_CHECK_SCHEMA)
    if set(checks) != expected:
        raise BindingError("readiness check set is missing, duplicated, or contains unknown requirements")
    if not READINESS_PROVIDED_INPUT_CHECKS.issubset(checks):
        raise BindingError("readiness omits a required customer-supplied input status")
    provided = set()
    for name, check in checks.items():
        if not isinstance(check, dict) or set(check) != READINESS_CHECK_RECORD_FIELDS:
            raise BindingError("readiness check record is malformed")
        status = check.get("result")
        schema = READINESS_CHECK_SCHEMA[name]
        if (status != check.get("status") or status != schema["requiredResult"]
                or check.get("reason") != check.get("code")
                or any(check.get(field) != schema[field] for field in (
                    "requirementId", "platformApplicability", "inputReference", "verificationMethod",
                    "independentReviewRequired"))):
            raise BindingError("readiness check metadata, platform applicability, or status is invalid")
        if status == "PROVIDED":
            provided.add(name)
        timestamp = check.get("verificationTimestamp")
        if status == "PASS" and (not isinstance(timestamp, str) or not timestamp):
            raise BindingError("verified readiness check lacks its verification timestamp")
        if status == "PROVIDED" and (name not in READINESS_PROVIDED_INPUT_CHECKS
                                      or not isinstance(timestamp, str) or not timestamp):
            raise BindingError("readiness has an unapproved or untimestamped PROVIDED result")
    if provided - READINESS_PROVIDED_INPUT_CHECKS:
        raise BindingError("readiness has a PROVIDED result that is not an explicitly approvable input")
    overall = report.get("overallStatus")
    if (provided and overall != "PROVIDED") or (not provided and overall != "PASS"):
        raise BindingError("readiness overall status conflicts with its detailed results")


def validate_readiness_approval(report_path: Path, report: dict, report_raw: bytes, *,
                                trust_loader=None, now: dt.datetime | None = None) -> dict:
    """Verify a customer-rooted, short-lived authorization of every PASS gate."""
    trust_loader = trust_loader or m3_customer_trust.load_trust
    trust, trust_digest = trust_loader()
    if report_raw != m3_customer_trust.canonical_json(report):
        raise BindingError("readiness report is not canonical JSON")
    approval_path = report_path.with_name(report_path.name + ".approval.json")
    signature_path = approval_path.with_name(approval_path.name + ".sig")
    approval_raw = m3_customer_trust.read_regular(approval_path, 128 * 1024)
    signature = m3_customer_trust.read_regular(signature_path, 4096)
    try:
        approval = json.loads(approval_raw, object_pairs_hook=m3_customer_trust.unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise BindingError("customer Terraform plan authorization is malformed") from error
    required = {"schemaVersion", "readinessReportSha256", "planBindingSha256", "trustConfigurationSha256",
                "approvedChecks", "reviewerIdentity", "decision", "approvedAt", "expiresAt", "rationale"}
    if (not isinstance(approval, dict) or set(approval) != required or approval.get("schemaVersion") != 1
            or approval_raw != m3_customer_trust.canonical_json(approval)):
        raise BindingError("customer Terraform plan authorization is incomplete or noncanonical")
    checks = report.get("checks")
    try:
        validate_readiness_results(report)
    except BindingError as error:
        raise BindingError("customer authorization cannot override a blocked, failed, missing, or unapproved readiness result") from error
    if (not isinstance(checks, dict)
            or any(not isinstance(checks.get(name), dict) or checks[name].get("result") != "PASS"
                   for name in READINESS_APPROVAL_CHECKS)):
        raise BindingError("customer authorization cannot override a blocked, failed, provided, or missing readiness gate")
    if (approval.get("readinessReportSha256") != hashlib.sha256(report_raw).hexdigest()
            or approval.get("planBindingSha256") != canonical_sha256(report.get("planBinding"))
            or approval.get("trustConfigurationSha256") != trust_digest
            or approval.get("decision") != "approved"
            or approval.get("approvedChecks") != sorted(READINESS_APPROVAL_CHECKS)
            or not isinstance(approval.get("rationale"), str) or len(approval["rationale"].strip()) < 12):
        raise BindingError("customer plan authorization does not bind the exact PASS report, plan inputs, and trust")
    try:
        generated = m3_customer_trust.parse_time(report["generatedAt"], "readiness.generatedAt")
        approved = m3_customer_trust.parse_time(approval["approvedAt"], "approval.approvedAt")
        expires = m3_customer_trust.parse_time(approval["expiresAt"], "approval.expiresAt")
        current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    except (KeyError, m3_customer_trust.TrustError) as error:
        raise BindingError("customer plan authorization validity timestamps are invalid") from error
    if (approved < generated or approved > current + dt.timedelta(minutes=2)
            or expires <= current or expires <= approved or expires - approved > dt.timedelta(hours=4)):
        raise BindingError("customer plan authorization is stale, expired, or out of order")
    public, fingerprint = m3_customer_trust.authorized_key(
        trust, approval["reviewerIdentity"], "deployment-approver", now=current)
    m3_customer_trust.verify_signature(approval_raw, signature, public)
    return {"identity": approval["reviewerIdentity"], "fingerprint": fingerprint,
            "trustConfigurationSha256": trust_digest, "approvalSha256": hashlib.sha256(approval_raw).hexdigest()}
