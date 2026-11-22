"""Canonical, secret-free bindings for the self-managed M3 Terraform plan."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import datetime as dt
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit


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
    """Bind Terraform source and every non-secret file embedded into the plan."""
    repository = module.parents[3]
    module_relative = module.relative_to(repository)
    listing = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "--",
                   module_relative.as_posix()],
                  cwd=repository, capture=True)
    # main.tf uses templatefile() and embeds secret_manager_bootstrap.py with
    # file(). Bind those bytes and the provider lock as well as .tf files; a
    # helper change can alter the instance startup script without changing a
    # Terraform expression.
    names = sorted(name for name in listing.splitlines()
                   if name.endswith((".tf", ".tftpl", ".py", ".terraform.lock.hcl")))
    if not names:
        raise BindingError("tracked Terraform source files are unavailable")
    parts = []
    for name in names:
        path = repository / name
        if path.is_symlink() or not path.is_file():
            raise BindingError("tracked Terraform source is unavailable or unsafe")
        data = path.read_bytes()
        relative = Path(name).relative_to(module_relative).as_posix()
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
        if value is None or type(value) in (str, bool, int, float):
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
    require(values.get("region") == expected_region and values.get("zone") == expected_zone
            and values.get("name_prefix") == expected_lab_id,
            "Terraform region, zone, or lab identity differs from readiness inputs")
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
             and re.fullmatch(r"13\.[0-9]+", point or "") is not None)
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


def validate_image_approval(path: Path, *, reader, terraform_values: dict,
                            artifact_report: dict) -> tuple[dict, str]:
    """Check an owner-supplied approval record; it remains subject to human identity review."""
    approval = _load(path, reader)
    expected_keys = {"schemaVersion", "approvalStatus", "approvalReference", "platformProfile",
                     "imageSelfLink", "imageUniqueId", "osId", "osVersion", "pointRelease", "architecture",
                     "imageOwner", "approvedAt", "evidenceReference"}
    if set(approval) != expected_keys or approval.get("schemaVersion") != 1 or approval.get("approvalStatus") != "approved":
        raise BindingError("image approval record is incomplete or not approved")
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
    if not isinstance(approval.get("approvedAt"), str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", approval["approvedAt"]):
        raise BindingError("image approval timestamp must be RFC3339 with a timezone")
    try:
        approved_at = dt.datetime.fromisoformat(approval["approvedAt"].replace("Z", "+00:00"))
    except ValueError as error:
        raise BindingError("image approval timestamp is invalid") from error
    if approved_at.tzinfo is None:
        raise BindingError("image approval timestamp must include a timezone")
    if approved_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
        raise BindingError("image approval timestamp is in the future")
    return approval, canonical_sha256(approval)
