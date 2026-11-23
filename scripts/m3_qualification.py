#!/usr/bin/env python3
"""Authoritative, read-only stage controller for M3 customer qualification.

This controller composes repository checks and inventories customer evidence.
It never invokes Terraform, gcloud, a registry, a customer endpoint, or a host.
Evidence files are classified as PROVIDED/UNVERIFIED until their existing
domain-specific verifier has actually accepted them. Stages never auto-advance.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "kordex-fleet-platform-515416"
REGION = "us-east1"
ZONE = "us-east1-b"
LAB_ID = "kordex-lab"
K3S_VERSION = "v1.36.6+k3s1"
MATRIX_SHA256 = "ba25ba7224b193e4de3d048fae1d4f027c3cca5626bb1734bf3a426d7807c9ad"
PLATFORMS = ("debian-13", "rhel-9.8+")
STATUSES = {"PASS", "FAIL", "PROVIDED", "NOT PROVIDED", "NOT_PROVIDED", "INVALID", "EXPIRED",
            "UNVERIFIED", "VERIFIED", "APPROVED", "BLOCKED"}
HEX = re.compile(r"^[a-f0-9]{64}$")
MAX_INPUT = 16 * 1024 * 1024 * 1024

# This is the authoritative customer-input contract. A null slot means no
# input was supplied. References are relative to the manifest and are always
# treated as untrusted evidence until the named verifier accepts them.
INPUTS: dict[str, dict[str, Any]] = {
    "maintenanceTrustConfiguration": {"owner": "Customer security custodian", "platforms": list(PLATFORMS), "kind": "root-signed customer trust configuration and detached signature"},
    "trustStateBackendConformance": {"owner": "Customer security/platform team", "platforms": list(PLATFORMS), "kind": "durable monotonic trust-state backend conformance report"},
    "signedReleaseBundle": {"owner": "Kordex release owner", "platforms": list(PLATFORMS), "kind": "signed release bundle, detached signature, image digest lock"},
    "toolProvenance": {"owner": "Kordex build/security owner", "platforms": list(PLATFORMS), "kind": "tool provenance public trust and signed provenance lock"},
    "collectorIdentity": {"owner": "Customer security custodian", "platforms": list(PLATFORMS), "kind": "root-authorized collector identity and public key"},
    "reviewerIdentity": {"owner": "Independent customer reviewer", "platforms": list(PLATFORMS), "kind": "distinct root-authorized reviewer identity and public key"},
    "replayRegistryConformance": {"owner": "Customer security/platform team", "platforms": list(PLATFORMS), "kind": "customer-operated durable replay registry conformance report and signed receipt trust"},
    "debianImageApproval": {"owner": "Debian image owner", "platforms": ["debian-13"], "kind": "signed exact project/self-link/image-ID/OS-release/architecture approval"},
    "debianImageIdentityEvidence": {"owner": "Independent Debian image reviewer", "platforms": ["debian-13"], "kind": "independent evidence of installed Debian 13 point release and image provenance"},
    "debianArtifactPreflightInputs": {"owner": "Debian artifact operator", "platforms": ["debian-13"], "kind": "customer-local M3 artifact preflight path map for the exact Debian 13 profile"},
    "debianArtifactPreflightReport": {"owner": "Debian artifact operator", "platforms": ["debian-13"], "kind": "fresh M3 artifact preflight report bound to the Debian 13 policy and artifacts"},
    "debianAptMetadata": {"owner": "Debian package repository owner", "platforms": ["debian-13"], "kind": "signed immutable Trixie and security repository metadata"},
    "debianPackagePolicy": {"owner": "Customer change approver", "platforms": ["debian-13"], "kind": "approved exact package baseline/target/kernel/reboot policy"},
    "debianPackageArtifacts": {"owner": "Debian package repository owner", "platforms": ["debian-13"], "kind": "approved .deb artifacts with package/version/architecture/SHA-256 inventory"},
    "rhelImageApproval": {"owner": "RHEL image owner", "platforms": ["rhel-9.8+"], "kind": "signed exact project/self-link/image-ID/RHEL-minor/architecture approval"},
    "rhelImageIdentityEvidence": {"owner": "Independent RHEL image reviewer", "platforms": ["rhel-9.8+"], "kind": "independent evidence of installed genuine RHEL release and provenance"},
    "rhelArtifactPreflightInputs": {"owner": "RHEL artifact operator", "platforms": ["rhel-9.8+"], "kind": "customer-local M3 artifact preflight path map for the exact RHEL 9 profile"},
    "rhelArtifactPreflightReport": {"owner": "RHEL artifact operator", "platforms": ["rhel-9.8+"], "kind": "fresh M3 artifact preflight report bound to the RHEL 9 policy and artifacts"},
    "rhelEntitlement": {"owner": "Customer RHEL subscription owner", "platforms": ["rhel-9.8+"], "kind": "non-secret entitlement/subscription status evidence"},
    "rhelRpmMetadata": {"owner": "RHEL package repository owner", "platforms": ["rhel-9.8+"], "kind": "signed private RPM repository metadata and signing-key identity"},
    "rhelPackagePolicy": {"owner": "Customer change approver", "platforms": ["rhel-9.8+"], "kind": "approved exact package baseline/target/kernel/reboot/SELinux policy"},
    "rhelPackageArtifacts": {"owner": "RHEL package repository owner", "platforms": ["rhel-9.8+"], "kind": "approved RPM artifacts with NEVRA/architecture/SHA-256 inventory"},
    "k3sBinaryLockAndSignature": {"owner": "K3s artifact approver", "platforms": list(PLATFORMS), "kind": "approved K3s binary, signed lock, signature and trust"},
    "k3sSystemImagesAndLock": {"owner": "K3s artifact approver", "platforms": list(PLATFORMS), "kind": "verified K3s system-image archive, signed lock and signature"},
    "kordexOciDigestLock": {"owner": "Kordex release owner", "platforms": list(PLATFORMS), "kind": "signed lock for all required Kordex OCI image digests"},
    "privateRegistryVerification": {"owner": "Private registry administrator", "platforms": list(PLATFORMS), "kind": "read-only destination digest and architecture verification report"},
    "helmSignerAllowlist": {"owner": "Customer platform security owner", "platforms": list(PLATFORMS), "kind": "approved Helm signer identity allowlist"},
    "gcpProjectOwnership": {"owner": "GCP project owner", "platforms": list(PLATFORMS), "kind": "independent project ID/number/ownership and designation evidence"},
    "gcpDisposableLabDesignation": {"owner": "GCP project owner", "platforms": list(PLATFORMS), "kind": "customer-approved disposable qualification designation and project labels"},
    "labDesignApproval": {"owner": "Customer platform owner", "platforms": list(PLATFORMS), "kind": "explicit confirmation of designated project, region, zone, lab topology and no-public-IP/no-NAT design"},
    "gcpPrincipalAttestation": {"owner": "GCP identity administrator", "platforms": list(PLATFORMS), "kind": "signed live authenticated-principal and impersonation attestation"},
    "gcpApiIamReview": {"owner": "GCP security administrator", "platforms": list(PLATFORMS), "kind": "approved API and least-privilege IAM review"},
    "gcpBillingBudget": {"owner": "GCP billing owner", "platforms": list(PLATFORMS), "kind": "current billing headroom and itemized spend estimate under hard USD 300 ceiling"},
    "gcpQuotaCapacity": {"owner": "GCP project owner", "platforms": list(PLATFORMS), "kind": "regional quota, image availability and capacity review"},
    "gcpIapOsLoginSerial": {"owner": "GCP access administrator", "platforms": list(PLATFORMS), "kind": "IAP/OS Login and serial recovery review"},
    "networkApproval": {"owner": "Customer network administrator", "platforms": list(PLATFORMS), "kind": "approved private CIDRs/routes/firewall/DNS/ports review"},
    "networkConfiguration": {"owner": "Customer network administrator", "platforms": list(PLATFORMS), "kind": "exact customer network inputs consumed by guarded lab readiness"},
    "relayPkiEvidence": {"owner": "Customer PKI/network administrator", "platforms": list(PLATFORMS), "kind": "public CA/certificate chain/SAN-to-cluster and rotation evidence; never private keys"},
    "connectivityEvidence": {"owner": "Customer network operator", "platforms": list(PLATFORMS), "kind": "signed live private-route connectivity and recovery test evidence"},
    "planReviewApproval": {"owner": "Independent deployment approver", "platforms": list(PLATFORMS), "kind": "signed approval binding exact plan digest and execution context"},
    "applyApproval": {"owner": "Separate infrastructure approver", "platforms": list(PLATFORMS), "kind": "separate signed authorization for the exact saved plan"},
    "postCreationImageEvidence": {"owner": "Independent infrastructure reviewer", "platforms": list(PLATFORMS), "kind": "created VM and boot-disk source self-link/image-ID verification"},
    "maintenanceApproval": {"owner": "Customer maintenance owner", "platforms": list(PLATFORMS), "kind": "signed host/operation/package/window approval"},
    "faultInjectionApprovals": {"owner": "Customer safety and platform owners", "platforms": list(PLATFORMS), "kind": "scenario-specific bounded fault approval and restoration mechanism"},
    "hostInventory": {"owner": "Customer cluster administrator", "platforms": list(PLATFORMS), "kind": "approved host/machine-ID/Kubernetes-Node identity inventory"},
    "evidenceCustody": {"owner": "Customer evidence custodian", "platforms": list(PLATFORMS), "kind": "customer-controlled immutable evidence location and retention record"},
    "executionWindow": {"owner": "Customer maintenance owner", "platforms": list(PLATFORMS), "kind": "approved execution window with recovery owner and escalation contact"},
}


class QualificationError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise QualificationError("qualification input is not canonical JSON") from error


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError("duplicate JSON key")
        result[key] = value
    return result


def read_json(path: Path, limit: int = 2 * 1024 * 1024) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or len(raw) != before.st_size or len(raw) > limit
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise QualificationError("qualification JSON is unsafe or changed while reading")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QualificationError("qualification JSON is unavailable or malformed") from error
    if not isinstance(value, dict):
        raise QualificationError("qualification document must be an object")
    return value


def validate_manifest(manifest: dict) -> None:
    required = {"schemaVersion", "customerId", "projectId", "region", "zone", "labId", "fixtureOnly",
                "canonicalMatrixSha256", "k3sVersion", "platformTargets", "residualRiskAcceptance", "inputs"}
    if set(manifest) != required or manifest.get("schemaVersion") != 1 or type(manifest.get("schemaVersion")) is not int:
        raise QualificationError("customer input manifest schema is incomplete or unsupported")
    if (not isinstance(manifest.get("customerId"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", manifest["customerId"])
            or manifest.get("projectId") != PROJECT or manifest.get("region") != REGION or manifest.get("zone") != ZONE
            or manifest.get("labId") != LAB_ID or manifest.get("canonicalMatrixSha256") != MATRIX_SHA256
            or manifest.get("k3sVersion") != K3S_VERSION
            or type(manifest.get("fixtureOnly")) is not bool):
        raise QualificationError("customer or designated project/region/zone binding is invalid")
    entries = manifest.get("inputs")
    if not isinstance(entries, dict) or set(entries) != set(INPUTS):
        missing = sorted(set(INPUTS) - set(entries or {})) if isinstance(entries, dict) else sorted(INPUTS)
        unknown = sorted(set(entries or {}) - set(INPUTS)) if isinstance(entries, dict) else []
        raise QualificationError(f"input inventory must contain every required slot exactly once (missing={missing}, unknown={unknown})")
    targets = manifest.get("platformTargets")
    if not isinstance(targets, dict) or set(targets) != set(PLATFORMS):
        raise QualificationError("platformTargets must contain Debian 13 and RHEL 9.8+ exactly")
    target_fields = {"osId", "osVersion", "architecture", "imageProject", "imageSelfLink", "imageId",
                     "packagePolicySha256"}
    image_pattern = re.compile(r"^https://www\.googleapis\.com/compute/v1/projects/[^/]+/global/images/[^/]+$")
    for platform, target in targets.items():
        if target is None:
            continue
        if not isinstance(target, dict) or set(target) != target_fields:
            raise QualificationError(f"{platform} image target is incomplete")
        if (target.get("architecture") != "amd64" or not isinstance(target.get("imageProject"), str)
                or not target["imageProject"] or not isinstance(target.get("imageSelfLink"), str)
                or not image_pattern.fullmatch(target["imageSelfLink"])
                or f"/projects/{target['imageProject']}/" not in target["imageSelfLink"]
                or not isinstance(target.get("imageId"), str) or not re.fullmatch(r"[1-9][0-9]*", target["imageId"])
                or not HEX.fullmatch(target.get("packagePolicySha256", ""))):
            raise QualificationError(f"{platform} image identity, architecture or package policy binding is invalid")
        version = target.get("osVersion")
        if platform == "debian-13":
            if (target.get("osId") != "debian" or target.get("imageProject") != "debian-cloud"
                    or not isinstance(version, str) or not re.fullmatch(r"13\.[0-9]+", version)):
                raise QualificationError("Debian target must bind an exact Debian 13 point release")
            policy_slot = "debianPackagePolicy"
            approval_slot = "debianImageApproval"
        else:
            match = re.fullmatch(r"9\.([0-9]+)", version if isinstance(version, str) else "")
            if target.get("osId") != "rhel" or not match or int(match.group(1)) < 8:
                raise QualificationError("RHEL target must bind genuine RHEL 9.8 or later, not a derivative")
            policy_slot = "rhelPackagePolicy"
            approval_slot = "rhelImageApproval"
        policy = entries.get(policy_slot)
        approval = entries.get(approval_slot)
        if (not isinstance(policy, dict) or policy.get("sha256") != target["packagePolicySha256"]
                or not isinstance(approval, dict)):
            raise QualificationError(f"{platform} image target must bind its package policy and image-owner approval inputs")
    acceptances = manifest.get("residualRiskAcceptance")
    if not isinstance(acceptances, dict) or set(acceptances) != set(PLATFORMS):
        raise QualificationError("residualRiskAcceptance must include separate Debian and RHEL scopes")
    acceptance_fields = {"riskId", "organization", "individual", "acceptedAt", "expiresAt", "projectId",
                         "labId", "platform", "imageSelfLink", "imageId", "recordReference", "recordSha256",
                         "signatureReference", "signatureSha256", "signerIdentity"}
    for platform, acceptance in acceptances.items():
        if acceptance is None:
            continue
        if not isinstance(acceptance, dict) or set(acceptance) != acceptance_fields:
            raise QualificationError(f"{platform} residual image-race acceptance record is incomplete")
        target = targets.get(platform)
        if target is None:
            raise QualificationError(f"{platform} residual risk cannot be accepted without an exact selected image")
        if (acceptance.get("riskId") != "GCE-BOOT-DISK-IMAGE-CREATE-TOCTOU"
                or not isinstance(acceptance.get("organization"), str) or not acceptance["organization"]
                or not isinstance(acceptance.get("individual"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", acceptance["individual"])
                or not isinstance(acceptance.get("signerIdentity"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", acceptance["signerIdentity"])
                or acceptance.get("projectId") != PROJECT or acceptance.get("labId") != LAB_ID
                or acceptance.get("platform") != platform
                or acceptance.get("imageSelfLink") != target["imageSelfLink"]
                or acceptance.get("imageId") != target["imageId"]
                or not isinstance(acceptance.get("recordReference"), str)
                or not isinstance(acceptance.get("signatureReference"), str)
                or not isinstance(acceptance.get("recordSha256"), str)
                or not HEX.fullmatch(acceptance.get("recordSha256", ""))
                or not isinstance(acceptance.get("signatureSha256"), str)
                or not HEX.fullmatch(acceptance.get("signatureSha256", ""))):
            raise QualificationError(f"{platform} residual risk record does not bind the exact approved image and lab")
        parse_time(acceptance["acceptedAt"])
        expires = parse_time(acceptance["expiresAt"])
        if expires <= parse_time(acceptance["acceptedAt"]):
            raise QualificationError(f"{platform} residual risk acceptance expiry must follow acceptance time")
        if (Path(acceptance["recordReference"]).is_absolute() or ".." in Path(acceptance["recordReference"]).parts
                or Path(acceptance["signatureReference"]).is_absolute()
                or ".." in Path(acceptance["signatureReference"]).parts
                or acceptance["recordReference"] == acceptance["signatureReference"]
                or any(word in (acceptance["recordReference"] + acceptance["signatureReference"]).lower()
                       for word in ("tfvars", "tfstate", "private-key", "credential", "password", "token"))):
            raise QualificationError(f"{platform} residual risk record path is unsafe")
    for input_id, item in entries.items():
        if item is None:
            continue
        if not isinstance(item, dict) or set(item) != {"reference", "sha256", "expiresAt"}:
            raise QualificationError(f"input {input_id} must be null or a reference/hash/expiry object")
        reference, digest, expires = item["reference"], item["sha256"], item["expiresAt"]
        if (not isinstance(reference, str) or not reference or Path(reference).is_absolute()
                or ".." in Path(reference).parts or not isinstance(digest, str) or not HEX.fullmatch(digest)
                or any(word in reference.lower() for word in ("tfvars", "tfstate", "private-key", "credential", "password", "token"))):
            raise QualificationError(f"input {input_id} reference is unsafe or malformed")
        if expires is not None:
            parse_time(expires)


def validate_platform_targets(manifest: dict) -> None:
    """Validate explicit release/image bindings without treating them as proof."""
    validate_manifest(manifest)
    for platform, target in manifest["platformTargets"].items():
        if target is None:
            continue
        if target["imageId"] == "0" or target["imageSelfLink"].endswith("/"):
            raise QualificationError(f"{platform} image identity is not a concrete approved image")


def parse_time(value: object) -> dt.datetime:
    if not isinstance(value, str):
        raise QualificationError("input expiry must be RFC3339")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError("input expiry must be RFC3339") from error
    if result.tzinfo is None:
        raise QualificationError("input expiry must include a timezone")
    return result.astimezone(dt.timezone.utc)


def inspect_reference(manifest_path: Path, input_id: str, item: dict | None, now: dt.datetime) -> dict:
    contract = INPUTS.get(input_id, {"owner": "Customer residual-risk approver",
                                     "platforms": [input_id.split(":", 1)[-1]],
                                     "kind": "signed image create-time identity race acceptance artifact"})
    common = {"inputId": input_id, "owner": contract["owner"],
              "platforms": contract["platforms"], "kind": contract["kind"]}
    if item is None:
        return {**common, "status": "NOT_PROVIDED", "reason": "required input reference is absent"}
    if item.get("expiresAt") is not None and parse_time(item["expiresAt"]) <= now:
        return {**common, "status": "EXPIRED", "reason": "input expiry is in the past"}
    path = manifest_path.parent / item["reference"]
    try:
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(manifest_path.parent.resolve(strict=True)):
            raise QualificationError("input reference escapes manifest directory or is a symlink")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_INPUT:
                raise QualificationError("input reference is not a bounded regular file")
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise QualificationError("input changed during hashing")
    except (OSError, RuntimeError, QualificationError):
        return {**common, "status": "INVALID", "reason": "input is unavailable or unsafe"}
    if digest.hexdigest() != item["sha256"]:
        return {**common, "status": "INVALID", "reason": "SHA-256 differs from manifest"}
    return {**common, "status": "UNVERIFIED", "reason": "reference and checksum match; domain-specific independent verification is still required"}


def load_input_report(path: Path, now: dt.datetime | None = None) -> dict:
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    manifest = read_json(path)
    validate_manifest(manifest)
    structural = load_matrix_verifier()
    if structural.FAILURE_MATRIX_SHA256 != MATRIX_SHA256:
        raise QualificationError("controller canonical matrix digest differs from pinned evidence verifier")
    structural.verify_pinned_matrix(ROOT / "tests/integration/host_upgrade_failure_matrix.json")
    items = [inspect_reference(path, key, value, current) for key, value in sorted(manifest["inputs"].items())]
    residual = {}
    for platform, acceptance in sorted(manifest["residualRiskAcceptance"].items()):
        if acceptance is None:
            residual[platform] = {"status": "NOT_PROVIDED", "riskId": "GCE-BOOT-DISK-IMAGE-CREATE-TOCTOU",
                                  "owner": "Customer infrastructure risk owner",
                                  "reason": "signed, image-scoped residual-risk acceptance is missing"}
            continue
        record = inspect_reference(path, f"residualRiskAcceptance:{platform}",
                                   {"reference": acceptance["recordReference"],
                                    "sha256": acceptance["recordSha256"],
                                    "expiresAt": acceptance["expiresAt"]}, current)
        signature = inspect_reference(path, f"residualRiskSignature:{platform}",
                                      {"reference": acceptance["signatureReference"],
                                       "sha256": acceptance["signatureSha256"],
                                       "expiresAt": acceptance["expiresAt"]}, current)
        state = "INVALID" if "INVALID" in {record["status"], signature["status"]} else (
            "EXPIRED" if "EXPIRED" in {record["status"], signature["status"]} else "UNVERIFIED")
        residual[platform] = {"status": "BLOCKED" if manifest["fixtureOnly"] else state,
                              "riskId": acceptance["riskId"], "owner": "Customer infrastructure risk owner",
                              "organization": acceptance["organization"], "individual": acceptance["individual"],
                              "acceptedAt": acceptance["acceptedAt"], "expiresAt": acceptance["expiresAt"],
                              "projectId": acceptance["projectId"], "labId": acceptance["labId"],
                              "platform": platform, "imageSelfLink": acceptance["imageSelfLink"],
                              "imageId": acceptance["imageId"], "signerIdentity": acceptance["signerIdentity"],
                              "signatureVerified": False,
                              "reason": "record hashes match at most; customer-rooted signer and independent approval are not verified"}
    if manifest["fixtureOnly"]:
        for item in items:
            if item["status"] == "UNVERIFIED":
                item["status"] = "BLOCKED"
                item["reason"] = "synthetic example is never production evidence"
        for item in residual.values():
            item["status"] = "BLOCKED"
            item["reason"] = "synthetic example is never production evidence"
    states = {item["status"] for item in items}
    if manifest["fixtureOnly"]:
        aggregate = "BLOCKED"
    elif "INVALID" in states:
        aggregate = "INVALID"
    elif "EXPIRED" in states:
        aggregate = "EXPIRED"
    elif "NOT_PROVIDED" in states:
        aggregate = "NOT_PROVIDED"
    elif "UNVERIFIED" in states:
        aggregate = "UNVERIFIED"
    else:
        aggregate = "VERIFIED"
    if any(value["status"] not in {"VERIFIED", "APPROVED"} for value in residual.values()):
        aggregate = "BLOCKED"
    artifact_preflights = {}
    for platform, stem in (("debian-13", "debian"), ("rhel-9.8+", "rhel")):
        config_slot, report_slot = f"{stem}ArtifactPreflightInputs", f"{stem}ArtifactPreflightReport"
        artifact_preflights[platform] = validate_artifact_preflight_refs(
            path, manifest, platform, config_slot, report_slot, current)
    preflight_states = {item["status"] for item in artifact_preflights.values()}
    if "INVALID" in preflight_states:
        aggregate = "INVALID"
    elif "EXPIRED" in preflight_states:
        aggregate = "EXPIRED"
    elif "FAIL" in preflight_states:
        aggregate = "FAIL"
    elif "BLOCKED" in preflight_states:
        aggregate = "BLOCKED"
    elif "NOT_PROVIDED" in preflight_states and aggregate in {"VERIFIED", "APPROVED"}:
        aggregate = "NOT_PROVIDED"
    elif "UNVERIFIED" in preflight_states and aggregate in {"VERIFIED", "APPROVED"}:
        aggregate = "UNVERIFIED"
    return {"schemaVersion": 1, "customerId": manifest["customerId"], "projectId": PROJECT,
            "fixtureOnly": manifest["fixtureOnly"],
            "inputs": items, "inputManifestSha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
            "platformTargets": {platform: {"status": "NOT_PROVIDED" if target is None else "UNVERIFIED",
                                             "osId": target.get("osId") if target else None,
                                             "osVersion": target.get("osVersion") if target else None,
                                             "architecture": target.get("architecture") if target else None,
                                             "imageProject": target.get("imageProject") if target else None,
                                             "imageSelfLink": target.get("imageSelfLink") if target else None,
                                             "imageId": target.get("imageId") if target else None,
                                             "packagePolicySha256": target.get("packagePolicySha256") if target else None,
                                             "independentApprovalVerified": False}
                               for platform, target in manifest["platformTargets"].items()},
            "residualRiskAcceptances": residual, "artifactPreflights": artifact_preflights,
            "productionReadiness": aggregate}


def validate_artifact_preflight_refs(manifest_path: Path, manifest: dict, platform: str,
                                     config_slot: str, report_slot: str, now: dt.datetime) -> dict:
    """Read-only recheck of existing artifact-preflight reports.

    The helper verifies report freshness and file/input bindings. Its unsigned
    report is still only PROVIDED/UNVERIFIED and cannot substitute for signed
    customer trust or independent review.
    """
    config_ref, report_ref = manifest["inputs"].get(config_slot), manifest["inputs"].get(report_slot)
    if manifest["fixtureOnly"]:
        return {"platform": platform, "status": "BLOCKED", "reason": "synthetic input manifests cannot establish artifact readiness"}
    if config_ref is None or report_ref is None:
        return {"platform": platform, "status": "NOT_PROVIDED",
                "reason": "platform-specific artifact preflight inputs and report are required"}
    config_status = inspect_reference(manifest_path, config_slot, config_ref, now)
    report_status = inspect_reference(manifest_path, report_slot, report_ref, now)
    if config_status["status"] == "INVALID" or report_status["status"] == "INVALID":
        return {"platform": platform, "status": "INVALID", "reason": "artifact preflight reference or digest is invalid"}
    if config_status["status"] == "EXPIRED" or report_status["status"] == "EXPIRED":
        return {"platform": platform, "status": "EXPIRED", "reason": "artifact preflight reference is expired"}
    config_path, report_path = manifest_path.parent / config_ref["reference"], manifest_path.parent / report_ref["reference"]
    try:
        checked = recheck_existing_artifact_preflight(config_path, report_path, now=now)
        if checked.get("status") != "PASS":
            return {"platform": platform, "status": "FAIL", "reason": "existing artifact preflight is stale, invalid, or not PASS"}
        report = read_json(report_path, 1024 * 1024)
        package = report["artifacts"]["hostPackageArtifacts"]
        target = manifest["platformTargets"].get(platform)
        expected_os = "debian" if platform == "debian-13" else "rhel"
        if (target is None or package.get("osId") != expected_os
                or package.get("osPointRelease") != target["osVersion"]
                or package.get("architecture") != target["architecture"]
                or package.get("policySha256") != target["packagePolicySha256"]):
            return {"platform": platform, "status": "FAIL",
                    "reason": "artifact preflight release, architecture, or package-policy binding differs from selected platform target"}
    except (OSError, ValueError, TypeError, KeyError, ImportError, AssertionError):
        return {"platform": platform, "status": "INVALID", "reason": "existing artifact preflight could not be safely rechecked"}
    return {"platform": platform, "status": "UNVERIFIED",
            "reason": "fresh local preflight report and exact package binding check passed; report origin and customer approval remain unverified"}


def recheck_existing_artifact_preflight(config_path: Path, report_path: Path, *, now: dt.datetime) -> dict:
    spec = importlib.util.spec_from_file_location("m3_deployment_readiness_for_controller",
                                                   ROOT / "scripts/m3_deployment_readiness.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.check_artifact_preflight(config_path, report_path, now=now)


def load_matrix_verifier():
    spec = importlib.util.spec_from_file_location("m3_matrix_verifier", ROOT / "scripts/verify-host-upgrade-qualification.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def verify_residual_risk_acceptance(manifest_path: Path, platform: str, trusted_configuration: object,
                                    *, now: dt.datetime | None = None) -> dict:
    """Verify the signed, exact-image-scoped TOCTOU risk acceptance.

    The trust snapshot must come from ``m3_trust_state.load_customer_trust``;
    a caller-provided document or matching fingerprint is not an accepted source.
    """
    try:
        try:
            from m3_trust_state import VerifiedCustomerTrust
        except ModuleNotFoundError:
            from scripts.m3_trust_state import VerifiedCustomerTrust
    except ImportError as error:
        raise QualificationError("durably verified customer trust integration is unavailable") from error
    if not isinstance(trusted_configuration, VerifiedCustomerTrust):
        raise QualificationError("residual-risk approval requires the opaque root-verified, monotonic trust snapshot")
    manifest = read_json(manifest_path)
    validate_manifest(manifest)
    if manifest["fixtureOnly"]:
        raise QualificationError("synthetic input manifests cannot approve residual risk")
    acceptance = manifest["residualRiskAcceptance"].get(platform)
    if acceptance is None:
        raise QualificationError(f"{platform} residual image-race acceptance is not provided")
    target = manifest["platformTargets"].get(platform)
    if target is None:
        raise QualificationError(f"{platform} exact image target is not provided")
    root = manifest_path.parent.resolve(strict=True)

    def read_bound(relative: str, expected_sha: str, limit: int) -> bytes:
        candidate = manifest_path.parent / relative
        try:
            if candidate.is_symlink() or not candidate.resolve(strict=True).is_relative_to(root):
                raise QualificationError("risk acceptance file escapes its input directory")
            fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                raw = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or len(raw) != before.st_size or len(raw) > limit
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or hashlib.sha256(raw).hexdigest() != expected_sha):
                raise QualificationError("risk acceptance file is unsafe or its digest differs")
            return raw
        except (OSError, RuntimeError) as error:
            raise QualificationError("risk acceptance file is unavailable or unsafe") from error

    record_raw = read_bound(acceptance["recordReference"], acceptance["recordSha256"], 64 * 1024)
    signature = read_bound(acceptance["signatureReference"], acceptance["signatureSha256"], 4096)
    record = json.loads(record_raw.decode("utf-8"), object_pairs_hook=unique_object)
    record_fields = {"schemaVersion", "riskId", "riskDescription", "organization", "approverIdentity",
                     "acceptedAt", "expiresAt", "projectId", "labId", "platform", "imageSelfLink",
                     "imageId", "rationale"}
    expected_description = ("Compute Engine boot-disk creation resolves the approved image by self-link/name; "
                           "an image may be replaced between final pre-apply verification and disk creation. "
                           "Post-create sourceImage/sourceImageId checks detect a mismatch after creation but "
                           "do not prevent the race.")
    expected = {"schemaVersion": 1, "riskId": acceptance["riskId"], "riskDescription": expected_description,
                "organization": acceptance["organization"], "approverIdentity": acceptance["individual"],
                "acceptedAt": acceptance["acceptedAt"], "expiresAt": acceptance["expiresAt"],
                "projectId": acceptance["projectId"], "labId": acceptance["labId"],
                "platform": platform, "imageSelfLink": target["imageSelfLink"],
                "imageId": target["imageId"]}
    if (not isinstance(record, dict) or set(record) != record_fields
            or record_raw != canonical_json(record)
            or any(record.get(key) != value for key, value in expected.items())
            or not isinstance(record.get("rationale"), str) or not record["rationale"].strip()
            or len(signature) != 64):
        raise QualificationError("signed residual-risk record does not bind the exact customer, image, platform and risk")
    try:
        try:
            from m3_customer_trust import authorized_key, verify_signature
        except ModuleNotFoundError:
            from scripts.m3_customer_trust import authorized_key, verify_signature
        public_key, fingerprint = authorized_key(trusted_configuration.document, acceptance["signerIdentity"],
                                                 "residual-risk-approver", now=now)
        if acceptance["signerIdentity"] != acceptance["individual"]:
            raise QualificationError("residual-risk approver identity differs from signed individual")
        verify_signature(record_raw, signature, public_key)
        accepted_at, expires = parse_time(acceptance["acceptedAt"]), parse_time(acceptance["expiresAt"])
        current = now or dt.datetime.now(dt.timezone.utc)
        if accepted_at > current + dt.timedelta(minutes=2) or expires <= current or expires <= accepted_at:
            raise QualificationError("residual-risk acceptance is future-dated or expired")
    except (ValueError, TypeError) as error:
        if isinstance(error, QualificationError):
            raise
        raise QualificationError("customer-rooted residual-risk signature verification failed") from error
    return {"status": "APPROVED", "riskId": acceptance["riskId"], "platform": platform,
            "projectId": PROJECT, "labId": LAB_ID, "imageSelfLink": target["imageSelfLink"],
            "imageId": target["imageId"], "approverIdentity": acceptance["individual"],
            "approverFingerprint": fingerprint, "signatureVerified": True,
            "requiresIndependentReview": True}


def stage_result(stage: str, status: str, reason: str, *, next_action: str, details: dict | None = None) -> dict:
    if status not in STATUSES:
        raise QualificationError("internal stage status is invalid")
    return {"stage": stage, "status": status, "reason": reason, "nextAction": next_action,
            "details": details or {}}


def stage_dependencies(stage: str) -> list[dict]:
    """Return exact open dependency records relevant to one blocked stage."""
    dependency_path = ROOT / "docs/m3-qualification-dependencies.json"
    graph = read_json(dependency_path, 2 * 1024 * 1024)
    validate_dependency_graph(graph)
    return [item for item in graph["dependencies"]
            if stage in {part.strip() for part in item["consumingStage"].split(",")}
            and item["currentStatus"] not in {"IMPLEMENTED", "LOCALLY VERIFIED"}]


def run_stage(stage: str, *, inputs_path: Path | None = None, evidence_path: Path | None = None,
              trusted_customer_configuration: object | None = None) -> dict:
    """Evaluate exactly one stage; no stage starts another stage or external operation."""
    if stage == "inspect":
        readiness_spec = importlib.util.spec_from_file_location("m3_deployment_readiness", ROOT / "scripts/m3_deployment_readiness.py")
        module = importlib.util.module_from_spec(readiness_spec)
        assert readiness_spec and readiness_spec.loader
        readiness_spec.loader.exec_module(module)
        checks = module.report(PROJECT, None, None, None)
        local = {name: checks["checks"][name] for name in ("trackedTerraformProfile", "localTools")}
        for item in local.values():
            if "verificationTimestamp" in item:
                # These are deterministic source/tool checks, not timestamped
                # customer verification records.
                item["verificationTimestamp"] = None
        local["trackedProjectDesignation"] = {"status": "PASS", "code": "TrackedProjectTargetOnly",
                                                "projectId": PROJECT, "liveProjectVerified": False}
        gate_source = (ROOT / "operator/cmd/kordex-operator/main.go").read_text(encoding="utf-8")
        default_off = ('switch os.Getenv("KORDEX_ENABLE_HOST_UPGRADES")' in gate_source
                       and 'case "", "false":\n\t\treturn nil, nil' in gate_source
                       and 'case "true":' in gate_source)
        local["hostUpgradeGateDefaultOff"] = {"status": "PASS" if default_off else "FAIL",
                                               "code": "HostUpgradeGateDefaultOff" if default_off else "HostUpgradeGateDefaultNotProven"}
        local_statuses = [item["status"] for item in local.values()]
        result_status = ("FAIL" if "FAIL" in local_statuses else
                         "BLOCKED" if any(value != "PASS" for value in local_statuses) else "PASS")
        reason = ("local repository/tool checks only" if result_status == "PASS" else
                  "a local tool prerequisite is unavailable" if result_status == "BLOCKED" else
                  "a local repository safety check failed")
        return stage_result(stage, result_status, reason,
                            next_action="python3 scripts/m3_qualification.py inputs --manifest <customer-manifest.json>",
                            details={"checks": local, "externalChecksPerformed": False})
    if stage == "inputs":
        if inputs_path is None:
            return stage_result(stage, "NOT_PROVIDED", "customer input manifest not supplied", next_action="create all version-1 input slots from docs/schemas/m3-customer-inputs-v1.json")
        try:
            result = load_input_report(inputs_path)
            pending = sum(x["status"] not in {"VERIFIED", "APPROVED"} for x in result["inputs"])
            state = "BLOCKED" if result["fixtureOnly"] else result["productionReadiness"]
            return stage_result(stage, state, f"{pending} input slots are not independently verified", next_action="run the artifact/trust verifier named for each provided input; hashes alone never establish approval", details=result)
        except (QualificationError, OSError, ValueError) as error:
            return stage_result(stage, "INVALID", str(error), next_action="correct the manifest and rerun inputs")
    if stage == "qualification":
        if inputs_path is None:
            return stage_result(stage, "BLOCKED", "customer manifest and signed residual image-race acceptance are required before qualification",
                                next_action="customer infrastructure owner supplies the exact-image signed acceptance for Debian and RHEL")
        try:
            input_report = load_input_report(inputs_path)
            if input_report["fixtureOnly"]:
                return stage_result(stage, "BLOCKED", "synthetic input fixture cannot authorize qualification",
                                    next_action="supply real customer inputs; fixture evidence is never accepted")
            incomplete = [item["inputId"] for item in input_report["inputs"]
                          if item["status"] not in {"VERIFIED", "APPROVED"}]
            unverified_targets = [platform for platform, target in input_report["platformTargets"].items()
                                  if target["status"] != "APPROVED" or not target["independentApprovalVerified"]]
            if incomplete or unverified_targets:
                unverified_risk = [platform for platform, item in input_report["residualRiskAcceptances"].items()
                                   if item.get("status") != "APPROVED"]
                return stage_result(stage, "BLOCKED",
                                    "all customer artifacts, trust results, exact images, and platform approvals must be verified before qualification",
                                    next_action="finish each input's domain-specific independent verifier and attach the approved exact Debian/RHEL image evidence",
                                    details={"unverifiedInputs": incomplete, "unverifiedPlatformTargets": unverified_targets,
                                             "unverifiedResidualRiskAcceptances": unverified_risk,
                                             "artifactPreflights": input_report["artifactPreflights"],
                                             "residualRiskAcceptances": input_report["residualRiskAcceptances"]})
            risk = {}
            for platform in PLATFORMS:
                if trusted_customer_configuration is None:
                    risk[platform] = input_report["residualRiskAcceptances"][platform]
                else:
                    risk[platform] = verify_residual_risk_acceptance(
                        inputs_path, platform, trusted_customer_configuration)
            unapproved = [platform for platform, result in risk.items() if result.get("status") != "APPROVED"]
            if unapproved:
                return stage_result(stage, "BLOCKED", "image create-time identity race acceptance is missing or not independently verified for every selected platform",
                                    next_action="root-trust authorized residual-risk approver signs the exact lab/image scope; verify against customer-rooted trust",
                                    details={"residualRiskAcceptances": risk,
                                             "residualRiskDescription": "GCE boot-disk source image is resolved by mutable self-link/name; post-create sourceImage/sourceImageId checks detect, but do not eliminate, substitution before disk creation"})
        except (QualificationError, OSError, ValueError, TypeError) as error:
            return stage_result(stage, "BLOCKED", f"qualification input or residual-risk acceptance is invalid: {error}",
                                next_action="repair the customer manifest and obtain independently verifiable acceptance")
        if evidence_path is None:
            return stage_result(stage, "NOT_PROVIDED", "real-host evidence directory not supplied", next_action="after approved deployment and preflight, run one approved canonical matrix scenario at a time")
        try:
            spec = importlib.util.spec_from_file_location("host_qualification_verifier", ROOT / "scripts/verify-host-upgrade-qualification.py")
            verifier = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(verifier)
            matrix_path = ROOT / "tests/integration/host_upgrade_failure_matrix.json"
            verifier.verify_pinned_matrix(matrix_path)
            verified = verifier.verify_directory(matrix_path, evidence_path)
            return stage_result(stage, "UNVERIFIED", "structural evidence checks passed; no host-origin, trust, or reviewer acceptance is implied",
                                next_action="run the customer-rooted provenance verifier after all 22 rows exist",
                                details={"structuralRows": len(verified), "realHostQualified": False})
        except Exception as error:
            return stage_result(stage, "INVALID", f"structural qualification evidence rejected: {error}", next_action="repair evidence without replaying mutations")
    if stage == "trust":
        return stage_result(stage, "BLOCKED", "customer root-signed trust configuration requires durable customer-backed monotonic state; no production backend selected/configured",
                            next_action="security owner selects and deploys a durable CAS trust-state backend, then supplies its independently reviewed conformance report",
                            details={"dependencies": stage_dependencies(stage)})
    if stage == "cloud-review":
        return stage_result(stage, "BLOCKED", "live project, authenticated principal, IAM/API, quota, recovery and billing evidence has not been independently verified",
                            next_action="GCP owner completes the read-only project and cost review; no GCP query was run",
                            details={"dependencies": stage_dependencies(stage)})
    if stage == "plan-review":
        return stage_result(stage, "BLOCKED", "no separately reviewed saved Terraform plan has been supplied; this controller does not invoke Terraform",
                            next_action="after all preceding approvals, use the guarded lab plan command and obtain independent review; do not apply from this controller",
                            details={"dependencies": stage_dependencies(stage)})
    if stage == "connectivity":
        return stage_result(stage, "BLOCKED", "live customer private route, DNS, PKI and recovery path have not been exercised",
                            next_action="network/PKI owner runs the existing connectivity diagnostic on the customer route and provides signed evidence",
                            details={"dependencies": stage_dependencies(stage)})
    if stage == "evidence":
        return stage_result(stage, "BLOCKED", "final evidence verification requires customer-rooted trust and a durable customer replay registry; not contacted",
                            next_action="after package review, explicitly run scripts/verify-m3-evidence-provenance.py verify with customer-approved package inputs",
                            details={"dependencies": stage_dependencies(stage)})
    raise QualificationError("unknown M3 qualification stage")


STAGES = ("inspect", "inputs", "trust", "cloud-review", "plan-review", "connectivity", "qualification", "evidence")


def status_report(*, inputs_path: Path | None = None, evidence_path: Path | None = None) -> dict:
    stages = [run_stage(name, inputs_path=inputs_path, evidence_path=evidence_path) for name in STAGES]
    spec = importlib.util.spec_from_file_location("m3_matrix_for_status", ROOT / "scripts/verify-host-upgrade-qualification.py")
    verifier = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(verifier)
    matrix_path = ROOT / "tests/integration/host_upgrade_failure_matrix.json"
    verifier.verify_pinned_matrix(matrix_path)
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"),
                        object_pairs_hook=unique_object)
    manifest = None
    if inputs_path is not None:
        try:
            candidate = read_json(inputs_path)
            validate_manifest(candidate)
            manifest = candidate
        except (QualificationError, OSError, ValueError):
            # The input stage carries the precise invalid result. Status must
            # not infer or repair a malformed manifest.
            manifest = None
    platform_for_family = {"debian": "debian-13", "rhel": "rhel-9.8+"}
    target_by_platform = (manifest or {}).get("platformTargets", {})
    input_by_name = (manifest or {}).get("inputs", {})
    owners = {
        "debian": "Customer Debian qualification operator and independent reviewer",
        "rhel": "Customer RHEL qualification operator and independent reviewer",
    }
    rows = []
    for case in matrix["cases"]:
        for family in matrix["osFamilies"]:
            platform = platform_for_family[family]
            target = target_by_platform.get(platform)
            inventory = input_by_name.get("hostInventory")
            rows.append({
                "scenarioId": case["id"],
                "platformId": platform,
                "matrixOsFamily": family,
                "acceptanceCriteria": case["description"],
                "allowedOutcomes": case["allowedOutcomes"],
                "exactOsRelease": target.get("osVersion") if isinstance(target, dict) else None,
                "selectedImage": ({"selfLink": target.get("imageSelfLink"), "imageId": target.get("imageId"),
                                   "verificationState": "UNVERIFIED"} if isinstance(target, dict) else None),
                "hostIdentity": None,
                "nodeIdentity": None,
                "operationId": None,
                "evidenceReferences": [],
                "executionState": "NOT RUN",
                "evidenceVerification": "NOT RUN",
                "reviewerDecision": "NOT RUN",
                "acceptanceRecord": None,
                "finalRowState": "NOT RUN",
                "status": "NOT RUN",
                "owner": owners[family],
                "hostInventoryInput": "NOT PROVIDED" if inventory is None else "UNVERIFIED",
                "blocker": "No genuine real-host execution, signed evidence, independent acceptance, or baseline restoration has been verified",
            })
    # Status is an aggregation only. It cannot upgrade an evidence status or
    # call the customer replay registry.
    accepted = False
    overall = "M3 NOT COMPLETE"
    dependency_path = ROOT / "docs/m3-qualification-dependencies.json"
    dependency_graph = read_json(dependency_path, 2 * 1024 * 1024)
    validate_dependency_graph(dependency_graph)
    missing_inputs = []
    if inputs_path is None:
        missing_inputs = [{"inputId": key, "owner": value["owner"], "platforms": value["platforms"],
                           "status": "NOT_PROVIDED", "kind": value["kind"]}
                          for key, value in sorted(INPUTS.items())]
    else:
        input_stage = next(stage for stage in stages if stage["stage"] == "inputs")
        input_details = input_stage.get("details", {})
        if "inputs" not in input_details:
            invalid = input_stage.get("status") == "INVALID"
            missing_inputs = [{"inputId": key, "owner": value["owner"], "platforms": value["platforms"],
                               "status": "INVALID" if invalid else "NOT_PROVIDED",
                               "kind": value["kind"],
                               "reason": input_stage.get("reason", "input manifest is absent")}
                              for key, value in sorted(INPUTS.items())]
        else:
            missing_inputs = [item for item in input_details.get("inputs", [])
                              if item.get("status") not in {"VERIFIED", "APPROVED"}]
    open_dependencies = [item for item in dependency_graph["dependencies"]
                         if item["currentStatus"] not in {"IMPLEMENTED", "LOCALLY VERIFIED"}]
    status_stage = stage_result("status", "BLOCKED", "M3 remains incomplete until every dependency and all 22 real-host rows are independently accepted",
                                next_action="resolve open dependencies in dependency order; do not proceed to cloud review without the exact approval",
                                details={"qualificationAccepted": accepted, "openDependencyCount": len(open_dependencies)})
    stages.append(status_stage)
    return {"schemaVersion": 1, "projectId": PROJECT, "region": REGION, "zone": ZONE,
            "requiredPlatforms": list(PLATFORMS),
            "stages": stages, "qualificationAccepted": accepted, "overallStatus": overall,
            "canonicalMatrixSha256": verifier.FAILURE_MATRIX_SHA256, "canonicalScenarioCount": len(rows),
            "canonicalRows": rows, "missingInputs": missing_inputs,
            "dependencyGraph": {"path": str(dependency_path.relative_to(ROOT)),
                                "sha256": hashlib.sha256(canonical_json(dependency_graph)).hexdigest(),
                                "dependencies": dependency_graph["dependencies"],
                                "openDependencies": open_dependencies},
            "operationsPerformed": {"gcp": "NONE", "terraform": "NONE", "customerSystems": "NONE",
                                    "hostMaintenance": "NONE", "faultInjection": "NONE"}}


DEPENDENCY_CLASSES = {"repo-complete", "repo-incomplete", "customer-decision", "customer-artifact",
                      "external-integration", "gcp-approval", "real-host-execution", "evidence-acceptance"}
DEPENDENCY_STATUSES = {"IMPLEMENTED", "LOCALLY VERIFIED", "CUSTOMER VERIFIED", "LIVE DEPLOYED",
                       "REAL-HOST QUALIFIED", "NOT PROVIDED", "BLOCKED", "NOT RUN"}


def validate_dependency_graph(graph: dict) -> None:
    if (not isinstance(graph, dict) or set(graph) != {"schemaVersion", "projectId", "matrixSha256", "dependencies", "edges"}
            or type(graph.get("schemaVersion")) is not int or graph.get("schemaVersion") != 1):
        raise QualificationError("M3 dependency graph schema is incomplete or unsupported")
    if graph.get("projectId") != PROJECT or graph.get("matrixSha256") != MATRIX_SHA256:
        raise QualificationError("M3 dependency graph project or matrix binding is invalid")
    dependencies = graph.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise QualificationError("M3 dependency graph must contain dependencies")
    ids = set()
    required = {"id", "classification", "description", "owner", "requiredInputOrDecision",
                "consumingStage", "validationCommand", "acceptanceCondition", "failureBehavior",
                "currentStatus", "nextAction"}
    for item in dependencies:
        if not isinstance(item, dict) or set(item) != required:
            raise QualificationError("M3 dependency graph entry has missing or unknown fields")
        if (not isinstance(item["id"], str) or not re.fullmatch(r"M3-[A-Z0-9-]+", item["id"])
                or item["id"] in ids or not isinstance(item["classification"], str)
                or item["classification"] not in DEPENDENCY_CLASSES
                or not isinstance(item["currentStatus"], str) or item["currentStatus"] not in DEPENDENCY_STATUSES
                or any(not isinstance(item[field], str) or not item[field].strip()
                       for field in required - {"id", "classification", "currentStatus"})):
            raise QualificationError("M3 dependency graph entry is invalid or duplicated")
        ids.add(item["id"])
    edges = graph.get("edges")
    if not isinstance(edges, list):
        raise QualificationError("M3 dependency graph edges must be a list")
    adjacency = {item: set() for item in ids}
    indegree = {item: 0 for item in ids}
    seen_edges = set()
    for edge in edges:
        if (not isinstance(edge, dict) or set(edge) != {"from", "to"}
                or not isinstance(edge["from"], str) or not isinstance(edge["to"], str)
                or edge["from"] not in ids or edge["to"] not in ids or edge["from"] == edge["to"]
                or (edge["from"], edge["to"]) in seen_edges):
            raise QualificationError("M3 dependency graph edge is invalid or duplicated")
        seen_edges.add((edge["from"], edge["to"]))
        adjacency[edge["from"]].add(edge["to"])
        indegree[edge["to"]] += 1
    ready = [node for node, degree in indegree.items() if degree == 0]
    visited = 0
    while ready:
        node = ready.pop()
        visited += 1
        for child in adjacency[node]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if visited != len(ids):
        raise QualificationError("M3 dependency graph contains a cycle")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=(*STAGES, "status", "schema", "example"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--evidence-directory", type=Path)
    args = parser.parse_args(argv)
    if args.stage == "schema":
        reference = {"type": "object", "additionalProperties": False, "required": ["reference", "sha256", "expiresAt"],
                     "properties": {"reference": {"type": "string", "minLength": 1},
                                    "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                                    "expiresAt": {"type": ["string", "null"], "format": "date-time"}}}
        target_properties = {}
        for platform in PLATFORMS:
            is_debian = platform == "debian-13"
            target_properties[platform] = {"oneOf": [{"type": "null"},
                {"type": "object", "additionalProperties": False,
                 "required": ["osId", "osVersion", "architecture", "imageProject", "imageSelfLink", "imageId", "packagePolicySha256"],
                 "properties": {"osId": {"const": "debian" if is_debian else "rhel"},
                     "osVersion": {"type": "string", "pattern": "^13\\.[0-9]+$" if is_debian else "^9\\.(8|9|[1-9][0-9]+)$"},
                     "architecture": {"const": "amd64"},
                     "imageProject": {"const": "debian-cloud"} if is_debian else {
                         "type": "string", "pattern": "^[a-z][a-z0-9-]{4,28}[a-z0-9]$"},
                     "imageSelfLink": {"type": "string", "format": "uri"},
                     "imageId": {"type": "string", "pattern": "^[1-9][0-9]*$"},
                     "packagePolicySha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}}}]}
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "Kordex M3 Customer Inputs v1",
                  "type": "object", "additionalProperties": False,
                  "required": ["schemaVersion", "customerId", "projectId", "region", "zone", "labId", "fixtureOnly",
                               "canonicalMatrixSha256", "k3sVersion", "platformTargets", "residualRiskAcceptance", "inputs"],
                  "properties": {"schemaVersion": {"const": 1}, "customerId": {"type": "string"},
                                 "projectId": {"const": PROJECT}, "region": {"const": REGION}, "zone": {"const": ZONE},
                                 "labId": {"const": LAB_ID}, "canonicalMatrixSha256": {"const": MATRIX_SHA256},
                                 "k3sVersion": {"const": K3S_VERSION},
                                 "fixtureOnly": {"type": "boolean"},
                                 "platformTargets": {"type": "object", "additionalProperties": False,
                                     "required": list(PLATFORMS),
                                     "properties": target_properties},
                                 "residualRiskAcceptance": {"type": "object", "additionalProperties": False,
                                     "required": list(PLATFORMS), "properties": {platform: {"oneOf": [
                                         {"type": "null"}, {"type": "object", "required": sorted({"riskId", "organization", "individual", "acceptedAt", "expiresAt", "projectId", "labId", "platform", "imageSelfLink", "imageId", "recordReference", "recordSha256", "signatureReference", "signatureSha256", "signerIdentity"}),
                                          "additionalProperties": False, "properties": {"riskId": {"const": "GCE-BOOT-DISK-IMAGE-CREATE-TOCTOU"},
                                              "organization": {"type": "string"}, "individual": {"type": "string"},
                                              "acceptedAt": {"type": "string", "format": "date-time"}, "expiresAt": {"type": "string", "format": "date-time"},
                                              "projectId": {"const": PROJECT}, "labId": {"const": LAB_ID}, "platform": {"const": platform},
                                              "imageSelfLink": {"type": "string", "format": "uri"}, "imageId": {"type": "string"},
                                              "recordReference": {"type": "string"}, "recordSha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                                              "signatureReference": {"type": "string"}, "signatureSha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                                              "signerIdentity": {"type": "string"}}}]} for platform in PLATFORMS}},
                                 "inputs": {"type": "object", "additionalProperties": False,
                                            "required": sorted(INPUTS),
                                            "properties": {key: {"oneOf": [{"type": "null"}, reference]} for key in INPUTS}}},
                  "x-kordex-input-contract": INPUTS,
                  "x-kordex-note": "A matching file hash is not verification or approval."}
        print(json.dumps(schema, sort_keys=True, indent=2))
        return 0
    if args.stage == "example":
        example = {"schemaVersion": 1, "customerId": "synthetic-only", "projectId": PROJECT,
                   "region": REGION, "zone": ZONE, "labId": LAB_ID, "fixtureOnly": True,
                   "canonicalMatrixSha256": MATRIX_SHA256, "k3sVersion": K3S_VERSION,
                   "platformTargets": {platform: None for platform in PLATFORMS},
                   "residualRiskAcceptance": {platform: None for platform in PLATFORMS},
                   "inputs": {key: None for key in INPUTS}}
        print(json.dumps(example, sort_keys=True, indent=2))
        return 0
    if args.stage == "status":
        result = status_report(inputs_path=args.manifest, evidence_path=args.evidence_directory)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result["qualificationAccepted"] else 1
    else:
        result = run_stage(args.stage, inputs_path=args.manifest, evidence_path=args.evidence_directory)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["status"] in {"PASS", "VERIFIED", "APPROVED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
