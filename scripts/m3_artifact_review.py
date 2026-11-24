#!/usr/bin/env python3
"""Verify an independent M3 artifact review against the exact pre-review report.

The reviewer signature uses the existing root-authorized Ed25519 trust store.
This module never creates keys, signatures, trust records, or approvals.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re

try:
    import m3_customer_trust as trust
    import m3_trust_state as trust_state
except ImportError:  # repository-relative importlib callers
    from scripts import m3_customer_trust as trust
    from scripts import m3_trust_state as trust_state


class ArtifactReviewError(ValueError):
    pass


SHA256 = re.compile(r"^[a-f0-9]{64}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}$")
CAMPAIGN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
REVIEW_FIELDS = {
    "schemaVersion", "campaignId", "osProfile", "osIdentity", "decision",
    "artifactBindings", "reportSha256", "verificationSha256", "artifactOwners", "signerIdentities",
    "trustConfigurationSha256", "trustRootFingerprint", "reviewerIdentity",
    "signatureIdentity", "reviewedAt", "expiresAt", "reviewReference", "rationale",
}


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def required_owner_slots(config: dict) -> set[str]:
    """Owner identities cover every locked image and every signed source set."""
    slots = {"release-bundle", "release-image-lock", "k3s-binary", "k3s-system-images"}
    try:
        from m3_artifact_preflight import REQUIRED_KORDEX_IMAGES
    except ImportError:
        from scripts.m3_artifact_preflight import REQUIRED_KORDEX_IMAGES
    slots.update(f"image:{name}" for name in REQUIRED_KORDEX_IMAGES)
    packages = config.get("packageArtifacts")
    metadata = packages.get("repositoryMetadata") if isinstance(packages, dict) else None
    repositories = metadata.get("repositories") if isinstance(metadata, dict) else None
    if isinstance(repositories, list):
        for row in repositories:
            if isinstance(row, dict) and isinstance(row.get("id"), str):
                slots.add(f"repository:{row['id']}")
    return slots


def signer_identities(report: dict) -> dict[str, list[str]]:
    """Return the exact signing principals observed by successful verifiers."""
    artifacts = report.get("artifacts", {})
    result: dict[str, list[str]] = {}

    def keys(row: object) -> list[str]:
        if not isinstance(row, dict):
            return []
        values = []
        if isinstance(row.get("signerKeyId"), str):
            values.append("key:" + row["signerKeyId"].lower())
        if isinstance(row.get("signerFingerprint"), str):
            values.append("key:" + row["signerFingerprint"].lower())
        for item in row.get("signerFingerprints", []) if isinstance(row.get("signerFingerprints"), list) else []:
            if isinstance(item, str):
                values.append("key:" + item.lower())
        return sorted(set(values))

    for name in ("artifactApprovalTrust", "releasePublicTrust", "toolProvenancePublicTrust"):
        row = artifacts.get(name, {})
        found = keys(row)
        if isinstance(row, dict):
            for value in row.get("keyIds", []) if isinstance(row.get("keyIds"), list) else []:
                if isinstance(value, str):
                    found.append("key:" + value.lower())
            if isinstance(row.get("fingerprint"), str):
                found.append("key:" + row["fingerprint"].lower())
        if found:
            result[name] = sorted(set(found))

    for name in ("k3sBinaryApproval", "k3sSystemImageApproval"):
        found = keys(artifacts.get(name, {}))
        if found:
            result[name] = found

    repository = artifacts.get("repositoryMetadataVerification", {})
    if isinstance(repository, dict):
        for row in repository.get("repositories", []) if isinstance(repository.get("repositories"), list) else []:
            if isinstance(row, dict) and isinstance(row.get("repositoryId"), str):
                found = keys(row)
                if found:
                    result[f"repository:{row['repositoryId']}"] = found

    provenance = artifacts.get("imageProvenanceVerification", {})
    if isinstance(provenance, dict):
        images = provenance.get("images")
        if isinstance(images, dict):
            for component, row in sorted(images.items()):
                found = keys(row)
                for field in ("builderId", "workflowIdentity"):
                    if isinstance(row.get(field), str):
                        found.append("identity:" + row[field])
                if found:
                    result[f"image:{component}"] = sorted(set(found))
    return dict(sorted(result.items()))


def verification_digest(report: dict) -> str:
    """Digest the complete signed-verification result, excluding its review row."""
    artifacts = report.get("artifacts", {})
    checks = report.get("checks", {})
    return _sha({
        "schemaVersion": report.get("schemaVersion"),
        "profile": report.get("profile"),
        "campaignId": report.get("campaignId"),
        "osIdentity": report.get("osIdentity"),
        "artifactOwners": report.get("artifactOwners"),
        "signerIdentities": report.get("signerIdentities"),
        "checks": {key: value for key, value in checks.items() if key != "independentApproval"},
        "artifacts": {key: value for key, value in artifacts.items() if key != "independentApproval"},
        "inputSha256": report.get("inputSha256"),
    })


def artifact_bindings(report: dict) -> dict:
    """Project the exact signed image, repository, and input identities reviewed.

    The report digest remains the authoritative complete binding. This
    projection makes the high-value identities visible in the signed review
    record and detects a projection/report mismatch independently.
    """
    artifacts = report.get("artifacts", {})
    sboms = artifacts.get("imageSBOMVerification", {}).get("images", {})
    provenance = artifacts.get("imageProvenanceVerification", {}).get("images", {})
    expected = set(required_owner_slots({}))
    expected_images = {slot.removeprefix("image:") for slot in expected if slot.startswith("image:")}
    if not isinstance(sboms, dict) or not isinstance(provenance, dict) or set(sboms) != expected_images or set(provenance) != expected_images:
        raise ArtifactReviewError("preflight report does not bind the complete six-image set")
    images = {}
    for component in sorted(expected_images):
        sbom = sboms[component]
        prov = provenance[component]
        if not isinstance(sbom, dict) or not isinstance(prov, dict):
            raise ArtifactReviewError("preflight image verification row is malformed")
        image_ref = prov.get("imageRef")
        image_digest = prov.get("imageDigest")
        if (not isinstance(image_ref, str) or not re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", image_ref)
                or not isinstance(image_digest, str) or image_ref.rsplit("sha256:", 1)[1] != image_digest
                or sbom.get("imageRef") != image_ref or sbom.get("imageDigest") != image_digest):
            raise ArtifactReviewError("preflight SBOM and provenance image identities disagree")
        images[component] = {
            "imageRef": image_ref,
            "imageDigest": image_digest,
            "sbomSha256": sbom.get("sbomSha256"),
            "sbomAttestationBundleSha256": sbom.get("sbomBundleSha256"),
            "provenanceBundleSha256": prov.get("provenanceBundleSha256"),
            "provenanceSubjectDigest": image_digest,
            "sourceRepository": prov.get("sourceRepository"),
            "sourceRef": prov.get("sourceRef"),
            "sourceCommit": prov.get("sourceCommit"),
            "builderId": prov.get("builderId"),
            "workflowIdentity": prov.get("workflowIdentity"),
            "buildType": prov.get("buildType"),
            "materials": prov.get("materials"),
        }
        required = ("sbomSha256", "sbomAttestationBundleSha256", "provenanceBundleSha256",
                    "sourceRepository", "sourceRef", "sourceCommit", "builderId", "workflowIdentity",
                    "buildType", "materials")
        if any(images[component][field] in (None, "", []) for field in required):
            raise ArtifactReviewError("preflight image binding omits SBOM, provenance, or builder evidence")
    repositories = artifacts.get("repositoryMetadataVerification", {}).get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ArtifactReviewError("preflight report does not bind signed repository metadata snapshots")
    return {
        "images": images,
        "repositoryMetadata": sorted(repositories, key=lambda row: row.get("repositoryId", "")),
        "verifiedInputSha256": report.get("inputSha256"),
    }


def _review_root_fingerprint() -> str:
    root_bytes = trust.read_regular(trust.TRUST_ROOT, 16 * 1024)
    return trust.fingerprint(root_bytes)


def _valid_identity(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise ArtifactReviewError(f"{field} is missing or malformed")
    return value


def validate_review(*, record_path: Path, signature_path: Path, config: dict,
                    pre_review_report: dict, now: dt.datetime,
                    trust_loader=None) -> dict:
    """Validate an authorized, unexpired, non-self-approved report review."""
    try:
        raw = trust.read_regular(record_path, 1024 * 1024)
        signature = trust.read_regular(signature_path, 16 * 1024)
        record = json.loads(raw, object_pairs_hook=trust.unique_object)
        if trust_loader is None:
            snapshot = trust_state.load_production_customer_trust()
            trust_document, trust_digest = snapshot.document, snapshot.sha256
            state_result = snapshot.state
        else:
            trust_document, trust_digest = trust_loader()
            state_result = None
        root_fingerprint = _review_root_fingerprint()
    except (OSError, UnicodeError, json.JSONDecodeError, trust.TrustError,
            trust_state.TrustStateError, ImportError) as error:
        raise ArtifactReviewError("artifact review, signature, or protected trust input is unavailable or malformed") from error
    if (not isinstance(record, dict) or set(record) != REVIEW_FIELDS
            or type(record.get("schemaVersion")) is not int or record["schemaVersion"] != 1
            or raw != trust.canonical_json(record)):
        raise ArtifactReviewError("artifact review record is noncanonical, incomplete, or unsupported")

    release = config.get("release") if isinstance(config.get("release"), dict) else {}
    package = config.get("packageArtifacts") if isinstance(config.get("packageArtifacts"), dict) else {}
    # The fully verified preflight report is authoritative for the OS identity.
    package_result = pre_review_report.get("artifacts", {}).get("hostPackageArtifacts", {})
    family = package_result.get("osFamily")
    profile = {"debian": "debian-13", "rhel": "rhel-9"}.get(family)
    os_identity = {"osId": package_result.get("osId"), "osMajor": str(package_result.get("osMajor", "")),
                   "osMinor": str(package_result.get("osMinor", "")),
                   "pointRelease": package_result.get("osPointRelease"), "architecture": "linux/amd64"}
    campaign_id = release.get("campaignId")
    if not isinstance(campaign_id, str) or not CAMPAIGN.fullmatch(campaign_id):
        raise ArtifactReviewError("M3 artifact review requires a unique campaign ID")
    if (record["campaignId"] != campaign_id or record["osProfile"] != profile
            or record["osIdentity"] != os_identity or profile is None):
        raise ArtifactReviewError("artifact review is bound to a different OS campaign or release identity")

    required_owners = required_owner_slots(config)
    configured_owners = release.get("artifactOwners")
    if (not isinstance(configured_owners, dict) or set(configured_owners) != required_owners
            or record["artifactOwners"] != configured_owners):
        raise ArtifactReviewError("artifact owner designation is missing or differs from the reviewed report")
    report_bytes = canonical_json(pre_review_report)
    report_sha = hashlib.sha256(report_bytes).hexdigest()
    verify_sha = verification_digest(pre_review_report)
    if (record["reportSha256"] != report_sha or record["verificationSha256"] != verify_sha
            or record["trustConfigurationSha256"] != trust_digest
            or record["trustRootFingerprint"] != root_fingerprint):
        raise ArtifactReviewError("review record does not bind the exact preflight report or trust identities")
    if record["artifactBindings"] != artifact_bindings(pre_review_report):
        raise ArtifactReviewError("review record artifact bindings differ from the verified preflight report")
    expected_signers = signer_identities(pre_review_report)
    if not expected_signers or record["signerIdentities"] != expected_signers:
        raise ArtifactReviewError("review record signer identities differ from verified artifact signers")
    if any(row.get("status") != "PASS" for name, row in pre_review_report["artifacts"].items()
           if name != "independentApproval"):
        raise ArtifactReviewError("artifact review cannot approve a report with incomplete verification checks")

    reviewer = _valid_identity(record["reviewerIdentity"], "reviewer identity")
    if record["signatureIdentity"] != reviewer or record["decision"] != "accepted":
        raise ArtifactReviewError("review signature identity or decision is invalid")
    try:
        reviewer_key, reviewer_fingerprint = trust.authorized_key(trust_document, reviewer, "reviewer", now=now)
        owner_fingerprints = {}
        for slot, owner_value in configured_owners.items():
            owner = _valid_identity(owner_value, f"artifact owner for {slot}")
            owner_key, owner_fingerprint = trust.authorized_key(trust_document, owner, "artifact-owner", now=now)
            owner_fingerprints[slot] = owner_fingerprint
            if owner == reviewer or owner_fingerprint == reviewer_fingerprint:
                raise ArtifactReviewError("independent reviewer is also an artifact/build owner")
        signing_key_fingerprints = {value.removeprefix("key:").lower()
                                    for values in expected_signers.values() for value in values
                                    if value.startswith("key:")}
        workflow_identities = {value.removeprefix("identity:")
                               for values in expected_signers.values() for value in values
                               if value.startswith("identity:")}
        if (reviewer_fingerprint in signing_key_fingerprints or reviewer in workflow_identities
                or any(owner in workflow_identities for owner in configured_owners.values())):
            raise ArtifactReviewError("reviewer or artifact owner aliases a verified artifact signer/builder")
        trust.verify_signature(raw, signature, reviewer_key)
    except trust.TrustError as error:
        raise ArtifactReviewError("reviewer is not currently authorized or signature verification failed") from error

    current = now.astimezone(dt.timezone.utc)
    try:
        reviewed_at = trust.parse_time(record["reviewedAt"], "reviewedAt")
        expires_at = trust.parse_time(record["expiresAt"], "expiresAt")
    except trust.TrustError as error:
        raise ArtifactReviewError("artifact review validity timestamps are invalid") from error
    if (reviewed_at > current + dt.timedelta(minutes=2) or reviewed_at > current
            or expires_at <= current or expires_at <= reviewed_at
            or expires_at - reviewed_at > dt.timedelta(days=30)):
        raise ArtifactReviewError("artifact review is stale, expired, or exceeds its validity period")
    if (not isinstance(record.get("reviewReference"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,255}", record["reviewReference"])
            or not isinstance(record.get("rationale"), str) or len(record["rationale"].strip()) < 12
            or any(ord(char) < 32 for char in record["rationale"])):
        raise ArtifactReviewError("artifact review reference or rationale is incomplete")
    result = {"status": "PASS", "reviewerIdentity": reviewer, "reviewerFingerprint": reviewer_fingerprint,
            "reviewReference": record["reviewReference"], "reviewedAt": reviewed_at.isoformat().replace("+00:00", "Z"),
            "expiresAt": expires_at.isoformat().replace("+00:00", "Z"),
            "reviewRecordSha256": hashlib.sha256(raw).hexdigest(),
            "reviewSignatureSha256": hashlib.sha256(signature).hexdigest(),
            "reviewedReportSha256": report_sha, "verificationSha256": verify_sha,
            "trustConfigurationSha256": trust_digest, "trustRootFingerprint": root_fingerprint,
            "artifactOwnerFingerprints": dict(sorted(owner_fingerprints.items()))}
    if state_result is not None:
        result["trustStateVersion"] = {key: state_result[key] for key in (
            "sequence", "configurationSha256", "backendIdentity", "namespace",
            "attestationFingerprint", "rootFingerprint", "rootSignatureSha256", "auditIds")}
        result["trustStateConformanceSha256"] = snapshot.conformanceSha256
    return result
