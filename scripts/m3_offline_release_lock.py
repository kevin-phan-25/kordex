#!/usr/bin/env python3
"""Verify an M3 six-image release package and sign its lock offline.

The verify command performs repository-signature and Sigstore verification
before emitting a canonical lock candidate and verification manifest. The
sign command is intentionally data-only: it accepts only those two files and
never imports or executes code from the candidate release package. Production
trust is loaded through the existing KIQT loader, including its durable
rollback-state requirement.
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
import shutil
import stat
import subprocess
import sys
import tempfile

try:
    import m3_customer_trust as customer_trust
    import m3_trust_state as trust_state
    import m3_supply_chain_verify as supply
    import assemble_m3_release_evidence as release_evidence
except ImportError:
    from scripts import m3_customer_trust as customer_trust
    from scripts import m3_trust_state as trust_state
    from scripts import m3_supply_chain_verify as supply
    from scripts import assemble_m3_release_evidence as release_evidence


COMPONENTS = ("agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres")
CAMPAIGNS = {"debian-13": ("debian", "13"), "rhel-9.8+": ("rhel", "9")}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
IMAGE = re.compile(r"^ghcr\.io/kevin-phan-25/kordex-([a-z0-9-]+)@sha256:([a-f0-9]{64})$")
WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yaml"
SCHEMA = Path(__file__).resolve().parents[1] / "schemas/m3-release-lock-verification-v1.json"


class CeremonyError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CeremonyError("verification record cannot be canonicalized") from error


def _validate_schema(value: dict, path: Path, label: str) -> None:
    """Validate ceremony JSON with the repository's pinned JSON Schema runtime."""
    try:
        import jsonschema

        schema, _raw = read_json(path, 2 * 1024 * 1024)
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()).validate(value)
    except ImportError as error:
        raise CeremonyError("pinned JSON Schema validator is unavailable") from error
    except (jsonschema.ValidationError, jsonschema.SchemaError, CeremonyError) as error:
        raise CeremonyError(f"{label} does not satisfy its versioned schema") from error


def read_regular(path: Path, limit: int = 128 * 1024 * 1024) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise CeremonyError(f"required input is unavailable or unsafe: {path.name}") from error
    if (not stat.S_ISREG(before.st_mode) or len(data) != before.st_size or len(data) > limit
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise CeremonyError(f"input is not a stable bounded regular file: {path.name}")
    return data


def read_json(path: Path, limit: int = 4 * 1024 * 1024) -> tuple[dict, bytes]:
    raw = read_regular(path, limit)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=customer_trust.unique_object)
    except (UnicodeError, json.JSONDecodeError, customer_trust.TrustError) as error:
        raise CeremonyError(f"JSON input is malformed: {path.name}") from error
    if not isinstance(value, dict):
        raise CeremonyError(f"JSON input must be an object: {path.name}")
    return value, raw


def hash_path(path: Path) -> str:
    return hashlib.sha256(read_regular(path)).hexdigest()


def tree_hashes(root: Path, prefix: str) -> dict[str, str]:
    if root.is_symlink() or not root.is_dir():
        raise CeremonyError(f"artifact root is missing or unsafe: {prefix}")
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise CeremonyError("release evidence tree contains a symbolic link")
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        result[f"{prefix}/{relative}"] = hash_path(path)
    if not result:
        raise CeremonyError(f"artifact tree is empty: {prefix}")
    return result


def git_source_state(root: Path) -> tuple[str, bool]:
    try:
        commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10).stdout.strip()
        status = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
                                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise CeremonyError("approved verifier/signing source revision cannot be established") from error
    if not COMMIT.fullmatch(commit):
        raise CeremonyError("source revision is not a full immutable Git commit")
    return commit, not status.strip()


def _validate_inputs(config: dict) -> None:
    required = {"schemaVersion", "campaign", "releaseTag", "sourceCommit", "workflowRun",
                "componentsRoot", "sigstoreTrustedRoot", "sigstoreTrustedRootSHA256",
                "imageAttestationMaxAgeDays", "packagePolicy", "packagePolicySHA256",
                "repositorySnapshotID", "privateMirrorURL", "repositoryMetadata"}
    if set(config) != required or config.get("schemaVersion") != 1:
        raise CeremonyError("offline release verification inputs are incomplete or contain unsupported fields")
    if config["campaign"] not in CAMPAIGNS or not TAG.fullmatch(str(config["releaseTag"])):
        raise CeremonyError("release tag or M3 OS campaign is invalid")
    if not COMMIT.fullmatch(str(config["sourceCommit"])):
        raise CeremonyError("release source commit must be a full immutable Git commit")
    run = config["workflowRun"]
    if (not isinstance(run, dict) or set(run) != {"id", "attempt"}
            or any(not isinstance(run.get(key), str) or not run[key].isdigit() for key in run)):
        raise CeremonyError("release workflow run identity is incomplete")
    if (type(config["imageAttestationMaxAgeDays"]) is not int
            or not 1 <= config["imageAttestationMaxAgeDays"] <= 365
            or not SHA256.fullmatch(str(config["sigstoreTrustedRootSHA256"]))
            or not SHA256.fullmatch(str(config["packagePolicySHA256"]))
            or not isinstance(config["repositorySnapshotID"], str) or not config["repositorySnapshotID"]
            or not isinstance(config["privateMirrorURL"], str) or not config["privateMirrorURL"].startswith("https://")):
        raise CeremonyError("release verification trust, freshness, or package snapshot policy is invalid")
    if not isinstance(config["repositoryMetadata"], dict):
        raise CeremonyError("signed repository metadata policy is missing")


def _package_policy(config: dict, campaign: str) -> tuple[dict, list[dict], str]:
    policy_path = Path(config["packagePolicy"])
    raw = read_regular(policy_path, 2 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != config["packagePolicySHA256"]:
        raise CeremonyError("package policy differs from its independently approved SHA-256")
    stager_path = Path(__file__).resolve().parents[1] / "scripts/install-offline-package-artifacts.py"
    spec = importlib.util.spec_from_file_location("kordex_m3_offline_package_stager", stager_path)
    if spec is None or spec.loader is None:
        raise CeremonyError("fixed offline package-policy verifier is unavailable")
    stager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stager)
    try:
        policy, plan_digest = stager.read_policy(policy_path)
    except (OSError, ValueError) as error:
        raise CeremonyError("approved offline package policy is invalid") from error
    plan = policy["spec"]["upgrade"]
    os_id, major = CAMPAIGNS[campaign]
    if plan.get("osId") != os_id or str(plan.get("osMajor")) != major or plan.get("artifactMode") != "OfflineArtifacts":
        raise CeremonyError("package policy OS identity or offline-artifact mode differs from the selected campaign")
    point = plan.get("osPointRelease")
    minor = str(plan.get("osMinor", ""))
    if campaign == "debian-13" and not re.fullmatch(r"13\.[0-9]+", str(point)):
        raise CeremonyError("Debian campaign requires an explicitly approved Debian 13 point release")
    if campaign == "rhel-9.8+" and (not minor.isdigit() or int(minor) < 8 or point != f"9.{minor}"):
        raise CeremonyError("RHEL campaign requires a genuine approved RHEL 9.8+ minor-release policy")
    packages = plan.get("packages")
    if not isinstance(packages, list) or not packages:
        raise CeremonyError("offline package policy contains no approved package artifacts")
    return policy, packages, plan_digest


def _load_release_trust() -> tuple[dict, str, str, dict, dict, dict]:
    try:
        snapshot = trust_state.load_production_customer_trust()
        document, digest = snapshot.document, snapshot.sha256
        signer = customer_trust.authorized_release_lock_signer(document)
        verifier = customer_trust.authorized_release_lock_verifier(document)
        root = customer_trust.read_regular(customer_trust.TRUST_ROOT, 64 * 1024)
        root_fingerprint = customer_trust.fingerprint(root)
        state = snapshot.state
        state_binding = {"sequence": state["sequence"], "configurationSha256": digest,
                         "backendIdentity": state["backendIdentity"], "namespace": state["namespace"],
                         "attestationFingerprint": state["attestationFingerprint"],
                         "rootFingerprint": state["rootFingerprint"],
                         "rootSignatureSha256": state["rootSignatureSha256"],
                         "conformanceSha256": snapshot.conformanceSha256, "auditIds": state["auditIds"]}
    except customer_trust.TrustError as error:
        raise CeremonyError("production KIQT signer/verifier authorization is unavailable or not rollback-verified") from error
    except Exception as error:
        raise CeremonyError("durable production KIQT trust-state adapter is unavailable or unauthenticated") from error
    return document, digest, root_fingerprint, signer, verifier, state_binding


def _repo_result(config: dict, packages: list[dict], campaign: str, point_release: str,
                 *, now: dt.datetime, run) -> dict:
    expected_family = "debian" if campaign == "debian-13" else "rhel"
    repository = config["repositoryMetadata"]
    if repository.get("family") != expected_family:
        raise CeremonyError("repository metadata family does not match the selected OS campaign")
    verifier = (supply.verify_debian_repositories if expected_family == "debian"
                else supply.verify_rpm_repositories)
    try:
        return verifier(
            repository, packages, now=now, run=run,
            expected_snapshot=config["repositorySnapshotID"],
            private_mirror_url=config["privateMirrorURL"],
            **({"os_point_release": point_release} if expected_family == "rhel" else {}))
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as error:
        raise CeremonyError("signed repository metadata or its package-index digest chain failed verification") from error


def _validate_repository_result(result: dict, campaign: str) -> None:
    family = "debian" if campaign == "debian-13" else "rhel"
    if (not isinstance(result, dict) or result.get("family") != family
            or not SHA256.fullmatch(str(result.get("keyringSha256", "")))
            or type(result.get("verifiedPackageCount")) is not int or result["verifiedPackageCount"] < 1
            or not isinstance(result.get("packages"), list)
            or len(result["packages"]) != result["verifiedPackageCount"]
            or not isinstance(result.get("repositories"), list) or not result["repositories"]):
        raise CeremonyError("verification manifest repository metadata result is incomplete")
    for package in result["packages"]:
        if (not isinstance(package, dict) or not isinstance(package.get("name"), str)
                or not isinstance(package.get("version"), str)
                or not SHA256.fullmatch(str(package.get("sha256", "")))):
            raise CeremonyError("verified repository package binding is malformed")
    for repository in result["repositories"]:
        if not isinstance(repository, dict) or not isinstance(repository.get("repositoryId"), str):
            raise CeremonyError("verified repository identity is malformed")
        if family == "debian":
            digest_values = [repository.get("releaseSha256")]
            for field in ("signedMetadataSha256", "signatureSha256", "signatureMetadataSha256"):
                values = repository.get(field)
                if not isinstance(values, list) or not values:
                    raise CeremonyError("verified Debian metadata lacks signature digest bindings")
                digest_values.extend(values)
            if (not isinstance(repository.get("indexes"), list) or not repository["indexes"]
                    or any(not SHA256.fullmatch(str(value)) for value in digest_values)
                    or not isinstance(repository.get("signerFingerprints"), list)
                    or not repository["signerFingerprints"]):
                raise CeremonyError("verified Debian Release/index signature bindings are incomplete")
        else:
            digest_values = [repository.get(field) for field in
                             ("repomdSha256", "signatureSha256", "primarySha256", "primaryOpenSha256")]
            if (any(not SHA256.fullmatch(str(value)) for value in digest_values)
                    or not isinstance(repository.get("signerFingerprint"), str)
                    or not re.fullmatch(r"[A-Fa-f0-9]{40,64}", repository["signerFingerprint"])):
                raise CeremonyError("verified RPM repomd/primary signature bindings are incomplete")


def _repository_snapshot(config: dict) -> dict[str, str]:
    repo_config = config["repositoryMetadata"]
    result = {}
    keyring = Path(repo_config.get("keyring", ""))
    result["repository-keyring"] = hash_path(keyring)
    for index, repo in enumerate(repo_config.get("repositories", [])):
        root = Path(repo.get("root", ""))
        result.update(tree_hashes(root, f"repository-{index}-{repo.get('id', 'unknown')}"))
    return result


def discover_components(root: Path) -> dict[str, Path]:
    manifests = sorted(root.rglob("component.json")) if root.is_dir() and not root.is_symlink() else []
    by_component = {}
    supplemental_seen = False
    for path in manifests:
        item, _raw = read_json(path, 1024 * 1024)
        component = item.get("component")
        if component == release_evidence.SUPPLEMENTAL:
            if supplemental_seen:
                raise CeremonyError("release package contains duplicate supplemental agent-relay evidence")
            supplemental_seen = True
            continue
        if component not in COMPONENTS or component in by_component:
            raise CeremonyError("release package must contain only one evidence set for each of the six M3 components")
        by_component[component] = path.parent
    if set(by_component) != set(COMPONENTS):
        raise CeremonyError("release package must contain exactly the six M3 components; agent-relay is supplemental and excluded")
    return by_component


def _build_candidate(config: dict, *, trust_digest: str, trust_root_fingerprint: str,
                     signer: dict, verifier: dict, trust_state_binding: dict,
                     now: dt.datetime, run=subprocess.run,
                     source_state: tuple[str, bool] | None = None,
                     input_map_sha256: str | None = None) -> tuple[bytes, bytes]:
    _validate_inputs(config)
    policy, packages, plan_digest = _package_policy(config, config["campaign"])
    _ = plan_digest
    release_tag, source_commit = config["releaseTag"], config["sourceCommit"]
    run_id, run_attempt = config["workflowRun"]["id"], config["workflowRun"]["attempt"]
    root = Path(config["componentsRoot"])
    by_component = discover_components(root)

    parsed = {}
    lock_lines = []
    for component in COMPONENTS:
        try:
            record = release_evidence._parse_component_evidence(
                component, by_component[component], tag=release_tag, commit=source_commit,
                run_id=run_id, run_attempt=run_attempt)
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise CeremonyError(f"component evidence is structurally invalid: {component}") from error
        parsed[component] = record
        lock_lines.append(f"{component}\t{record['imageReference']}")
    lock_bytes = ("\n".join(lock_lines) + "\n").encode("utf-8")
    image_lock = {name: parsed[name]["imageReference"] for name in COMPONENTS}
    attestations = {}
    input_hashes = {"packagePolicy": hashlib.sha256(read_regular(Path(config["packagePolicy"]))).hexdigest(),
                    "sigstoreTrustedRoot": hash_path(Path(config["sigstoreTrustedRoot"]))}
    for component in COMPONENTS:
        record = parsed[component]
        directory = by_component[component]
        attestations[component] = {
            "sbom": str(directory / f"{component}.cdx.json"),
            "sbomBundle": str(directory / f"{component}.sbom.bundle.jsonl"),
            "provenanceBundle": str(directory / f"{component}.provenance.bundle.jsonl"),
            "sourceRef": record["manifest"]["sourceRef"],
            "sourceCommit": record["manifest"]["sourceCommit"],
            "buildMaterials": record["manifest"]["buildMaterials"],
        }
        input_hashes.update(tree_hashes(directory, f"components/{component}"))
    try:
        image_result = supply.verify_image_attestations(
            {"imageAttestations": attestations,
             "sigstoreTrustedRoot": config["sigstoreTrustedRoot"],
             "sigstoreTrustedRootSHA256": config["sigstoreTrustedRootSHA256"],
             "maxAgeDays": config["imageAttestationMaxAgeDays"]},
            image_lock, now=now, run=run)
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as error:
        raise CeremonyError("cryptographic SBOM or provenance verification failed") from error
    repo_result = _repo_result(config, packages, config["campaign"],
                               policy["spec"]["upgrade"].get("osPointRelease", ""), now=now, run=run)
    _validate_repository_result(repo_result, config["campaign"])
    input_hashes.update(_repository_snapshot(config))
    input_hashes["verification-input-map"] = hashlib.sha256(canonical_json(config)).hexdigest()
    if input_map_sha256 is not None:
        if not SHA256.fullmatch(input_map_sha256):
            raise CeremonyError("verification input-map file digest is malformed")
        input_hashes["verification-input-map-file"] = input_map_sha256
    state = source_state or git_source_state(Path(__file__).resolve().parents[1])
    if not state[1]:
        raise CeremonyError("verification implementation source tree must be clean and immutable")
    if state[0] != signer.get("verifierSourceCommit"):
        raise CeremonyError("verification implementation revision is not the root-approved immutable source")
    script_digest = hashlib.sha256(read_regular(Path(__file__))).hexdigest()
    components = {}
    for component in COMPONENTS:
        result = image_result["images"][component]
        manifest = parsed[component]["manifest"]
        components[component] = {
            "imageReference": result["imageRef"], "imageDigest": result["imageDigest"],
            "sbomSha256": result["sbomSha256"], "sbomBundleSha256": result["sbomAttestationBundleSha256"],
            "provenanceBundleSha256": result["provenanceAttestationBundleSha256"],
            "provenanceSubjectDigest": result["imageDigest"],
            "sourceRepository": result["sourceRepository"], "sourceRef": result["sourceRef"],
            "sourceCommit": result["sourceCommit"], "builderId": result["builderId"],
            "workflowIdentity": result["workflowIdentity"], "buildType": result["buildType"],
            "buildParameters": manifest["buildParameters"], "materials": result["materials"],
            "sbomVerifiedAt": result["sbomAttestationVerifiedAt"],
            "provenanceVerifiedAt": result["provenanceAttestationVerifiedAt"],
        }
    repo_digest = hashlib.sha256(canonical_json(repo_result)).hexdigest()
    trust_bundle = {"configurationSha256": trust_digest, "rootFingerprint": trust_root_fingerprint,
                    "releaseLockSignerIdentity": signer["identity"],
                    "releaseLockSignerFingerprint": signer["fingerprint"],
                    "releaseLockVerifierIdentity": verifier["identity"],
                    "releaseLockVerifierFingerprint": verifier["fingerprint"],
                    "releaseLockVerifierSourceCommit": verifier["sourceCommit"],
                    "signerSourceCommit": signer["sourceCommit"],
                    "verifierSourceCommit": signer["verifierSourceCommit"]}
    manifest = {
        "schemaVersion": 1, "kind": "kordex-m3-release-lock-verification", "status": "PASS",
        "campaign": config["campaign"], "releaseTag": release_tag, "sourceCommit": source_commit,
        "workflowRun": {"id": run_id, "attempt": run_attempt},
        "verifier": {"sourceCommit": state[0], "sourceTreeClean": True, "scriptSha256": script_digest},
        "trust": trust_bundle, "trustState": trust_state_binding,
        "sigstoreTrustedRootSha256": image_result["trustedRootSha256"],
        "repositoryMetadata": {"resultSha256": repo_digest, "result": repo_result},
        "lockCandidateSha256": hashlib.sha256(lock_bytes).hexdigest(), "components": components,
        "inputSha256": dict(sorted(input_hashes.items())),
        "verifiedAt": now.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    _validate_manifest(manifest, lock_bytes, now=now)
    return lock_bytes, canonical_json(manifest)


def _validate_manifest(manifest: dict, lock: bytes, *, now: dt.datetime | None = None) -> None:
    _validate_schema(manifest, SCHEMA, "verification manifest")
    expected_fields = {"schemaVersion", "kind", "status", "campaign", "releaseTag", "sourceCommit",
                       "workflowRun", "verifier", "trust", "trustState", "sigstoreTrustedRootSha256",
                       "repositoryMetadata", "lockCandidateSha256", "components", "inputSha256", "verifiedAt"}
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise CeremonyError("verification manifest is incomplete or has unsupported fields")
    if (manifest.get("schemaVersion") != 1 or manifest.get("kind") != "kordex-m3-release-lock-verification"
            or manifest.get("status") != "PASS" or manifest.get("campaign") not in CAMPAIGNS
            or not TAG.fullmatch(str(manifest.get("releaseTag")))
            or not COMMIT.fullmatch(str(manifest.get("sourceCommit")))
            or hashlib.sha256(lock).hexdigest() != manifest.get("lockCandidateSha256")):
        raise CeremonyError("verification manifest status, source, or candidate digest is invalid")
    run = manifest.get("workflowRun")
    verifier = manifest.get("verifier")
    repository = manifest.get("repositoryMetadata")
    if (not isinstance(run, dict) or set(run) != {"id", "attempt"}
            or any(not isinstance(run.get(key), str) or not run[key].isdigit() for key in run)
            or not isinstance(verifier, dict) or set(verifier) != {"sourceCommit", "sourceTreeClean", "scriptSha256"}
            or not COMMIT.fullmatch(str(verifier.get("sourceCommit", "")))
            or verifier.get("sourceTreeClean") is not True
            or not SHA256.fullmatch(str(verifier.get("scriptSha256", "")))
            or not isinstance(repository, dict) or set(repository) != {"resultSha256", "result"}
            or not isinstance(repository.get("result"), dict)
            or hashlib.sha256(canonical_json(repository["result"])).hexdigest() != repository.get("resultSha256")
            or not SHA256.fullmatch(str(manifest.get("sigstoreTrustedRootSha256", "")))):
        raise CeremonyError("verification manifest verifier, repository, or trust-root evidence is malformed")
    if verifier["sourceCommit"] != manifest["trust"].get("releaseLockVerifierSourceCommit"):
        raise CeremonyError("verification manifest source revision differs from the root-authorized verifier")
    state = manifest.get("trustState")
    if (not isinstance(state, dict)
            or set(state) != {"sequence", "configurationSha256", "backendIdentity", "namespace",
                              "attestationFingerprint", "rootFingerprint", "rootSignatureSha256",
                              "conformanceSha256", "auditIds"}
            or type(state.get("sequence")) is not int or state["sequence"] < 1
            or state.get("configurationSha256") != manifest["trust"].get("configurationSha256")
            or not SHA256.fullmatch(str(state.get("configurationSha256", "")))
            or not SHA256.fullmatch(str(state.get("attestationFingerprint", "")))
            or not SHA256.fullmatch(str(state.get("rootFingerprint", "")))
            or not SHA256.fullmatch(str(state.get("rootSignatureSha256", "")))
            or not SHA256.fullmatch(str(state.get("conformanceSha256", "")))
            or any(not isinstance(state.get(field), str) or not state[field]
                   for field in ("backendIdentity", "namespace"))
            or not isinstance(state.get("auditIds"), list) or not state["auditIds"]
            or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", value)
                   for value in state["auditIds"])):
        raise CeremonyError("verification manifest durable trust-state version or audit binding is invalid")
    _validate_repository_result(repository["result"], manifest["campaign"])
    components = manifest.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CeremonyError("verification manifest must bind exactly the six M3 components")
    lines = lock.decode("utf-8", errors="strict").splitlines()
    if len(lines) != len(COMPONENTS) or lock != ("\n".join(lines) + "\n").encode("utf-8"):
        raise CeremonyError("lock candidate must contain exactly six component rows")
    verified_at = _parse_timestamp(manifest.get("verifiedAt"), "verification manifest verifiedAt")
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    if verified_at > current + dt.timedelta(minutes=2) or current - verified_at > dt.timedelta(hours=24):
        raise CeremonyError("verification manifest is future-dated or stale; rerun cryptographic pre-sign verification")
    for component, line in zip(COMPONENTS, lines, strict=True):
        fields = line.split("\t")
        record = components[component]
        required_component = {"imageReference", "imageDigest", "sbomSha256", "sbomBundleSha256",
                              "provenanceBundleSha256", "provenanceSubjectDigest", "sourceRepository",
                              "sourceRef", "sourceCommit", "builderId", "workflowIdentity", "buildType",
                              "buildParameters", "materials", "sbomVerifiedAt", "provenanceVerifiedAt"}
        if (len(fields) != 2 or fields[0] != component or not isinstance(record, dict)
                or set(record) != required_component
                or fields[1] != record.get("imageReference")
                or record.get("imageDigest") != fields[1].rsplit("sha256:", 1)[-1]
                or record.get("provenanceSubjectDigest") != record.get("imageDigest")
                or not IMAGE.fullmatch(fields[1])
                or IMAGE.fullmatch(fields[1]).group(1) != component
                or any(not SHA256.fullmatch(str(record.get(field, ""))) for field in
                       ("imageDigest", "sbomSha256", "sbomBundleSha256", "provenanceBundleSha256"))
                or record.get("sourceRepository") != supply.REPOSITORY
                or record.get("sourceRef") != f"refs/tags/{manifest['releaseTag']}"
                or record.get("sourceCommit") != manifest["sourceCommit"]
                or record.get("builderId") != supply.EXPECTED_BUILDER_ID
                or record.get("workflowIdentity") != supply.WORKFLOW_IDENTITY
                or record.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1"
                or not isinstance(record.get("buildParameters"), dict)
                or not isinstance(record.get("materials"), list) or not record["materials"]):
            raise CeremonyError("verification manifest component identity differs from the exact lock candidate")
        for material in record["materials"]:
            if (not isinstance(material, dict) or set(material) != {"uri", "digest"}
                    or not isinstance(material.get("uri"), str) or not material["uri"]
                    or not isinstance(material.get("digest"), dict) or not material["digest"]
                    or any(not isinstance(key, str) or not isinstance(value, str) or not value
                           for key, value in material["digest"].items())):
                raise CeremonyError("verification manifest build material identity is incomplete")
        for field in ("sbomVerifiedAt", "provenanceVerifiedAt"):
            verified_attestation_at = _parse_timestamp(record[field], f"component {field}")
            if verified_attestation_at > verified_at + dt.timedelta(minutes=2):
                raise CeremonyError("attestation verification time is later than the verification manifest")
    if (not isinstance(manifest.get("inputSha256"), dict) or not manifest["inputSha256"]
            or not {"verification-input-map", "verification-input-map-file", "packagePolicy",
                    "sigstoreTrustedRoot"}.issubset(manifest["inputSha256"])
            or any(not isinstance(value, str) or not SHA256.fullmatch(value)
                   for value in manifest["inputSha256"].values())):
        raise CeremonyError("verification manifest contains an invalid input digest")
    trust = manifest.get("trust")
    if (not isinstance(trust, dict) or set(trust) != {"configurationSha256", "rootFingerprint",
            "releaseLockSignerIdentity", "releaseLockSignerFingerprint", "releaseLockVerifierIdentity",
            "releaseLockVerifierFingerprint", "releaseLockVerifierSourceCommit",
            "signerSourceCommit", "verifierSourceCommit"}
            or any(not SHA256.fullmatch(str(trust.get(field, ""))) for field in
                   ("configurationSha256", "rootFingerprint", "releaseLockSignerFingerprint",
                    "releaseLockVerifierFingerprint"))
            or not isinstance(trust.get("releaseLockSignerIdentity"), str) or not trust["releaseLockSignerIdentity"]
            or not isinstance(trust.get("releaseLockVerifierIdentity"), str) or not trust["releaseLockVerifierIdentity"]
            or not COMMIT.fullmatch(str(trust.get("releaseLockVerifierSourceCommit", "")))
            or not COMMIT.fullmatch(str(trust.get("signerSourceCommit", "")))
            or not COMMIT.fullmatch(str(trust.get("verifierSourceCommit", "")))):
        raise CeremonyError("verification manifest is missing independent trust identity or immutable source bindings")


def _parse_timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise CeremonyError(f"{label} timestamp is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CeremonyError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise CeremonyError(f"{label} timestamp must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _write_new_output(output: Path, files: dict[str, bytes]) -> None:
    if output.exists() or output.is_symlink():
        raise CeremonyError("ceremony output directory must be new")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".kordex-m3-offline-lock-", dir=output.parent))
    os.chmod(staging, 0o700)
    try:
        for name, data in files.items():
            if Path(name).name != name:
                raise CeremonyError("ceremony output filename is invalid")
            path = staging / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        os.rename(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def verify_command(args: argparse.Namespace) -> None:
    config, raw = read_json(args.inputs)
    if "componentsRoot" in config:
        raise CeremonyError("componentsRoot is supplied as a command argument, not in the signed input map")
    document, trust_digest, root_fp, signer, verifier, state_binding = _load_release_trust()
    _ = document
    config["componentsRoot"] = str(args.components_root)
    lock, manifest = _build_candidate(config, trust_digest=trust_digest,
                                      trust_root_fingerprint=root_fp, signer=signer, verifier=verifier,
                                      trust_state_binding=state_binding,
                                      now=dt.datetime.now(dt.timezone.utc),
                                      input_map_sha256=hashlib.sha256(raw).hexdigest())
    manifest_signature = _sign_detached_payload(
        manifest, args.verification_key, verifier, checkout=Path(__file__).resolve().parents[1])
    output_files = {"kordex-images.tsv": lock,
                    "verification-manifest.json": manifest,
                    "verification-manifest.json.sig": manifest_signature,
                    "input-map.sha256": (hashlib.sha256(raw).hexdigest() + "  inputs.json\n").encode("ascii")}
    output_files["SHA256SUMS"] = ("\n".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}"
        for name, data in sorted(output_files.items())) + "\n").encode("ascii")
    _write_new_output(args.output_dir, output_files)


def _trusted_signing_source(signer: dict) -> Path:
    root = Path(__file__).resolve().parents[1]
    commit, clean = git_source_state(root)
    if not clean or commit != signer["sourceCommit"]:
        raise CeremonyError("offline signer must run from the exact clean root-approved immutable source revision")
    return root


def _private_key_fd(path: Path, checkout: Path) -> int:
    if not path.is_absolute():
        raise CeremonyError("protected signing-key path must be absolute")
    if ".." in path.parts:
        raise CeremonyError("protected signing-key path cannot contain parent-directory traversal")
    try:
        current = Path(path.anchor)
        for part in path.parts[1:-1]:
            current = current / part
            directory = current.lstat()
            if (stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode)
                    or directory.st_uid not in {0, os.geteuid()} or directory.st_mode & 0o022):
                raise CeremonyError("protected signing-key parent directories must be trusted, non-writable directories")
        resolved = path.resolve(strict=True)
        inside_checkout = resolved.is_relative_to(checkout.resolve())
    except CeremonyError:
        raise
    except ValueError:
        inside_checkout = False
    except OSError as error:
        raise CeremonyError("protected Ed25519 signing key is unavailable") from error
    if inside_checkout:
        raise CeremonyError("private signing key must be outside the trusted signer checkout")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
    except OSError as error:
        raise CeremonyError("protected Ed25519 signing key is unavailable or unsafe") from error
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        os.close(fd)
        raise CeremonyError("protected signing key must be a signer-owned, single-link regular file with mode 0600 or stricter")
    return fd


def _sign_detached_payload(payload: bytes, key_path: Path, identity: dict, *, checkout: Path) -> bytes:
    """Sign a verifier manifest using its separately root-authorized PEM key."""
    signer_fd = -1
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-verifier-sign-") as temporary:
            root = Path(temporary)
            payload_path = root / "payload.json"
            signature_path = root / "payload.json.sig"
            expected_public_path = root / "trusted-verifier.pub"
            derived_public_path = root / "derived-verifier.pub"
            payload_path.write_bytes(payload)
            expected_public_path.write_bytes(identity["publicKeyPem"].encode("ascii"))
            signature_path.touch(mode=0o600, exist_ok=False)
            signer_fd = _private_key_fd(key_path, checkout)
            private_path = Path(f"/proc/self/fd/{signer_fd}")
            if not private_path.exists():
                raise CeremonyError("secure inherited-key descriptor access is unavailable on this verifier host")
            common = {"check": True, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
                      "timeout": 30, "pass_fds": (signer_fd,)}
            subprocess.run(["openssl", "pkey", "-in", str(private_path), "-pubout",
                            "-out", str(derived_public_path)], **common)
            trusted_der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(expected_public_path),
                                          "-outform", "DER"], check=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, timeout=30).stdout
            derived_der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(derived_public_path),
                                          "-outform", "DER"], check=True, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, timeout=30).stdout
            if (trusted_der != derived_der or hashlib.sha256(trusted_der).hexdigest() != identity["fingerprint"]
                    or len(trusted_der) != 44 or not trusted_der.startswith(bytes.fromhex("302a300506032b6570032100"))):
                raise CeremonyError("verification key does not match the root-authorized Ed25519 verifier identity")
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_path),
                            "-in", str(payload_path), "-out", str(signature_path)], **common)
            verify_detached_signature(payload_path, signature_path,
                                      identity["publicKeyPem"].encode("ascii"))
            return read_regular(signature_path, 4096)
    except (OSError, subprocess.SubprocessError) as error:
        raise CeremonyError("verification-manifest signing or signature verification failed") from error
    finally:
        if signer_fd >= 0:
            os.close(signer_fd)


def verify_detached_signature(lock_path: Path, signature_path: Path, public_key: bytes,
                             *, run=subprocess.run) -> None:
    """Verify the exact lock bytes using the approved PEM Ed25519 public key."""
    try:
        payload = read_regular(lock_path, 1024 * 1024)
        signature = read_regular(signature_path, 4096)
        verify_detached_signature_bytes(payload, signature, public_key, run=run)
    except (OSError, CeremonyError) as error:
        raise CeremonyError("detached release-lock signature does not verify against the authorized signer") from error


def verify_detached_signature_bytes(payload: bytes, signature: bytes, public_key: bytes,
                                    *, run=subprocess.run) -> None:
    """Verify exact supplied bytes without reopening transfer paths."""
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-lock-verify-") as temporary:
            root = Path(temporary)
            public_path = root / "approved-public.pem"
            payload_path = root / "payload"
            signature_path = root / "payload.sig"
            public_path.write_bytes(public_key)
            payload_path.write_bytes(payload)
            signature_path.write_bytes(signature)
            run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_path), "-rawin",
                 "-in", str(payload_path), "-sigfile", str(signature_path)], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        raise CeremonyError("detached release-lock signature does not verify against the authorized signer") from error


def _validate_receipt(receipt: dict, lock: bytes, manifest_raw: bytes, signature: bytes,
                      manifest_signature: bytes, signer: dict,
                      trust_state_binding: dict | None = None,
                      *, now: dt.datetime | None = None) -> None:
    receipt_schema = Path(__file__).resolve().parents[1] / "schemas/m3-release-lock-signing-receipt-v1.json"
    _validate_schema(receipt, receipt_schema, "offline signing receipt")
    expected_fields = {"schemaVersion", "kind", "lockSha256", "verificationManifestSha256",
                       "verificationManifestSignatureSha256", "signerIdentity", "signerFingerprint",
                       "signerSourceCommit", "signedAt",
                       "signatureSha256", "signatureVerified", "trustState"}
    if (not isinstance(receipt, dict) or set(receipt) != expected_fields
            or receipt.get("schemaVersion") != 1
            or receipt.get("kind") != "kordex-m3-offline-release-lock-signing-receipt"
            or receipt.get("lockSha256") != hashlib.sha256(lock).hexdigest()
            or receipt.get("verificationManifestSha256") != hashlib.sha256(manifest_raw).hexdigest()
            or receipt.get("verificationManifestSignatureSha256") != hashlib.sha256(manifest_signature).hexdigest()
            or receipt.get("signerIdentity") != signer["identity"]
            or receipt.get("signerFingerprint") != signer["fingerprint"]
            or receipt.get("signerSourceCommit") != signer["sourceCommit"]
            or receipt.get("signatureSha256") != hashlib.sha256(signature).hexdigest()
            or receipt.get("trustState") != trust_state_binding
            or receipt.get("signatureVerified") is not True):
        raise CeremonyError("offline signing receipt does not bind the exact candidate, manifest, signer, and signature")
    signed_at = _parse_timestamp(receipt.get("signedAt"), "signing receipt signedAt")
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    if signed_at > current + dt.timedelta(minutes=2):
        raise CeremonyError("offline signing receipt is future-dated")


def _validate_manifest_trust(manifest: dict, trust_digest: str, root_fingerprint: str,
                             signer: dict, verifier: dict, trust_state_binding: dict) -> None:
    expected = {
        "configurationSha256": trust_digest,
        "rootFingerprint": root_fingerprint,
        "releaseLockSignerIdentity": signer["identity"],
        "releaseLockSignerFingerprint": signer["fingerprint"],
        "releaseLockVerifierIdentity": verifier["identity"],
        "releaseLockVerifierFingerprint": verifier["fingerprint"],
        "releaseLockVerifierSourceCommit": verifier["sourceCommit"],
        "signerSourceCommit": signer["sourceCommit"],
        "verifierSourceCommit": signer["verifierSourceCommit"],
    }
    if manifest.get("trust") != expected:
        raise CeremonyError("verification manifest trust identities or trust configuration digest changed")
    expected_state = {key: trust_state_binding.get(key) for key in (
        "sequence", "configurationSha256", "backendIdentity", "namespace",
        "attestationFingerprint", "rootFingerprint", "rootSignatureSha256", "conformanceSha256")}
    candidate_state = manifest.get("trustState")
    if (not isinstance(candidate_state, dict)
            or set(candidate_state) != set(expected_state) | {"auditIds"}
            or {key: candidate_state.get(key) for key in expected_state} != expected_state
            or not isinstance(candidate_state.get("auditIds"), list) or not candidate_state["auditIds"]
            or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}", value)
                   for value in candidate_state["auditIds"])):
        raise CeremonyError("verification manifest durable trust-state version or audit binding changed")
    if (manifest["verifier"].get("sourceCommit") != signer["verifierSourceCommit"]
            or manifest["verifier"].get("sourceTreeClean") is not True):
        raise CeremonyError("verification manifest was not produced by the root-approved clean verifier revision")


def _sign_candidate(args: argparse.Namespace, trust_doc: dict, trust_digest: str,
                    signer: dict, verifier: dict, root_fingerprint: str,
                    trust_state_binding: dict, *, now: dt.datetime | None = None) -> dict:
    _trusted_signing_source(signer)
    current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    lock = read_regular(args.lock_candidate, 1024 * 1024)
    manifest, manifest_raw = read_json(args.verification_manifest, 8 * 1024 * 1024)
    manifest_signature = read_regular(args.verification_manifest_signature, 4096)
    if manifest_raw != canonical_json(manifest):
        raise CeremonyError("verification manifest is not canonical UTF-8 JSON")
    _validate_manifest(manifest, lock, now=current)
    _validate_manifest_trust(manifest, trust_digest, root_fingerprint, signer, verifier, trust_state_binding)
    verify_detached_signature_bytes(manifest_raw, manifest_signature,
                                    verifier["publicKeyPem"].encode("ascii"))
    if manifest["verifier"]["sourceCommit"] != verifier["sourceCommit"]:
        raise CeremonyError("verification manifest source revision differs from the root-authorized verifier")
    if any(component["sourceCommit"] != manifest["sourceCommit"]
           for component in manifest["components"].values()):
        raise CeremonyError("verification manifest component source commit mismatch")
    output = args.output_dir
    if output.exists() or output.is_symlink():
        raise CeremonyError("signed lock output directory must be new")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".kordex-m3-signing-", dir=output.parent))
    os.chmod(staging, 0o700)
    key_fd = -1
    try:
        key_fd = _private_key_fd(args.private_key, Path(__file__).resolve().parents[1])
        key_proc_path = Path(f"/proc/self/fd/{key_fd}")
        if not key_proc_path.exists():
            raise CeremonyError("secure inherited-key descriptor access is unavailable on this signing host")
        trusted_public = signer["publicKeyPem"].encode("ascii")
        public_path = staging / "approved-release-lock-signer.pub"
        public_fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(public_fd, "wb") as stream:
            stream.write(trusted_public)
            stream.flush()
            os.fsync(stream.fileno())
        lock_path = staging / "kordex-images.tsv"
        lock_path.write_bytes(lock)
        signature_path = staging / "kordex-images.tsv.sig"
        signature_path.touch(mode=0o600, exist_ok=False)
        derived_path = staging / "derived-public.pem"
        run_common = {"check": True, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
                      "timeout": 30, "pass_fds": (key_fd,)}
        try:
            subprocess.run(["openssl", "pkey", "-in", str(key_proc_path), "-pubout", "-out", str(derived_path)], **run_common)
            der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(public_path), "-outform", "DER"],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=30).stdout
            derived_der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(derived_path), "-outform", "DER"],
                                         check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         timeout=30).stdout
            if (der != derived_der or hashlib.sha256(der).hexdigest() != signer["fingerprint"]
                    or len(der) != 44 or not der.startswith(bytes.fromhex("302a300506032b6570032100"))):
                raise CeremonyError("private key does not match the independently root-authorized Ed25519 public key")
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key_proc_path),
                            "-in", str(lock_path), "-out", str(signature_path)], **run_common)
            verify_detached_signature(lock_path, signature_path, trusted_public)
        except (OSError, subprocess.SubprocessError) as error:
            raise CeremonyError("offline release lock signing or independent signature verification failed") from error
        derived_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        signature = read_regular(signature_path, 4096)
        receipt = {
            "schemaVersion": 1, "kind": "kordex-m3-offline-release-lock-signing-receipt",
            "lockSha256": hashlib.sha256(lock).hexdigest(),
            "verificationManifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
            "verificationManifestSignatureSha256": hashlib.sha256(manifest_signature).hexdigest(),
            "signerIdentity": signer["identity"], "signerFingerprint": signer["fingerprint"],
            "signerSourceCommit": signer["sourceCommit"],
            "signedAt": current.isoformat().replace("+00:00", "Z"),
            "signatureSha256": hashlib.sha256(signature).hexdigest(),
            "trustState": trust_state_binding,
            "signatureVerified": True,
        }
        _validate_receipt(receipt, lock, manifest_raw, signature, manifest_signature, signer,
                          trust_state_binding, now=current)
        receipt_bytes = canonical_json(receipt)
        receipt_path = staging / "signing-receipt.json"
        receipt_path.write_bytes(receipt_bytes)
        sums = "\n".join(f"{hashlib.sha256((staging / name).read_bytes()).hexdigest()}  {name}"
                          for name in ("kordex-images.tsv", "kordex-images.tsv.sig", "signing-receipt.json")) + "\n"
        (staging / "SHA256SUMS").write_text(sums, encoding="ascii")
        os.rename(staging, output)
        return receipt
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if key_fd >= 0:
            os.close(key_fd)


def sign_command(args: argparse.Namespace) -> None:
    _document, trust_digest, root_fingerprint, signer, verifier, state_binding = _load_release_trust()
    receipt = _sign_candidate(args, _document, trust_digest, signer, verifier, root_fingerprint,
                              state_binding)
    print(json.dumps({"status": "PASS", "lockSha256": receipt["lockSha256"],
                      "signerIdentity": receipt["signerIdentity"],
                      "signerFingerprint": receipt["signerFingerprint"],
                      "receipt": "signing-receipt.json"}, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify six-image evidence and emit an unsigned candidate")
    verify.add_argument("--inputs", type=Path, required=True)
    verify.add_argument("--components-root", type=Path, required=True)
    verify.add_argument("--verification-key", type=Path, required=True,
                        help="protected Ed25519 PEM key for the root-authorized verification identity")
    verify.add_argument("--output-dir", type=Path, required=True)
    sign = commands.add_parser("sign", help="offline data-only signing ceremony on the approved signer workstation")
    sign.add_argument("--lock-candidate", type=Path, required=True)
    sign.add_argument("--verification-manifest", type=Path, required=True)
    sign.add_argument("--verification-manifest-signature", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify":
            verify_command(args)
        else:
            sign_command(args)
        return 0
    except (CeremonyError, customer_trust.TrustError, OSError, UnicodeError, json.JSONDecodeError,
            subprocess.SubprocessError, ValueError) as error:
        print(f"M3 offline release-lock ceremony blocked: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
