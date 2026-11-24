#!/usr/bin/env python3
"""Package M3 release image evidence using the existing six-image lock contract.

Component bundle checks here are structural only. Cryptographic verification
remains the responsibility of scripts/m3_supply_chain_verify.py and the
independently rooted M3 artifact preflight. The combined lock is signed only
with an externally provisioned Ed25519 key whose public key fingerprint is
independently pinned by the release environment.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
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
    from m3_supply_chain_verify import CYCLONEDX_PREDICATE, EXPECTED_BUILDER_ID, REPOSITORY, SLSA_PREDICATE, WORKFLOW
    from validate_image_sbom import validate_sbom_bytes
except ImportError:
    from scripts.m3_supply_chain_verify import CYCLONEDX_PREDICATE, EXPECTED_BUILDER_ID, REPOSITORY, SLSA_PREDICATE, WORKFLOW
    from scripts.validate_image_sbom import validate_sbom_bytes


COMPONENTS = ("agent", "operator", "control-plane", "dashboard", "ansible-ee", "postgres")
SUPPLEMENTAL = "agent-relay"
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_RE = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
IMAGE_RE = re.compile(r"^ghcr\.io/kevin-phan-25/kordex-([a-z0-9-]+)@sha256:([a-f0-9]{64})$")
SOURCE_URI = f"git+https://github.com/{REPOSITORY}@"


class ReleaseEvidenceError(ValueError):
    pass


def _regular_bytes(path: Path, limit: int = 64 * 1024 * 1024) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise ReleaseEvidenceError(f"required release evidence is missing or unsafe: {path.name}") from exc
    if (not stat.S_ISREG(before.st_mode) or not data or len(data) > limit or len(data) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ReleaseEvidenceError(f"release evidence is not a stable bounded file: {path.name}")
    return data


def _json_bytes(data: bytes, label: str) -> object:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseEvidenceError(f"{label} is not valid UTF-8 JSON") from exc


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _bundle_statement(data: bytes, label: str) -> dict:
    """Read one action/attest Sigstore bundle and its in-toto statement."""
    lines = [line for line in data.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ReleaseEvidenceError(f"{label} must contain exactly one Sigstore bundle")
    bundle = _json_bytes(lines[0], label)
    envelope = bundle.get("dsseEnvelope") if isinstance(bundle, dict) else None
    if not isinstance(envelope, dict) or envelope.get("payloadType") != "application/vnd.in-toto+json":
        raise ReleaseEvidenceError(f"{label} is not a Sigstore in-toto DSSE bundle")
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise ReleaseEvidenceError(f"{label} lacks a DSSE statement payload")
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ReleaseEvidenceError(f"{label} has malformed DSSE payload encoding") from exc
    statement = _json_bytes(decoded, f"{label} DSSE payload")
    if not isinstance(statement, dict) or statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ReleaseEvidenceError(f"{label} does not contain an in-toto Statement v1")
    return statement


def _check_subject(statement: dict, image_name: str, image_digest: str, label: str) -> None:
    subjects = statement.get("subject")
    if (not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict)
            or subjects[0].get("name") != image_name
            or not isinstance(subjects[0].get("digest"), dict)
            or subjects[0]["digest"].get("sha256") != image_digest):
        raise ReleaseEvidenceError(f"{label} subject does not bind the exact immutable image digest")


def _provenance_policy_fields(statement: dict, *, tag: str, commit: str) -> tuple[list[dict], dict]:
    if statement.get("predicateType") != SLSA_PREDICATE:
        raise ReleaseEvidenceError("provenance bundle has the wrong predicate type")
    predicate = statement.get("predicate")
    build = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    details = predicate.get("runDetails") if isinstance(predicate, dict) else None
    if (not isinstance(build, dict) or build.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1"
            or not isinstance(details, dict) or not isinstance(details.get("builder"), dict)
            or details["builder"].get("id") != EXPECTED_BUILDER_ID):
        raise ReleaseEvidenceError("provenance builder or build type is missing or unapproved")
    parameters = build.get("externalParameters")
    workflow = parameters.get("workflow") if isinstance(parameters, dict) else None
    if (not isinstance(workflow, dict) or workflow.get("repository") != REPOSITORY
            or workflow.get("ref") != f"refs/tags/{tag}" or workflow.get("path") != ".github/workflows/ci.yaml"):
        raise ReleaseEvidenceError("provenance workflow identity does not match the release tag and workflow")
    internal = build.get("internalParameters")
    github = internal.get("github") if isinstance(internal, dict) else None
    if (not isinstance(github, dict) or github.get("event_name") != "workflow_dispatch"
            or github.get("runner_environment") != "github-hosted"
            or not isinstance(github.get("repository_id"), str) or not github["repository_id"].isdigit()
            or not isinstance(github.get("repository_owner_id"), str) or not github["repository_owner_id"].isdigit()):
        raise ReleaseEvidenceError("provenance lacks the approved dispatch and hosted-runner identities")
    resolved = build.get("resolvedDependencies")
    if not isinstance(resolved, list) or not resolved:
        raise ReleaseEvidenceError("provenance does not identify resolved build materials")
    source_uri = SOURCE_URI + f"refs/tags/{tag}"
    sources = [row for row in resolved if isinstance(row, dict) and row.get("uri") == source_uri]
    if (len(sources) != 1 or not isinstance(sources[0].get("digest"), dict)
            or sources[0]["digest"].get("gitCommit") != commit):
        raise ReleaseEvidenceError("provenance does not bind the exact full source commit")
    materials = []
    for row in resolved:
        if not isinstance(row, dict) or not isinstance(row.get("uri"), str) or not isinstance(row.get("digest"), dict):
            raise ReleaseEvidenceError("provenance contains an incomplete resolved material")
        if row is sources[0]:
            continue
        digest = row["digest"]
        if (not row["uri"] or not digest or any(not isinstance(key, str) or not isinstance(value, str)
                or not SHA256_RE.fullmatch(value) for key, value in digest.items())):
            raise ReleaseEvidenceError("provenance material URI or SHA-256 digest is malformed")
        materials.append({"uri": row["uri"], "digest": dict(sorted(digest.items()))})
    if not materials:
        raise ReleaseEvidenceError("provenance has no non-source build materials")
    key = lambda row: (row["uri"], _canonical(row["digest"]))
    materials.sort(key=key)
    if len({key(row) for row in materials}) != len(materials):
        raise ReleaseEvidenceError("provenance contains duplicate build material identities")
    build_parameters = {
        "workflow": {"repository": workflow["repository"], "ref": workflow["ref"], "path": workflow["path"]},
        "github": {key: github[key] for key in ("event_name", "runner_environment", "repository_id", "repository_owner_id")},
    }
    return materials, build_parameters


def _parse_component_evidence(component: str, directory: Path, *, tag: str, commit: str,
                              run_id: str, run_attempt: str) -> dict:
    manifest_path = directory / "component.json"
    manifest = _json_bytes(_regular_bytes(manifest_path, 1024 * 1024), "component manifest")
    expected_fields = {"schemaVersion", "kind", "component", "buildResult", "imageReference", "sourceRef", "sourceCommit",
                       "repository", "workflow", "builderId", "buildType", "buildParameters", "buildMaterials", "releaseTag",
                       "runId", "runAttempt", "files"}
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise ReleaseEvidenceError("component manifest has missing or unsupported fields")
    if (manifest.get("schemaVersion") != 1 or manifest.get("kind") != "kordex-m3-release-image-evidence"
            or manifest.get("buildResult") != "PASS"
            or manifest.get("component") != component or manifest.get("releaseTag") != tag
            or manifest.get("sourceRef") != f"refs/tags/{tag}" or manifest.get("sourceCommit") != commit
            or manifest.get("repository") != REPOSITORY or manifest.get("workflow") != WORKFLOW
            or manifest.get("builderId") != EXPECTED_BUILDER_ID
            or manifest.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1"
            or manifest.get("runId") != run_id or manifest.get("runAttempt") != run_attempt):
        raise ReleaseEvidenceError("component manifest is not bound to this release source and workflow run")
    image_match = IMAGE_RE.fullmatch(manifest.get("imageReference", ""))
    if image_match is None or image_match.group(1) != component:
        raise ReleaseEvidenceError("component image reference is mutable or names a different component")
    image_name, image_digest = manifest["imageReference"].split("@", 1)
    image_digest = image_digest.removeprefix("sha256:")
    files = manifest.get("files")
    expected_names = {"image-reference.txt", f"{component}.cdx.json",
                      f"{component}.sbom.bundle.jsonl", f"{component}.provenance.bundle.jsonl"}
    if not isinstance(files, dict) or set(files) != expected_names:
        raise ReleaseEvidenceError("component evidence file manifest is incomplete")
    file_data = {}
    for name in sorted(expected_names):
        data = _regular_bytes(directory / name)
        if not isinstance(files[name], str) or hashlib.sha256(data).hexdigest() != files[name]:
            raise ReleaseEvidenceError(f"component evidence checksum mismatch: {name}")
        file_data[name] = data
    if file_data["image-reference.txt"].decode("utf-8").strip() != manifest["imageReference"]:
        raise ReleaseEvidenceError("component image reference file differs from its manifest")
    sbom = _json_bytes(file_data[f"{component}.cdx.json"], "CycloneDX SBOM")
    validate_sbom_bytes(file_data[f"{component}.cdx.json"])
    sbom_statement = _bundle_statement(file_data[f"{component}.sbom.bundle.jsonl"], "SBOM attestation bundle")
    if sbom_statement.get("predicateType") != CYCLONEDX_PREDICATE:
        raise ReleaseEvidenceError("SBOM attestation bundle has the wrong predicate type")
    _check_subject(sbom_statement, image_name, image_digest, "SBOM attestation")
    if _canonical(sbom_statement.get("predicate")) != _canonical(sbom):
        raise ReleaseEvidenceError("SBOM attestation predicate differs from the supplied SBOM")
    provenance = _bundle_statement(file_data[f"{component}.provenance.bundle.jsonl"], "SLSA provenance bundle")
    _check_subject(provenance, image_name, image_digest, "SLSA provenance")
    materials, build_parameters = _provenance_policy_fields(provenance, tag=tag, commit=commit)
    if manifest.get("buildMaterials") != materials or manifest.get("buildParameters") != build_parameters:
        raise ReleaseEvidenceError("component build parameters or materials differ from SLSA provenance")
    checksum_bytes = _regular_bytes(directory / "SHA256SUMS", 64 * 1024)
    expected_sums = {f"{digest}  {name}" for name, digest in files.items()}
    expected_sums.add(f"{hashlib.sha256(_regular_bytes(manifest_path, 1024 * 1024)).hexdigest()}  component.json")
    try:
        actual_sums = set(checksum_bytes.decode("ascii").splitlines())
    except UnicodeError as exc:
        raise ReleaseEvidenceError("component checksum manifest is not ASCII") from exc
    if actual_sums != expected_sums or len(actual_sums) != len(expected_sums):
        raise ReleaseEvidenceError("component checksum manifest is incomplete or mismatched")
    return {"manifest": manifest, "imageReference": manifest["imageReference"], "files": file_data}


def _safe_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _write_json(path: Path, value: object) -> bytes:
    data = _canonical(value) + b"\n"
    _safe_write(path, data)
    return data


def component_command(args: argparse.Namespace) -> None:
    if args.component not in (*COMPONENTS, SUPPLEMENTAL):
        raise ReleaseEvidenceError("unsupported release component")
    if not TAG_RE.fullmatch(args.release_tag) or not COMMIT_RE.fullmatch(args.source_commit):
        raise ReleaseEvidenceError("release tag or full source commit is invalid")
    if not args.run_id.isdigit() or not args.run_attempt.isdigit():
        raise ReleaseEvidenceError("workflow run identity is invalid")
    if args.source_ref != f"refs/tags/{args.release_tag}":
        raise ReleaseEvidenceError("release source ref differs from the selected immutable tag")
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    image_reference = args.image_reference
    temp_manifest = {
        "schemaVersion": 1, "kind": "kordex-m3-release-image-evidence", "component": args.component,
        "buildResult": "PASS",
        "imageReference": image_reference, "sourceRef": args.source_ref, "sourceCommit": args.source_commit,
        "repository": REPOSITORY, "workflow": WORKFLOW, "builderId": EXPECTED_BUILDER_ID,
        "buildType": "https://actions.github.io/buildtypes/workflow/v1", "buildParameters": {}, "buildMaterials": [],
        "releaseTag": args.release_tag, "runId": args.run_id, "runAttempt": args.run_attempt, "files": {},
    }
    image_match = IMAGE_RE.fullmatch(image_reference)
    if image_match is None or image_match.group(1) != args.component:
        raise ReleaseEvidenceError("release image reference is mutable or has the wrong component name")
    source_dir = args.output_dir.parent
    outputs = {
        "image-reference.txt": (image_reference + "\n").encode("utf-8"),
        f"{args.component}.cdx.json": _regular_bytes(args.sbom),
        f"{args.component}.sbom.bundle.jsonl": _canonical(_json_bytes(_regular_bytes(args.sbom_bundle), "SBOM bundle")) + b"\n",
        f"{args.component}.provenance.bundle.jsonl": _canonical(_json_bytes(_regular_bytes(args.provenance_bundle), "provenance bundle")) + b"\n",
    }
    for name, data in outputs.items():
        _safe_write(args.output_dir / name, data)
        temp_manifest["files"][name] = hashlib.sha256(data).hexdigest()
    sbom = _json_bytes(outputs[f"{args.component}.cdx.json"], "CycloneDX SBOM")
    validate_sbom_bytes(outputs[f"{args.component}.cdx.json"])
    image_name, digest_ref = image_reference.split("@", 1)
    digest = digest_ref.removeprefix("sha256:")
    sbom_statement = _bundle_statement(outputs[f"{args.component}.sbom.bundle.jsonl"], "SBOM attestation bundle")
    if sbom_statement.get("predicateType") != CYCLONEDX_PREDICATE:
        raise ReleaseEvidenceError("SBOM attestation bundle has the wrong predicate type")
    _check_subject(sbom_statement, image_name, digest, "SBOM attestation")
    if _canonical(sbom_statement.get("predicate")) != _canonical(sbom):
        raise ReleaseEvidenceError("SBOM attestation predicate differs from the supplied SBOM")
    provenance = _bundle_statement(outputs[f"{args.component}.provenance.bundle.jsonl"], "SLSA provenance bundle")
    _check_subject(provenance, image_name, digest, "SLSA provenance")
    temp_manifest["buildMaterials"], temp_manifest["buildParameters"] = _provenance_policy_fields(
        provenance, tag=args.release_tag, commit=args.source_commit)
    _write_json(args.output_dir / "component.json", temp_manifest)
    checks = []
    for name in sorted((*outputs.keys(), "component.json")):
        checks.append(f"{hashlib.sha256((args.output_dir / name).read_bytes()).hexdigest()}  {name}")
    _safe_write(args.output_dir / "SHA256SUMS", ("\n".join(checks) + "\n").encode("ascii"))


def _read_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ReleaseEvidenceError(f"protected release signing input is not configured: {name}")
    return value


def _sign_lock(lock: Path, signature: Path) -> str:
    private_path = Path(_read_env("KORDEX_RELEASE_PRIVATE_KEY"))
    public_path = Path(_read_env("KORDEX_RELEASE_PUBLIC_KEY"))
    expected_fingerprint = _read_env("KORDEX_RELEASE_PUBLIC_KEY_SHA256")
    if not SHA256_RE.fullmatch(expected_fingerprint):
        raise ReleaseEvidenceError("independently approved release public-key SHA-256 is malformed")
    try:
        private_info = private_path.lstat()
        repo_root = Path(__file__).resolve().parents[1]
        private_resolved = private_path.resolve(strict=True)
        private_resolved.relative_to(repo_root)
    except ValueError:
        pass
    except OSError as exc:
        raise ReleaseEvidenceError("protected release signer key file is unavailable") from exc
    else:
        raise ReleaseEvidenceError("release signing key must be supplied outside the checkout")
    if (not stat.S_ISREG(private_info.st_mode) or private_info.st_mode & 0o077
            or private_path.is_symlink()):
        raise ReleaseEvidenceError("protected release signer key must be a private regular file with mode 0600 or stricter")
    _regular_bytes(public_path, 64 * 1024)
    try:
        with tempfile.TemporaryDirectory(prefix="kordex-m3-release-signing-") as temporary:
            root = Path(temporary)
            derived_public, supplied_der, derived_der = (
                root / name for name in ("derived-public.pem", "supplied-public.der", "derived-public.der"))
            common = {"check": True, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL, "timeout": 30}
            subprocess.run(["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(derived_public)], **common)
            subprocess.run(["openssl", "pkey", "-pubin", "-in", str(public_path), "-outform", "DER", "-out", str(supplied_der)], **common)
            subprocess.run(["openssl", "pkey", "-pubin", "-in", str(derived_public), "-outform", "DER", "-out", str(derived_der)], **common)
            supplied_bytes = _regular_bytes(supplied_der, 64 * 1024)
            derived_bytes = _regular_bytes(derived_der, 64 * 1024)
            ed25519_spki = bytes.fromhex("302a300506032b6570032100")
            if (len(supplied_bytes) != 44 or not supplied_bytes.startswith(ed25519_spki)
                    or supplied_bytes != derived_bytes
                    or hashlib.sha256(supplied_bytes).hexdigest() != expected_fingerprint):
                raise ReleaseEvidenceError("protected signing identity differs from independently pinned release trust")
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_path),
                            "-in", str(lock), "-out", str(signature)], **common)
            subprocess.run(["bash", str(Path(__file__).with_name("verify-image-lock.sh")),
                            str(lock), str(signature), str(public_path)], **common)
    except ReleaseEvidenceError:
        raise
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        signature.unlink(missing_ok=True)
        raise ReleaseEvidenceError("release lock signing or signature verification failed") from exc
    return expected_fingerprint


def _assemble_into(args: argparse.Namespace) -> None:
    if not TAG_RE.fullmatch(args.release_tag) or not COMMIT_RE.fullmatch(args.source_commit):
        raise ReleaseEvidenceError("release tag or full source commit is invalid")
    if not args.run_id.isdigit() or not args.run_attempt.isdigit():
        raise ReleaseEvidenceError("workflow run identity is invalid")
    candidates = sorted(args.components_root.rglob("component.json"))
    by_component = {}
    for manifest_path in candidates:
        data = _json_bytes(_regular_bytes(manifest_path, 1024 * 1024), "component manifest")
        component = data.get("component") if isinstance(data, dict) else None
        if component not in (*COMPONENTS, SUPPLEMENTAL) or component in by_component:
            raise ReleaseEvidenceError("release component artifacts are duplicate or unsupported")
        by_component[component] = manifest_path.parent
    if set(by_component) != set(COMPONENTS) and set(by_component) != {*COMPONENTS, SUPPLEMENTAL}:
        missing = sorted(set(COMPONENTS) - set(by_component))
        raise ReleaseEvidenceError("exact six M3 component evidence sets are required; missing=" + ",".join(missing))
    evidence = {component: _parse_component_evidence(
        component, by_component[component], tag=args.release_tag, commit=args.source_commit,
        run_id=args.run_id, run_attempt=args.run_attempt) for component in COMPONENTS}
    lock_lines = []
    component_records = {}
    for component in COMPONENTS:
        record = evidence[component]
        image_ref = record["imageReference"]
        lock_lines.append(f"{component}\t{image_ref}")
        destination = args.output_dir / "components" / component
        destination.mkdir(mode=0o755, parents=True)
        for name, data in record["files"].items():
            _safe_write(destination / name, data)
        component_manifest = _canonical(record["manifest"]) + b"\n"
        _safe_write(destination / "component.json", component_manifest)
        component_sum = "\n".join(
            f"{hashlib.sha256((destination / name).read_bytes()).hexdigest()}  {name}"
            for name in sorted((*record["files"].keys(), "component.json"))) + "\n"
        _safe_write(destination / "SHA256SUMS", component_sum.encode("ascii"))
        component_records[component] = {
            "imageReference": image_ref,
            "imageDigest": image_ref.rsplit("sha256:", 1)[1],
            "sourceRef": record["manifest"]["sourceRef"],
            "sourceCommit": record["manifest"]["sourceCommit"],
            "buildResult": record["manifest"]["buildResult"],
            "builderId": record["manifest"]["builderId"],
            "workflow": record["manifest"]["workflow"],
            "buildParameters": record["manifest"]["buildParameters"],
            "buildMaterials": record["manifest"]["buildMaterials"],
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(record["files"].items())},
            "componentManifestSha256": hashlib.sha256(component_manifest).hexdigest(),
        }
    lock = ("\n".join(lock_lines) + "\n").encode("utf-8")
    lock_path = args.output_dir / "kordex-images.tsv"
    signature_path = args.output_dir / "kordex-images.tsv.sig"
    _safe_write(lock_path, lock)
    fingerprint = _sign_lock(lock_path, signature_path)
    manifest = {
        "schemaVersion": 1,
        "kind": "kordex-m3-six-image-release-evidence",
        "repository": REPOSITORY,
        "workflow": WORKFLOW,
        "releaseTag": args.release_tag,
        "sourceRef": f"refs/tags/{args.release_tag}",
        "sourceCommit": args.source_commit,
        "workflowRun": {"id": args.run_id, "attempt": args.run_attempt},
        "buildResult": "PASS",
        "lock": {"path": "kordex-images.tsv", "sha256": hashlib.sha256(lock).hexdigest(),
                 "signaturePath": "kordex-images.tsv.sig", "signatureSha256": hashlib.sha256(signature_path.read_bytes()).hexdigest(),
                 "signerPublicKeyDerSha256": fingerprint},
        "components": component_records,
        "supplementalComponentsExcluded": [SUPPLEMENTAL] if SUPPLEMENTAL in by_component else [],
    }
    _write_json(args.output_dir / "manifest.json", manifest)
    all_files = sorted(path for path in args.output_dir.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    sums = []
    for path in all_files:
        rel = path.relative_to(args.output_dir).as_posix()
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}")
    _safe_write(args.output_dir / "SHA256SUMS", ("\n".join(sums) + "\n").encode("ascii"))


def assemble_command(args: argparse.Namespace) -> None:
    target = args.output_dir
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ReleaseEvidenceError("combined release output directory must be new")
    staging = Path(tempfile.mkdtemp(prefix=".kordex-m3-release-", dir=target.parent))
    os.chmod(staging, 0o700)
    args.output_dir = staging
    try:
        _assemble_into(args)
        os.rename(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        args.output_dir = target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    component = commands.add_parser("component", help="validate and package one build's output evidence")
    component.add_argument("--component", required=True)
    component.add_argument("--image-reference", required=True)
    component.add_argument("--sbom", type=Path, required=True)
    component.add_argument("--sbom-bundle", type=Path, required=True)
    component.add_argument("--provenance-bundle", type=Path, required=True)
    component.add_argument("--source-ref", required=True)
    component.add_argument("--source-commit", required=True)
    component.add_argument("--release-tag", required=True)
    component.add_argument("--run-id", required=True)
    component.add_argument("--run-attempt", required=True)
    component.add_argument("--output-dir", type=Path, required=True)
    assemble = commands.add_parser("assemble", help="assemble and sign the exact six-image M3 release lock")
    assemble.add_argument("--components-root", type=Path, required=True)
    assemble.add_argument("--release-tag", required=True)
    assemble.add_argument("--source-commit", required=True)
    assemble.add_argument("--run-id", required=True)
    assemble.add_argument("--run-attempt", required=True)
    assemble.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "component":
            component_command(args)
        else:
            assemble_command(args)
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ReleaseEvidenceError, ValueError, subprocess.SubprocessError) as exc:
        print(f"M3 release evidence failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
