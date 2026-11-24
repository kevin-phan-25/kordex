#!/usr/bin/env python3
"""Run the trust-state contract suite using a root-authorized installed adapter.

This runner deliberately has no module-path, PYTHONPATH, import-name, or
transport-factory override. The external adapter is imported only after a
customer-root-signed bootstrap pins its installed distribution tree digest.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

# Never create bytecode caches in the runner checkout: cached files are
# git-ignored, so they would otherwise sit outside the clean-source check.
sys.dont_write_bytecode = True

# Isolated mode drops the script directory from sys.path. Re-add only this
# runner's adjacent Kordex verifier modules; customer adapters are discovered
# exclusively from protected installed entry-point metadata after digest pinning.
_KORDEX_SCRIPTS = Path(__file__).resolve().parent
if str(_KORDEX_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_KORDEX_SCRIPTS))

try:
    import m3_customer_trust as customer_trust
    import m3_trust_state as trust_state
    import m3_trust_state_conformance as conformance
except ModuleNotFoundError:
    from scripts import m3_customer_trust as customer_trust
    from scripts import m3_trust_state as trust_state
    from scripts import m3_trust_state_conformance as conformance


ENTRY_POINT_GROUP = "kordex.m3.trust_state.conformance"
ENTRY_POINT_NAME = "customer"
BOOTSTRAP_FIELDS = {
    "schemaVersion", "customerId", "backendIdentity", "endpointReference", "evidenceReference",
    "issuedAt", "expiresAt", "runnerSourceCommit", "adapterDistribution", "adapterVersion",
    "adapterTreeSha256", "attestationPublicKeyPem", "attestationFingerprint",
    "conformanceRootPublicKeyPem", "trustPolicyDocument", "trustPolicySignatureHex",
}
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,127}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
SOURCE_COMMIT = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")


class RunnerError(ValueError):
    pass


def read_file(path: Path, limit: int) -> bytes:
    try:
        return customer_trust.read_regular(path, limit)
    except customer_trust.TrustError as error:
        raise RunnerError(f"required trust/conformance input is unavailable or unsafe: {path}") from error


def read_trusted_root(path: Path) -> bytes:
    """Require the configured trust root and its parent chain to be root-owned."""
    if not path.is_absolute():
        raise RunnerError("customer qualification root path must be absolute")
    try:
        for directory in reversed(path.parents):
            info = directory.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0 or info.st_mode & 0o022):
                raise RunnerError("customer root-key directories must be root-owned and not group/world writable")
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0 or info.st_mode & 0o022):
            raise RunnerError("customer qualification root must be a protected root-owned regular file")
    except OSError as error:
        raise RunnerError("customer qualification root is unavailable or unsafe") from error
    return read_file(path, 16 * 1024)


def _validate_schema(document: dict, schema_path: Path, message: str) -> None:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError, ValidationError
        raw_schema = customer_trust.read_regular(schema_path, 512 * 1024)
        schema = json.loads(raw_schema.decode("utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    except (OSError, UnicodeError, json.JSONDecodeError, customer_trust.TrustError,
            SchemaError, ValidationError) as error:
        raise RunnerError(message) from error


def read_bootstrap(bootstrap_path: Path, signature_path: Path,
                   root_path: Path | None = None, *, now: dt.datetime | None = None,
                   repository: Path | None = None) -> tuple[dict, bytes]:
    root_path = root_path or customer_trust.TRUST_ROOT
    raw = read_file(bootstrap_path, 2 * 1024 * 1024)
    signature = read_file(signature_path, 4096)
    root_public_key = read_trusted_root(root_path)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=customer_trust.unique_object)
    except (UnicodeError, json.JSONDecodeError, customer_trust.TrustError) as error:
        raise RunnerError("adapter bootstrap is malformed") from error
    if not isinstance(document, dict) or set(document) != BOOTSTRAP_FIELDS:
        raise RunnerError("adapter bootstrap fields are incomplete or unsupported")
    try:
        if len(signature) != 64:
            raise RunnerError("bootstrap detached signature must be exactly 64 raw Ed25519 bytes")
        if raw != customer_trust.canonical_json(document):
            raise RunnerError("adapter bootstrap is not canonical JSON")
        customer_trust.verify_signature(raw, signature, root_public_key)
        repo = repository or Path(__file__).resolve().parents[1]
        schema_path = repo / "schemas/m3-trust-state-conformance-bootstrap-v1.json"
        _validate_schema(document, schema_path, "adapter bootstrap failed schema validation")
        current = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
        issued = customer_trust.parse_time(document["issuedAt"], "bootstrap.issuedAt")
        expires = customer_trust.parse_time(document["expiresAt"], "bootstrap.expiresAt")
        if issued > current + dt.timedelta(minutes=2) or expires <= current or expires <= issued or expires - issued > dt.timedelta(days=30):
            raise RunnerError("adapter bootstrap is expired, future-dated, or exceeds the 30-day limit")
        if (type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1
                or not IDENTITY.fullmatch(document["customerId"] or "")
                or not IDENTITY.fullmatch(document["backendIdentity"] or "")
                or not isinstance(document["endpointReference"], str)
                or not document["endpointReference"].startswith("https://")
                or not IDENTITY.fullmatch(document["evidenceReference"] or "")
                or not SOURCE_COMMIT.fullmatch(document["runnerSourceCommit"] or "")
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,127}", document["adapterDistribution"] or "")
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!-]{0,127}", document["adapterVersion"] or "")
                or not SHA256.fullmatch(document["adapterTreeSha256"] or "")
                or not SHA256.fullmatch(document["attestationFingerprint"] or "")
                or not isinstance(document["attestationPublicKeyPem"], str)
                or not isinstance(document["conformanceRootPublicKeyPem"], str)
                or not isinstance(document["trustPolicySignatureHex"], str)
                or not re.fullmatch(r"[a-f0-9]{128}", document["trustPolicySignatureHex"])
                or re.match(r"(?i)^(fixture|synthetic|test)[-_:/.]", document["evidenceReference"])):
            raise RunnerError("adapter bootstrap identity or policy binding is malformed")
        endpoint = customer_trust.urlsplit(document["endpointReference"])
        if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username is not None
                or endpoint.password is not None or endpoint.query or endpoint.fragment):
            raise RunnerError("backend endpoint must be a credential-free HTTPS reference")
        attestor_key = document["attestationPublicKeyPem"].encode("ascii")
        if customer_trust.fingerprint(attestor_key) != document["attestationFingerprint"]:
            raise RunnerError("attestor key does not match the independently supplied fingerprint")
        conformance_root_key = document["conformanceRootPublicKeyPem"].encode("ascii")
        # Parse and enforce Ed25519 for the isolated conformance root.
        customer_trust.fingerprint(conformance_root_key)
        policy = document["trustPolicyDocument"]
        policy_signature = bytes.fromhex(document["trustPolicySignatureHex"])
        if len(policy_signature) != 64:
            raise RunnerError("trust-policy test signature must be a raw Ed25519 signature")
        customer_trust.verify_signature(customer_trust.canonical_json(policy), policy_signature, root_public_key)
        customer_trust.validate_document(policy, now=current)
        _validate_policy_bindings(document, policy, root_public_key)
    except (KeyError, TypeError, AttributeError, UnicodeError, ValueError, customer_trust.TrustError) as error:
        if isinstance(error, RunnerError):
            raise
        raise RunnerError("adapter bootstrap signature, key, time, or trust policy is invalid") from error
    return document, root_public_key


def _validate_policy_bindings(bootstrap: dict, policy: dict, qualification_root_public_key: bytes) -> None:
    settings = policy.get("trustState")
    if (policy.get("customerId") != bootstrap["customerId"] or not isinstance(settings, dict)
            or settings.get("backendIdentity") != bootstrap["backendIdentity"]
            or settings.get("endpointReference") != bootstrap["endpointReference"]):
        raise RunnerError("root-signed trust policy does not bind the bootstrap customer/backend")
    for key in ("adapterDistribution", "adapterVersion", "adapterTreeSha256"):
        if key in settings and settings[key] != bootstrap.get(key):
            raise RunnerError("root-signed trust policy does not bind the bootstrap adapter package")
    attestor_identity = settings.get("attestorIdentity")
    reviewer_identity = settings.get("conformanceReviewerIdentity")
    if not isinstance(attestor_identity, str) or not isinstance(reviewer_identity, str):
        raise RunnerError("root-signed policy lacks distinct backend attestor and reviewer identities")
    attestor_key, attestor_fingerprint = customer_trust.authorized_key(
        policy, attestor_identity, "trust-state-attestor")
    reviewer_key, reviewer_fingerprint = customer_trust.authorized_key(
        policy, reviewer_identity, "reviewer")
    if (attestor_identity == reviewer_identity or attestor_key == reviewer_key
            or attestor_key != bootstrap["attestationPublicKeyPem"].encode("ascii")
            or attestor_fingerprint != bootstrap["attestationFingerprint"]):
        raise RunnerError("bootstrap attestor key differs from the root-authorized backend attestor")
    conformance_root = bootstrap["conformanceRootPublicKeyPem"].encode("ascii")
    conformance_fingerprint = customer_trust.fingerprint(conformance_root)
    qualification_fingerprint = customer_trust.fingerprint(qualification_root_public_key)
    policy_fingerprints = {
        item["fingerprint"] for item in policy.get("keys", [])
        if isinstance(item, dict) and isinstance(item.get("fingerprint"), str)
    }
    if conformance_fingerprint in (
            {qualification_fingerprint, attestor_fingerprint, reviewer_fingerprint} | policy_fingerprints):
        raise RunnerError("isolated conformance root must be distinct from qualification root, attestor, reviewer, and all policy keys")


def source_commit_and_cleanliness(repository: Path, expected_commit: str) -> str:
    try:
        repo_root = repository.resolve(strict=True)
    except OSError as error:
        raise RunnerError("conformance runner must execute from its approved Git source checkout") from error
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    clean_env["GIT_CONFIG_NOSYSTEM"] = "1"
    clean_env["GIT_CONFIG_GLOBAL"] = os.devnull
    clean_env["GIT_TERMINAL_PROMPT"] = "0"
    git = ["git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(repo_root)]
    try:
        toplevel = subprocess.run([*git, "rev-parse", "--show-toplevel"], check=True,
                                  capture_output=True, text=True, env=clean_env).stdout.strip()
        commit = subprocess.run([*git, "rev-parse", "HEAD"], check=True,
                                capture_output=True, text=True, env=clean_env).stdout.strip()
        # --ignored: git-ignored files (bytecode caches, local config) can
        # shadow imports, so the approved checkout must contain none.
        dirty = subprocess.run([*git, "status", "--porcelain", "--untracked-files=all", "--ignored"],
                               check=True, capture_output=True, text=True, env=clean_env).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise RunnerError("conformance runner must execute from its approved Git source checkout") from error
    try:
        resolved_toplevel = Path(toplevel).resolve(strict=True)
    except OSError as error:
        raise RunnerError("conformance runner must execute from its approved Git source checkout") from error
    if resolved_toplevel != repo_root:
        raise RunnerError("conformance runner must execute from its approved Git repository root")
    if commit != expected_commit or dirty:
        raise RunnerError("runner source commit differs from signed bootstrap or worktree is dirty")
    return commit


ENTRY_POINT_VALUE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r":([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)$"
)


def _entry_module_name(entry) -> str:
    value = getattr(entry, "value", None)
    match = ENTRY_POINT_VALUE.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        raise RunnerError("pinned conformance entry point has an invalid module reference")
    return match.group(1)


def _distribution_file_paths(distribution) -> set[Path]:
    try:
        return {Path(distribution.locate_file(item)).resolve(strict=True) for item in distribution.files}
    except (OSError, RuntimeError, TypeError) as error:
        raise RunnerError("pinned adapter distribution files cannot be resolved") from error


def _reject_unpinned_bytecode(origin: Path, allowed: set[Path]) -> None:
    try:
        cache = Path(importlib.util.cache_from_source(str(origin)))
    except (NotImplementedError, ValueError):
        return
    if cache.is_symlink():
        raise RunnerError("unpinned bytecode cache shadows pinned adapter module")
    if cache.exists():
        try:
            resolved_cache = cache.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise RunnerError("unpinned bytecode cache shadows pinned adapter module") from error
        if resolved_cache not in allowed:
            raise RunnerError("unpinned bytecode cache shadows pinned adapter module")


def _require_pinned_origin(origin, allowed: set[Path]) -> Path:
    try:
        if not isinstance(origin, str):
            resolved = None
        else:
            origin_path = Path(origin)
            if origin_path.is_symlink():
                raise RunnerError("adapter module origin must not be a symlink")
            resolved = origin_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RunnerError("adapter module origin cannot be resolved") from error
    if resolved is None or resolved not in allowed:
        raise RunnerError("adapter module resolves outside its root-authorized distribution")
    _reject_unpinned_bytecode(resolved, allowed)
    return resolved


def verify_entry_module_origin(entry) -> tuple[str, set[Path]]:
    """Fail closed unless import resolution reaches the digest-pinned files.

    The tree digest covers the distribution's files, but ``entry.load()``
    imports by module name through ``sys.path``. A same-named module earlier
    on the path, an unpinned submodule, or an unpinned bytecode cache would
    otherwise be executed instead of the pinned code.
    """
    module = _entry_module_name(entry)
    parts = module.split(".")
    top = parts[0]
    if any(name == top or name.startswith(top + ".") for name in sys.modules):
        raise RunnerError("adapter module was imported before its pinned origin could be verified")
    try:
        dist_root = Path(entry.dist.locate_file("")).resolve(strict=True)
    except (AttributeError, OSError, RuntimeError, TypeError) as error:
        raise RunnerError("pinned adapter distribution root cannot be resolved") from error
    allowed = _distribution_file_paths(entry.dist)
    try:
        # A top-level lookup locates the module without executing any code.
        spec = importlib.util.find_spec(top)
    except (ImportError, ValueError) as error:
        raise RunnerError("adapter module cannot be located") from error
    if spec is None:
        raise RunnerError("adapter module cannot be located")
    _require_pinned_origin(spec.origin, allowed)
    for idx in range(1, len(parts)):
        locations = spec.submodule_search_locations
        if not locations:
            raise RunnerError("adapter submodule package path is missing or invalid")
        verified_locations: list[str] = []
        for loc in locations:
            loc_path = Path(loc)
            try:
                if loc_path.is_symlink():
                    raise RunnerError("adapter package search path must not be a symlink")
                resolved_loc = loc_path.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise RunnerError("adapter package search path cannot be resolved") from error
            if not resolved_loc.is_relative_to(dist_root):
                raise RunnerError("adapter module resolves outside its root-authorized distribution")
            verified_locations.append(str(resolved_loc))
        subname = ".".join(parts[:idx + 1])
        # PathFinder.find_spec resolves the submodule without executing parent __init__.py.
        spec = importlib.machinery.PathFinder.find_spec(subname, verified_locations)
        if spec is None:
            raise RunnerError("adapter submodule cannot be located")
        _require_pinned_origin(spec.origin, allowed)
    return module, allowed


def verify_loaded_module_origin(module: str, allowed: set[Path]) -> None:
    parts = module.split(".")
    for idx in range(1, len(parts) + 1):
        prefix = ".".join(parts[:idx])
        loaded = sys.modules.get(prefix)
        _require_pinned_origin(getattr(loaded, "__file__", None), allowed)


def select_entry_point(entries, expected_distribution: str, expected_version: str,
                       expected_tree_digest: str):
    selected = [entry for entry in entries if entry.group == ENTRY_POINT_GROUP and entry.name == ENTRY_POINT_NAME]
    if len(selected) != 1:
        raise RunnerError("exactly one pinned customer conformance entry point must be installed")
    entry = selected[0]
    distribution = getattr(entry, "dist", None)
    if (distribution is None or distribution.name != expected_distribution
            or distribution.version != expected_version):
        raise RunnerError("installed conformance adapter distribution/version is not root-authorized")
    if trust_state.adapter_distribution_sha256(distribution) != expected_tree_digest:
        raise RunnerError("installed conformance adapter tree digest is not root-authorized")
    return entry


def run(bootstrap_path: Path, signature_path: Path, output_path: Path,
        *, root_path: Path | None = None, repository: Path | None = None) -> dict:
    repository = repository or Path(__file__).resolve().parents[1]
    bootstrap, root_public_key = read_bootstrap(
        bootstrap_path, signature_path, root_path, repository=repository)
    commit = source_commit_and_cleanliness(repository, bootstrap["runnerSourceCommit"])
    try:
        discovered = importlib.metadata.entry_points()
        entries = discovered.select(group=ENTRY_POINT_GROUP, name=ENTRY_POINT_NAME) if hasattr(discovered, "select") else discovered.get(ENTRY_POINT_GROUP, [])
        entry = select_entry_point(entries, bootstrap["adapterDistribution"], bootstrap["adapterVersion"],
                                   bootstrap["adapterTreeSha256"])
        module, allowed = verify_entry_module_origin(entry)
        adapter_factory = entry.load()
        verify_loaded_module_origin(module, allowed)
        adapter = adapter_factory({
            "customerId": bootstrap["customerId"], "backendIdentity": bootstrap["backendIdentity"],
            "endpointReference": bootstrap["endpointReference"],
            "evidenceReference": bootstrap["evidenceReference"],
        })
    except RunnerError:
        raise
    except Exception as error:
        raise RunnerError("pinned customer conformance adapter failed to load") from error
    if (not isinstance(adapter, dict) or set(adapter) != {"transportFactory", "signConformanceConfiguration"}
            or not callable(adapter["transportFactory"]) or not callable(adapter["signConformanceConfiguration"])):
        raise RunnerError("pinned adapter must provide only the documented conformance factory contract")
    policy = bootstrap["trustPolicyDocument"]
    try:
        result = conformance.run_conformance(
            transport_factory=adapter["transportFactory"], customer_id=bootstrap["customerId"],
            backend_identity=bootstrap["backendIdentity"], endpoint_reference=bootstrap["endpointReference"],
            attestation_public_key=bootstrap["attestationPublicKeyPem"].encode("ascii"),
            attestation_fingerprint=bootstrap["attestationFingerprint"],
            evidence_reference=bootstrap["evidenceReference"],
            conformance_root_public_key=bootstrap["conformanceRootPublicKeyPem"].encode("ascii"),
            sign_conformance_configuration=adapter["signConformanceConfiguration"],
            trust_policy_document=policy,
            trust_policy_signature=bytes.fromhex(bootstrap["trustPolicySignatureHex"]),
            trust_policy_root_public_key=root_public_key,
        )
    except RunnerError:
        raise
    except Exception as error:
        raise RunnerError("trust-state conformance execution failed") from error
    expected_conformance_fp = customer_trust.fingerprint(
        bootstrap["conformanceRootPublicKeyPem"].encode("ascii"))
    candidate = result.get("conformanceReportCandidate") if isinstance(result, dict) else None
    if (not isinstance(result, dict)
            or result.get("backendContractChecks") != "EXECUTED"
            or result.get("unitOrFixtureExecution") is not False
            or result.get("customerAdapterConformance") != "NOT ESTABLISHED"
            or result.get("productionTrustAccepted") is not False
            or result.get("requiresIndependentReview") is not True
            or result.get("customerId") != bootstrap["customerId"]
            or result.get("backendIdentity") != bootstrap["backendIdentity"]
            or result.get("endpointReference") != bootstrap["endpointReference"]
            or result.get("conformanceRootFingerprint") != expected_conformance_fp
            or not isinstance(candidate, dict)
            or candidate.get("customerId") != bootstrap["customerId"]
            or candidate.get("backendIdentity") != bootstrap["backendIdentity"]
            or candidate.get("endpointReference") != bootstrap["endpointReference"]
            or candidate.get("evidenceReference") != bootstrap["evidenceReference"]):
        raise RunnerError("conformance result is synthetic, incomplete, mismatched, or claims unsupported production acceptance")
    report = {
        "schemaVersion": 1,
        "runnerSourceCommit": commit,
        "bootstrapSha256": hashlib.sha256(customer_trust.canonical_json(bootstrap)).hexdigest(),
        "adapterDistribution": bootstrap["adapterDistribution"],
        "adapterVersion": bootstrap["adapterVersion"],
        "adapterTreeSha256": bootstrap["adapterTreeSha256"],
        "backendExecution": result,
        "productionTrustAccepted": False,
        "independentReviewRequired": True,
        "qualificationRowsAdvanced": 0,
    }
    schema_path = repository / "schemas/m3-trust-state-conformance-run-report-v1.json"
    _validate_schema(report, schema_path, "trust-state conformance runner produced an invalid report")
    _write_private_new(output_path, customer_trust.canonical_json(report))
    return report


def _write_private_new(path: Path, data: bytes) -> None:
    name = path.name
    if not name or name in {".", ".."} or "/" in name:
        raise RunnerError("conformance report path must name a file")
    parent = path.parent
    dir_fd = None
    try:
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(dir_fd)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise RunnerError("conformance output directory must be private, mode 0700 or stricter")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except RunnerError:
        raise
    except OSError as error:
        raise RunnerError("conformance report cannot overwrite an existing or unsafe path") from error
    finally:
        if dir_fd is not None:
            os.close(dir_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not sys.flags.isolated:
            raise RunnerError("conformance runner must be invoked with Python isolated mode (-I)")
        result = run(args.bootstrap, args.signature, args.output)
    except RunnerError as error:
        print(json.dumps({"status": "BLOCKED", "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
