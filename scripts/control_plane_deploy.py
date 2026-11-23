#!/usr/bin/env python3
"""Fail-closed customer Helm preflight and deployment for the control plane.

No credentials are accepted as values. The command reads protected file paths,
verifies external attestations and performs read-only checks before the one
explicitly authorized Helm deployment. An interrupted Helm operation is never
retried or rolled back automatically.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deployments/helm/kordex-control-plane"
MIGRATION = ROOT / "control-plane/migrations/016_lab_lifecycle_barrier.sql"
EXPECTED_CHART_VERSION = "0.7.0"
EXPECTED_APP_VERSION = "0.8.0"
EXPECTED_MIGRATION_SHA256 = "b98fff6f64ac5268f951d6ddc17bcc8331f49839d5f743f472ca9df5daab8b4d"
REPOSITORY = "kevin-phan-25/kordex"
GH_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
ALLOWED = {"PASS", "FAIL", "NOT PROVIDED", "NOT VERIFIED"}
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
IMAGE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


REQUIRED = {
    "target": {"kubeContext", "clusterServer", "kubeSystemNamespaceUID", "namespace", "releaseName"},
    "release": {"tag", "sourceCommit", "imageRepository", "imageDigest"},
    "database": {"pgServiceFile", "pgServiceName", "credentialsSecretName"},
    "oidc": {"issuer", "audience", "tokenMode", "accessClientID", "accessRequiredScopes"},
    "ingress": {"host", "tlsSecretName", "caBundlePath"},
    "evidence": {"backup"},
    "lifecycle": {"controlPlaneUrl", "organizationID", "clusterID", "adminTokenFile", "viewerTokenFile", "tlsCertificateSha256"},
    "helmValuesFile": None,
}
SECTION_KEYS = {
    "target": {"kubeContext", "clusterServer", "kubeSystemNamespaceUID", "namespace", "releaseName"},
    "release": {"tag", "sourceCommit", "imageRepository", "imageDigest"},
    "database": {"pgServiceFile", "pgServiceName", "credentialsSecretName"},
    "oidc": {"issuer", "audience", "tokenMode", "accessClientID", "accessRequiredScopes"},
    "ingress": {"host", "tlsSecretName", "caBundlePath"},
    "evidence": {"backup"},
    "lifecycle": {"controlPlaneUrl", "organizationID", "clusterID", "adminTokenFile", "viewerTokenFile", "tlsCertificateSha256"},
}
EVIDENCE_KEYS = {"path", "signature", "publicKey", "targetID", "observedAt", "expiresAt"}


class DeployError(RuntimeError):
    pass


class MissingInput(DeployError):
    pass


class Runner:
    def run(self, command: list[str], *, env: dict[str, str] | None = None,
            input_data: bytes | None = None, timeout: int = 60) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(command, input=input_data, env=env, text=input_data is None,
                                  capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DeployError("external command unavailable or timed out") from exc


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeployError("duplicate JSON field")
        result[key] = value
    return result


def read_manifest(path: Path) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        raise MissingInput("deployment manifest was not provided")
    try:
        if path.is_symlink() or not path.is_file():
            raise DeployError("manifest must be a regular file")
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DeployError("manifest is missing or invalid JSON") from exc
    if (not isinstance(value, dict) or isinstance(value.get("schemaVersion"), bool)
            or value.get("schemaVersion") != 1 or "fixtureOnly" in value):
        raise DeployError("manifest is not a production version-1 input")
    allowed_top = {"schemaVersion", "target", "release", "database", "oidc", "ingress", "evidence", "lifecycle", "helmValuesFile"}
    if set(value) - allowed_top:
        raise DeployError("manifest fields do not match the strict deployment contract")
    for section, keys in SECTION_KEYS.items():
        member = value.setdefault(section, {})
        if not isinstance(member, dict) or set(member) - keys:
            raise DeployError(f"manifest {section} fields do not match the strict contract")
    evidence_root = value.setdefault("evidence", {})
    if not isinstance(evidence_root, dict) or set(evidence_root) - {"backup"}:
        raise DeployError("manifest evidence fields do not match the strict contract")
    evidence = evidence_root.setdefault("backup", {})
    if not isinstance(evidence, dict) or set(evidence) - EVIDENCE_KEYS:
        raise DeployError("manifest backup evidence fields do not match the strict contract")
    value["_manifestSha256"] = hashlib.sha256(raw).hexdigest()
    value["_manifestPath"] = str(path.resolve())
    return value


def _path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise DeployError(f"{label} path is missing")
    result = Path(value).expanduser()
    if not result.exists() and not result.is_symlink():
        raise MissingInput(f"{label} file was not provided")
    if result.is_symlink() or not result.is_file():
        raise DeployError(f"{label} must be a regular file")
    return result


def _private_file(path: Path, label: str) -> None:
    info = path.stat()
    if not path.is_file() or path.is_symlink() or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise DeployError(f"{label} must be an owner-only regular file")


def _safe_check(report: dict, name: str, fn) -> Any:
    try:
        result, detail = fn()
        if result not in ALLOWED:
            result, detail = "FAIL", "invalid internal check result"
    except MissingInput as exc:
        result, detail = "NOT PROVIDED", str(exc)
    except DeployError as exc:
        result, detail = "FAIL", str(exc)
    except Exception:
        result, detail = "FAIL", "check failed; sensitive output was suppressed"
    report["checks"].append({"id": name, "status": result, "detail": detail})
    return result


def _run_ok(runner: Runner, command: list[str], *, timeout: int = 60,
            env: dict[str, str] | None = None, input_data: bytes | None = None) -> subprocess.CompletedProcess:
    result = runner.run(command, env=env, timeout=timeout, input_data=input_data)
    if result.returncode != 0:
        raise DeployError("required command failed; stdout and stderr suppressed")
    return result


def _require_can_i(result: subprocess.CompletedProcess) -> None:
    if result.stdout.strip() != "yes":
        raise DeployError("Kubernetes identity lacks a required permission")


def _capture_json(runner: Runner, command: list[str], *, timeout: int = 60,
                  env: dict[str, str] | None = None) -> Any:
    result = _run_ok(runner, command, timeout=timeout, env=env)
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise DeployError("required command returned invalid JSON") from exc


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _version_at_least(value: str, minimum: tuple[int, int]) -> bool:
    match = re.search(r"v?(\d+)\.(\d+)", value)
    return bool(match and tuple(map(int, match.groups())) >= minimum)


def quantity(value: Any, *, cpu: bool) -> int:
    """Convert Kubernetes CPU to millicores or memory to bytes."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise DeployError("resource quantity is missing or malformed")
    raw = str(value)
    if cpu:
        if raw.endswith("m"):
            return int(raw[:-1])
        return int(float(raw) * 1000)
    units = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40,
             "K": 10**3, "M": 10**6, "G": 10**9, "T": 10**12}
    for suffix, factor in units.items():
        if raw.endswith(suffix):
            return int(float(raw[:-len(suffix)]) * factor)
    return int(float(raw))


def pod_resource_requests(spec: dict, *, strict_resources: bool = True) -> tuple[int, int]:
    containers = spec.get("containers", [])
    init = spec.get("initContainers", [])
    if not containers:
        raise DeployError("rendered pod has no regular containers")

    def totals(rows: list[dict]) -> tuple[int, int]:
        cpu_total = memory_total = 0
        for container in rows:
            resources = container.get("resources", {})
            request = resources.get("requests", {})
            limits = resources.get("limits", {})
            if strict_resources and (not all(key in request for key in ("cpu", "memory")) or "memory" not in limits):
                raise DeployError("every rendered container must set CPU/memory requests and a memory limit")
            cpu_req = quantity(request.get("cpu", "0"), cpu=True)
            memory_req = quantity(request.get("memory", "0"), cpu=False)
            if "memory" in limits and quantity(limits["memory"], cpu=False) < memory_req:
                raise DeployError("container memory limit is below its memory request")
            cpu_total += cpu_req
            memory_total += memory_req
        return cpu_total, memory_total

    regular = totals(containers)
    init_max = (0, 0)
    for container in init:
        one = totals([container])
        init_max = max(init_max[0], one[0]), max(init_max[1], one[1])
    overhead = spec.get("overhead", {})
    return (max(regular[0], init_max[0]) + quantity(overhead.get("cpu", "0"), cpu=True),
            max(regular[1], init_max[1]) + quantity(overhead.get("memory", "0"), cpu=False))


def json_documents(text: str) -> list[dict]:
    chunks = re.split(r"(?m)^---\s*$", text.strip())
    values = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            value = json.loads(chunk)
        except json.JSONDecodeError as exc:
            raise DeployError("Kubernetes server-side validation did not return parseable JSON objects") from exc
        if isinstance(value, dict) and value.get("kind") == "List":
            values.extend(item for item in value.get("items", []) if isinstance(item, dict))
        elif isinstance(value, dict):
            values.append(value)
    if not values:
        raise DeployError("Kubernetes server-side validation returned no objects")
    return values


def _resource_demands(objects: list[dict]) -> tuple[int, int]:
    cpu = memory = 0
    for obj in objects:
        kind = obj.get("kind")
        spec = obj.get("spec", {})
        if kind == "Deployment":
            replicas = spec.get("replicas", 1)
            if not isinstance(replicas, int) or replicas < 1:
                raise DeployError("deployment replica count is invalid")
            pod = spec.get("template", {}).get("spec", {})
            pod_cpu, pod_memory = pod_resource_requests(pod)
            surge = max(1, (replicas + 3) // 4)
            cpu += (replicas + surge) * pod_cpu
            memory += (replicas + surge) * pod_memory
        elif kind == "Job":
            pod = spec.get("template", {}).get("spec", {})
            pod_cpu, pod_memory = pod_resource_requests(pod)
            parallelism = spec.get("parallelism", 1)
            if not isinstance(parallelism, int) or parallelism < 1:
                raise DeployError("migration Job parallelism is invalid")
            cpu += parallelism * pod_cpu
            memory += parallelism * pod_memory
    return cpu, memory


def _available_capacity(nodes: dict, pods: dict) -> tuple[int, int]:
    alloc_cpu = alloc_memory = used_cpu = used_memory = 0
    ready = set()
    for node in nodes.get("items", []):
        status = node.get("status", {})
        conditions = status.get("conditions", [])
        if node.get("spec", {}).get("unschedulable"):
            continue
        if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions):
            continue
        name = node.get("metadata", {}).get("name")
        if not name:
            continue
        ready.add(name)
        alloc = status.get("allocatable", {})
        alloc_cpu += quantity(alloc.get("cpu"), cpu=True)
        alloc_memory += quantity(alloc.get("memory"), cpu=False)
    if not ready:
        raise DeployError("cluster has no Ready schedulable nodes")
    for pod in pods.get("items", []):
        spec = pod.get("spec", {})
        if spec.get("nodeName") not in ready or pod.get("status", {}).get("phase") in {"Succeeded", "Failed"}:
            continue
        cpu, memory = pod_resource_requests(spec, strict_resources=False)
        used_cpu += cpu
        used_memory += memory
    return max(0, alloc_cpu - used_cpu), max(0, alloc_memory - used_memory)


def verify_migration_ledger(ledger: list[tuple[int, str]]) -> None:
    expected = []
    for migration in sorted((ROOT / "control-plane/migrations").glob("*.sql")):
        match = re.match(r"^(\d+)_", migration.name)
        if not match:
            raise DeployError("migration filename is not versioned")
        expected.append((int(match.group(1)), _hash_file(migration)))
    if len(ledger) > len(expected) or ledger != expected[:len(ledger)]:
        raise DeployError("PostgreSQL migration history is not a valid prefix of this release")


def verify_migration_016(ledger: list[tuple[int, str]]) -> None:
    if sum(version == 16 for version, _ in ledger) != 1 or not ledger or ledger[-1] != (16, EXPECTED_MIGRATION_SHA256):
        raise DeployError("migration 016 is absent, duplicated, or has the wrong checksum")


def lifecycle_state_unchanged(before: Any, after: Any) -> bool:
    return isinstance(before, dict) and isinstance(after, dict) and before == after


def require_viewer_denied(status: int) -> None:
    if status != 403:
        raise DeployError("non-administrator lifecycle mutation was not denied with HTTP 403")


def require_admin_authorized(status: int, body: Any) -> None:
    if status != 200 or body != {"authorized": True, "role": "administrator"}:
        raise DeployError("lifecycle token is not an authenticated organization administrator")


def _opaque(checks: list[dict], name: str) -> str | None:
    for check in checks:
        if check["id"] == name and check["status"] == "PASS":
            return check.get("_value")
    return None


def _read_secret_json(runner: Runner, context: str, namespace: str, secret: str) -> dict:
    return _capture_json(runner, ["kubectl", "--context", context, "get", "secret", secret,
                                  "-n", namespace, "-o", "json"])


def _verify_tls_secret(secret_obj: dict, host: str, ca_bundle: Path) -> None:
    if secret_obj.get("type") != "kubernetes.io/tls":
        raise DeployError("ingress TLS Secret has the wrong type")
    data = secret_obj.get("data")
    if not isinstance(data, dict) or not data.get("tls.crt") or not data.get("tls.key"):
        raise DeployError("ingress TLS Secret is missing certificate material")
    cert = base64.b64decode(data["tls.crt"], validate=True)
    key = base64.b64decode(data["tls.key"], validate=True)
    with tempfile.TemporaryDirectory(prefix="kordex-deploy-tls-") as temp:
        directory = Path(temp)
        os.chmod(directory, 0o700)
        cert_path, key_path = directory / "tls.crt", directory / "tls.key"
        cert_path.write_bytes(cert)
        key_path.write_bytes(key)
        os.chmod(cert_path, 0o600)
        os.chmod(key_path, 0o600)
        _run_ok(Runner(), ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkhost", host, "-checkend", "86400"])
        verified = _run_ok(Runner(), ["openssl", "verify", "-CAfile", str(ca_bundle), str(cert_path)])
        cert_key = _run_ok(Runner(), ["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"])
        private_key = _run_ok(Runner(), ["openssl", "pkey", "-in", str(key_path), "-pubout"])
        if cert_key.stdout != private_key.stdout or not verified.stdout:
            raise DeployError("ingress certificate, key, host, or trust chain verification failed")


def _verify_evidence(runner: Runner, item: dict, expected_key_hash: str, *, target_id: str,
                     kind: str, now: float) -> tuple[str, dict | None]:
    if not isinstance(item, dict) or any(not item.get(key) for key in EVIDENCE_KEYS):
        return "NOT PROVIDED", None
    if not SHA256.fullmatch(expected_key_hash or ""):
        return "NOT VERIFIED", None
    try:
        evidence_path = _path(item.get("path"), f"{kind} evidence")
        sig_path = _path(item.get("signature"), f"{kind} signature")
        key_path = _path(item.get("publicKey"), f"{kind} public key")
        if _hash_file(key_path) != expected_key_hash:
            return "FAIL", None
        _run_ok(runner, ["cosign", "verify-blob", "--key", str(key_path), "--signature", str(sig_path), str(evidence_path)])
        doc = json.loads(evidence_path.read_text(encoding="utf-8"), object_pairs_hook=_pairs_no_duplicates)
        if not isinstance(doc, dict) or doc.get("schemaVersion") != 1 or doc.get("targetID") != target_id:
            return "FAIL", None
        observed = parse_time(doc.get("observedAt"))
        expires = parse_time(doc.get("expiresAt"))
        if observed > now or now - observed > 24 * 60 * 60 or expires <= now or expires <= observed:
            return "FAIL", None
        if item.get("targetID") != target_id or item.get("observedAt") != doc.get("observedAt") or item.get("expiresAt") != doc.get("expiresAt"):
            return "FAIL", None
        fields = doc.get("fields")
        if not isinstance(fields, dict):
            return "FAIL", None
        return "PASS", doc
    except MissingInput:
        return "NOT PROVIDED", None
    except (DeployError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return "FAIL", None


def parse_time(value: Any) -> float:
    if not isinstance(value, str):
        raise ValueError("timestamp missing")
    from datetime import datetime
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp timezone missing")
    return parsed.timestamp()


def _database_check(runner: Runner, cfg: dict) -> tuple[str, str, list[tuple[int, str]]]:
    db = cfg["database"]
    service_file = _path(db["pgServiceFile"], "PostgreSQL service file")
    _private_file(service_file, "PostgreSQL service file")
    cfg["_databaseServiceSha256"] = _hash_file(service_file)
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(service_file)
        section = parser[db["pgServiceName"]]
    except (KeyError, configparser.Error) as exc:
        raise DeployError("PostgreSQL service entry is unavailable") from exc
    if section.get("sslmode") != "verify-full" or not section.get("host") or not section.get("dbname"):
        raise DeployError("PostgreSQL service must pin host, database, and sslmode=verify-full")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PGSERVICEFILE": str(service_file),
           "PGSSLMODE": "verify-full", "PGCONNECT_TIMEOUT": "5"}
    result = _run_ok(runner, ["psql", f"service={db['pgServiceName']}", "--no-psqlrc", "-X", "-A", "-t",
                              "-v", "ON_ERROR_STOP=1", "-c",
                              "SELECT current_setting('server_version_num') || '|' || COALESCE((SELECT ssl::text FROM pg_stat_ssl WHERE pid=pg_backend_pid()),'false') || '|' || COALESCE(to_regclass('public.schema_migrations')::text,'');"],
                    timeout=15, env=env)
    fields = result.stdout.strip().split("|")
    if len(fields) != 3 or not fields[0].isdigit() or int(fields[0]) < 100000 or fields[1] != "true":
        raise DeployError("PostgreSQL reachability, TLS, or migration compatibility check failed")
    ledger: list[tuple[int, str]] = []
    if fields[2]:
        history = _run_ok(runner, ["psql", f"service={db['pgServiceName']}", "--no-psqlrc", "-X", "-A", "-t", "-F", "|",
                                   "-v", "ON_ERROR_STOP=1", "-c", "SELECT version,checksum FROM schema_migrations ORDER BY version;"],
                         timeout=15, env=env)
        for row in history.stdout.splitlines():
            try:
                version, digest = row.split("|", 1)
                ledger.append((int(version), digest))
            except ValueError as exc:
                raise DeployError("PostgreSQL migration history is malformed") from exc
    verify_migration_ledger(ledger)
    return "PASS", "TLS-verified PostgreSQL reachable; migration history is a compatible prefix", ledger


def _database_target_fingerprint(cfg: dict) -> str:
    service_file = _path(cfg["database"]["pgServiceFile"], "PostgreSQL service file")
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(service_file)
    section = parser[cfg["database"]["pgServiceName"]]
    target = "|".join((section.get("host", ""), section.get("port", "5432"), section.get("dbname", "")))
    if not all(target.split("|")[index] for index in (0, 2)):
        raise DeployError("PostgreSQL target identity is incomplete")
    return hashlib.sha256(target.encode("utf-8")).hexdigest()


def _fetch_oidc(issuer: str) -> tuple[dict, dict]:
    parsed = urlsplit(issuer)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise DeployError("OIDC issuer must be an HTTPS origin")
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with urlopen(discovery_url, timeout=10) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise DeployError("OIDC discovery response is oversized")
        doc = json.loads(data)
    except (OSError, URLError, json.JSONDecodeError) as exc:
        raise DeployError("OIDC discovery is unreachable or invalid") from exc
    jwks = doc.get("jwks_uri")
    jwks_parsed = urlsplit(jwks or "")
    if doc.get("issuer") != issuer or jwks_parsed.scheme != "https" or not jwks_parsed.hostname:
        raise DeployError("OIDC issuer or HTTPS JWKS configuration mismatch")
    try:
        with urlopen(jwks, timeout=10) as response:
            body = response.read(1024 * 1024 + 1)
        jwks_doc = json.loads(body)
    except (OSError, URLError, json.JSONDecodeError) as exc:
        raise DeployError("OIDC JWKS endpoint is unreachable or invalid") from exc
    if len(body) > 1024 * 1024 or not isinstance(jwks_doc.get("keys"), list) or not jwks_doc["keys"]:
        raise DeployError("OIDC JWKS is empty or oversized")
    return doc, jwks_doc


def _check_release(runner: Runner, cfg: dict) -> tuple[str, str]:
    release = cfg["release"]
    repo = release.get("imageRepository")
    digest = release.get("imageDigest")
    tag = release.get("tag")
    source = release.get("sourceCommit")
    if not isinstance(repo, str) or repo != "ghcr.io/kevin-phan-25/kordex-control-plane":
        raise DeployError("deployment image must use the release workflow's pinned source repository")
    if not isinstance(digest, str) or not IMAGE_DIGEST.fullmatch(digest):
        raise DeployError("mutable or malformed image reference is forbidden")
    if not isinstance(tag, str) or not TAG.fullmatch(tag) or not isinstance(source, str) or not COMMIT.fullmatch(source):
        raise DeployError("release tag or source commit is invalid")
    clean = _run_ok(runner, ["git", "status", "--porcelain"], timeout=10)
    if clean.stdout.strip():
        raise DeployError("release checkout must be clean")
    head = _run_ok(runner, ["git", "rev-parse", "HEAD"], timeout=10).stdout.strip()
    tag_commit = _run_ok(runner, ["git", "rev-parse", f"{tag}^{{commit}}"], timeout=10).stdout.strip()
    if head != source or tag_commit != source:
        raise DeployError("checked out source does not exactly match the approved release tag and commit")
    expected_identity = f"https://github.com/{REPOSITORY}/.github/workflows/ci.yaml@refs/tags/{tag}"
    image_ref = f"{repo}@{digest}"
    _run_ok(runner, ["cosign", "verify", "--certificate-identity", expected_identity,
                     "--certificate-oidc-issuer", GH_OIDC_ISSUER, image_ref], timeout=120)
    _run_ok(runner, ["gh", "attestation", "verify", f"oci://{image_ref}", "--repo", REPOSITORY,
                     "--signer-workflow", f"{REPOSITORY}/.github/workflows/ci.yaml",
                     "--source-ref", f"refs/tags/{tag}", "--source-digest", source,
                     "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"], timeout=120)
    return image_ref, expected_identity


def _preflight(cfg: dict | None, runner: Runner, *, backup_key_sha256: str,
               trusted_cluster_uid: str = "", trusted_api_server: str = "") -> dict:
    report = {"schemaVersion": 1, "kind": "kordex-control-plane-deployment-preflight", "checks": [],
              "overall": "BLOCKED", "deploymentAllowed": False, "recoveryRequired": False}
    if cfg is None:
        report["checks"].append({"id": "inputs.manifest", "status": "NOT PROVIDED", "detail": "deployment manifest was not supplied"})
        for section, keys in REQUIRED.items():
            if section == "helmValuesFile":
                report["checks"].append({"id": "input.helmValuesFile", "status": "NOT PROVIDED", "detail": "customer Helm values file is required"})
            else:
                for key in sorted(keys):
                    report["checks"].append({"id": f"input.{section}.{key}", "status": "NOT PROVIDED", "detail": "required customer input missing"})
        for key in sorted(EVIDENCE_KEYS):
            report["checks"].append({"id": f"input.evidence.backup.{key}", "status": "NOT PROVIDED", "detail": "required signed customer evidence missing"})
        return report

    missing = []
    for section, keys in REQUIRED.items():
        if section == "helmValuesFile":
            if not cfg.get(section):
                missing.append("helmValuesFile")
            continue
        member = cfg.get(section, {})
        if not isinstance(member, dict):
            missing.append(section)
            continue
        for key in sorted(keys):
            value = member.get(key)
            if value is None or value == "":
                missing.append(f"{section}.{key}")
    member = cfg.get("evidence", {}).get("backup", {})
    for key in sorted(EVIDENCE_KEYS):
        if member.get(key) in (None, ""):
            missing.append(f"evidence.backup.{key}")
    if missing:
        report["checks"].append({"id": "inputs.manifest", "status": "FAIL", "detail": "manifest is incomplete"})
        report["checks"].extend({"id": f"input.{name}", "status": "NOT PROVIDED", "detail": "required customer input missing"}
                                for name in sorted(set(missing)))
        return report

    def static_contract():
        chart = (CHART / "Chart.yaml").read_text(encoding="utf-8")
        if not re.search(r"(?m)^version:\s*['\"]?0\.7\.0['\"]?\s*$", chart):
            raise DeployError("control-plane chart version mismatch")
        if not re.search(r"(?m)^appVersion:\s*['\"]?0\.8\.0['\"]?\s*$", chart):
            raise DeployError("control-plane app version mismatch")
        if _hash_file(MIGRATION) != EXPECTED_MIGRATION_SHA256:
            raise DeployError("migration 016 checksum mismatch")
        return "PASS", "chart 0.7.0/app 0.8.0 and migration 016 checksum match repository policy"
    _safe_check(report, "repository.contract", static_contract)

    def local_tools():
        required_tools = ("kubectl", "helm", "cosign", "gh", "psql", "openssl", "git")
        missing_tools = [tool for tool in required_tools if shutil.which(tool) is None]
        if missing_tools:
            return "NOT PROVIDED", "required local tools are unavailable: " + ", ".join(missing_tools)
        return "PASS", "required preflight and deployment tools are present; no tools were downloaded"
    tool_status = _safe_check(report, "operator.local_tools", local_tools)
    if tool_status != "PASS":
        for identifier in (
            "target.independent_binding", "release.signature_provenance",
            "kubernetes.identity_version_namespace", "kubernetes.permissions",
            "kubernetes.credentials_secret", "database.connectivity_tls_compatibility",
            "oidc.discovery_jwks", "ingress.tls_prerequisites", "helm.render_schema_capacity_inputs",
            "database.backup_restore_evidence", "lifecycle.verification_inputs",
        ):
            report["checks"].append({"id": identifier, "status": "NOT VERIFIED",
                                     "detail": "skipped because required local tools are unavailable"})
        return report

    def target_binding():
        if not trusted_cluster_uid or not trusted_api_server:
            return "NOT PROVIDED", "independently approved Kubernetes API endpoint and cluster UID are required"
        if cfg["target"]["kubeSystemNamespaceUID"] != trusted_cluster_uid:
            raise DeployError("manifest cluster UID differs from independent target confirmation")
        if cfg["target"]["clusterServer"] != trusted_api_server:
            raise DeployError("manifest API server differs from independent target confirmation")
        cfg["_trustedClusterUID"] = trusted_cluster_uid
        cfg["_trustedApiServer"] = trusted_api_server
        return "PASS", "manifest target matches separately supplied platform-owner endpoint and cluster UID"
    _safe_check(report, "target.independent_binding", target_binding)

    def release_check():
        reference, identity = _check_release(runner, cfg)
        report["imageReference"] = reference
        report["releaseIdentity"] = identity
        return "PASS", "immutable image signature and source-bound SLSA provenance verified"
    _safe_check(report, "release.signature_provenance", release_check)

    target = cfg["target"]
    cfg["_backupKeySha256"] = backup_key_sha256
    ns = target["namespace"]
    context = target["kubeContext"]
    kube_values: dict[str, Any] = {}

    def required_after_cluster_identity() -> None:
        for identifier in (
            "kubernetes.permissions", "operator.local_tools", "kubernetes.credentials_secret",
            "database.connectivity_tls_compatibility", "oidc.discovery_jwks",
            "ingress.tls_prerequisites", "helm.render_schema_capacity_inputs",
            "database.backup_restore_evidence", "lifecycle.verification_inputs",
        ):
            report["checks"].append({"id": identifier, "status": "NOT VERIFIED",
                                     "detail": "skipped because the independently bound Kubernetes target was not verified"})

    def kubernetes_identity():
        if (not trusted_cluster_uid or not trusted_api_server
                or target["kubeSystemNamespaceUID"] != trusted_cluster_uid
                or target["clusterServer"] != trusted_api_server):
            raise DeployError("independently confirmed Kubernetes target is missing or mismatched")
        context_json = _capture_json(runner, ["kubectl", "config", "view", "--minify", "--context", context, "-o", "json"])
        contexts = context_json.get("contexts", [])
        clusters = context_json.get("clusters", [])
        server = clusters[0].get("cluster", {}).get("server") if len(clusters) == 1 else None
        current = contexts[0].get("name") if len(contexts) == 1 else None
        if current != context or server != target["clusterServer"] or (trusted_api_server and server != trusted_api_server):
            raise DeployError("Kubernetes context or API endpoint differs from approved target")
        system_ns = _capture_json(runner, ["kubectl", "--context", context, "get", "namespace", "kube-system", "-o", "json"])
        uid = system_ns.get("metadata", {}).get("uid")
        if uid != target["kubeSystemNamespaceUID"]:
            raise DeployError("Kubernetes cluster identity UID mismatch")
        version = _capture_json(runner, ["kubectl", "--context", context, "version", "-o", "json"]).get("serverVersion", {}).get("gitVersion", "")
        if not _version_at_least(version, (1, 21)):
            raise DeployError("Kubernetes server version is below the chart API minimum (1.21)")
        _capture_json(runner, ["kubectl", "--context", context, "get", "namespace", ns, "-o", "json"])
        kube_values.update({"version": version, "server": server, "uid": uid})
        return "PASS", "Kubernetes API, pinned cluster identity, namespace, and minimum API version verified"
    cluster_identity_status = _safe_check(report, "kubernetes.identity_version_namespace", kubernetes_identity)
    if cluster_identity_status != "PASS":
        required_after_cluster_identity()
        report["overall"] = "BLOCKED"
        report["deploymentAllowed"] = False
        return report

    def rbac_check():
        resources = ["deployments", "services", "jobs", "configmaps", "secrets", "pods", "poddisruptionbudgets", "networkpolicies"]
        for verb in ("get", "list", "watch", "create", "update", "patch", "delete"):
            for resource in resources:
                result = _run_ok(runner, ["kubectl", "--context", context, "auth", "can-i", verb, resource, "-n", ns], timeout=15)
                _require_can_i(result)
        for command in (["list", "nodes"], ["list", "pods", "--all-namespaces"]):
            result = _run_ok(runner, ["kubectl", "--context", context, "auth", "can-i", *command], timeout=15)
            _require_can_i(result)
        return "PASS", "kubectl authorization checks succeeded for Helm-managed namespaced resources"
    _safe_check(report, "kubernetes.permissions", rbac_check)

    def secret_check():
        secret = _read_secret_json(runner, context, ns, cfg["database"]["credentialsSecretName"])
        data = secret.get("data", {})
        keys = set(data)
        required = {"databaseURL", "migrationDatabaseURL", "maintenanceSigningKey"}
        if not required <= keys:
            raise DeployError("credentials Secret is missing required keys")
        decoded = {key: base64.b64decode(data[key], validate=True) for key in required}
        if any(not decoded[key] for key in required):
            raise DeployError("credentials Secret contains an empty required value")
        database_targets = []
        for key in ("databaseURL", "migrationDatabaseURL"):
            dsn = decoded[key].decode("utf-8")
            parsed = urlsplit(dsn)
            query = parse_qs(parsed.query)
            if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname or not parsed.path.strip("/") or query.get("sslmode") != ["verify-full"]:
                raise DeployError("database Secret URLs must identify PostgreSQL and require sslmode=verify-full")
            database_targets.append((parsed.hostname, parsed.port or 5432, parsed.path.strip("/")))
        if database_targets[0] != database_targets[1]:
            raise DeployError("runtime and migration URLs must target the same PostgreSQL database")
        encoded_seed = decoded["maintenanceSigningKey"].decode("ascii").strip()
        maintenance_seed = base64.b64decode(encoded_seed + "=" * (-len(encoded_seed) % 4), validate=True)
        if len(maintenance_seed) not in {32, 64}:
            raise DeployError("maintenance signing key is not a valid Ed25519 seed/private key encoding")
        cfg["_credentialsSecretSha256"] = _canonical_digest(data)
        if cfg["oidc"]["tokenMode"] == "access_token" and (not cfg["oidc"]["accessClientID"] or not cfg["oidc"]["accessRequiredScopes"]):
            raise DeployError("access-token mode requires client ID and scopes")
        return "PASS", "required credential Secret metadata and key names verified; values suppressed"
    _safe_check(report, "kubernetes.credentials_secret", secret_check)

    def db_check():
        status, detail, ledger = _database_check(runner, cfg)
        report["migrationHistory"] = {"appliedVersions": [version for version, _ in ledger],
                                      "migration016Present": any(version == 16 for version, _ in ledger)}
        return status, detail
    _safe_check(report, "database.connectivity_tls_compatibility", db_check)

    def oidc_check():
        oidc = cfg["oidc"]
        if oidc["tokenMode"] not in {"id_token", "access_token"} or not oidc["audience"]:
            raise DeployError("OIDC mode or audience is missing")
        if oidc["tokenMode"] == "id_token" and (oidc["accessClientID"] or oidc["accessRequiredScopes"]):
            raise DeployError("access-token settings cannot be set in ID-token mode")
        _fetch_oidc(oidc["issuer"])
        return "PASS", "OIDC issuer discovery and HTTPS JWKS endpoint verified"
    _safe_check(report, "oidc.discovery_jwks", oidc_check)

    def tls_check():
        ingress = cfg["ingress"]
        if not re.fullmatch(r"[A-Za-z0-9.-]+", ingress["host"]):
            raise DeployError("ingress host is invalid")
        ca = _path(ingress["caBundlePath"], "TLS trust bundle")
        secret = _read_secret_json(runner, context, ns, ingress["tlsSecretName"])
        _verify_tls_secret(secret, ingress["host"], ca)
        cfg["_tlsBundleSha256"] = _hash_file(ca)
        cfg["_ingressSecretSha256"] = _canonical_digest(secret.get("data", {}))
        return "PASS", "ingress TLS Secret type, hostname, key match, expiry, and CA chain verified"
    _safe_check(report, "ingress.tls_prerequisites", tls_check)

    def helm_render():
        values_path = _path(cfg["helmValuesFile"], "Helm values file")
        _private_file(values_path, "Helm values file")
        values_bytes = values_path.read_bytes()
        raw = values_bytes.decode("utf-8")
        values_digest = hashlib.sha256(values_bytes).hexdigest()
        if re.search(r"(?im)^\s*(?:password|token|databaseURL|migrationDatabaseURL|maintenanceSigningKey|privateKey)\s*:", raw):
            raise DeployError("Helm values file appears to contain secret material")
        reference, _identity = _check_release(runner, cfg)
        values_temp = tempfile.TemporaryDirectory(prefix="kordex-helm-values-")
        values_dir = Path(values_temp.name)
        os.chmod(values_dir, 0o700)
        values_snapshot = values_dir / "values.yaml"
        values_snapshot.write_bytes(values_bytes)
        os.chmod(values_snapshot, 0o600)
        cfg["_helmValuesTemporaryDirectory"] = values_temp
        cfg["_helmValuesSnapshot"] = str(values_snapshot)
        report["deploymentBindings"] = {
            "manifestSha256": cfg.get("_manifestSha256"),
            "helmValuesSha256": values_digest,
            "sourceCommit": release["sourceCommit"],
            "imageDigest": release["imageDigest"],
        }
        release = cfg["release"]
        common = ["--namespace", ns, "--values", str(values_snapshot), "--set-string", f"image.repository={release['imageRepository']}",
                  "--set-string", f"image.digest={release['imageDigest']}", "--set", "image.requireDigest=true"]
        _run_ok(runner, ["helm", "lint", str(CHART), *common], timeout=120)
        rendered = _run_ok(runner, ["helm", "template", target["releaseName"], str(CHART), *common], timeout=120)
        image_lines = re.findall(r"(?m)^\s*image:\s*([^\s]+)\s*$", rendered.stdout)
        if not image_lines or any(item != reference for item in image_lines):
            raise DeployError("rendered workloads do not all use the exact immutable image digest")
        for env_name, env_value in (("KORDEX_OIDC_ISSUER", cfg["oidc"]["issuer"]),
                                    ("KORDEX_OIDC_AUDIENCE", cfg["oidc"]["audience"])):
            if not re.search(rf"(?m)name:\s*{re.escape(env_name)}\s*\n\s*value:\s*{re.escape(json.dumps(env_value))}\s*$", rendered.stdout):
                raise DeployError("rendered OIDC issuer/audience differs from the reviewed inputs")
        if cfg["database"]["credentialsSecretName"] not in rendered.stdout:
            raise DeployError("rendered chart does not reference the verified credentials Secret")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="kordex-render-", suffix=".yaml", delete=False) as stream:
            os.chmod(stream.name, 0o600)
            stream.write(rendered.stdout)
            manifest_path = stream.name
        try:
            dry_run = _run_ok(runner, ["kubectl", "--context", context, "apply", "--dry-run=server", "--validate=strict", "-n", ns,
                                       "-f", manifest_path, "-o", "json"], timeout=120)
        finally:
            Path(manifest_path).unlink(missing_ok=True)
        objects = json_documents(dry_run.stdout)
        if any(obj.get("kind") == "Secret" and (obj.get("data") or obj.get("stringData")) for obj in objects):
            raise DeployError("rendered manifests contain Secret payload data")
        required_cpu, required_memory = _resource_demands(objects)
        nodes = _capture_json(runner, ["kubectl", "--context", context, "get", "nodes", "-o", "json"])
        pods = _capture_json(runner, ["kubectl", "--context", context, "get", "pods", "--all-namespaces", "-o", "json"])
        available_cpu, available_memory = _available_capacity(nodes, pods)
        report["capacity"] = {"requiredCpuMilli": required_cpu, "requiredMemoryBytes": required_memory,
                              "availableCpuMilli": available_cpu, "availableMemoryBytes": available_memory}
        if available_cpu < required_cpu or available_memory < required_memory:
            raise DeployError("cluster schedulable capacity is below rendered requests including rollout surge")
        return "PASS", "Helm lint/render, server-side validation, resource requests/limits, and live schedulable capacity passed"
    _safe_check(report, "helm.render_schema_capacity_inputs", helm_render)

    def backup_evidence():
        status, doc = _verify_evidence(runner, cfg["evidence"]["backup"], backup_key_sha256,
                                       target_id=target["clusterSystemNamespaceUID"] if "clusterSystemNamespaceUID" in target else target["kubeSystemNamespaceUID"],
                                       kind="backup", now=time.time())
        if status != "PASS" or doc is None:
            return status, "signed, fresh database backup/restore evidence is missing or invalid"
        fields = doc["fields"]
        restored_at = parse_time(fields.get("restoreTestAt")) if fields.get("restoreTestAt") else 0
        if (fields.get("restoreTestPassed") is not True or not fields.get("backupReference")
                or fields.get("databaseTargetSha256") != _database_target_fingerprint(cfg)
                or restored_at <= 0 or restored_at > time.time() or time.time() - restored_at > 90 * 24 * 60 * 60):
            return "FAIL", "backup evidence does not prove a successful restore test"
        cfg["_backupEvidenceSha256"] = {
            key: _hash_file(_path(cfg["evidence"]["backup"][key], f"backup {key}"))
            for key in ("path", "signature", "publicKey")
        }
        return "PASS", "customer-signed, fresh database backup and restore evidence verified"
    _safe_check(report, "database.backup_restore_evidence", backup_evidence)

    def local_credentials():
        for key in ("adminTokenFile", "viewerTokenFile"):
            path = _path(cfg["lifecycle"][key], key)
            _private_file(path, key)
        cfg["_lifecycleTokenSha256"] = {
            key: hashlib.sha256(_read_token(Path(cfg["lifecycle"][key])).encode("utf-8")).hexdigest()
            for key in ("adminTokenFile", "viewerTokenFile")
        }
        life = cfg["lifecycle"]
        if not UUID.fullmatch(life["organizationID"]) or not UUID.fullmatch(life["clusterID"]):
            raise DeployError("lifecycle organization and cluster UUIDs are required")
        if not SHA256.fullmatch(life["tlsCertificateSha256"]):
            raise DeployError("pinned control-plane TLS certificate digest is required")
        endpoint = urlsplit(life["controlPlaneUrl"])
        if endpoint.scheme != "https" or endpoint.hostname != cfg["ingress"]["host"] or endpoint.username or endpoint.password:
            raise DeployError("control-plane URL must be HTTPS on the approved ingress host")
        return "PASS", "private lifecycle token paths, UUIDs, and TLS pin are valid"
    _safe_check(report, "lifecycle.verification_inputs", local_credentials)

    report["overall"] = "PASS" if report["checks"] and all(item["status"] == "PASS" for item in report["checks"]) else "BLOCKED"
    report["deploymentAllowed"] = report["overall"] == "PASS"
    return report


def _write_report(report: dict, path: Path | None, *, replace: bool = False) -> None:
    encoded = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if path is None:
        sys.stdout.buffer.write(encoded)
        return
    if path.is_symlink() or path.exists():
        if not replace or path.is_symlink() or not path.is_file():
            raise DeployError("report output already exists")
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise DeployError("existing deployment journal is not owner-controlled")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    if replace:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temp_path = Path(temp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as target:
                target.write(encoded)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temp_path, path)
            dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            temp_path.unlink(missing_ok=True)
        return
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(encoded)
        target.flush()
        os.fsync(target.fileno())
    dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _read_token(path: Path) -> str:
    _private_file(path, "lifecycle token")
    token = path.read_text(encoding="utf-8").strip()
    if not token or any(char.isspace() for char in token):
        raise DeployError("lifecycle token file is malformed")
    return token


def _lifecycle_status(base_url: str, organization: str, cluster: str, token_file: Path,
                      cert_sha256: str, *, method: str = "GET", action: str = "") -> tuple[int, dict | None]:
    token = _read_token(token_file)
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DeployError("lifecycle endpoint must use HTTPS without embedded credentials")
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context, timeout=15)
    try:
        conn.connect()
        cert = conn.sock.getpeercert(binary_form=True)
        if hashlib.sha256(cert).hexdigest() != cert_sha256:
            raise DeployError("control-plane TLS certificate pin mismatch")
        path = parsed.path.rstrip("/") + f"/v1/organizations/{organization}/clusters/{cluster}/lab-lifecycle"
        if action:
            path += "/" + action
        conn.request(method, path, headers={"Authorization": "Bearer " + token, "Accept": "application/json", "Content-Length": "0"})
        response = conn.getresponse()
        body = response.read(256 * 1024 + 1)
        if len(body) > 256 * 1024:
            raise DeployError("lifecycle API response exceeded its limit")
        try:
            value = json.loads(body) if body else None
        except json.JSONDecodeError:
            value = None
        return response.status, value
    finally:
        conn.close()


def _health_check(runner: Runner, context: str, namespace: str, release: str) -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen(["kubectl", "--context", context, "port-forward", "-n", namespace,
                                f"service/{release}-api", f"{port}:8080"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise DeployError("API port-forward exited before health verification")
            try:
                with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as response:
                    if response.status == 200 and json.loads(response.read()) == {"status": "ok"}:
                        break
            except Exception:
                time.sleep(0.25)
        else:
            raise DeployError("API liveness check failed")
        with urlopen(f"http://127.0.0.1:{port}/readyz", timeout=5) as response:
            if response.status != 200 or json.loads(response.read()) != {"status": "ready"}:
                raise DeployError("API readiness check failed")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _verify_post_deploy(cfg: dict, runner: Runner, report: dict, base_url: str) -> None:
    target, life = cfg["target"], cfg["lifecycle"]
    ns, context, release = target["namespace"], target["kubeContext"], target["releaseName"]
    checks = report["checks"]

    def migration():
        _run_ok(runner, ["helm", "status", release, "-n", ns], timeout=30)
        status, detail, ledger = _database_check(runner, cfg)
        verify_migration_016(ledger)
        return "PASS", "migration 016 is recorded exactly once with the approved checksum"
    if _safe_check(report, "postdeploy.migration016", migration) != "PASS":
        report["recoveryRequired"] = True
        return

    def rollouts():
        _run_ok(runner, ["kubectl", "--context", context, "rollout", "status", f"deployment/{release}-api", "-n", ns, "--timeout=5m"], timeout=310)
        _run_ok(runner, ["kubectl", "--context", context, "rollout", "status", f"deployment/{release}-scheduler", "-n", ns, "--timeout=5m"], timeout=310)
        _health_check(runner, context, ns, release)
        return "PASS", "API and scheduler rollouts and /healthz,/readyz verified"
    if _safe_check(report, "postdeploy.health", rollouts) != "PASS":
        report["recoveryRequired"] = True
        return

    def admin_auth():
        from m3_lab_lifecycle import ControlPlaneClient
        status, authorization = _lifecycle_status(base_url, life["organizationID"], life["clusterID"],
                                                 Path(life["adminTokenFile"]), life["tlsCertificateSha256"],
                                                 action="authorization")
        require_admin_authorized(status, authorization)
        client = ControlPlaneClient(base_url, life["organizationID"], life["clusterID"],
                                    Path(life["adminTokenFile"]), life["tlsCertificateSha256"])
        state = client.request()
        report["lifecycleStateBeforeRestart"] = state
        return "PASS", "administrator lifecycle GET passed over TLS-pinned HTTPS"
    if _safe_check(report, "postdeploy.lifecycle_admin", admin_auth) != "PASS":
        report["recoveryRequired"] = True
        return

    def viewer_denied():
        status, _ = _lifecycle_status(base_url, life["organizationID"], life["clusterID"],
                                      Path(life["viewerTokenFile"]), life["tlsCertificateSha256"],
                                      action="authorization")
        require_viewer_denied(status)
        after_probe = _lifecycle_status(base_url, life["organizationID"], life["clusterID"],
                                        Path(life["adminTokenFile"]), life["tlsCertificateSha256"])[1]
        if not lifecycle_state_unchanged(report.get("lifecycleStateBeforeRestart"), after_probe):
            raise DeployError("lifecycle state changed during read-only non-administrator authorization probe")
        return "PASS", "non-administrator read-only authorization probe returned HTTP 403; response body suppressed"
    if _safe_check(report, "postdeploy.lifecycle_nonadmin_denied", viewer_denied) != "PASS":
        report["recoveryRequired"] = True
        return

    def restart_persistence():
        _run_ok(runner, ["kubectl", "--context", context, "rollout", "restart", f"deployment/{release}-api", "-n", ns], timeout=60)
        _run_ok(runner, ["kubectl", "--context", context, "rollout", "status", f"deployment/{release}-api", "-n", ns, "--timeout=5m"], timeout=310)
        from m3_lab_lifecycle import ControlPlaneClient
        client = ControlPlaneClient(base_url, life["organizationID"], life["clusterID"],
                                    Path(life["adminTokenFile"]), life["tlsCertificateSha256"])
        after = client.request()
        before = report.get("lifecycleStateBeforeRestart")
        if not lifecycle_state_unchanged(before, after):
            raise DeployError("durable lifecycle response changed across API restart")
        report["lifecycleStateAfterRestart"] = after
        return "PASS", "lifecycle response remained byte-equivalent across API pod restart"
    if _safe_check(report, "postdeploy.lifecycle_restart_persistence", restart_persistence) != "PASS":
        report["recoveryRequired"] = True


def _deployment_approval(cfg: dict, bindings: dict) -> str:
    target, release = cfg["target"], cfg["release"]
    if (not isinstance(bindings, dict)
            or not SHA256.fullmatch(str(bindings.get("manifestSha256", "")))
            or not SHA256.fullmatch(str(bindings.get("helmValuesSha256", "")))
            or bindings.get("sourceCommit") != release.get("sourceCommit")
            or bindings.get("imageDigest") != release.get("imageDigest")):
        raise DeployError("deployment authorization bindings are incomplete or inconsistent")
    return (f"APPROVE_KORDEX_CONTROL_PLANE_DEPLOY {target['kubeSystemNamespaceUID']} "
            f"{target['namespace']} {target['releaseName']} {release['imageDigest']} "
            f"{bindings['manifestSha256']} {bindings['helmValuesSha256']}")


def _verify_inputs_unchanged(cfg: dict, runner: Runner, bindings: dict) -> None:
    target = cfg["target"]
    context = target["kubeContext"]
    local_files = [
        (cfg["database"]["pgServiceFile"], cfg.get("_databaseServiceSha256"), "PostgreSQL service file"),
        (cfg["ingress"]["caBundlePath"], cfg.get("_tlsBundleSha256"), "TLS trust bundle"),
    ]
    for key, digest in cfg.get("_backupEvidenceSha256", {}).items():
        local_files.append((cfg["evidence"]["backup"][key], digest, f"backup {key}"))
    for field, digest in cfg.get("_lifecycleTokenSha256", {}).items():
        path = _path(cfg["lifecycle"][field], field)
        current = hashlib.sha256(_read_token(path).encode("utf-8")).hexdigest()
        if current != digest:
            raise DeployError("lifecycle credential changed after preflight")
    for value, expected, label in local_files:
        path = _path(value, label)
        if not expected or _hash_file(path) != expected:
            raise DeployError(f"{label} changed after preflight")

    if (cfg.get("_manifestPath")
            and _hash_file(_path(cfg["_manifestPath"], "deployment manifest")) != bindings["manifestSha256"]):
        raise DeployError("deployment manifest changed after preflight")
    values_path = _path(cfg["helmValuesFile"], "Helm values file")
    if _hash_file(values_path) != bindings["helmValuesSha256"]:
        raise DeployError("Helm values file changed after preflight")
    if _hash_file(_path(cfg.get("_helmValuesSnapshot", str(values_path)), "reviewed Helm values snapshot")) != bindings["helmValuesSha256"]:
        raise DeployError("reviewed Helm values snapshot changed after preflight")

    backup_status, backup_doc = _verify_evidence(
        runner, cfg["evidence"]["backup"], cfg.get("_backupKeySha256", ""),
        target_id=target["kubeSystemNamespaceUID"], kind="backup", now=time.time(),
    )
    if backup_status != "PASS" or backup_doc is None:
        raise DeployError("database backup/restore evidence expired or changed after preflight")
    backup_fields = backup_doc["fields"]
    restore_time = parse_time(backup_fields.get("restoreTestAt")) if backup_fields.get("restoreTestAt") else 0
    if (backup_fields.get("restoreTestPassed") is not True or not backup_fields.get("backupReference")
            or backup_fields.get("databaseTargetSha256") != _database_target_fingerprint(cfg)
            or restore_time <= 0 or restore_time > time.time()
            or time.time() - restore_time > 90 * 24 * 60 * 60):
        raise DeployError("database backup/restore evidence is no longer current")
    _database_check(runner, cfg)
    _fetch_oidc(cfg["oidc"]["issuer"])

    live_context = _capture_json(runner, ["kubectl", "config", "view", "--minify", "--context", context, "-o", "json"])
    contexts, clusters = live_context.get("contexts", []), live_context.get("clusters", [])
    if (len(contexts) != 1 or len(clusters) != 1 or contexts[0].get("name") != context
            or clusters[0].get("cluster", {}).get("server") != cfg.get("_trustedApiServer")):
        raise DeployError("Kubernetes target changed after preflight")
    system_ns = _capture_json(runner, ["kubectl", "--context", context, "get", "namespace", "kube-system", "-o", "json"])
    if system_ns.get("metadata", {}).get("uid") != cfg.get("_trustedClusterUID"):
        raise DeployError("Kubernetes cluster identity changed after preflight")
    credentials = _read_secret_json(runner, context, target["namespace"], cfg["database"]["credentialsSecretName"])
    if _canonical_digest(credentials.get("data", {})) != cfg.get("_credentialsSecretSha256"):
        raise DeployError("database credentials Secret changed after preflight")
    ingress = _read_secret_json(runner, context, target["namespace"], cfg["ingress"]["tlsSecretName"])
    if _canonical_digest(ingress.get("data", {})) != cfg.get("_ingressSecretSha256"):
        raise DeployError("ingress TLS Secret changed after preflight")
    reference, identity = _check_release(runner, cfg)
    if reference != f"{cfg['release']['imageRepository']}@{bindings['imageDigest']}":
        raise DeployError("signed release image binding changed after preflight")
    if not identity:
        raise DeployError("signed release identity is unavailable")


def deployment_command(cfg: dict, runner: Runner, report: dict, approval: str, base_url: str) -> dict:
    bindings = report.get("deploymentBindings", {})
    try:
        report["deploymentAuthorizationRequired"] = _deployment_approval(cfg, bindings)
    except DeployError:
        report["deploymentState"] = "ABORTED_PREMUTATION"
        raise
    if (report.get("overall") != "PASS"
            or (not report.get("deploymentAllowed") and report.get("deploymentAuthorizationAccepted") is not True)):
        report["deploymentState"] = "ABORTED_PREMUTATION"
        raise DeployError("deployment preflight is not fully PASS")
    if approval != report["deploymentAuthorizationRequired"]:
        report["deploymentState"] = "ABORTED_PREMUTATION"
        raise DeployError("exact target-bound deployment authorization did not match")
    report["deploymentAuthorizationAccepted"] = True
    target, release = cfg["target"], cfg["release"]
    try:
        _verify_inputs_unchanged(cfg, runner, bindings)
    except DeployError:
        report["deploymentState"] = "ABORTED_PREMUTATION"
        raise
    values_snapshot = _path(cfg.get("_helmValuesSnapshot", cfg["helmValuesFile"]), "reviewed Helm values snapshot")
    cmd = ["helm", "upgrade", "--install", target["releaseName"], str(CHART), "--namespace", target["namespace"],
           "--values", str(values_snapshot), "--set-string", f"image.repository={release['imageRepository']}",
           "--set-string", f"image.digest={release['imageDigest']}", "--set", "image.requireDigest=true", "--wait", "--timeout", "10m"]
    try:
        _run_ok(runner, cmd, timeout=620)
    except DeployError:
        report["recoveryRequired"] = True
        report["deploymentState"] = "RECOVERY_REQUIRED"
        report["checks"].append({"id": "deployment.helm_release", "status": "FAIL",
                                 "detail": "Helm did not return successful completion; migration or rollout may have committed; inspect release and database before any retry"})
        report["overall"] = "FAIL"
        raise
    report["checks"].append({"id": "deployment.helm_release", "status": "PASS", "detail": "Helm upgrade/install completed; no automatic rollback requested"})
    _verify_post_deploy(cfg, runner, report, base_url)
    report["overall"] = "PASS" if all(item["status"] == "PASS" for item in report["checks"]) else "FAIL"
    report["deploymentAllowed"] = False
    report["deploymentState"] = "COMPLETE" if report["overall"] == "PASS" else "RECOVERY_REQUIRED"
    return report


def gcp_readiness_report() -> dict:
    def row(identifier: str, status: str, detail: str) -> dict:
        return {"id": identifier, "status": status, "detail": detail}
    checks = [
        row("project.identity", "NOT VERIFIED", "expected project kordex-fleet-platform-515416 / 209068399397; live identity evidence not queried"),
        row("project.isolation", "NOT VERIFIED", "dedicated disposable designation and inherited IAM not independently checked"),
        row("region", "NOT VERIFIED", "us-east1 is the configured target, not live capacity evidence"),
        row("zone", "NOT VERIFIED", "us-east1-b is the configured target, not live capacity evidence"),
        row("iam.terraform_principal", "NOT VERIFIED", "Terraform principal and provisioning/resource roles are implemented locally; no live identity/effective policy verified"),
        row("iam.lifecycle_principal", "NOT VERIFIED", "separate lifecycle principal and inventory/power roles are implemented locally; impersonation/effective grants not verified"),
        row("iam.server_workload_principal", "NOT VERIFIED", "server workload identity and direct actAs/secret scopes are not live verified"),
        row("iam.worker_workload_principal", "NOT VERIFIED", "worker workload identity and direct actAs/secret scopes are not live verified"),
        row("terraform.provider_identity", "NOT VERIFIED", "no current Terraform execution context or attestation captured"),
        row("apis", "NOT VERIFIED", "previously reported enabled; no live API inventory performed in this command"),
        row("network_dns", "NOT PROVIDED", "private CIDRs, DNS, routes, relay, and recovery evidence not supplied"),
        row("billing.headroom", "BLOCKED_BILLING_HEADROOM_NOT_PROVIDED", "no authoritative credit/headroom evidence"),
        row("cost.90d_stopped", "NOT VERIFIED", "no defensible total: disks, snapshots, stopped RHEL PAYG, logging, network, artifact/registry storage, and other charges unresolved"),
        row("cost.90d_running", "NOT VERIFIED", "no defensible total: VM runtime, RHEL PAYG, disks, snapshots, logging, network, artifact/registry storage, and other charges unresolved"),
    ]
    return {"schemaVersion": 1, "kind": "kordex-m3-gcp-lab-readiness", "projectId": "kordex-fleet-platform-515416",
            "projectNumber": "209068399397", "region": "us-east1", "zone": "us-east1-b", "budgetCeilingUsd": 300,
            "evidenceClass": "repository-only-not-live", "costProjectionsUsd": {"stopped90Days": None, "running90Days": None},
            "overall": "BLOCKED_BILLING_HEADROOM_NOT_PROVIDED", "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pre = sub.add_parser("preflight", help="run read-only customer deployment checks")
    pre.add_argument("--inputs", type=Path)
    pre.add_argument("--report", type=Path)
    pre.add_argument("--backup-key-sha256", default="")
    pre.add_argument("--expected-cluster-uid", default="")
    pre.add_argument("--expected-api-server", default="")
    deploy = sub.add_parser("deploy", help="preflight and deploy after exact interactive authorization")
    deploy.add_argument("--inputs", type=Path, required=True)
    deploy.add_argument("--report", type=Path, required=True)
    deploy.add_argument("--backup-key-sha256", required=True)
    deploy.add_argument("--expected-cluster-uid", required=True)
    deploy.add_argument("--expected-api-server", required=True)
    gcp = sub.add_parser("gcp-readiness", help="emit current local GCP readiness blockers; makes no cloud calls")
    gcp.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if args.command == "gcp-readiness":
        _write_report(gcp_readiness_report(), args.report)
        return 2
    runner = Runner()
    cfg = None
    report = None
    deployment_journal_written = False
    try:
        if args.inputs:
            cfg = read_manifest(args.inputs)
        report = _preflight(cfg, runner, backup_key_sha256=args.backup_key_sha256,
                            trusted_cluster_uid=getattr(args, "expected_cluster_uid", ""),
                            trusted_api_server=getattr(args, "expected_api_server", ""))
        if args.command == "preflight":
            _write_report(report, args.report)
            return 0 if report["overall"] == "PASS" else 2
        if report["overall"] != "PASS":
            _write_report(report, args.report)
            return 2
        bindings = report.get("deploymentBindings", {})
        expected = _deployment_approval(cfg, bindings)
        print(f"Verified image: {report.get('imageReference', 'unavailable')}", file=sys.stderr)
        print(f"Verified release identity: {report.get('releaseIdentity', 'unavailable')}", file=sys.stderr)
        print(f"Chart/app: {EXPECTED_CHART_VERSION}/{EXPECTED_APP_VERSION}", file=sys.stderr)
        print(f"Migration 016 SHA-256: {EXPECTED_MIGRATION_SHA256}", file=sys.stderr)
        bindings = report["deploymentBindings"]
        print(f"Verified source commit: {bindings['sourceCommit']}", file=sys.stderr)
        print(f"Manifest SHA-256: {bindings['manifestSha256']}", file=sys.stderr)
        print(f"Helm values SHA-256: {bindings['helmValuesSha256']}", file=sys.stderr)
        print("Migration runs in the Helm pre-install/pre-upgrade hook under a PostgreSQL advisory lock and transaction.", file=sys.stderr)
        print("Database migrations are forward-only; Helm rollback does not reverse them.", file=sys.stderr)
        print(f"Target-bound deployment authorization required: {expected}", file=sys.stderr)
        supplied = input("Type the exact authorization phrase to deploy: ")
        if supplied != expected:
            raise DeployError("exact target-bound deployment authorization did not match")
        report["deploymentAuthorizationRequired"] = expected
        report["deploymentAuthorizationAccepted"] = True
        report["deploymentState"] = "IN_PROGRESS"
        report["deploymentAllowed"] = False
        _write_report(report, args.report)
        deployment_journal_written = True
        report = deployment_command(cfg, runner, report, supplied, cfg["lifecycle"]["controlPlaneUrl"])
        _write_report(report, args.report, replace=True)
        return 0 if report["overall"] == "PASS" else 2
    except (DeployError, OSError, ValueError, KeyError) as exc:
        if report is None:
            report = {"schemaVersion": 1, "kind": "kordex-control-plane-deployment-preflight", "checks": [],
                      "overall": "BLOCKED" if isinstance(exc, MissingInput) else "FAIL",
                      "deploymentAllowed": False, "recoveryRequired": False}
        if report is not None:
            report["overall"] = "BLOCKED" if isinstance(exc, MissingInput) else "FAIL"
            report["deploymentAllowed"] = False
            error_id = ("deployment.command" if deployment_journal_written else
                        "inputs.manifest" if cfg is None else "preflight.execution")
            report["checks"].append({"id": error_id,
                                     "status": "NOT PROVIDED" if isinstance(exc, MissingInput) else "FAIL",
                                     "detail": str(exc)})
            if deployment_journal_written and report.get("deploymentState") == "IN_PROGRESS":
                report["deploymentState"] = "RECOVERY_REQUIRED"
                report["recoveryRequired"] = True
            try:
                _write_report(report, args.report, replace=deployment_journal_written)
            except DeployError:
                pass
        print(f"control-plane deployment blocked: {exc}", file=sys.stderr)
        return 2
    finally:
        if cfg and isinstance(cfg.get("_helmValuesTemporaryDirectory"), tempfile.TemporaryDirectory):
            cfg["_helmValuesTemporaryDirectory"].cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
