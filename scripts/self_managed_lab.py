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


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infrastructure/terraform/gcp/self-managed-lab"
RUNNER = ROOT / "tests/integration/self_managed_upgrade_smoke.py"
VERIFIER = ROOT / "scripts/verify-host-upgrade-qualification.py"
PRODUCT_PROJECT = "kordex-fleet-platform"
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


def run_command(args: list[str], *, cwd: Path | None = None, capture: bool = False,
                timeout: int | None = None) -> str:
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            timeout=timeout,
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


def private_tfvars(project_id: str) -> Path:
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
        match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*\"([^\"]+)\"\s*(?:#.*)?$", raw)
        if not match:
            raise LabError(f"terraform.tfvars must set {name} as a quoted string")
        return match.group(1)

    configured_project = value("project_id")
    if configured_project != project_id:
        raise LabError("--project-id must exactly match project_id in terraform.tfvars")
    if value("project_id_confirmation") != project_id:
        raise LabError("project_id_confirmation in terraform.tfvars must exactly match the reviewed project")
    allowlist = re.search(r"(?ms)^\s*allowed_project_ids\s*=\s*\[(.*?)\]", raw)
    allowed_ids = re.findall(r'"([^"\n]+)"', allowlist.group(1)) if allowlist else []
    if allowed_ids != [project_id]:
        raise LabError("allowed_project_ids in terraform.tfvars must contain exactly the reviewed target project")
    return path


def terraform_init(run: Callable = run_command) -> None:
    run(["terraform", "init", "-backend=false", "-input=false", "-lockfile=readonly"], cwd=MODULE)


def terraform_validate(run: Callable = run_command) -> None:
    run(["terraform", "fmt", "-check", "-recursive"], cwd=MODULE)
    terraform_init(run)
    run(["terraform", "validate"], cwd=MODULE)


def ask_confirmation(expected: str, *, input_fn: Callable[[str], str] | None = None) -> None:
    if not sys.stdin.isatty():
        raise LabError("mutation confirmation requires an interactive terminal")
    input_fn = input if input_fn is None else input_fn
    entered = input_fn(f"Type exactly {expected!r} to continue: ")
    if entered != expected:
        raise LabError("confirmation did not match; no Terraform apply was run")


def terraform_plan(project_id: str, run: Callable = run_command) -> None:
    validate_project_id(project_id)
    private_tfvars(project_id)
    terraform_init(run)
    run(["terraform", "plan", "-input=false"], cwd=MODULE)


def verify_disposable_project(project_id: str, run: Callable = run_command) -> None:
    validate_project_id(project_id)
    private_tfvars(project_id)
    gcloud = os.environ.get("GCLOUD", "gcloud")
    output = run(
        [gcloud, "projects", "describe", project_id,
         "--format=json(projectId,projectNumber,lifecycleState,labels)"],
        cwd=ROOT,
        capture=True,
        timeout=30,
    )
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


def terraform_apply(project_id: str, run: Callable = run_command, confirm: Callable = ask_confirmation,
                    verify_project: Callable = verify_disposable_project) -> None:
    validate_project_id(project_id)
    private_tfvars(project_id)
    terraform_init(run)
    old_umask = os.umask(0o077)
    plan_name = ""
    try:
        fd, plan_name = tempfile.mkstemp(prefix=".kordex-lab-apply-", suffix=".tfplan", dir=MODULE)
        os.close(fd)
        run(["terraform", "plan", "-input=false", f"-out={plan_name}"], cwd=MODULE)
        run(["terraform", "show", plan_name], cwd=MODULE)
        confirm(f"APPLY {project_id}")
        verify_project(project_id, run=run)
        run(["terraform", "apply", "-input=false", plan_name], cwd=MODULE)
    finally:
        os.umask(old_umask)
        if plan_name:
            Path(plan_name).unlink(missing_ok=True)


def terraform_destroy(project_id: str, run: Callable = run_command, confirm: Callable = ask_confirmation,
                      verify_project: Callable = verify_disposable_project) -> None:
    validate_project_id(project_id)
    private_tfvars(project_id)
    terraform_init(run)
    state_project = run(["terraform", "output", "-raw", "project_id"], cwd=MODULE, capture=True).strip()
    if state_project != project_id:
        raise LabError("refusing destroy: Terraform state project_id does not match the confirmed disposable project")
    old_umask = os.umask(0o077)
    plan_name = ""
    try:
        fd, plan_name = tempfile.mkstemp(prefix=".kordex-lab-destroy-", suffix=".tfplan", dir=MODULE)
        os.close(fd)
        run(["terraform", "plan", "-destroy", "-input=false", f"-out={plan_name}"], cwd=MODULE)
        run(["terraform", "show", plan_name], cwd=MODULE)
        confirm(f"DESTROY {project_id}")
        verify_project(project_id, run=run)
        run(["terraform", "apply", "-input=false", plan_name], cwd=MODULE)
    finally:
        os.umask(old_umask)
        if plan_name:
            Path(plan_name).unlink(missing_ok=True)


def runner_command(execute: bool, evidence: Path, case: str | None = None, timeout: int = 14400,
                   cancel_phase: str | None = None, target_confirmation: str | None = None,
                   run: Callable = run_command, project_id: str | None = None,
                   confirm_project: Callable = ask_confirmation,
                   verify_project: Callable = verify_disposable_project) -> None:
    command = [sys.executable, str(RUNNER)]
    if execute:
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
        verify_project(project_id, run=run)
        confirm_project(f"EXECUTE IN DISPOSABLE PROJECT {project_id}")
        command.extend(["--execute", "--qualification-case", case, "--timeout-seconds", str(timeout)])
        if cancel_phase:
            if cancel_phase not in PHASES:
                raise LabError("unsupported cancellation phase")
            command.extend(["--cancel-on-phase", cancel_phase])
    command.extend(["--evidence", str(evidence)])
    run(command, cwd=ROOT)


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
    apply = commands.add_parser("apply", help="review a fresh plan, then require typed project confirmation")
    apply.add_argument("--project-id", required=True)
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
    collect = commands.add_parser("collect", help="collect redacted Kubernetes and Kordex diagnostics")
    collect.add_argument("--output-dir", type=Path, required=True)
    collect.add_argument("--namespace", default=os.environ.get("KORDEX_NAMESPACE", "kordex-system"))
    verify = commands.add_parser("verify", help="validate qualification evidence against the full matrix")
    verify.add_argument("evidence_directory", type=Path)
    archive = commands.add_parser("archive", help="create a checksum-manifested local archive for off-cluster retention")
    archive.add_argument("--source", type=Path, required=True)
    archive.add_argument("--destination", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            terraform_validate()
        elif args.command == "plan":
            terraform_plan(args.project_id)
        elif args.command == "apply":
            terraform_apply(args.project_id)
        elif args.command == "destroy":
            terraform_destroy(args.project_id)
        elif args.command == "preflight":
            runner_command(False, args.evidence)
        elif args.command == "execute":
            runner_command(True, args.evidence, args.qualification_case, args.timeout_seconds,
                           args.cancel_on_phase, args.target_confirmation, project_id=args.project_id)
        elif args.command == "collect":
            print(f"Diagnostics retained at {collect_diagnostics(args.output_dir, args.namespace)}")
        elif args.command == "verify":
            run_command([sys.executable, str(VERIFIER), str(args.evidence_directory)], cwd=ROOT)
        elif args.command == "archive":
            paths = archive_evidence(args.source, args.destination)
            print("Evidence archive written:", *paths)
        return 0
    except LabError as error:
        print(f"qualification lab error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
