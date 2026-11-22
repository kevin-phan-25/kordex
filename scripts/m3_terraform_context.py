"""Controlled, secret-free Terraform execution context for the M3 lab."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


class ContextError(ValueError):
    pass


WORKSPACE = "default"
CLI_CONFIG = Path(os.devnull)
CLI_CONFIG_SHA256 = hashlib.sha256(b"").hexdigest()
HOME = "/nonexistent"
TMPDIR = "/tmp"
COMMAND_POLICY = ["init -backend=false -input=false -lockfile=readonly", "plan -input=false",
                  "show <saved-plan>", "apply -input=false <saved-plan>"]
PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]{4,127}@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com$")


def canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def describe(principal: str, *, module: Path, binary: str | None = None) -> dict:
    if not isinstance(principal, str) or not PRINCIPAL.fullmatch(principal):
        raise ContextError("an approved Terraform service-account principal is required")
    ambient = os.environ
    if ambient.get("TF_WORKSPACE", WORKSPACE) != WORKSPACE:
        raise ContextError("Terraform workspace must be the bound default workspace")
    if ambient.get("TF_CLI_CONFIG_FILE", str(CLI_CONFIG)) != str(CLI_CONFIG):
        raise ContextError("ambient Terraform CLI configuration is not permitted")
    expected_data_dir = str(module / ".terraform")
    if ambient.get("TF_DATA_DIR", expected_data_dir) != expected_data_dir:
        raise ContextError("Terraform data directory differs from the controlled module data directory")
    executable = binary or shutil.which("terraform")
    if not executable:
        raise ContextError("Terraform executable is unavailable")
    path = Path(executable).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ContextError("Terraform executable is not a regular executable file")
    try:
        binary_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        version_env = {
            "PATH": f"{path.parent}:/usr/bin:/bin", "HOME": HOME, "TMPDIR": TMPDIR,
            "LANG": "C", "LC_ALL": "C", "TF_WORKSPACE": WORKSPACE,
            "TF_CLI_CONFIG_FILE": str(CLI_CONFIG), "TF_DATA_DIR": expected_data_dir,
            "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
        }
        version_result = subprocess.run([str(path), "version", "-json"], check=True, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=version_env)
        version = json.loads(version_result.stdout).get("terraform_version")
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise ContextError("Terraform version or executable identity could not be established") from error
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ContextError("Terraform version output is invalid")
    return {
        "schemaVersion": 1,
        "terraformVersion": version,
        "terraformExecutableSha256": binary_sha,
        "workspace": WORKSPACE,
        "workspaceOverridePolicy": "environment-pinned-default",
        "dataDirectory": expected_data_dir,
        "cliConfigSha256": CLI_CONFIG_SHA256,
        "cliConfigPath": str(CLI_CONFIG),
        "providerInstallationConfiguration": "disabled-cli-config-dev-null",
        "homePath": HOME,
        "tempPath": TMPDIR,
        "dataDirectoryPolicy": "module-local-fixed-path",
        "providerIdentityMode": "google-provider-service-account-impersonation",
        "providerPrincipal": principal,
        "environmentPolicy": ["PATH(terraform-and-system)", "GOOGLE_APPLICATION_CREDENTIALS(path-only)",
                              "HOME=fixed-empty", "TMPDIR=/tmp", "LANG=C", "LC_ALL=C",
                              "TF_WORKSPACE=default", "TF_CLI_CONFIG_FILE=/dev/null",
                              "TF_DATA_DIR=module/.terraform", "TF_IN_AUTOMATION=1", "TF_INPUT=0"],
        "commandPolicy": COMMAND_POLICY,
        "cliArgumentEnvironmentPolicy": "all-TF_CLI_ARGS-and-TF_VAR-variables-omitted",
    }


def execution_environment(principal: str, *, module: Path, binary: str | None = None) -> tuple[dict[str, str], dict]:
    context = describe(principal, module=module, binary=binary)
    executable = str(Path(binary or shutil.which("terraform")).resolve(strict=True))
    credential_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not credential_path or not Path(credential_path).is_absolute():
        raise ContextError("explicit Google credential configuration is required; credential contents are not inspected")
    return _base_environment(module, executable, credential_path), context


def tool_environment(*, module: Path, binary: str | None = None) -> dict[str, str]:
    """Fixed CLI environment for local non-planning validation/init commands."""
    if os.environ.get("TF_WORKSPACE", WORKSPACE) != WORKSPACE:
        raise ContextError("Terraform workspace must be the bound default workspace")
    if os.environ.get("TF_CLI_CONFIG_FILE", str(CLI_CONFIG)) != str(CLI_CONFIG):
        raise ContextError("ambient Terraform CLI configuration is not permitted")
    if os.environ.get("TF_DATA_DIR", str(module / ".terraform")) != str(module / ".terraform"):
        raise ContextError("Terraform data directory differs from the controlled module data directory")
    executable = str(Path(binary or shutil.which("terraform")).resolve(strict=True))
    return _base_environment(module, executable, os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"))


def _base_environment(module: Path, executable: str, credential_path: str | None) -> dict[str, str]:
    if credential_path is not None and not Path(credential_path).is_absolute():
        raise ContextError("Google credential configuration path must be absolute")
    # This is an allowlist. Ambient TF_*, GOOGLE_*, CLOUDSDK_*, proxy and user
    # configuration variables are omitted except the credential-config path.
    env = {
        "PATH": f"{Path(executable).parent}:/usr/bin:/bin",
        "HOME": HOME,
        "TMPDIR": TMPDIR,
        "LANG": "C",
        "LC_ALL": "C",
        "TF_WORKSPACE": WORKSPACE,
        "TF_CLI_CONFIG_FILE": str(CLI_CONFIG),
        "TF_DATA_DIR": str(module / ".terraform"),
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
    }
    if credential_path:
        env["GOOGLE_APPLICATION_CREDENTIALS"] = credential_path
    return env
