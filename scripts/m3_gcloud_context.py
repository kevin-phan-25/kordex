"""Pinned, secret-free execution context for security-sensitive gcloud checks."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess


class GCloudContextError(ValueError):
    pass


SEARCH_PATH = "/usr/bin:/bin"
CONFIG_DIR = Path("/etc/kordex/gcloud")
HOME = "/nonexistent"
_ALLOWED_INSTALL_ROOTS = (Path("/usr/bin"), Path("/usr/lib/google-cloud-sdk"),
                         Path("/usr/lib64/google-cloud-sdk"), Path("/opt/google-cloud-sdk"))


def environment(config_dir: Path = CONFIG_DIR) -> dict[str, str]:
    """Return a fixed gcloud environment; caller HOME/PATH/Cloud SDK knobs are ignored."""
    _check_config_dir(config_dir)
    return {
        "PATH": SEARCH_PATH,
        "HOME": HOME,
        "TMPDIR": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "CLOUDSDK_CONFIG": str(config_dir),
        "CLOUDSDK_ACTIVE_CONFIG_NAME": "kordex-m3",
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
    }


def _check_config_dir(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise GCloudContextError("dedicated gcloud configuration directory is unavailable") from error
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise GCloudContextError("dedicated gcloud configuration directory must be a protected root-owned directory")


def executable_path(path: str | Path | None = None) -> Path:
    """Resolve only the system-installed gcloud executable and reject writable substitutions."""
    candidate = Path(path) if path is not None else Path(shutil.which("gcloud", path=SEARCH_PATH) or "")
    if not candidate.is_absolute():
        raise GCloudContextError("gcloud executable must be selected from the controlled absolute search path")
    try:
        link_info = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise GCloudContextError("trusted gcloud executable is unavailable") from error
    candidate_allowed = any(candidate == root or root in candidate.parents for root in _ALLOWED_INSTALL_ROOTS)
    allowed = any(resolved == root or root in resolved.parents for root in _ALLOWED_INSTALL_ROOTS)
    if (not candidate_allowed or not allowed or not (stat.S_ISREG(info.st_mode) and os.access(resolved, os.X_OK))
            or info.st_uid != 0 or info.st_mode & 0o022
            or (stat.S_ISLNK(link_info.st_mode) and link_info.st_uid != 0)
            or (not stat.S_ISLNK(link_info.st_mode) and link_info.st_mode & 0o022)):
        raise GCloudContextError("gcloud executable is outside the protected system installation")
    return resolved


def describe(*, path: str | Path | None = None, config_dir: Path = CONFIG_DIR,
             run=subprocess.run) -> dict:
    binary = executable_path(path)
    env = environment(config_dir)
    try:
        result = run([str(binary), "version"], check=True, text=True, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, env=env, timeout=15)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise GCloudContextError("gcloud version could not be verified") from error
    match = re.search(r"(?m)^Google Cloud SDK ([0-9]+\.[0-9]+\.[0-9]+)\s*$", result.stdout or "")
    if not match:
        raise GCloudContextError("gcloud version output is not recognized")
    return {
        "executablePath": str(binary),
        "executableSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "version": match.group(1),
        "configurationDirectory": str(config_dir),
        "configurationName": "kordex-m3",
        "homePath": HOME,
        "environmentPolicy": "fixed-gcloud-system-path-and-dedicated-config",
    }


def command(args: list[str], *, config_dir: Path = CONFIG_DIR,
            path: str | Path | None = None) -> tuple[list[str], dict[str, str], dict]:
    context = describe(path=path, config_dir=config_dir)
    return [context["executablePath"], *args], environment(config_dir), context
