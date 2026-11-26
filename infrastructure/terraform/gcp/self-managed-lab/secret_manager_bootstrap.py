#!/usr/bin/env python3
"""Minimal Secret Manager bridge for the disposable K3s join credential.

The secret value is accepted only on stdin or written to a root-only tmpfs
path. It is never included in arguments, output, or exception text.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request


API = "https://secretmanager.googleapis.com/v1"
METADATA_TOKEN = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/token"
)
METADATA_PROJECT_NUMBER = "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id"
PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
PROJECT_NUMBER_RE = re.compile(r"^[0-9]{1,20}$")
SECRET_RE = re.compile(r"^[a-zA-Z0-9_-]{1,255}$")
VERSION_RE = re.compile(
    r"^projects/(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})/secrets/"
    r"[a-zA-Z0-9_-]{1,255}/versions/[1-9][0-9]*$"
)


class SecretManagerError(Exception):
    """Error message intentionally excludes request and response contents."""


def checked_resource(project: str, secret: str) -> str:
    if not PROJECT_RE.fullmatch(project) or not SECRET_RE.fullmatch(secret):
        raise SecretManagerError("invalid Secret Manager resource identifier")
    return f"projects/{project}/secrets/{secret}"


def access_token() -> str:
    request = urllib.request.Request(METADATA_TOKEN, headers={"Metadata-Flavor": "Google"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            value = json.load(response).get("access_token", "")
    except Exception as error:  # noqa: BLE001 - do not surface URL or response details
        raise SecretManagerError("could not obtain VM service-account access token") from error
    if not isinstance(value, str) or not value:
        raise SecretManagerError("VM service-account access token was missing")
    return value


def numeric_project_id() -> str:
    """Return the GCE-authenticated numeric project identity for response binding."""
    request = urllib.request.Request(METADATA_PROJECT_NUMBER, headers={"Metadata-Flavor": "Google"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            value = response.read(64).decode("ascii").strip()
    except Exception as error:  # noqa: BLE001 - do not surface URL or response details
        raise SecretManagerError("could not obtain VM numeric project identity") from error
    if not PROJECT_NUMBER_RE.fullmatch(value):
        raise SecretManagerError("VM numeric project identity was malformed")
    return value


def request(method: str, resource: str, body: bytes | None = None) -> tuple[int, bytes]:
    token = access_token()
    req = urllib.request.Request(
        f"{API}/{resource}",
        data=body,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        # HTTP body may contain secret payload data; never log or re-raise it.
        return error.code, b""
    except Exception as error:  # noqa: BLE001
        raise SecretManagerError("Secret Manager request failed") from error


def publish(project: str, secret: str) -> None:
    resource = checked_resource(project, secret)
    project_number = numeric_project_id()
    value = sys.stdin.buffer.read().strip()
    if not value or b"\n" in value or b"\r" in value:
        raise SecretManagerError("bootstrap credential input was empty or malformed")
    body = json.dumps({"payload": {"data": base64.b64encode(value).decode("ascii")}}).encode()
    status, response_body = request("POST", f"{resource}:addVersion", body)
    if status not in (200, 201):
        raise SecretManagerError(f"Secret Manager version creation failed (HTTP {status})")
    try:
        name = json.loads(response_body).get("name", "")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SecretManagerError("Secret Manager returned an invalid version reference") from error
    if not isinstance(name, str) or not VERSION_RE.fullmatch(name):
        raise SecretManagerError("Secret Manager returned an unexpected version reference")
    parts = name.split("/")
    expected_projects = {project, project_number}
    if parts[0] != "projects" or parts[2] != "secrets" or parts[3] != secret or parts[1] not in expected_projects:
        raise SecretManagerError("Secret Manager returned an unexpected version reference")
    print(name)


def fetch(project: str, secret: str, output: Path) -> None:
    resource = checked_resource(project, secret)
    status, response_body = request("GET", f"{resource}/versions/latest:access")
    if status != 200:
        raise SecretManagerError(f"Secret Manager credential retrieval failed (HTTP {status})")
    try:
        encoded = json.loads(response_body)["payload"]["data"]
        value = base64.b64decode(encoded, validate=True)
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SecretManagerError("Secret Manager returned malformed credential data") from error
    if not value or b"\n" in value or b"\r" in value:
        raise SecretManagerError("Secret Manager credential was empty or malformed")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(value)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        output.unlink(missing_ok=True)
        raise


def destroy(version: str, project: str, secret: str) -> None:
    checked_resource(project, secret)
    if not VERSION_RE.fullmatch(version):
        raise SecretManagerError("invalid Secret Manager version reference")
    parts = version.split("/")
    if parts[0] != "projects" or parts[2] != "secrets" or parts[3] != secret:
        raise SecretManagerError("Secret Manager version does not match the requested secret")
    if parts[1] == project:
        pass
    elif PROJECT_NUMBER_RE.fullmatch(parts[1]):
        if parts[1] != numeric_project_id():
            raise SecretManagerError("Secret Manager version belongs to a different project")
    else:
        raise SecretManagerError("Secret Manager version belongs to a different project")
    status, _ = request("POST", version + ":destroy", b"{}")
    if status not in (200, 204):
        raise SecretManagerError(f"Secret Manager version destruction failed (HTTP {status})")


def present(project: str, secret: str) -> bool:
    resource = checked_resource(project, secret)
    status, response_body = request("GET", f"{resource}/versions/latest")
    if status == 404:
        return False
    if status != 200:
        raise SecretManagerError(f"Secret Manager credential status check failed (HTTP {status})")
    try:
        state = json.loads(response_body).get("state")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SecretManagerError("Secret Manager returned invalid version metadata") from error
    if state == "ENABLED":
        return True
    if state in ("DISABLED", "DESTROYED"):
        return False
    raise SecretManagerError("Secret Manager returned an unknown version state")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("publish")
    add.add_argument("--project", required=True)
    add.add_argument("--secret", required=True)
    get = sub.add_parser("fetch")
    get.add_argument("--project", required=True)
    get.add_argument("--secret", required=True)
    get.add_argument("--output", required=True, type=Path)
    remove = sub.add_parser("destroy")
    remove.add_argument("--version", required=True)
    remove.add_argument("--project", required=True)
    remove.add_argument("--secret", required=True)
    check = sub.add_parser("present")
    check.add_argument("--project", required=True)
    check.add_argument("--secret", required=True)
    args = parser.parse_args()
    try:
        if args.command == "publish":
            publish(args.project, args.secret)
        elif args.command == "fetch":
            fetch(args.project, args.secret, args.output)
        elif args.command == "destroy":
            destroy(args.version, args.project, args.secret)
        elif args.command == "present":
            return 0 if present(args.project, args.secret) else 1
    except SecretManagerError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
