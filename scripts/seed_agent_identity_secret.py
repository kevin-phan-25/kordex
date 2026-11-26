#!/usr/bin/env python3
"""Seed the public empty-state CAS value before starting a Kordex agent.

This installer helper never prints Secret data. It uses a resourceVersion test
so concurrent seed attempts cannot replace identity written by another actor.
The agent itself retains patch-only access and never reads the Secret API.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import subprocess
import sys
from typing import Callable


EMPTY_STATE_B64 = "e30="  # UTF-8 bytes for the non-secret JSON object {}


def _identity(secret: object, namespace: str, name: str) -> tuple[str, str, dict[str, str]]:
    if not isinstance(secret, dict) or secret.get("apiVersion") != "v1" or secret.get("kind") != "Secret":
        raise ValueError("target is not a core/v1 Secret")
    metadata = secret.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("name") != name or metadata.get("namespace") != namespace:
        raise ValueError("Secret identity does not match the requested namespace and name")
    uid, resource_version = metadata.get("uid"), metadata.get("resourceVersion")
    if not isinstance(uid, str) or not uid or not isinstance(resource_version, str) or not resource_version:
        raise ValueError("Secret UID and resourceVersion are required")
    data = secret.get("data", {})
    if data is None:
        data = {}
    if not isinstance(data, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in data.items()):
        raise ValueError("Secret data map is malformed")
    if secret.get("type", "Opaque") != "Opaque":
        raise ValueError("identity Secret must have Opaque type")
    return uid, resource_version, data


def seed_identity_secret(
    run: Callable[..., subprocess.CompletedProcess[str]],
    *,
    kubectl: str,
    context: str,
    namespace: str,
    name: str,
    kubeconfig: str | None = None,
) -> bool:
    """Ensure an absent state key is initialized to {}, without overwriting it.

    Returns True when this invocation seeded the marker and False when the
    Secret already has a state key. A present state key is never interpreted as
    valid qualification identity; the agent's normal state validator decides.
    """
    if not all((kubectl, context, namespace, name)):
        raise ValueError("kubectl, context, namespace, and Secret name are required")

    prefix = [kubectl]
    if kubeconfig:
        prefix += ["--kubeconfig", kubeconfig]
    prefix += ["--context", context, "--namespace", namespace]

    result = run(prefix + ["get", "secret", name, "--output=json"], text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError("unable to read the named identity Secret; no change was made")
    try:
        secret = json.loads(result.stdout)
        uid, resource_version, data = _identity(secret, namespace, name)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"identity Secret validation failed: {exc}") from exc

    if "state.json" in data:
        if set(data) != {"state.json"}:
            raise RuntimeError("identity Secret contains unexpected data keys; no change was made")
        try:
            decoded = base64.b64decode(data["state.json"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("existing identity state is not valid base64; no change was made") from exc
        if not decoded:
            raise RuntimeError("existing identity state is empty; no change was made")
        return False
    if data:
        raise RuntimeError("identity Secret contains unexpected data keys; no change was made")

    patch = [
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "add", "path": "/data", "value": {"state.json": EMPTY_STATE_B64}},
    ]
    encoded_patch = json.dumps(patch, separators=(",", ":"))
    result = run(
        prefix + ["patch", "secret", name, "--type=json", "--patch", encoded_patch, "--output=json"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("identity Secret changed during initialization; no change was made, inspect and retry")
    try:
        updated = json.loads(result.stdout)
        updated_uid, _, updated_data = _identity(updated, namespace, name)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("seed response did not identify the expected Secret") from exc
    if updated_uid != uid or updated_data.get("state.json") != EMPTY_STATE_B64 or set(updated_data) != {"state.json"}:
        raise RuntimeError("seed response did not preserve the expected Secret identity and empty-state marker")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, help="explicit Kubernetes context to target")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--name", required=True, help="agent identity Secret name")
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--kubeconfig")
    args = parser.parse_args(argv)
    try:
        seeded = seed_identity_secret(
            subprocess.run,
            kubectl=args.kubectl,
            context=args.context,
            namespace=args.namespace,
            name=args.name,
            kubeconfig=args.kubeconfig,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"identity Secret seed failed: {exc}", file=sys.stderr)
        return 1
    print("identity Secret CAS seed created" if seeded else "identity Secret already has state; no change made")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
