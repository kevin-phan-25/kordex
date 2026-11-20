#!/usr/bin/env python3
"""Fail closed unless the rendered GKE inventory overlay is deployable."""

from __future__ import annotations

import re
import ipaddress
import os
import socket
import ssl
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "deployments/kustomize/overlays/gke-inventory"
IMAGE_DIGEST = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)))


def management_url(rendered: str) -> str | None:
    match = re.search(r"^\s+controlPlaneURL:\s*[\x27\"]?([^\x27\"\s]+)", rendered, re.MULTILINE)
    return match.group(1) if match else None


def private_addresses(host: str, resolver=socket.getaddrinfo) -> list[str]:
    """Resolve a management hostname and require every answer to be private."""
    records = resolver(host, None, type=socket.SOCK_STREAM)
    addresses = sorted({record[4][0].split("%", 1)[0] for record in records})
    if not addresses:
        raise ValueError("management hostname did not resolve")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not any(address.version == network.version and address in network for network in PRIVATE_NETWORKS):
            raise ValueError("management hostname resolves outside RFC1918/ULA private ranges")
    return addresses


def verify_management_tls(url: str, ca_file: str, resolver=socket.getaddrinfo, connector=socket.create_connection) -> list[str]:
    """Verify private DNS and a hostname-checked TLS connection using the mounted CA."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("management URL must be an HTTPS origin without path, query, or fragment")
    if not ca_file or not Path(ca_file).is_file():
        raise ValueError("KORDEX_MANAGEMENT_CA_FILE must name an existing CA certificate file")

    addresses = private_addresses(parsed.hostname, resolver=resolver)
    context = ssl.create_default_context(cafile=ca_file)
    port = parsed.port or 443
    last_error: Exception | None = None
    for address in addresses:
        try:
            with connector((address, port), timeout=5) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=parsed.hostname):
                    return addresses
        except (OSError, ssl.SSLError) as error:
            last_error = error
    raise ValueError(f"TLS connection or hostname verification failed: {type(last_error).__name__ if last_error else 'unknown error'}")

def validation_errors(rendered: str) -> list[str]:
    errors: list[str] = []
    if "REPLACE_" in rendered or "PROJECT_ID/REPOSITORY" in rendered:
        errors.append("overlay still contains required deployment placeholders")

    images = re.findall(r"^\s+image:\s*(\S+)\s*$", rendered, re.MULTILINE)
    if len(images) != 1 or not IMAGE_DIGEST.fullmatch(images[0]):
        errors.append("agent image must be one immutable sha256 digest reference")

    match = re.search(r"^\s+clusterID:\s*[\x27\"]?([^\x27\"\s]+)", rendered, re.MULTILINE)
    try:
        if match is None or str(uuid.UUID(match.group(1))) != match.group(1).lower():
            raise ValueError
    except ValueError:
        errors.append("clusterID must be a registered UUID")

    endpoint = management_url(rendered)
    try:
        parsed = urlsplit(endpoint) if endpoint else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
            or parsed.port == 8080
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
    except ValueError:
        errors.append("controlPlaneURL must be a non-loopback HTTPS origin, not bootstrap port 8080")

    if "enrollmentToken" in rendered or "enrollment-token" in rendered:
        errors.append("enrollment credentials must not be rendered into manifests")
    if "secretName: kordex-enrollment" not in rendered or "key: token" not in rendered:
        errors.append("agent must mount the token key from the kordex-enrollment Secret")
    if "secretName: kordex-agent-identity" not in rendered or "key: state.json" not in rendered:
        errors.append("agent must mount only its projected state.json identity key")

    secret_rule = re.search(
        r"resourceNames:\n\s+- kordex-agent-identity\n\s+resources:\n\s+- secrets\n\s+verbs:\n(?P<verbs>(?:\s+- [a-z]+\n)+)",
        rendered,
    )
    secret_verbs = re.findall(r"- ([a-z]+)", secret_rule.group("verbs")) if secret_rule else []
    if secret_verbs != ["patch"]:
        errors.append("agent RBAC must allow patch only on the identity Secret, with no Secret reads")
    return errors

def main() -> int:
    result = subprocess.run(
        ["kubectl", "kustomize", str(OVERLAY)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        print("FAIL: Kustomize could not render the inventory overlay")
        return result.returncode
    errors = validation_errors(result.stdout)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    endpoint = management_url(result.stdout)
    ca_file = os.environ.get("KORDEX_MANAGEMENT_CA_FILE", "")
    try:
        addresses = verify_management_tls(endpoint or "", ca_file)
    except (OSError, ssl.SSLError, ValueError, socket.gaierror) as error:
        print(f"FAIL: management endpoint private DNS/TLS preflight: {error}")
        return 1
    print(f"PASS: management endpoint resolves privately and TLS hostname verification succeeds ({len(addresses)} private address(es))")
    print("PASS: inventory overlay is configured for deployment")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
