#!/usr/bin/env python3
"""Interactively grant one explicit administrator membership via local bootstrap."""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / "deployments/local/.env"
API = "http://127.0.0.1:8080"
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")


def bootstrap_token() -> str:
    if not ENV_FILE.is_file():
        raise SystemExit("deployments/local/.env is missing")
    for line in ENV_FILE.read_text().splitlines():
        if line.startswith("KORDEX_ADMIN_TOKEN="):
            value = line.partition("=")[2].strip().strip("\"'")
            if len(value) >= 32:
                return value
    raise SystemExit("KORDEX_ADMIN_TOKEN was not found in the local Compose env file")


def main() -> int:
    organization_id = input("Existing organization UUID: ").strip()
    subject = input("Actual Keycloak sub (from the authenticated identity): ").strip()
    if not UUID.fullmatch(organization_id):
        raise SystemExit("Invalid organization UUID")
    if not subject or len(subject) > 255 or any(ord(c) < 0x20 or ord(c) > 0x7E for c in subject):
        raise SystemExit("Invalid OIDC subject")

    print("This grants administrator access to exactly one existing organization.")
    expected = f"GRANT ADMIN {organization_id}"
    if input(f"Type '{expected}' to continue: ").strip() != expected:
        print("No membership change made.")
        return 1

    token = bootstrap_token()
    body = json.dumps({"subject": subject, "role": "administrator"}).encode()
    request = urllib.request.Request(
        f"{API}/v1/organizations/{organization_id}/memberships",
        data=body,
        method="PUT",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            if response.status != 200:
                print(f"Membership request failed with HTTP {response.status}", file=sys.stderr)
                return 1
    except urllib.error.HTTPError as error:
        print(f"Membership request failed with HTTP {error.code}", file=sys.stderr)
        return 1
    except OSError:
        print("Membership request could not reach the local bootstrap API", file=sys.stderr)
        return 1
    print("Administrator membership granted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
