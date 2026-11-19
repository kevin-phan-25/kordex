#!/usr/bin/env python3
"""Grant one explicitly confirmed local Keycloak organization membership."""
from __future__ import annotations

import argparse
import sys

from local_oidc_common import (
    BOOTSTRAP_API, DEFAULT_ROLE, BootstrapAPI, ConfirmationRequired, LocalOIDCError, ROOT, ROLES,
    grant_membership, read_env_value,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--organization", help="existing organization UUID")
    parser.add_argument("--subject", help="actual Keycloak user ID/sub from local provisioning")
    parser.add_argument("--role", choices=sorted(ROLES), default=DEFAULT_ROLE, help="defaults to least-privileged viewer")
    parser.add_argument("--api", default=BOOTSTRAP_API)
    args = parser.parse_args()
    organization_id = args.organization or input("Existing organization UUID: ").strip()
    subject = args.subject or input("Actual Keycloak user ID/sub: ").strip()
    try:
        token = read_env_value(ROOT / "deployments/local/.env", "KORDEX_ADMIN_TOKEN")
        api = BootstrapAPI(token, args.api)
        try:
            changed = grant_membership(api, organization_id, subject, args.role, "")
        except ConfirmationRequired as pending:
            print(f"This will set role '{args.role}' for one subject in one existing organization.")
            confirmation = input(f"Type '{pending.phrase}' to continue: ").strip()
            changed = grant_membership(api, organization_id, subject, args.role, confirmation)
    except LocalOIDCError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("No membership change made.", file=sys.stderr)
        return 1
    if changed:
        print(f"Membership granted and verified: role={args.role}.")
    else:
        print(f"Membership already exists and was verified: role={args.role}; no write made.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
