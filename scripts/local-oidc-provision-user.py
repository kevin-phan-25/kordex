#!/usr/bin/env python3
"""Create or reuse a local Keycloak user and print its actual OIDC subject."""
from __future__ import annotations

import argparse
import getpass
import re
import sys

from local_oidc_common import KeycloakAdmin, LocalOIDCError, admin_credentials, oidc_dir, provision_user


EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True, help="explicit Keycloak username")
    parser.add_argument("--email", required=True, help="explicit local test-user email")
    parser.add_argument("--first-name", help="profile given name (defaults to username)")
    parser.add_argument("--last-name", default="Kordex Local", help="profile family name")
    args = parser.parse_args()
    if (not args.username.strip() or len(args.username) > 128
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in args.username)
            or not EMAIL.fullmatch(args.email)):
        parser.error("provide a valid non-empty username and email")
    username, email = args.username.strip(), args.email.strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in args.first_name or "") or any(
        ord(char) < 0x20 or ord(char) == 0x7f for char in args.last_name
    ):
        parser.error("profile names may not contain control characters")
    admin_user, admin_password = admin_credentials()
    ca_file = oidc_dir() / "certs/ca.crt"
    admin = KeycloakAdmin(admin_user, admin_password, ca_file)

    def new_password() -> str:
        while True:
            password = getpass.getpass("New test-user password (12+ characters): ")
            repeated = getpass.getpass("Confirm test-user password: ")
            if password != repeated:
                print("Passwords did not match; try again.", file=sys.stderr)
                continue
            if len(password) < 12:
                print("Password must be at least 12 characters.", file=sys.stderr)
                continue
            return password

    def confirm_existing_update(existing_username: str) -> bool:
        phrase = f"UPDATE USER {existing_username}"
        print("This may enable the existing account and fill missing profile names; it never resets the password.", file=sys.stderr)
        return input(f"Type '{phrase}' to continue: ").strip() == phrase

    try:
        subject = provision_user(
            admin, username, email, new_password, args.first_name, args.last_name,
            confirm_existing_update,
        )
    except LocalOIDCError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("No user provisioning/update completed.", file=sys.stderr)
        return 1
    # The ID is the actual Keycloak user ID/sub from the Admin REST response,
    # never a username or email substitute. It is intentionally usable by the
    # membership helper; passwords and tokens are never emitted.
    print(subject)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
