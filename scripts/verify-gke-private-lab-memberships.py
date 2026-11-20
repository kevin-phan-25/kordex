#!/usr/bin/env python3
"""Compare membership subjects from stdin with Keycloak export user IDs without printing either set."""
import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("realm_export_dir", type=Path)
    args = parser.parse_args()
    user_ids = set()
    for path in sorted(args.realm_export_dir.glob("*.json")):
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
        users = value.get("users", []) if isinstance(value, dict) else []
        if isinstance(users, list):
            user_ids.update(user["id"] for user in users if isinstance(user, dict) and isinstance(user.get("id"), str))
    if not user_ids:
        raise SystemExit("realm export contains no user IDs")
    subjects = {line.strip() for line in sys.stdin if line.strip()}
    missing = subjects - user_ids
    print(f"membership subjects={len(subjects)} matched={len(subjects)-len(missing)} unmatched={len(missing)}")
    if missing:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
