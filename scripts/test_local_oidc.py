from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_oidc_common import (  # noqa: E402
    DEFAULT_ROLE, LocalOIDCError, grant_membership, membership_confirmation, provision_user,
)


ORG = "80bd80f9-f097-4474-86f4-b80986fd5423"
SUB = "90bd80f9-f097-4474-86f4-b80986fd5423"


class FakeKeycloak:
    def __init__(self, users=None):
        self.users = users or []
        self.payload = None
        self.update_payload = None
        self.created_id = "a0bd80f9-f097-4474-86f4-b80986fd5423"

    def exact_user(self, username):
        return [user for user in self.users if user["username"] == username]

    def exact_email(self, email):
        return [user for user in self.users if user["email"].casefold() == email.casefold()]

    def request(self, method, path, payload=None, *, allowed=(200,)):
        if method == "POST" and path == "/admin/realms/kordex/users":
            self.payload = payload
            user = {**payload, "id": self.created_id}
            self.users.append(user)
            return 201, {"Location": f"https://keycloak.localhost/admin/realms/kordex/users/{self.created_id}"}, None
        if method == "GET" and path.endswith(self.created_id):
            return 200, {}, next(user for user in self.users if user["id"] == self.created_id)
        if method == "GET" and path.startswith("/admin/realms/kordex/users/"):
            user_id = path.rsplit("/", 1)[-1]
            return 200, {}, next(user for user in self.users if user["id"] == user_id)
        if method == "PUT" and path.startswith("/admin/realms/kordex/users/"):
            self.update_payload = payload
            user = next(user for user in self.users if user["id"] == payload["id"])
            user.update(payload)
            return 204, {}, None
        raise AssertionError(f"unexpected Keycloak request: {method} {path}")


class FakeBootstrapAPI:
    def __init__(self, exists=True, role=None):
        self.exists = exists
        self.role = role
        self.writes = []

    def organization(self, org):
        if not self.exists or org != ORG:
            raise LocalOIDCError("HTTP 404")
        return {"id": org}

    def set_membership(self, org, subject, role):
        self.writes.append((org, subject, role))
        self.role = role


class LocalOIDCTests(unittest.TestCase):
    def test_new_user_returns_actual_keycloak_id_sets_profile_and_is_idempotent(self):
        admin = FakeKeycloak()
        calls = []
        subject = provision_user(admin, "alice", "alice@example.test", lambda: calls.append(1) or "correct-horse-battery")
        self.assertEqual(subject, admin.created_id)
        self.assertNotEqual(subject, "alice")
        self.assertEqual(calls, [1])
        self.assertTrue(admin.payload["enabled"])
        self.assertEqual(admin.payload["email"], "alice@example.test")
        self.assertEqual(admin.payload["firstName"], "alice")
        self.assertEqual(admin.payload["lastName"], "Kordex Local")
        self.assertEqual(admin.payload["credentials"][0]["value"], "correct-horse-battery")
        self.assertEqual(provision_user(admin, "alice", "alice@example.test", lambda: self.fail("must not reset an existing password")), subject)
        self.assertEqual(calls, [1])

    def test_existing_user_is_reused_without_password_reset(self):
        admin = FakeKeycloak([{"id": SUB, "username": "alice", "email": "alice@example.test", "enabled": True,
                               "firstName": "Alice", "lastName": "Local"}])
        self.assertEqual(provision_user(admin, "alice", "alice@example.test", lambda: self.fail("password must not be requested")), SUB)
        self.assertIsNone(admin.payload)

    def test_existing_profile_conflict_or_disabled_user_fails_closed(self):
        mismatch = FakeKeycloak([{"id": SUB, "username": "alice", "email": "other@example.test", "enabled": True}])
        with self.assertRaises(LocalOIDCError):
            provision_user(mismatch, "alice", "alice@example.test", lambda: "unused")
        disabled = FakeKeycloak([{"id": SUB, "username": "alice", "email": "alice@example.test", "enabled": False,
                                  "firstName": "Alice", "lastName": "Local"}])
        with self.assertRaises(LocalOIDCError):
            provision_user(disabled, "alice", "alice@example.test", lambda: "unused")

    def test_existing_user_enable_requires_confirmation_and_never_resets_password(self):
        user = {"id": SUB, "username": "alice", "email": "alice@example.test", "enabled": False,
                "firstName": "Alice", "lastName": "Local", "credentials": [{"type": "password", "value": "opaque"}]}
        admin = FakeKeycloak([user])
        self.assertEqual(provision_user(admin, "alice", "alice@example.test", lambda: self.fail("no password reset"),
                                        approve_existing_update=lambda username: username == "alice"), SUB)
        self.assertTrue(admin.update_payload["enabled"])
        self.assertNotIn("credentials", admin.update_payload)

    def test_email_collision_and_short_password_are_rejected(self):
        admin = FakeKeycloak([{"id": SUB, "username": "other", "email": "alice@example.test", "enabled": True}])
        with self.assertRaises(LocalOIDCError):
            provision_user(admin, "alice", "alice@example.test", lambda: "unused")
        with self.assertRaises(LocalOIDCError):
            provision_user(FakeKeycloak(), "alice", "alice@example.test", lambda: "short")

    def test_admin_grant_requires_exact_org_confirmation_and_readback(self):
        api = FakeBootstrapAPI()
        read_role = lambda _org, _subject: api.role
        with self.assertRaises(LocalOIDCError):
            grant_membership(api, ORG, SUB, "administrator", "GRANT ADMIN wrong", read_role)
        self.assertEqual(api.writes, [])
        self.assertEqual(membership_confirmation(ORG, "administrator"), f"GRANT ADMIN {ORG}")
        self.assertTrue(grant_membership(api, ORG, SUB, "administrator", f"GRANT ADMIN {ORG}", read_role))
        self.assertEqual(api.writes, [(ORG, SUB, "administrator")])
        self.assertFalse(grant_membership(api, ORG, SUB, "administrator", "", read_role))
        self.assertEqual(len(api.writes), 1)

    def test_viewer_is_default_role_contract_and_invalid_org_never_writes(self):
        self.assertEqual(DEFAULT_ROLE, "viewer")
        self.assertEqual(membership_confirmation(ORG, "viewer"), f"GRANT VIEWER {ORG}")
        api = FakeBootstrapAPI(exists=False)
        with self.assertRaises(LocalOIDCError):
            grant_membership(api, ORG, SUB, "viewer", f"GRANT VIEWER {ORG}", lambda _org, _subject: None)
        self.assertEqual(api.writes, [])


if __name__ == "__main__":
    unittest.main()
