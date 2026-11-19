"""Small, secret-safe helpers for the opt-in local Keycloak setup."""
from __future__ import annotations

import getpass
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / "deployments/local/.env"
ISSUER = "https://keycloak.localhost:8443/realms/kordex"
KEYCLOAK_ADMIN = "https://keycloak.localhost:8443"
BOOTSTRAP_API = "http://127.0.0.1:8080"
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
SUBJECT_RE = UUID_RE
ROLES = {"viewer", "operator", "approver", "administrator"}
DEFAULT_ROLE = "viewer"


class LocalOIDCError(RuntimeError):
    pass


class ConfirmationRequired(LocalOIDCError):
    def __init__(self, phrase: str):
        super().__init__("Confirmation did not match; no membership change made")
        self.phrase = phrase


def oidc_dir() -> Path:
    return Path(os.environ.get("KORDEX_LOCAL_OIDC_DIR", Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "kordex/local-oidc"))


def read_env_value(path: Path, name: str) -> str:
    if not path.is_file():
        raise LocalOIDCError(f"Required local configuration file is missing: {path}")
    for line in path.read_text().splitlines():
        if line.startswith(name + "="):
            value = line.partition("=")[2].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                return value
    raise LocalOIDCError(f"{name} is not configured in {path}")


def _opener(ca_file: Path | None = None) -> urllib.request.OpenerDirector:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
            return None

    handlers: list[Any] = [urllib.request.ProxyHandler({}), NoRedirect()]
    if ca_file is not None:
        if not ca_file.is_file():
            raise LocalOIDCError("Local CA certificate is missing; run scripts/local-oidc-init.sh")
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_file))))
    return urllib.request.build_opener(*handlers)


def _request_json(opener: urllib.request.OpenerDirector, url: str, method: str = "GET", *,
                  headers: dict[str, str] | None = None, body: bytes | None = None,
                  timeout: int = 10, allowed: tuple[int, ...] = (200,)) -> tuple[int, dict[str, str], Any]:
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with opener.open(request, timeout=timeout) as response:
            status, response_headers, raw = response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        # Never include response bodies or request headers: either may contain credentials.
        status, response_headers, raw = error.code, dict(error.headers.items()), error.read()
    except (OSError, urllib.error.URLError, ssl.SSLError) as error:
        raise LocalOIDCError(f"Local service request failed ({type(error).__name__})") from None
    if status not in allowed:
        raise LocalOIDCError(f"Local service returned HTTP {status}")
    if not raw:
        return status, response_headers, None
    try:
        return status, response_headers, json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LocalOIDCError("Local service returned invalid JSON") from None


@dataclass
class KeycloakAdmin:
    username: str
    password: str = field(repr=False)
    ca_file: Path
    base_url: str = KEYCLOAK_ADMIN
    opener: urllib.request.OpenerDirector = field(init=False, repr=False)
    _token: str | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        self.opener = _opener(self.ca_file)

    def token(self) -> str:
        if self._token:
            return self._token
        if not self.username or not self.password:
            raise LocalOIDCError("Keycloak admin username or password is empty")
        form = urllib.parse.urlencode({
            "grant_type": "password", "client_id": "admin-cli",
            "username": self.username, "password": self.password,
        }).encode()
        _, _, result = _request_json(
            self.opener, f"{self.base_url}/realms/master/protocol/openid-connect/token",
            "POST", headers={"content-type": "application/x-www-form-urlencoded"},
            body=form, allowed=(200,),
        )
        token = result.get("access_token") if isinstance(result, dict) else None
        if not isinstance(token, str) or not token:
            raise LocalOIDCError("Keycloak did not return an admin access token")
        self._token = token
        return token

    def request(self, method: str, path: str, payload: Any = None, *, allowed: tuple[int, ...] = (200,)) -> tuple[int, dict[str, str], Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"authorization": f"Bearer {self.token()}", "accept": "application/json"}
        if body is not None:
            headers["content-type"] = "application/json"
        return _request_json(self.opener, f"{self.base_url}{path}", method, headers=headers, body=body, allowed=allowed)

    def exact_user(self, username: str) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"username": username, "exact": "true"})
        _, _, users = self.request("GET", f"/admin/realms/kordex/users?{query}")
        if not isinstance(users, list):
            raise LocalOIDCError("Keycloak returned an invalid user list")
        return [user for user in users if user.get("username") == username]

    def exact_email(self, email: str) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"email": email, "exact": "true"})
        _, _, users = self.request("GET", f"/admin/realms/kordex/users?{query}")
        if not isinstance(users, list):
            raise LocalOIDCError("Keycloak returned an invalid user list")
        return [user for user in users if str(user.get("email", "")).casefold() == email.casefold()]


def provision_user(admin: KeycloakAdmin, username: str, email: str,
                   password_provider: Callable[[], str], first_name: str | None = None,
                   last_name: str = "Kordex Local",
                   approve_existing_update: Callable[[str], bool] | None = None) -> str:
    """Create an enabled local test user, or reuse a matching enabled account."""
    users = admin.exact_user(username)
    if len(users) > 1:
        raise LocalOIDCError("Keycloak returned multiple exact username matches")
    if users:
        user = users[0]
        if str(user.get("email", "")).casefold() != email.casefold():
            raise LocalOIDCError("Existing Keycloak username has a different email; no changes made")
        subject = user.get("id")
        if not isinstance(subject, str) or not SUBJECT_RE.fullmatch(subject):
            raise LocalOIDCError("Existing Keycloak user has no valid UUID subject")
        needs_update = user.get("enabled") is not True or not user.get("firstName") or not user.get("lastName")
        if needs_update:
            if approve_existing_update is None or not approve_existing_update(username):
                raise LocalOIDCError(f"Existing Keycloak user needs enabling/profile fields; confirm 'UPDATE USER {username}' to proceed")
            _, _, details = admin.request("GET", f"/admin/realms/kordex/users/{urllib.parse.quote(subject, safe='')}")
            if (not isinstance(details, dict) or details.get("id") != subject
                    or details.get("username") != username
                    or str(details.get("email", "")).casefold() != email.casefold()):
                raise LocalOIDCError("Existing Keycloak user could not be read for a safe profile update")
            update = {
                "id": subject,
                "username": username,
                "email": email,
                "enabled": True,
                "firstName": details.get("firstName") or first_name or username,
                "lastName": details.get("lastName") or last_name,
            }
            if "emailVerified" in details:
                update["emailVerified"] = details["emailVerified"]
            if "attributes" in details:
                update["attributes"] = details["attributes"]
            admin.request("PUT", f"/admin/realms/kordex/users/{urllib.parse.quote(subject, safe='')}", update, allowed=(204,))
            _, _, details = admin.request("GET", f"/admin/realms/kordex/users/{urllib.parse.quote(subject, safe='')}")
            if (not isinstance(details, dict) or details.get("id") != subject
                    or details.get("enabled") is not True
                    or not details.get("firstName") or not details.get("lastName")):
                raise LocalOIDCError("Updated Keycloak user profile could not be verified")
        return subject

    email_matches = admin.exact_email(email)
    if email_matches:
        raise LocalOIDCError("Email already belongs to another Keycloak username; no changes made")

    password = password_provider()
    if len(password) < 12:
        raise LocalOIDCError("Test-user password must be at least 12 characters")
    payload = {
        "username": username,
        "email": email,
        "firstName": first_name or username,
        "lastName": last_name,
        "enabled": True,
        "emailVerified": False,
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    _, headers, _ = admin.request("POST", "/admin/realms/kordex/users", payload, allowed=(201,))
    location = headers.get("Location", "")
    subject = location.rstrip("/").rsplit("/", 1)[-1] if location else ""
    if not SUBJECT_RE.fullmatch(subject):
        matches = admin.exact_user(username)
        if len(matches) != 1:
            raise LocalOIDCError("User was created but Keycloak did not return a retrievable user ID")
        subject = str(matches[0].get("id", ""))
    if not SUBJECT_RE.fullmatch(subject):
        raise LocalOIDCError("Keycloak returned an invalid user ID")
    _, _, created = admin.request("GET", f"/admin/realms/kordex/users/{urllib.parse.quote(subject, safe='')}")
    if (not isinstance(created, dict) or created.get("id") != subject
            or created.get("username") != username
            or str(created.get("email", "")).casefold() != email.casefold()
            or created.get("enabled") is not True):
        raise LocalOIDCError("Created Keycloak user could not be verified")
    return subject


class BootstrapAPI:
    def __init__(self, token: str, base_url: str = BOOTSTRAP_API):
        self.token_value = token
        self.base_url = base_url.rstrip("/")
        self.opener = _opener()

    def request(self, method: str, path: str, payload: Any = None, *, allowed: tuple[int, ...] = (200,)) -> tuple[int, dict[str, str], Any]:
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"authorization": f"Bearer {self.token_value}", "accept": "application/json"}
        if body is not None:
            headers["content-type"] = "application/json"
        return _request_json(self.opener, f"{self.base_url}{path}", method, headers=headers, body=body, allowed=allowed)

    def organization(self, organization_id: str) -> dict[str, Any]:
        _, _, organization = self.request("GET", f"/v1/organizations/{organization_id}")
        if not isinstance(organization, dict) or organization.get("id") != organization_id:
            raise LocalOIDCError("Organization lookup returned an unexpected result")
        return organization

    def set_membership(self, organization_id: str, subject: str, role: str) -> None:
        self.request("PUT", f"/v1/organizations/{organization_id}/memberships",
                     {"subject": subject, "role": role})


def current_membership(organization_id: str, subject: str) -> str | None:
    if not UUID_RE.fullmatch(organization_id) or not SUBJECT_RE.fullmatch(subject):
        raise LocalOIDCError("Invalid IDs for the read-only local membership check")
    container = os.environ.get("KORDEX_LOCAL_POSTGRES_CONTAINER", "kordex-local_postgres_1")
    # Both interpolated values have already passed a strict UUID regex, so this
    # SQL literal construction cannot introduce quotes or SQL syntax.
    query = f"SELECT role FROM memberships WHERE organization_id='{organization_id}'::uuid AND subject='{subject}';"
    command = ["podman", "exec", container, "psql", "-U", "kordex", "-d", "kordex", "-X", "-A", "-t", "-c", query]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise LocalOIDCError("Could not perform the read-only local membership check") from None
    if result.returncode:
        raise LocalOIDCError("Could not perform the read-only local membership check")
    value = result.stdout.strip()
    if not value:
        return None
    if value not in ROLES:
        raise LocalOIDCError("Membership database returned an unknown role")
    return value


def membership_confirmation(organization_id: str, role: str) -> str:
    label = "ADMIN" if role == "administrator" else role.upper()
    return f"GRANT {label} {organization_id}"


def grant_membership(api: BootstrapAPI, organization_id: str, subject: str, role: str,
                     confirmation: str, read_role: Callable[[str, str], str | None] = current_membership) -> bool:
    if not UUID_RE.fullmatch(organization_id):
        raise LocalOIDCError("Invalid organization UUID")
    if not SUBJECT_RE.fullmatch(subject):
        raise LocalOIDCError("Invalid Keycloak subject UUID")
    if role not in ROLES:
        raise LocalOIDCError("Unsupported organization role")
    api.organization(organization_id)
    current = read_role(organization_id, subject)
    if current == role:
        return False
    expected = membership_confirmation(organization_id, role)
    if confirmation != expected:
        raise ConfirmationRequired(expected)
    api.set_membership(organization_id, subject, role)
    if read_role(organization_id, subject) != role:
        raise LocalOIDCError("Membership write returned but read-back verification failed")
    return True


def admin_credentials() -> tuple[str, str]:
    username = os.environ.get("KORDEX_KEYCLOAK_ADMIN_USERNAME", "kordex-local-admin")
    password_file = oidc_dir() / "keycloak-admin-password"
    if password_file.is_file():
        metadata = password_file.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise LocalOIDCError("Keycloak admin password file must be a regular file accessible only to its owner")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise LocalOIDCError("Keycloak admin password file must be owned by the current user")
        password = password_file.read_text().rstrip("\r\n")
        if not password:
            raise LocalOIDCError("Keycloak admin password file is empty")
        return username, password
    print("Local Keycloak admin password file is unavailable; enter the admin password securely.", file=sys.stderr)
    password = getpass.getpass("Keycloak admin password: ")
    if not password:
        raise LocalOIDCError("Keycloak admin password cannot be empty")
    return username, password
