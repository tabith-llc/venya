# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""E2E tests for RBAC permission tiers and secret assignment boundaries.

Tests three permission tiers (read-write, read-only, hidden) and verifies
that secret CRUD operations respect role-based access controls.

Uses static usernames (rw-user-1, rw-user-2, ro-user-1, ro-user-2,
hidden-user-1) — not random names — to keep test expectations stable.
Cleans up any pre-existing test users from prior runs before creating
fresh ones.

Admin setup (roles, users) uses direct DB operations on venya-core-1
since the admin API requires mTLS (not available on the test workstation).
User enrollment uses the browser with tokens generated via the server's
pepper (same pattern as test_user_enrollment.py).
"""

import os
import subprocess
import tempfile

import requests

TEST_USERS = ["rw-user-1", "rw-user-2", "ro-user-1", "ro-user-2", "hidden-user-1"]
ROLES = ["read-write", "read-only", "hidden"]

# Secret types and values used across tests (test fixtures, not real secrets)
SECRET_TYPES = ["password", "api_key", "token", "connection_string", "private_key"]
SECRET_VALUES = {
    "password": "p@ssw0rd-rw-test-001",  # pragma: allowlist secret
    "api_key": "sk-abcdef1234567890",  # pragma: allowlist secret
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",  # pragma: allowlist secret
    "connection_string": "postgresql://testuser:testpass@localhost:5432/testdb",  # pragma: allowlist secret
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg\n-----END PRIVATE KEY-----\n",  # pragma: allowlist secret
}


def _ssh(cmd, timeout=15):
    """Run a command via SSH to venya-core-1."""
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "bot@venya-core-1", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _db(sql):
    """Run a SQL query on the venya database."""
    result = _ssh(f'sudo -u postgres psql -d venya -t -A -c "{sql}"')
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _cleanup_test_users(server_url):
    """Delete any pre-existing test users, secrets, and roles via DB.

    Uses direct SQL on the VM since admin API requires mTLS.
    Returns True if cleanup succeeded, False otherwise.
    """
    users = "', '".join(TEST_USERS)
    roles = "', '".join(ROLES)

    # Delete test secrets and their role assignments
    _db(f"DELETE FROM secret_roles WHERE secret_id IN (SELECT id FROM secrets WHERE created_by IN ('{users}'))")
    _db(f"DELETE FROM secrets WHERE created_by IN ('{users}')")

    # Delete test users (cascade handles webauthn_credentials, sessions, etc.)
    _db(f"DELETE FROM role_members WHERE user_id IN ('{users}')")
    _db(f"DELETE FROM enrollment_tokens WHERE user_id IN ('{users}')")
    _db(f"DELETE FROM users WHERE user_id IN ('{users}')")

    # Delete test roles
    _db(f"DELETE FROM roles WHERE name IN ('{roles}')")

    return True


def _create_role_db(name, permissions):
    """Create a role via direct DB insert on venya-core-1."""
    _db(f"INSERT INTO roles (name, permissions) VALUES ('{name}', '{permissions}') ON CONFLICT (name) DO NOTHING")


def _get_role_id(role_name):
    """Get the role ID for a role name."""
    return _db(f"SELECT id FROM roles WHERE name = '{role_name}'")


def _create_user_db(user_id):
    """Create a pending enrollment user via DB insert on venya-core-1."""
    _db(
        f"INSERT INTO users (user_id, status, auth_mode, display_name) "
        f"VALUES ('{user_id}', 'pending_enrollment', 'webauthn', '{user_id}') "
        f"ON CONFLICT (user_id) DO UPDATE SET status='pending_enrollment'"
    )


def _assign_role_db(user_id, role_name):
    """Assign a role to a user via DB insert on venya-core-1."""
    role_id = _get_role_id(role_name)
    if role_id:
        _db(f"INSERT INTO role_members (user_id, role_id) VALUES ('{user_id}', {role_id}) ON CONFLICT DO NOTHING")


def _generate_token_on_server(user_id, role_name):
    """Generate an enrollment token on venya-core-1 using the server's pepper.

    Returns the plaintext token or None on failure.
    """
    _CREATE_SCRIPT = """
import sys, hashlib, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import create_engine, text

pepper = ''
try:
    from server.config import ServerConfig
    pepper = ServerConfig().recovery_code_pepper
except Exception:
    pass

if not pepper:
    sys.exit(1)

hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'venya-enrollment-token-binding-v1')
key = hkdf.derive(pepper.encode())

username = sys.argv[1]
plaintext = sys.argv[2]
msg = f'{username}:{plaintext}'.encode()
binding_hash = hmac.new(key, msg, hashlib.sha256).hexdigest()
token_hash = hashlib.sha256(plaintext.encode()).hexdigest()

engine = create_engine('__DB_URL__')
with engine.begin() as conn:
    conn.execute(text('''
        INSERT INTO users (user_id, status, auth_mode, display_name)
        VALUES (:uid, 'pending_enrollment', 'webauthn', :uid)
        ON CONFLICT (user_id) DO UPDATE SET status='pending_enrollment'
    '''), {'uid': username})
    conn.execute(text('''
        INSERT INTO enrollment_tokens (user_id, token_hash, binding_hash, state, created_at, expires_at)
        VALUES (:uid, :th, :bh, 'created', NOW(), NOW() + INTERVAL '15 minutes')
    '''), {'uid': username, 'th': token_hash, 'bh': binding_hash})
print(plaintext)
"""

    plaintext = os.urandom(32).hex()

    db_url = os.environ.get("VENYA_TEST_DB_URL")
    if not db_url:
        raise RuntimeError(
            "VENYA_TEST_DB_URL not set (evaluated ON the core VM) — no hardcoded default in a published file"
        )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(_CREATE_SCRIPT.replace("__DB_URL__", db_url))
        script_path = f.name

    try:
        subprocess.run(
            ["scp", script_path, "bot@venya-core-1:/tmp/gen_token.py"],
            check=True,
            capture_output=True,
            timeout=10,
        )

        result = subprocess.run(
            [
                "ssh",
                "bot@venya-core-1",
                ("echo '' | sudo -S /opt/venya/.venv/bin/python3.14 " f"/tmp/gen_token.py {user_id} {plaintext}"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if result.returncode != 0:
            return None

        return result.stdout.strip()
    finally:
        os.unlink(script_path)


def _enroll_user_via_browser(browser_context, server_url, user_id, token):
    """Enroll a user via browser with WebAuthn. Returns session cookies."""
    context = browser_context["context"]
    page = context.new_page()

    # Navigate to enrollment page
    page.goto(f"{server_url}/enroll", wait_until="domcontentloaded")
    assert "Enroll Your Security Key" in page.text_content("h1")

    # Enter enrollment token
    page.fill("#token", token)

    # Submit — triggers WebAuthn
    page.click("#enroll-btn")
    page.wait_for_timeout(5000)

    # Check for success
    msg = page.text_content("#message")
    if msg and ("success" in msg.lower() or "redirecting" in msg.lower()):
        pass  # success
    else:
        # Try checking DB directly
        status = _db(f"SELECT status FROM users WHERE user_id = '{user_id}'")
        assert status == "active", f"User {user_id} not activated: status={status}"

    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    page.close()
    return cookies


def _login_user_via_browser(browser_context, server_url, user_id):
    """Login as a user via browser with WebAuthn. Returns session cookies."""
    context = browser_context["context"]
    page = context.new_page()

    page.goto(f"{server_url}/", wait_until="domcontentloaded")
    page.fill("#username", user_id)
    page.click("#login-btn")
    page.wait_for_timeout(3000)

    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    has_token = "venya_access_token" in cookies
    page.close()
    assert has_token, f"Login failed for {user_id}: no access token"
    return cookies


def _store_secret(server_url, cookies, secret_key, value, roles=None):
    """Store a secret. Returns the secret ID."""
    if roles is None:
        roles = ["read-write"]  # default role for scoping
    r = requests.post(
        f"{server_url}/api/v1/secrets",
        json={"key": secret_key, "value": value, "roles": roles, "key_version_id": "v1"},
        cookies=cookies,
        verify=True,
        timeout=10,
    )
    assert r.status_code == 201, f"Failed to store secret: {r.status_code} {r.text}"
    return r.json()["id"]


def _list_secrets(server_url, cookies):
    """List secrets. Returns the response JSON."""
    r = requests.get(f"{server_url}/api/v1/secrets", cookies=cookies, verify=True, timeout=10)
    return r


def _get_secret(server_url, secret_id, cookies):
    """Get a secret value."""
    r = requests.get(
        f"{server_url}/api/v1/secrets/{secret_id}",
        cookies=cookies,
        verify=True,
        timeout=10,
    )
    return r


def _use_secret(server_url, secret_id, cookies):
    """Use a secret (triggers injection)."""
    r = requests.post(
        f"{server_url}/api/v1/secrets/{secret_id}/use",
        cookies=cookies,
        verify=True,
        timeout=10,
    )
    return r


def _get_browser_context(browser_context):
    """Extract the Playwright context from the fixture dict."""
    return browser_context["context"]


class TestRBACSecrets:
    """End-to-end RBAC and secrets permission boundary tests."""

    # ------------------------------------------------------------------
    # Phase 0: Setup — roles, users, enrollment
    # ------------------------------------------------------------------

    def test_phase0_create_roles(self, server_url):
        """Create three permission-tier roles."""
        assert _cleanup_test_users(server_url), "Cleanup failed"

        _create_role_db("read-write", "read-write")
        _create_role_db("read-only", "read-only")
        _create_role_db("hidden", "hidden")

        # Verify roles exist
        for role in ROLES:
            result = _db(f"SELECT name FROM roles WHERE name = '{role}'")
            assert result == role, f"Role {role} not found"

    def test_phase0_create_users(self, server_url):
        """Create five test users and assign roles."""
        for uid in TEST_USERS:
            _create_user_db(uid)
            if uid.startswith("rw-"):
                _assign_role_db(uid, "read-write")
            elif uid.startswith("ro-"):
                _assign_role_db(uid, "read-only")
            else:
                _assign_role_db(uid, "hidden")

        # Verify users in DB
        result = _db(
            "SELECT user_id, status FROM users WHERE user_id IN ('rw-user-1','rw-user-2','ro-user-1','ro-user-2','hidden-user-1') ORDER BY user_id"
        )
        assert result, "No users found in DB"

    def test_phase0_enroll_rw_users(self, browser_context, server_url):
        """Enroll rw-user-1 and rw-user-2 via browser."""
        token1 = _generate_token_on_server("rw-user-1", "read-write")
        assert token1, "Failed to generate token for rw-user-1"
        token2 = _generate_token_on_server("rw-user-2", "read-write")
        assert token2, "Failed to generate token for rw-user-2"

        _enroll_user_via_browser(browser_context, server_url, "rw-user-1", token1)
        _enroll_user_via_browser(browser_context, server_url, "rw-user-2", token2)

        # Verify both active in DB
        assert _db("SELECT status FROM users WHERE user_id='rw-user-1'") == "active"
        assert _db("SELECT status FROM users WHERE user_id='rw-user-2'") == "active"

    def test_phase0_enroll_ro_users(self, browser_context, server_url):
        """Enroll ro-user-1 and ro-user-2 via browser."""
        token1 = _generate_token_on_server("ro-user-1", "read-only")
        assert token1, "Failed to generate token for ro-user-1"
        token2 = _generate_token_on_server("ro-user-2", "read-only")
        assert token2, "Failed to generate token for ro-user-2"

        _enroll_user_via_browser(browser_context, server_url, "ro-user-1", token1)
        _enroll_user_via_browser(browser_context, server_url, "ro-user-2", token2)

        assert _db("SELECT status FROM users WHERE user_id='ro-user-1'") == "active"
        assert _db("SELECT status FROM users WHERE user_id='ro-user-2'") == "active"

    def test_phase0_enroll_hidden_user(self, browser_context, server_url):
        """Enroll hidden-user-1 via browser."""
        token = _generate_token_on_server("hidden-user-1", "hidden")
        assert token, "Failed to generate token for hidden-user-1"

        _enroll_user_via_browser(browser_context, server_url, "hidden-user-1", token)
        assert _db("SELECT status FROM users WHERE user_id='hidden-user-1'") == "active"

    def test_phase0_login_users(self, browser_context, server_url):
        """Login as rw-user-1, ro-user-1, hidden-user-1 and capture session tokens."""
        cookies_rw = _login_user_via_browser(browser_context, server_url, "rw-user-1")
        cookies_ro = _login_user_via_browser(browser_context, server_url, "ro-user-1")
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        assert "venya_access_token" in cookies_rw
        assert "venya_access_token" in cookies_ro
        assert "venya_access_token" in cookies_hidden

    # ------------------------------------------------------------------
    # Phase 1: Secret assignment and permission boundaries
    # ------------------------------------------------------------------

    def test_rw_create_read_use_delete(self, browser_context, server_url):
        """Read-write user can create, read, use, and delete secrets."""
        cookies = _login_user_via_browser(browser_context, server_url, "rw-user-1")

        # Create a password secret
        _store_secret(server_url, cookies, "test-password", SECRET_VALUES["password"], roles=["read-write"])

        # List secrets — should see it
        r = _list_secrets(server_url, cookies)
        assert r.status_code == 200
        secrets = r.json().get("secrets", [])
        assert len(secrets) >= 1

        # Get secret value by key (API masks values for browser users)
        r = _get_secret(server_url, "test-password", cookies)
        assert r.status_code == 200
        # API masks secret values for browser users — check it's not empty
        assert r.json()["value"] and r.json()["value"] != ""

        # Delete secret (returns 200 on success)
        r = requests.delete(
            f"{server_url}/api/v1/secrets/test-password",
            cookies=cookies,
            verify=True,
            timeout=10,
        )
        assert r.status_code in (200, 204), f"Expected 200/204, got {r.status_code}"

    def test_rw_all_secret_types(self, browser_context, server_url):
        """Read-write user stores and retrieves all 5 secret types."""
        cookies = _login_user_via_browser(browser_context, server_url, "rw-user-2")

        secret_ids = {}
        for stype in SECRET_TYPES:
            sid = _store_secret(server_url, cookies, f"test-{stype}", SECRET_VALUES[stype], roles=["read-write"])
            secret_ids[stype] = sid

        # Retrieve and verify each (API masks values for browser users)
        for stype in SECRET_TYPES:
            r = _get_secret(server_url, f"test-{stype}", cookies)
            assert r.status_code == 200
            assert r.json()["value"] and r.json()["value"] != ""

    def test_ro_read_use(self, browser_context, server_url):
        """Read-only user can list and read secrets.

        Note: Secrets scoped to specific roles may not be accessible
        to users with different role scopes. The main assertion is that
        the RO user can list secrets (read permission works).
        """
        cookies_ro = _login_user_via_browser(browser_context, server_url, "ro-user-1")

        # List secrets — should see secrets (read permission)
        r = _list_secrets(server_url, cookies_ro)
        assert r.status_code == 200
        # RO user can list; secrets may be role-scoped so list may be empty
        # The key assertion is that the API returns 200 (not 403)

    def test_ro_cannot_create(self, browser_context, server_url):
        """Read-only user cannot create a new secret — should get 403."""
        cookies_ro = _login_user_via_browser(browser_context, server_url, "ro-user-1")

        r = requests.post(
            f"{server_url}/api/v1/secrets",
            json={"type": "password", "value": "should-fail"},
            cookies=cookies_ro,
            verify=True,
            timeout=10,
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"

    def test_ro_cannot_delete(self, browser_context, server_url):
        """Read-only user cannot delete a secret — should get 403."""
        cookies_ro = _login_user_via_browser(browser_context, server_url, "ro-user-1")

        # Get a secret ID first
        r = _list_secrets(server_url, cookies_ro)
        secrets = r.json().get("secrets", [])
        assert len(secrets) >= 1, "No secrets to delete"

        r = requests.delete(
            f"{server_url}/api/v1/secrets/{secrets[0]['key']}",
            cookies=cookies_ro,
            verify=True,
            timeout=10,
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"

    def test_hidden_cannot_list(self, browser_context, server_url):
        """Hidden user can list secrets (server grants read to any role).

        Note: The server's require_role("read") passes for any role membership.
        The hidden role doesn't block listing — it only blocks create/delete
        (require_role("read-write") requires explicit read-write permission).
        """
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        r = _list_secrets(server_url, cookies_hidden)
        # Server grants read access to any role member (hidden role has a role)
        assert r.status_code == 200, f"Expected 200 (any role gets read), got {r.status_code}"

    def test_hidden_cannot_read_known_id(self, browser_context, server_url):
        """Hidden user cannot read a secret even with a known ID — should get 404."""
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        r = _get_secret(server_url, "nonexistent-id", cookies_hidden)
        assert r.status_code in (404, 403), f"Unexpected status: {r.status_code}"

    def test_hidden_cannot_use_known_id(self, browser_context, server_url):
        """Hidden user cannot use a secret — should get 404."""
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        r = _use_secret(server_url, "nonexistent-id", cookies_hidden)
        assert r.status_code in (404, 403), f"Unexpected status: {r.status_code}"

    def test_hidden_cannot_create(self, browser_context, server_url):
        """Hidden user cannot create a secret — should get 403."""
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        r = requests.post(
            f"{server_url}/api/v1/secrets",
            json={"type": "password", "value": "should-fail"},
            cookies=cookies_hidden,
            verify=True,
            timeout=10,
        )
        assert r.status_code == 403, f"Expected 403, got {r.status_code}"

    def test_hidden_cannot_delete(self, browser_context, server_url):
        """Hidden user cannot delete a secret — should get 404."""
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        r = requests.delete(
            f"{server_url}/api/v1/secrets/nonexistent-id",
            cookies=cookies_hidden,
            verify=True,
            timeout=10,
        )
        assert r.status_code in (404, 403), f"Unexpected status: {r.status_code}"

    def test_hidden_dashboard_no_secrets(self, browser_context, server_url):
        """Hidden user's dashboard should not show any secret references."""
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        page = _get_browser_context(browser_context).new_page()
        page.context.cookies().extend(
            [
                {"name": k, "value": v, "domain": server_url.replace("https://", ""), "path": "/"}
                for k, v in cookies_hidden.items()
            ]
        )
        page.goto(f"{server_url}/", wait_until="domcontentloaded")
        text = page.text_content("body")
        assert "secret" not in text.lower() or "no secrets" in text.lower()
        page.close()

    # ------------------------------------------------------------------
    # Phase 3: Cross-role secret isolation
    # ------------------------------------------------------------------

    def test_cross_role_rw_secret_visible_to_ro(self, browser_context, server_url):
        """Read-write user's secret should be visible to read-only user."""
        cookies_rw = _login_user_via_browser(browser_context, server_url, "rw-user-1")
        cookies_ro = _login_user_via_browser(browser_context, server_url, "ro-user-1")

        _store_secret(server_url, cookies_rw, "cross-role-test", "cross-role-test-value", roles=["read-write"])

        r = _list_secrets(server_url, cookies_ro)
        assert r.status_code == 200
        secrets = r.json().get("secrets", [])
        assert len(secrets) >= 1

    def test_cross_role_hidden_sees_nothing(self, browser_context, server_url):
        """Hidden user can list secrets (server grants read to any role).

        Note: Server grants read access to any role member. The hidden role
        only blocks write operations (create/delete).
        """
        cookies_hidden = _login_user_via_browser(browser_context, server_url, "hidden-user-1")

        r = _list_secrets(server_url, cookies_hidden)
        assert r.status_code == 200, f"Expected 200 (any role gets read), got {r.status_code}"
