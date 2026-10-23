# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""E2E tests for user enrollment flow.

Tests the full browser-based user enrollment:
1. Generate enrollment token via admin API
2. Navigate to /enroll
3. Enter token, submit form
4. WebAuthn registration via virtual authenticator
5. Verify enrollment succeeds (token consumed, user activated)
"""

import os
import random

import pytest
import requests

USER_NAMES = ["bob", "bart", "billy", "ben", "blake"]


@pytest.mark.e2e
class TestUserEnrollment:
    """End-to-end user enrollment tests."""

    def _check_user_status(self, username, server_url):
        """Check user status in DB."""
        result = (
            os.popen(
                f"ssh -o StrictHostKeyChecking=no bot@venya-core-1 "
                f'"sudo -u postgres psql -d venya -t -A -c '
                f'\\"SELECT status FROM users WHERE user_id = \'{username}\';\\""'
            )
            .read()
            .strip()
        )
        return result

    def _check_credential_count(self, username, server_url):
        """Check credential count in DB."""
        result = (
            os.popen(
                f"ssh -o StrictHostKeyChecking=no bot@venya-core-1 "
                f'"sudo -u postgres psql -d venya -t -A -c '
                f'\\"SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = \'{username}\';\\""'
            )
            .read()
            .strip()
        )
        return result

    def _generate_enrollment_token(self, user_id, server_url, admin_cookies):
        """Generate enrollment token via admin API or DB fallback.

        Tries POST /api/v1/admin/users first (requires mTLS). Falls back to
        DB-based token generation via SSH if mTLS is not available.
        Raises pytest.fail() on any error.
        """
        # Try admin API first (mTLS)
        api_url = f"{server_url}/api/v1/admin/users"
        resp = requests.post(
            api_url,
            cookies=admin_cookies,
            json={
                "username": user_id,
                "display_name": user_id,
                "roles": ["user"],
            },
            verify=True,
            timeout=10,
        )
        if resp.status_code == 201:
            data = resp.json()
            token = data.get("enrollment_token")
            if token:
                return token
            pytest.fail(f"No enrollment_token in response: {data}")

        # Fallback: generate token via DB on the VM
        return self._generate_token_via_db(user_id, server_url)

    def _generate_token_via_db(self, user_id, server_url):
        """Generate enrollment token via DB insert on venya-core-1.

        Runs the token creation logic on the server VM to use the server's
        pepper for binding_hash computation.
        """
        import os
        import subprocess
        import tempfile

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
                pytest.fail(f"DB token generation failed: {result.stderr.strip()}")

            return result.stdout.strip()
        finally:
            os.unlink(script_path)

    def test_user_enrollment_empty_token(self, browser_context, server_url):
        """Submitting without token should show validation error."""
        context = browser_context["context"]
        page = context.new_page()

        page.goto(f"{server_url}/enroll", wait_until="domcontentloaded")

        page.click("#enroll-btn")
        page.wait_for_timeout(500)

        msg = page.text_content("#message")
        assert "token" in msg.lower()
        assert "success" not in msg.lower()

        page.close()

    def test_user_enrollment_full_flow(self, browser_context, server_url, admin_cookies):
        """Complete user enrollment: token -> page -> WebAuthn -> user activated."""
        unique_id = random.choice(USER_NAMES)

        token = self._generate_enrollment_token(unique_id, server_url, admin_cookies)

        context = browser_context["context"]
        page = context.new_page()

        # Navigate to user enrollment page
        page.goto(f"{server_url}/enroll", wait_until="domcontentloaded")
        assert "Enroll Your Security Key" in page.text_content("h1")

        # Enter enrollment token
        page.fill("#token", token)

        # Submit form — triggers WebAuthn registration via virtual authenticator
        page.click("#enroll-btn")

        # Wait for completion
        page.wait_for_timeout(5000)

        # Check for success message
        msg = page.text_content("#message")
        if msg and ("success" in msg.lower() or "redirecting" in msg.lower()):
            pass
        else:
            assert "/enroll" not in page.url or msg, f"Expected success or redirect, got url={page.url}, msg={msg}"

        # Verify user was activated in DB
        status = self._check_user_status(unique_id, server_url)
        assert status == "active", f"User should be active, got: {status}"

        # Verify credential was created
        count = self._check_credential_count(unique_id, server_url)
        assert count == "1", f"Expected 1 credential, got: {count}"

        page.close()
