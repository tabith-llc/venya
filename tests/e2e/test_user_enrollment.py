"""E2E tests for user enrollment flow.

Tests the full browser-based user enrollment:
1. Generate enrollment token via DB (bypasses admin API)
2. Navigate to /enroll
3. Enter token, submit form
4. WebAuthn registration via virtual authenticator
5. Verify enrollment succeeds (token consumed, user activated)
"""

import os
import subprocess

import pytest
import requests


def _generate_token_via_db(server_url, username="testuser"):
    """Generate enrollment token by running DB insert on venya-core-1.

    Uses the server's Python to compute binding_hash with the server's pepper.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    gen_script = os.path.join(script_dir, "gen_token.py")

    result = subprocess.run(
        ["python3.14", gen_script, username],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _check_user_status(username):
    """Check user status in DB."""
    result = subprocess.run(
        ["ssh", "bot@venya-core-1",
         "sudo -u postgres psql -d venya -t -A -c "
         f"\"SELECT status FROM users WHERE user_id = '{username}';\""],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _check_credential_count(username):
    """Check credential count in DB."""
    result = subprocess.run(
        ["ssh", "bot@venya-core-1",
         "sudo -u postgres psql -d venya -t -A -c "
         f"\"SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = '{username}';\""],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


class TestUserEnrollment:
    """End-to-end user enrollment tests."""

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

    def test_user_enrollment_full_flow(self, browser_context, server_url):
        """Complete user enrollment: token -> page -> WebAuthn -> user activated."""
        import time
        unique_id = f"e2e{int(time.time())}"
        token = _generate_token_via_db(server_url, username=unique_id)
        if not token:
            pytest.skip("Could not generate enrollment token via DB")

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
            assert (
                "/enroll" not in page.url or msg
            ), f"Expected success or redirect, got url={page.url}, msg={msg}"

        # Verify user was activated in DB
        status = _check_user_status(unique_id)
        assert status == "active", f"User should be active, got: {status}"

        # Verify credential was created
        count = _check_credential_count(unique_id)
        assert count == "1", f"Expected 1 credential, got: {count}"

        page.close()
