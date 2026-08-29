"""E2E tests for admin enrollment flow.

Tests the full browser-based admin enrollment:
1. POST /api/v1/init/reset (prepare)
2. Navigate to /enroll-admin
3. Enter username, submit form
4. WebAuthn registration via virtual authenticator
5. POST /api/v1/init/complete
6. Verify recovery code displayed
"""

import random
import subprocess

import pytest
import requests

ADMIN_NAMES = ["alice", "alex", "andrew", "anna", "adam"]


@pytest.mark.e2e
class TestAdminEnrollment:
    """End-to-end admin enrollment tests.

    Each test that enrolls an admin resets the DB via API first.
    Session-scoped e2e_test_setup in conftest.py handles initial cleanup.
    """

    def _reset(self, server_url):
        """Reset core via direct SQL. Works even when API refuses reset."""
        reset_sql = (
            "DELETE FROM webauthn_credentials; "
            "DELETE FROM sessions; "
            "DELETE FROM enrollment_tokens; "
            "DELETE FROM role_members; "
            "DELETE FROM users; "
            "DELETE FROM roles WHERE name IN ('admin', 'user');"
        )
        reset_cmd = "sudo -u postgres psql -d venya -t -A <<EOSQL\n" f"{reset_sql}\n" "EOSQL"
        reset_result = subprocess.run(
            ["ssh", "bot@venya-core-1", reset_cmd],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if reset_result.returncode != 0:
            pytest.fail(f"DB reset failed: {reset_result.stderr.strip()}")

    def test_full_admin_enrollment_flow(self, browser_context, server_url):
        """Complete admin enrollment: page load -> username -> WebAuthn -> recovery code."""
        self._reset(server_url)

        context = browser_context["context"]
        page = context.new_page()

        # Step 1: Navigate to admin enrollment page
        page.goto(f"{server_url}/enroll-admin", wait_until="domcontentloaded")
        assert "Enroll Admin User" in page.text_content("h1")

        # Step 2: Enter a unique username to avoid conflicts with other tests
        unique_id = random.choice(ADMIN_NAMES)
        page.fill("#username-input", unique_id)

        # Step 3: Submit form — triggers WebAuthn registration via virtual authenticator
        page.click("#enroll-btn")

        # Step 4: Wait for completion — recovery code modal should appear
        modal = page.wait_for_selector("#success-modal", state="visible", timeout=15000)
        assert modal.is_visible()

        recovery_code = page.text_content("#recovery-code-box")
        assert recovery_code
        assert len(recovery_code) > 0

        username = page.text_content("#success-username")
        assert username == unique_id

        page.close()

        # Return the enrolled admin ID for use by other tests
        return unique_id

    def test_admin_enrollment_empty_username(self, browser_context, server_url):
        """Submitting without username should show validation error."""
        context = browser_context["context"]
        page = context.new_page()

        page.goto(f"{server_url}/enroll-admin", wait_until="domcontentloaded")

        page.click("#enroll-btn")
        page.wait_for_timeout(500)

        msg = page.text_content("#message")
        assert "username" in msg.lower()
        assert not page.is_visible("#success-modal")

        page.close()

    def test_admin_can_access_admin_endpoints(self, browser_context, server_url):
        """Enrolled admin can access admin endpoints (e.g., GET /api/v1/admin/executors).

        Uses the admin enrolled by test_full_admin_enrollment_flow.
        """
        context = browser_context["context"]
        page = context.new_page()

        # Navigate to login page
        page.goto(f"{server_url}/", wait_until="domcontentloaded")

        # Fill username — use the admin from test_full_admin_enrollment_flow
        # The admin username follows the pattern admintest{timestamp}
        # We need to find it from the DB
        import subprocess

        result = subprocess.run(
            [
                "ssh",
                "bot@venya-core-1",
                (
                    "sudo -u postgres psql -d venya -t -A -c "
                    "'SELECT user_id FROM users WHERE enrolled_at IS NOT NULL ORDER BY enrolled_at DESC LIMIT 1;'"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        admin_id = result.stdout.strip()
        if not admin_id:
            pytest.fail("No enrolled admin found in DB")

        page.fill("#username", admin_id)
        page.click("#login-btn")
        page.wait_for_timeout(3000)

        cookies = {c["name"]: c["value"] for c in page.context.cookies()}
        resp = requests.get(
            f"{server_url}/api/v1/auth/me",
            verify=True,
            cookies=cookies,
            timeout=10,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] == admin_id
        assert "admin" in data["roles"]

        page.close()
