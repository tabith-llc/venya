"""E2E tests for admin enrollment flow.

Tests the full browser-based admin enrollment:
1. POST /api/v1/init/reset (prepare)
2. Navigate to /enroll-admin
3. Enter username, submit form
4. WebAuthn registration via virtual authenticator
5. POST /api/v1/init/complete
6. Verify recovery code displayed
"""

import requests


class TestAdminEnrollment:
    """End-to-end admin enrollment tests."""

    def _reset_core(self, server_url):
        """Reset core to pre-initialization state via API."""
        # 403 means admin already enrolled — test will fail on init (409) which is expected
        # The test should be run after manual DB cleanup if needed
        requests.post(f"{server_url}/api/v1/init/reset", verify=False, timeout=10)

    def test_full_admin_enrollment_flow(self, browser_context, server_url):
        """Complete admin enrollment: page load -> username -> WebAuthn -> recovery code."""
        # Reset core first
        self._reset_core(server_url)

        context = browser_context["context"]
        page = context.new_page()

        # Step 1: Navigate to admin enrollment page
        page.goto(f"{server_url}/enroll-admin", wait_until="domcontentloaded")
        assert "Enroll Admin User" in page.text_content("h1")

        # Step 2: Enter username
        page.fill("#username-input", "testadmin")

        # Step 3: Submit form — triggers WebAuthn registration via virtual authenticator
        page.click("#enroll-btn")

        # Step 4: Wait for completion — recovery code modal should appear
        modal = page.wait_for_selector("#success-modal", state="visible", timeout=15000)
        assert modal.is_visible()

        recovery_code = page.text_content("#recovery-code-box")
        assert recovery_code
        assert len(recovery_code) > 0

        username = page.text_content("#success-username")
        assert username == "testadmin"

        page.close()

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
