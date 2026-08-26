"""E2E tests for user enrollment flow.

Tests the full browser-based user enrollment:
1. Admin generates enrollment token via API
2. Navigate to /enroll
3. Enter token, submit form
4. WebAuthn registration via virtual authenticator
5. Verify session cookie set
"""


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
