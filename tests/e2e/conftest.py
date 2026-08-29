"""E2E test configuration for browser-based enrollment.

Tests run headless on venya-test-workstation against venya-core-1.
Uses Playwright context.credentials API for WebAuthn virtual authenticator.
"""

import os
import subprocess
import sys
import time

import pytest
from playwright.sync_api import sync_playwright


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "e2e: End-to-end browser tests (requires Playwright + Chromium)",
    )


def pytest_collection_modifyitems(items):
    if not os.environ.get("RUN_E2E_TESTS"):
        skip_e2e = pytest.mark.skip(
            reason="E2E tests disabled. Set RUN_E2E_TESTS=1 to enable.",
        )
        for item in items:
            if "e2e" in item.keywords:
                item.add_marker(skip_e2e)


@pytest.fixture(scope="session")
def server_url():
    """Core server URL — the VM being tested, not localhost."""
    url = os.environ.get("VENYA_TEST_SERVER_URL")
    if not url:
        pytest.exit(
            "VENYA_TEST_SERVER_URL not set. " "Example: https://venya-core-1 or https://10.27.28.11",
        )
    return url


@pytest.fixture(scope="session", autouse=True)
def e2e_test_setup(server_url):
    """Reset the DB once at the start of the E2E test session.

    Uses direct SQL to clear all test data. This works even when the
    API refuses reset due to existing credentials.
    """
    # Clean stale known_hosts entries before any SSH connections
    subprocess.run(
        ["ssh-keygen", "-f", "/home/dust/.ssh/known_hosts", "-R", "venya-core-1"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    subprocess.run(
        ["ssh-keygen", "-f", "/home/dust/.ssh/known_hosts", "-R", "10.27.28.11"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

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
        ["ssh", "-o", "StrictHostKeyChecking=no", "bot@venya-core-1", reset_cmd],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if reset_result.returncode != 0:
        # During infra provisioning tests, postgres user may not exist yet
        # — this is expected. Skip the reset if postgres user is missing.
        if "unknown user postgres" in reset_result.stderr:
            return
        pytest.exit(f"E2E test session aborted: DB reset failed — {reset_result.stderr.strip()}")


@pytest.fixture(scope="session")
def browser_context(server_url):
    """Browser context with virtual WebAuthn authenticator."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 720},
        )

        # Extract rpId from server URL
        rp_id = server_url.replace("https://", "").replace("http://", "").split(":")[0]

        # Seed a virtual credential and activate the authenticator
        # MUST be called before any page navigation
        context.credentials.create(rp_id)
        context.credentials.install()

        yield {
            "browser": browser,
            "context": context,
            "rp_id": rp_id,
        }

        browser.close()


_ADMIN_LOGIN_SCRIPT = """
import sys
from playwright.sync_api import sync_playwright

server_url = sys.argv[1]
admin_id = sys.argv[2] if len(sys.argv) > 2 else "testadmin"
rp_id = server_url.replace("https://", "").replace("http://", "").split(":")[0]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 720})
    context.credentials.create(rp_id)
    context.credentials.install()

    page = context.new_page()

    # Step 1: Try to log in as admin_id (may fail if credential mismatch from prior runs)
    page.goto(f"{server_url}/", wait_until="domcontentloaded")
    page.fill("#username", admin_id)
    page.click("#login-btn")
    page.wait_for_timeout(3000)

    cookies = page.context.cookies()
    has_token = any(c["name"] == "venya_access_token" for c in cookies)

    if has_token:
        for c in cookies:
            print(f"{c['name']}={c['value']}")
        page.close()
        browser.close()
        sys.exit(0)

    # Step 2: Login failed (credential mismatch or user doesn't exist).
    # Enroll admin_id via browser.
    page.goto(f"{server_url}/enroll-admin", wait_until="domcontentloaded")
    page.fill("#username-input", admin_id)
    page.click("#enroll-btn")
    page.wait_for_timeout(10000)

    # Check if enrollment succeeded (success modal or error message)
    modal = page.query_selector("#success-modal")
    is_visible = modal.is_visible() if modal else False

    if is_visible:
        page.close()
        # Now log in with the newly enrolled credential (reuse same context)
        page2 = context.new_page()
        page2.goto(f"{server_url}/", wait_until="domcontentloaded")
        page2.fill("#username", admin_id)
        page2.click("#login-btn")
        page2.wait_for_timeout(3000)
        cookies = page2.context.cookies()
        has_token = any(c["name"] == "venya_access_token" for c in cookies)
        if has_token:
            for c in cookies:
                print(f"{c['name']}={c['value']}")
            page2.close()
            browser.close()
            sys.exit(0)
        page2.close()

    browser.close()
    print("ENROLLMENT_FAILED", file=sys.stderr)
    sys.exit(1)
"""


@pytest.fixture(scope="function")
def admin_cookies(server_url):
    """Authenticate as testadmin via browser login and return session cookies.

    Runs the Playwright login in a subprocess to avoid asyncio event loop
    conflicts with other session-scoped fixtures. Uses a unique admin username
    per test run to avoid credential conflicts from prior runs.

    Resets the DB via SSH before enrollment to handle stale state from
    previous test runs.
    """
    admin_id = f"e2eadm{int(time.time())}"

    # Reset DB via SSH to clear stale state
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
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if reset_result.returncode != 0:
        pytest.fail(f"DB reset failed: {reset_result.stderr.strip()}")

    result = subprocess.run(
        [sys.executable, "-c", _ADMIN_LOGIN_SCRIPT, server_url, admin_id],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Admin login failed (exit {result.returncode}): {result.stderr.strip()}\n"
            "Ensure admin enrollment succeeded."
        )

    cookies = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            cookies[name] = value

    if "venya_access_token" not in cookies:
        pytest.fail("Admin login failed: no venya_access_token cookie in response.")

    return cookies
