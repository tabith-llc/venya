"""E2E test configuration for browser-based enrollment.

Tests run headless on venya-test-workstation against venya-core-1.
Uses Playwright context.credentials API for WebAuthn virtual authenticator.
"""

import os

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


@pytest.fixture(scope="function")
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
