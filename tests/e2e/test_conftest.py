# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Unit tests for the e2e harness skip decision (conftest._e2e_skip_reason).

Pure unit tests — no browser, no fleet. They pin that the e2e suite skips
LOUDLY (the reason names the missing env) instead of hard-aborting when the
operator's lab env is not configured.

The sibling conftest is loaded by file path so this import does not depend on
pytest's conftest / import-mode wiring. The session-scoped autouse
``e2e_test_setup`` fixture (DB reset over the lab) is shadowed with a no-op so
this module does not inherit it — otherwise a dry run (no lab env) would sweep
these unit tests into the e2e skip/failure path.
"""

import importlib.util
from pathlib import Path

import pytest


def _load_conftest():
    conftest_path = Path(__file__).resolve().with_name("conftest.py")
    spec = importlib.util.spec_from_file_location("e2e_conftest_under_test", conftest_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_e2e_skip_reason = _load_conftest()._e2e_skip_reason


@pytest.fixture(scope="session", autouse=True)
def e2e_test_setup():
    """No-op shadow of the real autouse e2e DB-reset fixture (see module docstring)."""
    yield


def test_skips_when_run_flag_unset(monkeypatch):
    monkeypatch.delenv("RUN_E2E_TESTS", raising=False)
    monkeypatch.delenv("VENYA_TEST_SERVER_URL", raising=False)
    assert "RUN_E2E_TESTS" in _e2e_skip_reason()


def test_skips_loudly_naming_missing_server_url(monkeypatch):
    monkeypatch.setenv("RUN_E2E_TESTS", "1")
    monkeypatch.delenv("VENYA_TEST_SERVER_URL", raising=False)
    reason = _e2e_skip_reason()
    assert reason is not None
    assert "VENYA_TEST_SERVER_URL" in reason


def test_runs_when_lab_env_configured(monkeypatch):
    monkeypatch.setenv("RUN_E2E_TESTS", "1")
    monkeypatch.setenv("VENYA_TEST_SERVER_URL", "https://venya-core-1")
    assert _e2e_skip_reason() is None
