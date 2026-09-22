# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Shared fixtures for the venya-cli test suite."""

import pytest


@pytest.fixture(autouse=True)
def _hermetic_venya_env(monkeypatch):
    """Keep ambient VENYA_* resolution envs out of every test.

    The CLI reads VENYA_SERVER_URL (run_command chokepoint, _get_server_url)
    and VENYA_EXECUTOR_ENROLLMENT_TOKEN (executor_register) from os.environ.
    An export on a dev/CI machine must not silently drive resolution chains —
    tests that exercise these set them explicitly (patch.dict / monkeypatch).
    """
    monkeypatch.delenv("VENYA_SERVER_URL", raising=False)
    monkeypatch.delenv("VENYA_EXECUTOR_ENROLLMENT_TOKEN", raising=False)
