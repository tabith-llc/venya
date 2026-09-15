# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

import pytest


@pytest.fixture(autouse=True)
def _executor_ids_resolvable(monkeypatch):
    """Stub DNS for registration tests — the suite registers synthetic executor ids.

    Yields the REAL _dial_hostname_resolvable for tests that exercise actual
    resolution. Resolvability enforcement at the endpoint is covered by
    TestExecutorRegistration tests that override this stub.
    """
    from server.routes import executors as _ex

    real = _ex._dial_hostname_resolvable
    monkeypatch.setattr(_ex, "_dial_hostname_resolvable", lambda host: True)
    return real
