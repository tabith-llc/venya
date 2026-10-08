# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#466 guards: the executor suite must run where the server package is absent.

On an executor-only install the server package is not shipped, so the shared
test CA fixture and the server-facing integration module must be handled by a
named, attributable skip — never a collection crash (rc=4). With both
packages present (the workstation case) nothing here hides a cell: every
dependent test still runs.
"""

import pytest

from . import conftest


def test_skip_reason_names_ticket_466() -> None:
    """The #466 skip reason is stated and always names the ticket."""
    assert "#466" in conftest.SERVER_ABSENT_REASON


def test_server_dependent_cells_run_when_server_present() -> None:
    """AC3 negative half: with both packages installed, the guard hides nothing.

    When the server package is absent this cell reports a named #466 skip, so
    the skip set is enumerated in the summary rather than silent.
    """
    if not conftest.SERVER_AVAILABLE:
        pytest.skip(conftest.SERVER_ABSENT_REASON)
    assert "test_integration.py" not in getattr(conftest, "collect_ignore", [])
    assert conftest.CAManager is not None


def test_integration_module_is_named_when_server_absent() -> None:
    """Server absent: the dependent module is skipped BY NAME in conftest."""
    if conftest.SERVER_AVAILABLE:
        assert "test_integration.py" not in getattr(conftest, "collect_ignore", [])
        return
    assert "test_integration.py" in conftest.collect_ignore
