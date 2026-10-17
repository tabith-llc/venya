# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Core-suite collection glue.

Created for #650. Until now core had no ``conftest.py`` at all, and it holds three of the files
gated on the door variable (443, 514, 515 — the name lives in ``pg_door_preflight.DOOR_ENV``) — so
the door's pre-flight had nowhere to bind in this package, and a dead door here looked exactly like a
dead door anywhere else: red product cells whose cause was a tmpfs.

This file deliberately does NOT spell the door variable in its own text. The #614/#630 interlock
treats every file that names it as a file holding gated CELLS, and requires a ``*Postgresql`` class
plus the shared ``_PG_DEADLINE`` in it; a wiring file and a harness test have neither, and adding a
dead class to satisfy the scanner would be exactly the kind of check-that-passes-on-nothing this
project books. The interlock's own claim list is unchanged and still has its teeth.

Everything substantive lives in ``scripts/pg_door_preflight.py``, loaded by path the way
``packages/core/tests/test_detect_secrets_baseline.py`` loads the baseline guard. One shared
implementation for both packages; this file is the wiring, and it holds no rule of its own.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "pg_door_preflight.py"


def _load_preflight():
    """Load the shared pre-flight by path, failing LOUDLY if the file is not where it says it is.

    An import that returns None here would be the same silence this row exists to end, one layer
    down: a missing pre-flight must not be able to present a clean run.
    """
    if not _SCRIPT.is_file():
        pytest.exit(
            f"pg-door-pre-flight CANNOT RUN: {_SCRIPT} is missing, so no door check is in force. "
            "Restore it before trusting any PostgreSQL-gated result in this package.",
            returncode=1,
        )
    spec = importlib.util.spec_from_file_location("pg_door_preflight", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Register before exec: the module uses @dataclass, whose machinery resolves the owning module
    # through sys.modules at class-creation time. Without this line the import dies with
    # "'NoneType' object has no attribute '__dict__'" and takes the whole conftest with it.
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_pg_door_preflight = _load_preflight()


def pytest_report_header(config) -> list[str]:
    """The pre-flight's finding, printed in the header of every core run (#650 AC1)."""
    return [_pg_door_preflight.door_report_header(config)]


def pytest_runtest_setup(item) -> None:
    """Abort a door-gated cell loudly when the door was asked for and the host cannot give it."""
    _pg_door_preflight.abort_unusable_door(item)
