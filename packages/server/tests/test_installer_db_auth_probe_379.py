# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of the repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Source-pin: #379 auth probe precedes every DB mutation.

A partial wipe (DROP DATABASE without DROP ROLE) leaves the cluster-wide
role 'venya' alive on its old password while a fresh install carries a new
one; the stored-.env mismatch guard is blind when the wipe also removes
.env. The probe authenticates the existing role BEFORE any DB write and
aborts with the fix printed. Both halves of the pin: the marker text must
be present, and it must appear before the first DB-affecting mutation
(CREATE DATABASE) — a relocated probe that lands after the writes fails
the ordering half even if the marker survives.
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]

_MARKER = "does not authenticate with the password this install will use"
_FIRST_DB_WRITE = "CREATE DATABASE venya OWNER venya"


class TestInstallerDbAuthProbe379:
    def test_probe_present_and_before_first_db_write(self):
        core = (_ROOT / "install-venya-core.sh").read_text()
        assert _MARKER in core
        assert core.index(_MARKER) < core.index(_FIRST_DB_WRITE)
