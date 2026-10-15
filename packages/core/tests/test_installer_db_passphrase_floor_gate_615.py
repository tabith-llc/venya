# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#615 interlock: the installer's DB-passphrase floor gate must stay the SAME gate
the core enforces at boot — same number, same words, asked earlier.

`install-venya-core.sh` re-embeds the owner-blessed refusal block shipped at
``core.engine.backend.short_passphrase_refusal`` (function declaration, backend.py:126)
as a quoted heredoc, because a bash string cannot interpolate the two constants. That
re-embedment is exactly the class of copy that drifts: an edit to the python sentence,
or to the floor number, silently leaves the installer telling the operator something the
core no longer says (and vice versa). This is the generated-docs interlock pattern
(``docs/bandit-nosec-suppressions.md``) pointed at a hand-copied string instead.

Truth-table halves, both directions:
  - byte-identical text, write path (``Nothing was written.`` present), and the floor
    literal in bash equals ``MIN_PASSPHRASE_CODE_POINTS``;
  - NEGATIVE: no ceiling door in bash (backend.py:76 / server/ca.py:101 state MAX 64 and
    never enforce it — an installer that refuses a long passphrase invented a door the
    core does not have), and the gate sits BEFORE the first mutation.
"""

import re
from pathlib import Path

from core.engine.backend import (
    MIN_PASSPHRASE_CODE_POINTS,
    short_passphrase_refusal,
)

_ROOT = Path(__file__).resolve().parents[3]
_INSTALLER = _ROOT / "install-venya-core.sh"

_HEREDOC = re.compile(
    r"<<'VENYA_DB_PASSPHRASE_FLOOR_REFUSAL'\n(.*?)\nVENYA_DB_PASSPHRASE_FLOOR_REFUSAL\n",
    re.DOTALL,
)
_FLOOR = re.compile(r"^DB_PASSPHRASE_FLOOR=(\d+)$", re.MULTILINE)
# The first thing the script does that changes machine state — anything earlier is
# resolution and validation only.
_FIRST_MUTATION = "venya_install_python314"


def _installer_text() -> str:
    return _INSTALLER.read_text(encoding="utf-8")


def _bash_refusal() -> str:
    hits = _HEREDOC.findall(_installer_text())
    assert len(hits) == 1, (
        f"expected exactly one VENYA_DB_PASSPHRASE_FLOOR_REFUSAL heredoc in "
        f"install-venya-core.sh, found {len(hits)} — the #615 gate moved or was duplicated"
    )
    return hits[0]


class TestInstallerDbPassphraseFloorGate615:
    def test_bash_refusal_is_the_python_block_byte_for_byte(self):
        assert _bash_refusal() == short_passphrase_refusal("VENYA_DB_PASSPHRASE"), (
            "install-venya-core.sh re-embeds a refusal that no longer matches "
            "core.engine.backend.short_passphrase_refusal('VENYA_DB_PASSPHRASE') — "
            "the installer would tell an operator something the boot gate does not say"
        )

    def test_write_path_clause_is_kept(self):
        # The installer refuses before writing, so the write-path variant (with
        # "Nothing was written.") is the honest one; the read-path form drops it.
        assert " Nothing was written." in _bash_refusal()

    def test_bash_floor_literal_equals_the_core_constant(self):
        hits = _FLOOR.findall(_installer_text())
        assert len(hits) == 1, f"expected one DB_PASSPHRASE_FLOOR pin, found {len(hits)}"
        assert int(hits[0]) == MIN_PASSPHRASE_CODE_POINTS, (
            f"installer floor {hits[0]} vs core MIN_PASSPHRASE_CODE_POINTS "
            f"{MIN_PASSPHRASE_CODE_POINTS} — the two doors no longer measure the same thing"
        )

    def test_no_ceiling_door_was_invented(self):
        # Negative half: backend.py:76 and server/ca.py:101 state MAX 64 and never refuse
        # on it. The gate may only refuse BELOW the floor.
        gate = _installer_text().split("# --- #573 DB-KEK passphrase floor")[1].split("# --- Recovery-code pepper")[0]
        assert '-lt "$DB_PASSPHRASE_FLOOR"' in gate
        for banned in ("-gt", "-ge", "MAX_PASSPHRASE", "FLOOR_MAX", "64 ]"):
            assert banned not in gate, f"a ceiling comparison ({banned}) appeared in the gate"

    def test_gate_runs_before_the_first_mutation(self):
        text = _installer_text()
        gate_at = text.index("# --- #573 DB-KEK passphrase floor")
        mutate_at = text.index(_FIRST_MUTATION)
        assert gate_at < mutate_at, (
            "the floor gate was moved past the installer's first state change — a short "
            "passphrase would be written before it is refused (#615 is the pre-mutation claim)"
        )
