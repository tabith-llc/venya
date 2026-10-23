# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#610 paired negative: the ADMIN_CERT_DIR pin must land 0700 on EVERY run.

Same mechanism as #606 (which tightened $ADMIN_CA_DIR, the sibling pin one line
above): `install -d -m` RE-APPLIES its mode to an EXISTING directory on every
invocation, and /etc/venya/admin has no product-side re-narrowing at all — so a
group bit in this pin is the steady state after every installer run, over the
directory holding the machine-plane admin key (admin.key, minted in the same
block). Files keep their own 0644/0600 pins; the DIR is the row.

Two halves per the truth-table rule, shape carried from
test_installer_ca_dir_mode_606.py:
- source-pin: exactly one `install -d ... "$ADMIN_CERT_DIR"` line, digit 0700;
- functional: a real coreutils `install -d` replay of the pin digit over a
  hand-widened 0770 dir must pull it back to 0700 — the digit parsed from the
  installer source IS the mechanism; identity flags (-o/-g venya) are dropped
  because the test runs unprivileged.
"""

import re
import stat
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]

_PIN = re.compile(
    r'^[ \t]*install -d -m (\d{3,4})(?: -o venya -g venya)? "\$ADMIN_CERT_DIR"[ \t]*$',
    re.MULTILINE,
)


def _pin_mode() -> str:
    hits = _PIN.findall((_ROOT / "install-venya-core.sh").read_text())
    assert len(hits) == 1, f"expected exactly one ADMIN_CERT_DIR install -d pin, found {len(hits)}"
    return hits[0]


class TestAdminCertDirMode610:
    def test_admin_cert_dir_pin_is_0700(self):
        mode = _pin_mode()
        assert mode == "0700", (
            f"the $ADMIN_CERT_DIR leaf pins mode {mode}: install -d re-applies that mode "
            "on EVERY invocation and nothing re-narrows /etc/venya/admin afterwards — a "
            "group bit here is the #610 re-widening over the machine-plane admin key dir "
            "(same mechanism as #606, which tightened $ADMIN_CA_DIR)"
        )

    def test_rerun_reapplies_the_pin_over_a_widened_dir(self, tmp_path):
        mode = _pin_mode()
        target = tmp_path / "admin"
        target.mkdir()
        target.chmod(0o770)  # what the pre-#610 pin left after every run
        subprocess.run(["install", "-d", "-m", mode, str(target)], check=True)
        final = stat.S_IMODE(target.stat().st_mode)
        assert final == 0o700, (
            f"the {mode} pin left a hand-widened 0770 dir at {oct(final)} — the guard "
            "is inert and a re-run keeps /etc/venya/admin wider than 0700"
        )
