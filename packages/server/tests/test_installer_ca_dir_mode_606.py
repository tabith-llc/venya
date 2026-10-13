# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#606 paired negative: the admin CA dir pin must land 0700 on EVERY installer
invocation, not only the first.

docs/BACKUPS.md §2 item 4 promises the CA material under /var/lib/venya/ca/ at
mode 0700. `install -d -m` RE-APPLIES its mode to an EXISTING directory on every
run, so the leaf pin's digit — not the fresh-creation tightening — is what a
re-run leaves behind: AdminCAManager.initialize (server/ca.py, chmod 0o700) is
skipped on the has-CA-preserved path. Before #606 the pin was 0770, so every
re-run re-widened admin-ca past the documented promise.

Two halves per the truth-table rule:
- positive: the single ADMIN_CA_DIR pin reads 0700, and the failure text names
  the re-run mechanism if it does not;
- functional: a real coreutils `install -d` replay of that pin over a hand-
  widened 0770 dir must pull it back to 0700 — proving the pin is the guard,
  not a decoration. This runs the same `install` the installer uses with the
  digit parsed out of the installer source, so it is not weaker than the text
  assertion; the identity flags (-o/-g venya) are dropped because the test runs
  unprivileged and the mode digit is the whole mechanism under test.
"""

import re
import stat
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]

_PIN = re.compile(
    r'^[ \t]*install -d -m (\d{3,4})(?: -o venya -g venya)? "\$ADMIN_CA_DIR"[ \t]*$',
    re.MULTILINE,
)


def _pin_mode() -> str:
    hits = _PIN.findall((_ROOT / "install-venya-core.sh").read_text())
    assert len(hits) == 1, f"expected exactly one ADMIN_CA_DIR install -d pin, found {len(hits)}"
    return hits[0]


class TestAdminCaDirMode606:
    def test_admin_ca_dir_pin_is_the_doc_promise_0700(self):
        mode = _pin_mode()
        assert mode == "0700", (
            f"the $ADMIN_CA_DIR leaf pins mode {mode}: install -d re-applies that mode "
            "on EVERY invocation, and the re-run path skips AdminCAManager.initialize's "
            "0700 (CA preserved) — so a group bit here IS the #606 re-widening "
            "(docs/BACKUPS.md §2 item 4 promises 0700)"
        )

    def test_rerun_reapplies_the_pin_over_a_widened_dir(self, tmp_path):
        mode = _pin_mode()
        target = tmp_path / "admin-ca"
        target.mkdir()
        target.chmod(0o770)  # the state the pre-#606 pin left after any re-run
        subprocess.run(["install", "-d", "-m", mode, str(target)], check=True)
        final = stat.S_IMODE(target.stat().st_mode)
        assert final == 0o700, (
            f"the {mode} pin left a hand-widened 0770 dir at {oct(final)} — the "
            "guard is inert and a re-run keeps admin-ca wider than BACKUPS.md promises"
        )
