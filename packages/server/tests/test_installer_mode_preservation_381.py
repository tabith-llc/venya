# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Source-pin: core installer mode-preservation sites (#381, core half).

A truncating write (`>`, `cat >`, `sed >`, python write_bytes) over an
EXISTING file keeps the incumbent inode's mode — the entry `umask 077`
governs only CREATION. Physically proven independently (K30 vhost 0644 at
core-2/core-3 sweeps; unit-file class at executor X-rows). The fix shape
per the ticket: delete-then-create (`rm -f` immediately before each
managed-file write) plus an explicit mode pin at the PRESERVE sites.
Each cell pins the marker text AND the ordering half (rm strictly before
the write, chmod strictly after it) — a relocated or dropped hunk fails
even if a marker survives elsewhere.
Full design: installer-mode-preservation-381-propose-20261003.md §3.
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]


def _core() -> str:
    return (_ROOT / "install-venya-core.sh").read_text()


class TestCoreInstallerModePreservation381:
    def test_p1_vhost_rm_write_chmod_ordering(self):
        """P1: rm -f before the vhost heredoc, chmod 600 after EOF (K30)."""
        core = _core()
        rm = "rm -f /etc/nginx/sites-available/venya\n"
        w = "cat > /etc/nginx/sites-available/venya << EOF"
        pin = "chmod 600 /etc/nginx/sites-available/venya\n"
        assert rm in core and w in core and pin in core
        assert core.index(rm) < core.index(w) < core.index(pin)

    def test_p2_core_unit_rm_write_chmod_and_comment_fix(self):
        """P2: rm/chmod bracket the sed > unit install; stale 0644 comment gone."""
        core = _core()
        rm = 'rm -f "$SYSTEMD_DIR/venya-core.service"'
        w = '> "$SYSTEMD_DIR/venya-core.service"'
        pin = 'chmod 600 "$SYSTEMD_DIR/venya-core.service"'
        assert rm in core and pin in core
        assert core.index(rm) < core.index(w) < core.index(pin)
        assert "0644 root:root unit" not in core  # #381 comment fix pinned

    def test_w1_env_rm_before_write_block(self):
        """W1: the .env write block starts on a fresh inode (#317 window)."""
        core = _core()
        rm = 'rm -f "$INSTALL_DIR/.env"'
        assert rm in core
        assert core.index(rm) < core.index('} > "$INSTALL_DIR/.env"')

    def test_w2_core_env_rm_before_first_printf(self):
        """W2: venya-core.env gets a fresh inode before the passphrase print."""
        core = _core()
        rm = "rm -f /etc/venya/venya-core.env"
        assert rm in core
        assert core.index(rm) < core.index("> /etc/venya/venya-core.env")

    def test_w3_admin_pair_unlinked_before_write(self):
        """W3: embedded-python unlinks both admin files before write_bytes.

        Needle is the ESCAPED form — the block lives inside a `python -c "..."`
        string, so the file text carries backslash-quote literally.
        """
        core = _core()
        unlink_key = r"Path(\"$2/admin.key\").unlink(missing_ok=True)"
        unlink_crt = r"Path(\"$2/admin.crt\").unlink(missing_ok=True)"
        assert unlink_key in core and unlink_crt in core
        assert core.index(unlink_key) < core.index('Path(\\"$2/admin.key\\").write_bytes(key_pem)')
        assert core.index(unlink_crt) < core.index('Path(\\"$2/admin.crt\\").write_bytes(cert_pem)')
