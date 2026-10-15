# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Source-pin: executor installer mode-preservation sites (#381, executor half).

Same incumbent-inode class as the core half (X13/X14/X15 unit files +
venya-executor.seccomp 0644 physically observed, flash4 LEG-3 sweep, lead
live spot-check). Fix shape per the ticket: rm-then-create + explicit chmod
at the cat > sites; the three cp unit installs become install -m 0600
(unlink+create with the mode pinned); the bootstrap-token write gets a
fresh inode INSIDE the CA/token guard, leaving the #380 unconditional dir
pin untouched above it. Design: installer-mode-preservation-381-propose-20261003.md §3.
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]


def _executor() -> str:
    return (_ROOT / "install-venya-executor.sh").read_text()


class TestExecutorInstallerModePreservation381:
    def test_p3_sandboxd_rm_write_chmod_ordering(self):
        """P3: rm before the sandboxd unit heredoc, chmod after its close."""
        ex = _executor()
        rm = "rm -f /etc/systemd/system/venya-sandboxd.service\n"
        w = "cat > /etc/systemd/system/venya-sandboxd.service <<'SANDBOXD_UNIT'"
        pin = "chmod 600 /etc/systemd/system/venya-sandboxd.service\n"
        assert rm in ex and w in ex and pin in ex
        assert ex.index(rm) < ex.index(w) < ex.index(pin)

    def test_p4_dropin_rm_write_chmod_ordering(self):
        """P4: rm before the ordering drop-in heredoc, chmod after its close."""
        ex = _executor()
        rm = "rm -f /etc/systemd/system/venya-executor.service.d/10-sandboxd.conf\n"
        w = "cat > /etc/systemd/system/venya-executor.service.d/10-sandboxd.conf <<'DROPIN'"
        pin = "chmod 600 /etc/systemd/system/venya-executor.service.d/10-sandboxd.conf\n"
        assert rm in ex and w in ex and pin in ex
        assert ex.index(rm) < ex.index(w) < ex.index(pin)

    def test_p5_unit_files_install_m_replaces_cp(self):
        """P5: all three unit files land via install -m 0600; no cp revival."""
        ex = _executor()
        for name in ("venya-executor.service", "tmp-venya_secrets.mount", "venya-executor.seccomp"):
            assert f'install -m 0600 "$INSTALL_DIR/systemd/{name}" "$SYSTEMD_DIR/"' in ex
        assert 'cp "$INSTALL_DIR/systemd/' not in ex

    def test_w4_bootstrap_token_fresh_inode_inside_guard(self):
        """W4: rm precedes the token write, both inside the CA/token guard;
        the #380 unconditional dir pin stays OUTSIDE and above the guard."""
        ex = _executor()
        guard = 'if [ -n "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" ] && [ "$CA_INSTALLED" != true ]; then'
        rm = "rm -f /var/lib/venya/executor/bootstrap-token"
        w = "> /var/lib/venya/executor/bootstrap-token"
        pin380 = "install -d -m 0750 -o venya -g venya /var/lib/venya/executor"
        assert guard in ex and rm in ex
        assert ex.index(pin380) < ex.index(guard)  # #380 boundary preserved
        assert ex.index(guard) < ex.index(rm) < ex.index(w)
        assert ex.count(pin380) == 1
