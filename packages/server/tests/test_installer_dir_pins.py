# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Source-pin tripwire for ticket installer-umask077-mkdir-parents-block-traversal (#358).

The entry `umask 077` (#317 batch) makes root `mkdir -p` create parent chains
0700 root:root; later `sudo -u venya` children cannot traverse them. Physically
proven 2026-10-02: a fresh core install aborted at the Python-3.14 step
(/opt/venya 0700 root, uv os error 13). Truth table per the rule: the pin must
be present AND the bare `mkdir -p` sink must be gone (the negative half — a
re-introduced bare mkdir fails this test even if a pin is kept elsewhere).
"""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]


def _script(name: str) -> str:
    return (_ROOT / name).read_text()


class TestInstallerDirPins:
    def test_python314_uv_tree_pinned(self):
        """venya_install_python314: pinned chain, no bare mkdir -p sink."""
        common = _script("venya-common.sh")
        assert (
            'install -d -m 0750 -g venya "$INSTALL_DIR" "$INSTALL_DIR/.local"'
            ' "$INSTALL_DIR/.local/share" "$INSTALL_DIR/.local/share/uv"' in common
        )
        assert 'install -d -m 0770 -o venya -g venya "$INSTALL_DIR/.local/share/uv/python"' in common
        assert 'mkdir -p "$INSTALL_DIR/.local/share/uv/python"' not in common

    def test_admin_ca_block_pinned(self):
        """Core admin-CA/cert dirs: traversed parents pinned, bare mkdir gone."""
        core = _script("install-venya-core.sh")
        assert 'mkdir -p "$ADMIN_CA_DIR"' not in core
        assert 'mkdir -p "$ADMIN_CERT_DIR"' not in core
        assert "install -d -m 0750 -g venya /var/lib/venya /var/lib/venya/ca" in core
        assert 'install -d -m 0770 -o venya -g venya "$ADMIN_CA_DIR"' in core
        assert "install -d -m 0750 -g venya /etc/venya" in core
        assert 'install -d -m 0770 -o venya -g venya "$ADMIN_CERT_DIR"' in core

    def test_sbx_state_tree_pinned(self):
        """Executor sbx state dir: parents venya must traverse, leaf is venya-owned."""
        executor = _script("install-venya-executor.sh")
        assert "mkdir -p /home/venya/.local/share/sandboxes" not in executor
        assert "install -d -m 0750 -g venya /home/venya/.local /home/venya/.local/share" in executor
        assert "install -d -m 0770 -o venya -g venya /home/venya/.local/share/sandboxes" in executor

    def test_executor_daemon_dir_pin_unconditional(self):
        """#380: the /var/lib/venya/executor pin lives OUTSIDE the CA/token guard."""
        src = _script("install-venya-executor.sh")
        pin = "install -d -m 0750 -o venya -g venya /var/lib/venya/executor"
        guard = 'if [ -n "${VENYA_EXECUTOR_ENROLLMENT_TOKEN:-}" ] && [ "$CA_INSTALLED" != true ]; then'
        assert src.count(pin) == 1  # single source of truth
        guard_at = src.index(guard)
        guard_end = guard_at + src[guard_at:].index("\nfi")
        assert pin not in src[guard_at:guard_end]  # negative half: not re-nestable
        assert src.index(pin) < guard_at  # positive: unconditional, precedes guard
