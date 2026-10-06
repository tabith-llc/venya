# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#499 ca-key-write-umask-window — create-time mode cells for both CA keywriters.

``CAManager.initialize`` / ``AdminCAManager.initialize`` used ``Path.write_bytes``
(mode ``0666 & ~umask`` at create) and pinned 0600 only in the chmod that lands
AFTER the full key body is on disk. The parent dir's 0700 pin bounds the exposure
(the LOW severity in the ticket), but the product idiom for secret writes is
create-time mode — ``os.open(path, O_WRONLY|O_CREAT|O_TRUNC, 0o600)``
(sbx_strategy.py's env-file write). The umask can only CLEAR bits, so a file
created with ``0o600`` is never observable wider than 0600 under any umask.

Cells observe the mode at the earliest point a file object exists: an ``os.open``
spy fstats the new fd immediately after the real call. RED at HEAD under umask
0o022 because the key then arrives via ``write_bytes`` (no ``os.open`` record for
the key path at all).
"""

import os
import stat

import pytest
from server.ca import AdminCAManager, CAManager

_PERMISSIVE_UMASK = 0o022


@pytest.fixture
def permissive_umask():
    """Process umask 0o022 for the duration of the test, restored after."""
    old = os.umask(_PERMISSIVE_UMASK)
    try:
        yield
    finally:
        os.umask(old)


@pytest.fixture
def no_passphrases(monkeypatch):
    """Worst case per the ticket body: unset passphrase envs -> unencrypted PEM."""
    monkeypatch.delenv("VENYA_CA_KEY_PASSPHRASE", raising=False)
    monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)


def _watch_open_modes(monkeypatch) -> dict:
    """Record st_mode for every path created through os.open, right after create."""
    seen: dict = {}
    real_open = os.open

    def spy(path, flags, mode=0o777, *args, **kwargs):
        fd = real_open(path, flags, mode, *args, **kwargs)
        try:
            key = os.fsdecode(os.fspath(path))
        except TypeError:
            return fd  # fd-relative open — nothing to record
        if key not in seen:
            seen[key] = stat.S_IMODE(os.fstat(fd).st_mode)
        return fd

    monkeypatch.setattr(os, "open", spy)
    return seen


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


class TestCaKeyWriteModeWindow499:
    def test_ac1_root_ca_key_never_created_wide(self, tmp_path, monkeypatch, permissive_umask, no_passphrases):
        """AC1 (RED at HEAD): under umask 0o022 the root CA key's create-time mode
        is 0600 — no group/world-readable window between create and chmod."""
        seen = _watch_open_modes(monkeypatch)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        assert str(manager.ca_key_path) in seen, "CA key not created via os.open — write window restored"
        assert seen[str(manager.ca_key_path)] == 0o600
        assert _mode(manager.ca_key_path) == 0o600

    def test_ac2_admin_ca_key_never_created_wide(self, tmp_path, monkeypatch, permissive_umask, no_passphrases):
        """AC2 (RED at HEAD): same create-time guarantee for the admin CA key."""
        seen = _watch_open_modes(monkeypatch)
        manager = AdminCAManager(tmp_path / "admin-ca")
        manager.initialize()
        assert str(manager.ca_key_path) in seen, "admin CA key not created via os.open — write window restored"
        assert seen[str(manager.ca_key_path)] == 0o600
        assert _mode(manager.ca_key_path) == 0o600

    def test_ac3_incumbent_key_not_widened_by_reinit(self, tmp_path, permissive_umask, no_passphrases):
        """AC3 paired negative: a re-initialize that lands on an existing key inode
        (cert removed) leaves the incumbent mode at 0600 and the dir pin at 0700.
        O_CREAT's mode argument applies only to NEW files; the 0600 chmod pin
        still lands, so nothing is widened."""
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        assert _mode(manager.ca_key_path) == 0o600
        manager.ca_cert_path.unlink()  # partial state: initialize() proceeds

        retry = CAManager(str(tmp_path / "ca"))
        retry.initialize()
        assert _mode(retry.ca_key_path) == 0o600, "incumbent key was widened"
        assert _mode(retry.ca_dir) == 0o700, "CA directory pin changed"

    def test_reinit_with_full_ca_raises_and_touches_nothing(self, tmp_path, permissive_umask, no_passphrases):
        """Existence guard intact under both managers: a full re-run raises before
        any write; bytes and modes are untouched. (AdminCAManager raises
        RuntimeError; CAManager raises CAExistsError, a RuntimeError subclass.)"""
        for manager in (
            CAManager(str(tmp_path / "ca")),
            AdminCAManager(tmp_path / "admin-ca"),
        ):
            manager.initialize()
            snapshot = {
                "key_bytes": manager.ca_key_path.read_bytes(),
                "key_mode": _mode(manager.ca_key_path),
                "cert_bytes": manager.ca_cert_path.read_bytes(),
            }
            with pytest.raises(RuntimeError):
                manager.initialize()
            assert manager.ca_key_path.read_bytes() == snapshot["key_bytes"]
            assert _mode(manager.ca_key_path) == snapshot["key_mode"]
            assert manager.ca_cert_path.read_bytes() == snapshot["cert_bytes"]

    def test_final_states_pinned_under_permissive_umask(self, tmp_path, permissive_umask, no_passphrases):
        """Final-state regression pin (also passes at HEAD — that is its point):
        key 0600, cert 0644, CA dir 0700, for BOTH managers."""
        root = CAManager(str(tmp_path / "ca"))
        root.initialize()
        assert _mode(root.ca_key_path) == 0o600
        assert _mode(root.ca_cert_path) == 0o644
        assert _mode(root.ca_dir) == 0o700

        admin = AdminCAManager(tmp_path / "admin-ca")
        admin.initialize()
        assert _mode(admin.ca_key_path) == 0o600
        assert _mode(admin.ca_cert_path) == 0o644
        assert _mode(admin.ca_path) == 0o700

    def test_encrypted_payload_still_round_trips(self, tmp_path, monkeypatch, permissive_umask):
        """The idiom swap must not disturb encryption: with the passphrase env
        set, the key lands encrypted and loads with that passphrase."""
        from cryptography.hazmat.primitives import serialization

        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "test-ca-passphrase-499")
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        assert b"ENCRYPTED PRIVATE KEY" in manager.ca_key_path.read_bytes()
        key = serialization.load_pem_private_key(
            manager.ca_key_path.read_bytes(),
            password=b"test-ca-passphrase-499",
        )
        assert key is not None
