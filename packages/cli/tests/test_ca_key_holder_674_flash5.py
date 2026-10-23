# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#674 — the split and restore custody paths hold unwrapped root-CA plaintext in a `SecretHolder`.

`venya admin export-ca-key` was given a holder by #538; `split-ca-key` and BOTH
arms of `restore-ca-key` (`shares`, `backup`) were left holding the same class of
material — the unwrapped root-CA private key as plaintext — in an ordinary local
`bytes` that nothing ever erased. This file pins the fix and nothing else.

**The claim is erasure, not residency.** `secret_holder.py` says so in its own
words: the copy the holder owns is zeroized on release, the pin is attempted and
reported and never fatal, and copies made by other code are NOT removed. So every
cell below asserts a lifetime fact this process controls — was the buffer erased
on this exit path — and no cell asserts that key material escaped the process or
that any particular byte pattern is absent from machine memory. That would be a
leak claim, and this row does not make one.

Truth table, both halves per path and per arm:

+--------------------------------------------------------+-----------------------------------------------+
| shape                                                  | expected                                      |
+--------------------------------------------------------+-----------------------------------------------+
| split, happy path                                      | one holder, released AND zeroized on exit;    |
|                                                        | shares still reconstruct the same key         |
| split, threshold > shares (refusal inside the window)  | rc=1, holder released+zeroized, NO share file |
| restore/shares, happy path                             | one holder, released+zeroized; at-rest key    |
|                                                        | still unwraps to the original                 |
| restore/shares, wrong SERVER passphrase                | rc=1, released+zeroized, incumbent byte-      |
|                                                        | identical                                     |
| restore/backup, happy path                             | same as the shares arm — the second arm is    |
|                                                        | not an afterthought                           |
| restore/backup, under-floor passphrase (refusal BEFORE | rc=1 and NO holder ever built — the gate      |
| the holder)                                            | still runs first                              |
| every path                                             | the holder, not a local `bytes`, is what is   |
|                                                        | handed to the consumers                       |
+--------------------------------------------------------+-----------------------------------------------+

Cells are behavioural (a recording subclass of the real holder), plus one
source-shape cell per path, because the regression here is "a future edit drops
the `with` and rebinds the local" — a behaviour-only suite would not name which
path went unmanaged.
"""

import inspect
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import patch

import pytest
from venya_cli.at_rest_key import rewrap_at_rest, unwrap_at_rest
from venya_cli.commands import (
    cmd_admin_export_ca_key,
    cmd_admin_restore_ca_key,
    cmd_admin_split_ca_key,
)
from venya_cli.secret_holder import SecretHolder

SERVER_PW = "srv-pw-674"  # pragma: allowlist secret — TEST passphrase, never real
OP_PW = "op-pw-674-operator"  # pragma: allowlist secret
UNDER_PW = "0123456789abcd"  # pragma: allowlist secret — 14 code points: below the #573 floor


@pytest.fixture(autouse=True)
def _operator_terminal(monkeypatch):
    """#593: both CA-key custody doors now refuse before prompting when stdin is not a TTY.
    The backup-arm prompt cells here are the operator-at-a-terminal path; the non-tty half
    of the truth table is test_ca_key_nontty_refusal_593_flash3.py. Shares-mode cells prompt
    nothing and are unaffected by this fixture either way."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)


def _real_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _encrypted_ca(tmp_path, passphrase=SERVER_PW):
    d = tmp_path / "ca"
    d.mkdir(parents=True, exist_ok=True)
    key = _real_key_pem()
    (d / "ca.key").write_bytes(rewrap_at_rest(key, passphrase))
    return d, key


def _split(ca_dir, out_dir, threshold=2, shares=3):
    return cmd_admin_split_ca_key(
        SimpleNamespace(ca_dir=str(ca_dir), output_dir=str(out_dir), threshold=threshold, shares=shares)
    )


def _restore_shares(ca_dir, paths):
    return cmd_admin_restore_ca_key(SimpleNamespace(mode="shares", shares=paths, backup_file=None, ca_dir=str(ca_dir)))


def _restore_backup(ca_dir, blob, op_pw=OP_PW):
    with patch("venya_cli.commands.getpass.getpass", side_effect=[op_pw]):
        return cmd_admin_restore_ca_key(
            SimpleNamespace(mode="backup", backup_file=str(blob), shares=None, ca_dir=str(ca_dir))
        )


def _export(ca_dir, out, op_pw=OP_PW):
    with patch("venya_cli.commands.getpass.getpass", side_effect=[op_pw, op_pw]):
        return cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca_dir)))


class _Recording(SecretHolder):
    """The REAL holder, with an instance ledger — so a cell can say whether the
    buffer was ever built at all, released, and observed zeroized.

    Deliberately a subclass, not a mock: a mock would let a cell pass on an object
    that never allocates, never pins and never erases, which is the one thing this
    row must not pretend to prove.
    """

    built: ClassVar[list[_Recording]] = []

    def __init__(self, data):
        super().__init__(data)
        _Recording.built.append(self)


@pytest.fixture
def record_holder(monkeypatch):
    """Swap `commands.SecretHolder` for the recording subclass, per cell."""
    _Recording.built = []
    monkeypatch.setattr("venya_cli.commands.SecretHolder", _Recording)
    return _Recording.built


@pytest.fixture(autouse=True)
def _server_passphrase_env(monkeypatch):
    """These custody paths read an AT-REST-ENCRYPTED ca.key, so unwrapping needs the
    server passphrase; supplied through the env door the product itself uses (the
    shape an unattended operator gets), and one cell overrides it with a wrong value.
    """
    monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", SERVER_PW)
    monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)


def _assert_erased(built: list, why: str) -> None:
    """The single assertion every half shares: it WAS managed, and it WAS erased."""
    assert built, f"{why}: no SecretHolder was ever built — the path is unmanaged again"
    for holder in built:
        assert holder.released, f"{why}: holder survived its command — nothing erased it"
        assert holder.zeroized, f"{why}: release did not observe the buffer zeroed"


class TestSplitIsManaged:
    """`cmd_admin_split_ca_key` — unwrapped root-CA plaintext, pre-shard."""

    def test_split_happy_path_builds_one_holder_and_erases_it(self, tmp_path, record_holder) -> None:
        ca, _key = _encrypted_ca(tmp_path)
        out = tmp_path / "shards"

        assert _split(ca, out) == 0
        _assert_erased(record_holder, "split")
        assert len(record_holder) == 1, "split built more than one holder — a second copy appeared"
        assert sorted(p.name for p in out.glob("share-*")) == ["share-01", "share-02", "share-03"]

    def test_split_shares_still_reconstruct_the_same_key(self, tmp_path, record_holder) -> None:
        """Zero behavioral change to the material itself: the holder moved the
        lifetime, not the bytes. Reconstruct and compare against the original."""
        ca, key = _encrypted_ca(tmp_path)
        out = tmp_path / "shards"
        assert _split(ca, out) == 0

        paths = [str(p) for p in sorted(out.glob("share-*"))[:2]]
        assert _restore_shares(ca, paths) == 0
        assert unwrap_at_rest((ca / "ca.key").read_bytes(), SERVER_PW) == key

    def test_split_refusal_inside_the_window_still_erases(self, tmp_path, record_holder) -> None:
        """Paired negative: `threshold > shares` is refused AFTER the holder exists.
        The `with` must still erase on that exit, and no shard may be written."""
        ca, _key = _encrypted_ca(tmp_path)
        out = tmp_path / "shards"

        assert _split(ca, out, threshold=4, shares=3) == 1
        _assert_erased(record_holder, "the split threshold refusal")
        assert not out.exists(), "a refused split created the output directory"

    def test_split_hands_the_holder_to_the_splitter_not_a_local(self, record_holder) -> None:
        """Source shape, the cell that names the regression: if a future edit drops
        the `with` and rebinds `plaintext_key`, the consumer is fed a bare local and
        the holder guards nothing."""
        src = inspect.getsource(cmd_admin_split_ca_key)
        assert "with SecretHolder(plaintext_key)" in src
        assert "split(key_material" in src, "the splitter is no longer fed the holder's view"
        assert "split(plaintext_key" not in src, "the unmanaged local is back on the consumer line"


class TestRestoreSharesArmIsManaged:
    """`cmd_admin_restore_ca_key`, arm 1 of 2 — `mode="shares"`."""

    def _restore_ok(self, tmp_path, record_holder):
        ca, key = _encrypted_ca(tmp_path)
        out = tmp_path / "shards"
        assert _split(ca, out) == 0
        (ca / "ca.key").write_bytes(rewrap_at_rest(key, SERVER_PW))  # incumbent, keeps its envelope
        before = (ca / "ca.key").read_bytes()
        record_holder.clear()  # forget the split cell's holder; this assert is about restore

        paths = [str(p) for p in sorted(out.glob("share-*"))[:2]]
        rc = _restore_shares(ca, paths)
        return rc, ca, key, before, paths

    def test_restore_shares_builds_a_holder_and_erases_it(self, tmp_path, record_holder) -> None:
        rc, _ca, _key, _before, _paths = self._restore_ok(tmp_path, record_holder)
        assert rc == 0
        _assert_erased(record_holder, "restore/shares")

    def test_restore_shares_wrong_server_passphrase_refuses_and_erases(
        self, tmp_path, record_holder, monkeypatch
    ) -> None:
        """Paired negative: the incumbent at-rest key needs SERVER_PW; the cell hands
        it a wrong one through the env door `restore_at_rest_bytes` probes. The refusal
        lands INSIDE the holder window, so erase-on-exit is the thing under test, and
        the incumbent must keep its bytes."""
        rc, ca, _key, _before, paths = self._restore_ok(tmp_path, record_holder)
        assert rc == 0
        record_holder.clear()
        # Snapshot AFTER the successful restore above — the incumbent this refusal
        # must not touch is the envelope that restore just wrote, not the fixture.
        incumbent = (ca / "ca.key").read_bytes()
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "totally-wrong-674")

        # The env door carries a WRONG value and stdin is not a TTY, so
        # acquire_server_passphrase hands it over and the probe against the
        # incumbent refuses by name — no owner prompt, no silent pass-through.
        monkeypatch.setenv("VENYA_CA_KEY_PASSPHRASE", "totally-wrong-674")
        got = _restore_shares(ca, paths)
        assert got == 1, "a wrong server passphrase wrote over the incumbent key"
        _assert_erased(record_holder, "the restore/shares wrong-passphrase refusal")
        assert (ca / "ca.key").read_bytes() == incumbent, "a refusal changed the incumbent at-rest key"

    def test_restore_shares_source_shape_still_routes_through_the_holder(self) -> None:
        src = inspect.getsource(cmd_admin_restore_ca_key)
        assert "with SecretHolder(reconstructed)" in src
        assert "restore_at_rest_bytes(ca_key_path, validated)" in src
        assert "restore_at_rest_bytes(ca_key_path, reconstructed)" not in src, "the bare local is back"


class TestRestoreBackupArmIsManaged:
    """`cmd_admin_restore_ca_key`, arm 2 of 2 — `mode="backup"`.

    AC2 names both arms, so a fix that routed only the shares arm would leave this
    command "closed" with one whole path still unmanaged.
    """

    def _blob(self, tmp_path, ca):
        out = tmp_path / "b.enc"
        assert _export(ca, out) == 0
        return out

    def test_restore_backup_builds_a_holder_and_erases_it(self, tmp_path, record_holder) -> None:
        ca, key = _encrypted_ca(tmp_path)
        blob = self._blob(tmp_path, ca)
        record_holder.clear()  # the export path's holder is #538's, not this arm's

        assert _restore_backup(ca, blob) == 0
        _assert_erased(record_holder, "restore/backup")
        assert unwrap_at_rest((ca / "ca.key").read_bytes(), SERVER_PW) == key

    def test_restore_backup_under_floor_passphrase_refuses_before_any_holder(self, tmp_path, record_holder) -> None:
        """Paired negative, and the ORDER is the point: #573's read door runs ahead of
        the custody window, so an under-floor passphrase unseals nothing and builds
        nothing. Asserting "no holder was built" here is asserting the gate still
        fires first — not an erase claim."""
        ca, _key = _encrypted_ca(tmp_path)
        blob = self._blob(tmp_path, ca)
        record_holder.clear()

        assert _restore_backup(ca, blob, op_pw=UNDER_PW) == 1
        assert record_holder == [], "an under-floor passphrase reached the custody window"

    def test_restore_backup_source_shape_is_the_same_holder_as_the_shares_arm(self) -> None:
        """One holder for both arms — the second-convention failure #565 ruled out."""
        src = inspect.getsource(cmd_admin_restore_ca_key)
        assert src.count("with SecretHolder(") == 1, "the two arms grew parallel holders"
        assert "class " not in src  # no local holder type invented in this function
