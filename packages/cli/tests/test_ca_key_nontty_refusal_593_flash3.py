# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#593 — the CA-key custody doors refuse BEFORE prompting when stdin is not a TTY.

The defect: `cmd_admin_export_ca_key` and `cmd_admin_restore_ca_key` (backup arm) read the
CA-key passphrase with `getpass` and no tty guard, so a piped/CI invocation falls into getpass's
echo-uncontrolled fallback and the CLI itself announces "Warning: Password input may be
echoed." before reading a root-CA sealing passphrase from a stream it does not control.
The fix ships the blessed shape from the two sibling doors (at_rest_key.acquire_server_passphrase,
executor_key.acquire_write_passphrase): a NAMED refusal before any getpass call, no new argv/env
input surface (#593 AC4 — a value there is visible to `ps`, shell history and logs).

Truth table, both halves (the project's paired-negative law):
- NON-TTY: named refusal, rc 1, `getpass` NEVER called — so the fallback warning cannot be
  emitted — and zero bytes written (no output file, no staged temp, incumbent key untouched).
- TTY: both doors prompt exactly as before and still succeed.
- SHARES-mode restore prompts nothing and must keep running headless (guard is backup-arm only;
  test_shamir_threshold.py::TestRestoreHandler carries the same truth at base, green with the
  guard in place — pinned here too as a first-class cell).

AC5 limitation, stated so the row close carries it: the owner-present PHYSICAL tty cell is
barred in this leg. Every "tty" cell here is library+source level (faked `isatty` and a patched
`getpass`), plus one subprocess cell driving the real stream with `stdin=DEVNULL`. The claim
"at a real terminal the doors still prompt unchanged" stands at that level until the owner runs
the physical cell.
"""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


def _boom(*_a, **_k):
    raise AssertionError("getpass was reached — the #593 guard must refuse BEFORE any prompt")


def _nontty(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)


def _tty(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)


def _real_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _plaintext_ca(tmp_path):
    """A plaintext-at-rest CA dir: the doors' only earlier I/O is reading this key,
    and no server-passphrase prompt (unwrap passthrough) stands between entry and gate."""
    d = tmp_path / "ca"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ca.key").write_bytes(_real_key_pem())
    return d


PW = "prompt-round-trip-passphrase-593"  # >= MIN_PASSPHRASE_CODE_POINTS, never echoed anywhere


class TestExportDoorRefusesOffTerminal:
    def test_refusal_before_any_getpass_and_no_echo_warning(self, tmp_path, monkeypatch, capsys):
        from venya_cli.commands import cmd_admin_export_ca_key

        ca = _plaintext_ca(tmp_path)
        out = tmp_path / "export" / "ca.key.enc"
        _nontty(monkeypatch)
        with patch("venya_cli.commands.getpass.getpass", side_effect=_boom) as gp:
            rc = cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca)))
        err = capsys.readouterr().err
        assert rc == 1
        assert gp.call_count == 0, "the door prompted before the guard could refuse"
        assert "REFUSED:" in err
        assert "stdin is not a TTY" in err
        # The load-bearing half of AC1: the getpass fallback warning text can never appear.
        assert "may be echoed" not in err
        assert "GetPassWarning" not in err

    def test_zero_bytes_written_and_incumbent_key_untouched(self, tmp_path, monkeypatch, capsys):
        from venya_cli.commands import cmd_admin_export_ca_key

        ca = _plaintext_ca(tmp_path)
        before = (ca / "ca.key").read_bytes()
        out = tmp_path / "export" / "ca.key.enc"
        _nontty(monkeypatch)
        with patch("venya_cli.commands.getpass.getpass", side_effect=_boom):
            rc = cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca)))
        assert rc == 1
        assert not out.exists()
        assert not out.parent.exists(), "the staged directory is created only after the prompts"
        assert not list(tmp_path.glob(".venya-cabackup-*")), "no orphaned staged temp"
        assert (ca / "ca.key").read_bytes() == before, "the refusal must not touch the CA key"

    def test_refusal_names_the_export_door_and_carries_no_value(self, tmp_path, monkeypatch, capsys):
        """AC6: the refusal is a constant string — it names the door and the condition, and it
        cannot carry a value because this path reads no input at all."""
        from venya_cli.commands import cmd_admin_export_ca_key

        ca = _plaintext_ca(tmp_path)
        _nontty(monkeypatch)
        with patch("venya_cli.commands.getpass.getpass", side_effect=_boom):
            cmd_admin_export_ca_key(SimpleNamespace(output=str(tmp_path / "o.enc"), ca_dir=str(ca)))
        err = capsys.readouterr().err
        assert "export passphrase" in err
        assert PW not in err  # nothing was read; nothing can leak

    def test_subprocess_devnull_refuses_without_the_echo_warning(self, tmp_path):
        """The real stream, not a mock: run the shipped script with stdin=/dev/null and prove
        the refusal path emits the named REFUSED and NEVER the fallback warning line."""
        script = Path(sys.executable).parent / "venya"
        if not script.is_file():
            pytest.skip("venya script not on this interpreter's bin dir — library-level coverage stands")
        ca = _plaintext_ca(tmp_path)
        out = tmp_path / "o.enc"
        env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "XDG_CONFIG_HOME": str(tmp_path / ".config")}
        proc = subprocess.run(
            # nosec B603 — fixed argv, no shell, our own venv interpreter's script;
            # check=False because the return code itself is what the cell asserts.
            [str(script), "admin", "export-ca-key", "--ca-dir", str(ca), "--output", str(out)],
            input=b"",
            capture_output=True,
            env=env,
            timeout=60,
            cwd=str(tmp_path),
            check=False,
        )
        err = proc.stderr.decode()
        assert proc.returncode == 1
        assert "REFUSED:" in err, f"expected the named refusal, got: {err[:200]}"
        assert "may be echoed" not in err
        assert "GetPassWarning" not in err
        assert not out.exists()


class TestRestoreBackupDoorRefusesOffTerminal:
    def _restore_args(self, ca, blob):
        return SimpleNamespace(mode="backup", backup_file=str(blob), shares=None, ca_dir=str(ca))

    def test_refusal_before_any_getpass_and_no_echo_warning(self, tmp_path, monkeypatch, capsys):
        from venya_cli.commands import cmd_admin_restore_ca_key

        ca = _plaintext_ca(tmp_path)
        blob = tmp_path / "backup.enc"
        blob.write_bytes(b"not a real VENYACA1 blob - the guard must fire before it is read")
        _nontty(monkeypatch)
        with patch("venya_cli.commands.getpass.getpass", side_effect=_boom) as gp:
            rc = cmd_admin_restore_ca_key(self._restore_args(ca, blob))
        err = capsys.readouterr().err
        assert rc == 1
        assert gp.call_count == 0, "the door prompted before the guard could refuse"
        assert "REFUSED:" in err
        assert "backup passphrase" in err
        assert "may be echoed" not in err
        assert "GetPassWarning" not in err

    def test_incumbent_key_untouched_and_nothing_decrypted(self, tmp_path, monkeypatch):
        from venya_cli.commands import cmd_admin_restore_ca_key

        ca = _plaintext_ca(tmp_path)
        before = (ca / "ca.key").read_bytes()
        blob = tmp_path / "backup.enc"
        blob.write_bytes(b"\x00garbage")
        _nontty(monkeypatch)
        with patch("venya_cli.commands.getpass.getpass", side_effect=_boom):
            rc = cmd_admin_restore_ca_key(self._restore_args(ca, blob))
        assert rc == 1
        assert (ca / "ca.key").read_bytes() == before, "the refusal must not touch the incumbent key"
        assert not list(ca.glob(".venya-*.tmp*")), "no staged write left behind"

    def test_usage_errors_keep_their_precedence(self, tmp_path, monkeypatch, capsys):
        """The guard sits after the --backup-file usage/existence checks, not at function entry:
        a missing flag still reports the missing flag off a tty."""
        from venya_cli.commands import cmd_admin_restore_ca_key

        ca = _plaintext_ca(tmp_path)
        _nontty(monkeypatch)
        rc = cmd_admin_restore_ca_key(SimpleNamespace(mode="backup", backup_file=None, shares=None, ca_dir=str(ca)))
        err = capsys.readouterr().err
        assert rc == 1
        assert "--backup-file required" in err, "the tty guard widened over the usage-error precedence"


class TestTtyPathStillPrompts:
    """AC2's paired negative, asserted directly: with a terminal, the refusal does NOT fire and
    both doors prompt and succeed exactly as before."""

    def test_export_prompts_and_writes_with_a_tty(self, tmp_path, monkeypatch):
        from venya_cli.commands import cmd_admin_export_ca_key

        ca = _plaintext_ca(tmp_path)
        out = tmp_path / "o.enc"
        _tty(monkeypatch)
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", return_value=PW) as gp:
            rc = cmd_admin_export_ca_key(SimpleNamespace(output=str(out), ca_dir=str(ca)))
        assert rc == 0
        assert gp.call_count == 2, "prompt + confirm, both hidden, both still reached on a tty"
        assert out.exists()
        assert out.stat().st_mode & 0o777 == 0o600

    def test_restore_round_trip_prompts_and_succeeds_with_a_tty(self, tmp_path, monkeypatch):
        from venya_cli.commands import cmd_admin_export_ca_key, cmd_admin_restore_ca_key

        ca = _plaintext_ca(tmp_path)
        key_before = (ca / "ca.key").read_bytes()
        blob = tmp_path / "b.enc"
        _tty(monkeypatch)
        with patch("venya_cli.commands.getpass.getpass", return_value=PW):
            assert cmd_admin_export_ca_key(SimpleNamespace(output=str(blob), ca_dir=str(ca))) == 0
        with patch("venya_cli.commands.getpass.getpass", return_value=PW):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(blob), shares=None, ca_dir=str(ca))
            )
        assert rc == 0
        assert (ca / "ca.key").read_bytes() == key_before, "round trip must return the same key bytes"


class TestSharesArmStaysHeadless:
    def test_shares_restore_runs_off_a_terminal(self, tmp_path, monkeypatch):
        """The guard belongs to the BACKUP arm only. Shares mode prompts nothing today and
        must keep working in CI — this is the paired negative against guard over-widening."""
        from venya_cli.commands import cmd_admin_restore_ca_key
        from venya_cli.shamir import split

        secret = _real_key_pem()
        shares = split(secret, threshold=2, shares=3)
        ca_dir = tmp_path / "restored-ca"
        ca_dir.mkdir()
        paths = []
        for s in (shares[0], shares[2]):
            p = tmp_path / f"share-{s[0]:02d}"
            p.write_bytes(s[1:])
            paths.append(str(p))
        _nontty(monkeypatch)
        rc = cmd_admin_restore_ca_key(
            SimpleNamespace(mode="shares", shares=paths, backup_file=None, ca_dir=str(ca_dir))
        )
        assert rc == 0, "the #593 guard spilled into shares mode — it prompts nothing"
        assert (ca_dir / "ca.key").read_bytes() == secret
