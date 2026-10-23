# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression for ticket export-ca-key-echoed-passphrase.

The CA-key export/restore passphrase prompts used echoed input() — the
passphrase protecting the exported (encrypted) CA private key was typed in
cleartext. Fixed to getpass. These tests booby-trap builtins.input: if any
secret-material prompt regresses to echoed input, the test fails loudly.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from venya_cli.commands import cmd_admin_export_ca_key, cmd_admin_restore_ca_key


@pytest.fixture(autouse=True)
def _operator_terminal(monkeypatch):
    """#593: both CA-key custody doors now refuse before prompting when stdin is not a TTY.
    Every cell in this file is the operator-at-a-terminal path, so the tty is faked here;
    the non-tty half of the truth table is test_ca_key_nontty_refusal_593_flash3.py."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)


def _boom(*_a, **_k):
    raise AssertionError("secret-material prompt regressed to echoed input()")


def _real_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


class TestCaKeyPromptsHidden:
    def test_export_uses_getpass_and_encrypts(self, tmp_path):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        key = _real_key_pem()
        (ca_dir / "ca.key").write_bytes(key)
        out = tmp_path / "export" / "ca.key.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch(
            "venya_cli.commands.getpass.getpass", side_effect=["s3cret-prompt-passphrase", "s3cret-prompt-passphrase"]
        ) as gp:
            rc = cmd_admin_export_ca_key(args)
        assert rc == 0
        assert gp.call_count == 2  # prompt + confirm, both hidden
        data = out.read_bytes()
        assert key not in data  # actually encrypted
        assert out.stat().st_mode & 0o777 == 0o600

    def test_export_mismatch_reprompts(self, tmp_path):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(_real_key_pem())
        args = SimpleNamespace(output=str(tmp_path / "o.enc"), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch(
            "venya_cli.commands.getpass.getpass", side_effect=["a", "b", "prompt-round-trip-pw", "prompt-round-trip-pw"]
        ) as gp:
            rc = cmd_admin_export_ca_key(args)
        assert rc == 0
        assert gp.call_count == 4

    def test_export_empty_passphrase_rejected(self, tmp_path):
        """Negative half: empty passphrase must fail, not export an empty-key file."""
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(_real_key_pem())
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", side_effect=["", ""]):
            rc = cmd_admin_export_ca_key(args)
        assert rc == 1
        assert not out.exists()

    @pytest.mark.parametrize("blank", [" ", "   ", "\t"], ids=["space1", "space3", "tab"])
    def test_export_whitespace_only_passphrase_rejected(self, tmp_path, capsys, blank):
        """#554 (owner deny-whitespace batch): a typed value of only spaces is as empty
        as no value. The exported envelope is PBKDF2 over the passphrase, so a blank one
        is a file anyone can open — the same reason the prompt refuses "" today.

        The shipped sentence is asserted byte-for-byte (no new wording) and the
        filesystem half is the load-bearing one: nothing was written.
        """
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(_real_key_pem())
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch(
            "venya_cli.commands.getpass.getpass", side_effect=[blank, blank]
        ) as gp:
            rc = cmd_admin_export_ca_key(args)
        assert rc == 1, f"a {blank!r} passphrase still exported a CA key"
        assert gp.call_count == 2, "both prompts are the hidden pair, as shipped"
        assert not out.exists(), f"a {blank!r} passphrase still wrote {out}"
        assert "Error: passphrase cannot be empty" in capsys.readouterr().err

    def test_export_whitespace_as_content_still_encrypts(self, tmp_path):
        """The paired positive, and the guard against a TRIM reading: a phrase whose
        spaces are CONTENT is a real passphrase, exported with the bytes exactly as
        typed — the stripped form must not open the envelope it sealed."""
        typed = " padded export phrase 554 "  # dev-only synthetic value
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        key = _real_key_pem()
        (ca_dir / "ca.key").write_bytes(key)
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", side_effect=[typed, typed]):
            assert cmd_admin_export_ca_key(args) == 0
        assert out.exists() and out.read_bytes() != key, "the export must not be the plaintext key"
        (ca_dir / "ca.key").unlink()
        # #593: trailing "" declines the absent-target server-passphrase prompt (Enter = leave
        # unencrypted) — the door guard now requires a tty, so that second prompt is reachable.
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", side_effect=[typed, ""]):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(out), shares=None, ca_dir=str(ca_dir))
            )
        assert rc == 0, "the untrimmed phrase must open the envelope it sealed"
        assert (ca_dir / "ca.key").read_bytes() == key
        # The sharp half: the stripped phrase is a DIFFERENT secret and must fail.
        (ca_dir / "ca.key").unlink()
        with patch("builtins.input", _boom), patch("venya_cli.commands.getpass.getpass", side_effect=[typed.strip()]):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(out), shares=None, ca_dir=str(ca_dir))
            )
        assert rc == 1, "a trimmed passphrase must NOT open what the untrimmed one sealed"
        assert not (ca_dir / "ca.key").exists(), "the failed restore wrote nothing"

    def test_restore_backup_roundtrip_uses_getpass(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(key)
        backup = tmp_path / "b.enc"
        with patch("builtins.input", _boom), patch(
            "venya_cli.commands.getpass.getpass", side_effect=["prompt-export-passphrase", "prompt-export-passphrase"]
        ):
            assert cmd_admin_export_ca_key(SimpleNamespace(output=str(backup), ca_dir=str(ca_dir))) == 0
        (ca_dir / "ca.key").unlink()
        # #593: trailing "" declines the absent-target server-passphrase prompt (Enter = leave
        # unencrypted), which the faked-tty path now reaches.
        with patch("builtins.input", _boom), patch(
            "venya_cli.commands.getpass.getpass", side_effect=["prompt-export-passphrase", ""]
        ):
            rc = cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(backup), shares=None, ca_dir=str(ca_dir))
            )
        assert rc == 0
        assert (ca_dir / "ca.key").read_bytes() == key
        assert Path(ca_dir / "ca.key").stat().st_mode & 0o777 == 0o600
