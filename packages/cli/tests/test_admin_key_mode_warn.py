# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth-table tests for the admin-key loose-mode warning (feature: modewarn).

Ruled shape (features/admin-key-mode-warn.md, owner ruled YES 2026-10-07): when
the CLI is about to use an admin KEY file whose permission bits grant READ to
group or other, print ONE warning line on stderr before doing anything else —
warn, do NOT block. Correct modes stay silent; a warning that fires on a correct
setup is the failure mode of this feature, so every positive here is paired with
its accepted half. POSIX-only: Windows has no mode bits and must never print a
fabricated "looks fine".

Construction notes mirror the admin-mTLS home (test_api_client_mtls.py): the
load block only does isfile + stat, so dummy file content is sufficient — the
TLS context that PARSES the pair is built lazily on first dial (client._http),
which none of these cells trigger.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from venya_cli import api_client
from venya_cli.api_client import APIClient, APIClientError, _warn_if_loose_admin_key


def _pair(tmp_path: Path, key_mode: int, cert_mode: int = 0o600) -> tuple[Path, Path]:
    """Write a dummy cert+key pair with explicit modes (content is not parsed here)."""
    cert = tmp_path / "admin.crt"
    key = tmp_path / "admin.key"
    cert.write_text("dummy cert")
    key.write_text("dummy key")
    cert.chmod(cert_mode)
    key.chmod(key_mode)
    return cert, key


class TestLooseKeyWarns:
    """Group- or other-READABLE key → one stderr line, request proceeds."""

    @pytest.mark.parametrize("mode,found", [(0o644, "0644"), (0o604, "0604"), (0o666, "0666")])
    def test_readable_key_warns_and_proceeds(self, tmp_path, monkeypatch, capsys, mode, found):
        cert, key = _pair(tmp_path, key_mode=mode)
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)

        client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
        captured = capsys.readouterr()
        try:
            # Warn, do not block: the client constructed, the flag is still True.
            assert client.has_admin_mtls is True
        finally:
            client.close()

        assert "warning" in captured.err.lower()
        assert found in captured.err  # the mode found, octal
        assert "0600" in captured.err  # the wanted mode
        assert str(key) in captured.err  # the path
        assert "security-key" in captured.err  # the no-security-key-touch fact
        # The warning is on stderr ONLY — stdout stays byte-clean of it.
        assert found not in captured.out

    def test_warning_text_carries_all_four_required_pieces(self, tmp_path, capsys):
        """Substring cells over the one line: path, found mode, 0600, security-key fact."""
        key = tmp_path / "admin.key"
        key.write_text("dummy key")
        key.chmod(0o644)

        _warn_if_loose_admin_key(str(key))

        err = capsys.readouterr().err
        assert str(key) in err
        assert "0644" in err
        assert "0600" in err
        assert "without a security-key touch" in err


class TestCorrectModeSilent:
    """The mandated silent-correct-case negatives: no output at all when the key is safe."""

    @pytest.mark.parametrize("mode", [0o600, 0o400])
    def test_owner_only_key_is_silent(self, tmp_path, monkeypatch, capsys, mode):
        cert, key = _pair(tmp_path, key_mode=mode)
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)

        client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
        captured = capsys.readouterr()
        try:
            assert client.has_admin_mtls is True
        finally:
            client.close()

        assert captured.err == ""  # a warning on a correct setup is the failure mode
        assert captured.out == ""

    def test_public_cert_loose_never_alarms(self, tmp_path, monkeypatch, capsys):
        """Paired negative (ruling point 6): only the KEY is checked.

        A public cert is not a secret — 0644 on the cert, 0600 on the key, must
        print NOTHING (the faithful key-only default).
        """
        cert, key = _pair(tmp_path, key_mode=0o600, cert_mode=0o644)
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(key))
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)

        client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
        captured = capsys.readouterr()
        try:
            assert client.has_admin_mtls is True
        finally:
            client.close()

        assert captured.err == ""


class TestOwnerBitNotFlagged:
    """Ruling point 4 call: the trigger is the group/other READ class (mode & 0o044).

    An owner exec bit (0700) grants read to NOBODY but the owner, so it stays
    silent — recorded as the deliberate call in the report.
    """

    def test_owner_exec_bit_silent(self, tmp_path, capsys):
        key = tmp_path / "admin.key"
        key.write_text("dummy key")
        key.chmod(0o700)

        _warn_if_loose_admin_key(str(key))

        assert capsys.readouterr().err == ""


class TestNonPosixSkips:
    """Platform honesty: no mode bits → skip, and never print a fabricated OK."""

    def test_windows_shape_is_silent(self, tmp_path, monkeypatch, capsys):
        key = tmp_path / "admin.key"
        key.write_text("dummy key")
        key.chmod(0o644)  # a mode that WOULD warn on POSIX

        # Non-POSIX: the file content is a real readable file, but os.name is not
        # posix — the check must return without printing (neither warn nor fake-OK).
        monkeypatch.setattr(api_client.os, "name", "nt", raising=False)
        _warn_if_loose_admin_key(str(key))

        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""


class TestExistenceLegNotRegressed:
    """The existing APIClientError existence leg still fires (I did not displace it)."""

    @patch("venya_cli.api_client.httpx2.Client")
    def test_missing_key_still_raises(self, mock_client_cls, tmp_path, monkeypatch):
        cert = tmp_path / "admin.crt"
        cert.write_text("dummy cert")
        monkeypatch.setenv("VENYA_ADMIN_CERT", str(cert))
        monkeypatch.setenv("VENYA_ADMIN_KEY", str(tmp_path / "nonexistent.key"))

        with pytest.raises(APIClientError, match="does not exist"):
            APIClient(config_file=tmp_path / "config.json")

        mock_client_cls.assert_not_called()
