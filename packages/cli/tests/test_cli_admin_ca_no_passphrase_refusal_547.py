# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#547 — ``venya admin init-admin-ca`` REFUSES a passphrase-less run (AC2).

Owner ruling on #547: "match server. no passphrase? then no key." The CLI used to
fall through to ``serialization.NoEncryption()`` and write a plaintext admin CA
key — where the server (``server/ca.py``, #537) refuses the same case and writes
nothing. This file is the two-sided half: the refusal cells (N1/N2) plus the
positive cells that prove the encrypted path and the pre-existing-CA guard still
behave (P1-P4).

#554 moved one of those positive cells, and it is worth saying which and why: P4
used to pin a whitespace-only value as an ACCEPTED passphrase ("STATE OF THE CODE,
asserted exactly"), which is the truthiness hole the owner ruled away with the
deny-whitespace batch. P4 is now a refusal cell with the same filesystem proof as
N1/N2, and P4B keeps the positive half — spaces that are CONTENT are still a real
passphrase, and the value is never trimmed. The refusal text is #547's, imported
and compared byte-for-byte, because "no material" and "not set" are the same
answer to this command.

The load-bearing assertion in the refusal cells is on the FILESYSTEM, not the
message: no directory, no key, no certificate, no temp file. The refusal must
fire before ``output_dir.mkdir()`` (see ``server/ca.py`` "refuse before ANY
filesystem work").
"""

import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from venya_cli.commands import _admin_ca_no_passphrase_refusal, cmd_admin_init_admin_ca

PASSPHRASE = "test_passphrase_547"


def _args(output_dir) -> object:
    return type("Args", (), {"output_dir": str(output_dir)})()


@pytest.fixture
def passphrase(monkeypatch):
    """Set VENYA_ADMIN_CA_KEY_PASSPHRASE for this cell only."""
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", PASSPHRASE)
    return PASSPHRASE


@pytest.fixture
def no_passphrase(monkeypatch):
    """Guarantee VENYA_ADMIN_CA_KEY_PASSPHRASE is unset for this cell."""
    monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)


def _dir_listing(path: Path) -> list[str]:
    return sorted(p.name for p in path.iterdir())


class TestRefusalNoPassphrase:
    """N1/N2: unset or empty passphrase -> refuse, write NOTHING, exit non-zero."""

    def test_n1_no_passphrase_refuses_and_touches_no_filesystem(self, tmp_path, no_passphrase, capsys):
        out = tmp_path / "admin-ca"
        rc = cmd_admin_init_admin_ca(_args(out))

        captured = capsys.readouterr()
        assert rc == 1, f"passphrase-less run exited {rc}; expected refusal"
        assert "REFUSED" in captured.err
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in captured.err
        # The filesystem proof — the message is not the check.
        assert not out.exists(), f"refusal still created {out}"
        assert _dir_listing(tmp_path) == [], "refusal wrote something next to the target dir"

    def test_n1_refusal_names_the_var_the_cli_reads(self, tmp_path, no_passphrase, capsys):
        """The repair step must name VENYA_ADMIN_CA_KEY_PASSPHRASE (the CLI's own var),
        and must not tell the operator to set only the core-service env file."""
        # (separate cell so the N1 filesystem proof above stays atomic)
        cmd_admin_init_admin_ca(_args(tmp_path / "admin-ca"))
        err = capsys.readouterr().err
        assert err.count("VENYA_ADMIN_CA_KEY_PASSPHRASE") >= 2
        assert "admin CA key" in err  # the workstation admin CA, not the root CA
        assert "Nothing was written." in err

    def test_n2_empty_passphrase_counts_as_unset(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "")
        out = tmp_path / "admin-ca"

        assert cmd_admin_init_admin_ca(_args(out)) == 1
        assert not out.exists()

    def test_p2_refusal_before_any_filesystem_work_nested_missing_path(self, tmp_path, no_passphrase):
        """--output-dir pointing at a nonexistent nested path: the refusal must not
        create it (and must not create any parent)."""
        out = tmp_path / "deep" / "deeper" / "admin-ca"

        assert cmd_admin_init_admin_ca(_args(out)) == 1
        assert not out.exists()
        assert not out.parent.exists()
        assert _dir_listing(tmp_path) == []


class TestEncryptedPathStillWorks:
    """P1/P3/P4: the set-passphrase path and the pre-existing-CA guard are unchanged."""

    def test_p1_passphrase_set_writes_encrypted_pkcs8(self, tmp_path, passphrase):
        out = tmp_path / "admin-ca"

        assert cmd_admin_init_admin_ca(_args(out)) == 0
        key_bytes = (out / "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" in key_bytes, "key is not encrypted on disk"
        # PEM header check: the unencrypted header must NOT be what we got.
        assert not key_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")  # pragma: allowlist secret

        key = serialization.load_pem_private_key(key_bytes, password=passphrase.encode())
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)
        # Wrong passphrase must not open it.
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(key_bytes, password=b"not-it")

        assert stat.S_IMODE((out / "admin-ca.key").stat().st_mode) == 0o600
        assert stat.S_IMODE(out.stat().st_mode) == 0o700
        assert not list(out.glob(".venya-cakey-*"))

    def test_p3_preexisting_ca_guard_still_fires(self, tmp_path, passphrase):
        out = tmp_path / "admin-ca"
        assert cmd_admin_init_admin_ca(_args(out)) == 0
        before = (out / "admin-ca.key").read_bytes()

        assert cmd_admin_init_admin_ca(_args(out)) == 1
        assert (out / "admin-ca.key").read_bytes() == before, "existing key was rewritten"

    def test_p3_passphrase_less_run_against_existing_ca_refuses_on_the_passphrase_rule(
        self, tmp_path, passphrase, monkeypatch
    ):
        """The paired negative: an existing CA must not rescue a passphrase-less run,
        and the refusal must not modify the existing key."""
        out = tmp_path / "admin-ca"
        assert cmd_admin_init_admin_ca(_args(out)) == 0
        before = (out / "admin-ca.key").read_bytes()
        before_mode = stat.S_IMODE((out / "admin-ca.key").stat().st_mode)
        monkeypatch.delenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", raising=False)

        assert cmd_admin_init_admin_ca(_args(out)) == 1
        assert (out / "admin-ca.key").read_bytes() == before
        assert stat.S_IMODE((out / "admin-ca.key").stat().st_mode) == before_mode
        assert sorted(p.name for p in out.iterdir()) == ["admin-ca.crt", "admin-ca.key"]

    @pytest.mark.parametrize("blank", [" ", "   ", "\t", "\n"], ids=["space1", "space3", "tab", "nl"])
    def test_p4_whitespace_only_passphrase_refuses_and_writes_nothing(self, tmp_path, monkeypatch, capsys, blank):
        """#554 REPLACES the cell that pinned acceptance as "STATE OF THE CODE".

        This cell used to assert the opposite: a whitespace-only value is truthy, so the
        guard treated it as SET and encrypted the admin CA key with three spaces. That
        acceptance is the defect the owner ruled away in the deny-whitespace batch
        (s85, verbatim: "whitespace-only passphrase should not be acceptable"), and the
        server closed its half of it in #554. The two paths must not answer "is a
        passphrase set?" differently — that divergence is exactly what #547 was filed to
        end — so the state of the code moved and this assertion moved with it, same shape
        as N1/N2: the refusal plus the filesystem proof. The lead blessed the
        replacement (wren-9-0ce003). A minimum LENGTH is still not ruled and is not
        asserted here.
        """
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", blank)
        out = tmp_path / "admin-ca"

        assert cmd_admin_init_admin_ca(_args(out)) == 1, f"a {blank!r} passphrase still wrote a key"
        assert not out.exists(), f"a {blank!r} passphrase still created {out}"
        assert _dir_listing(tmp_path) == [], "the refusal wrote something next to the target dir"
        err = capsys.readouterr().err
        # Zero new wording: #547's own sentence, byte-for-byte, because "no material" and
        # "not set" are the same answer to this command.
        assert err == _admin_ca_no_passphrase_refusal() + "\n", "the refusal must be #547's verbatim"
        assert "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err

    def test_p4b_whitespace_as_content_is_still_a_real_passphrase(self, tmp_path, monkeypatch):
        """The paired positive, and the sharp edge against a TRIM reading.

        Spaces that are CONTENT are not blankness: the value is DENIED only when nothing
        but whitespace was supplied. The operator's bytes are used as typed, so the key
        opens with the untrimmed phrase and NOT with a stripped one — a trim would have
        silently changed the secret and locked the operator out of their own CA.
        """
        padded = " test ca phrase 547 with spaces "  # dev-only synthetic value
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", padded)
        out = tmp_path / "admin-ca"

        assert cmd_admin_init_admin_ca(_args(out)) == 0
        key_bytes = (out / "admin-ca.key").read_bytes()
        assert b"ENCRYPTED" in key_bytes
        assert serialization.load_pem_private_key(key_bytes, password=padded.encode()) is not None
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(key_bytes, password=padded.strip().encode())
