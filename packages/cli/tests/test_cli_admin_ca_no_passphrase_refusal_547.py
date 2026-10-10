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

import inspect
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from venya_cli.commands import (
    _admin_ca_no_passphrase_refusal,
    cmd_admin_generate_admin_cert,
    cmd_admin_init_admin_ca,
)

PASSPHRASE = "test_passphrase_547"


def _admin_ca(tmp_path: Path, phrase: str) -> Path:
    """A real admin CA on disk, minted through the shipped #547 path with `phrase`."""
    os.environ["VENYA_ADMIN_CA_KEY_PASSPHRASE"] = phrase
    ca_dir = tmp_path / "admin-ca"
    assert cmd_admin_init_admin_ca(_args(ca_dir)) == 0, "admin CA mint failed"
    return ca_dir


def _gen_args(ca_dir: Path, out: Path) -> object:
    return type("Args", (), {"identity": "admin@example.com", "ca_dir": str(ca_dir), "output_dir": str(out)})()


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


class TestAdminCACertReadGate554:
    """#554 addendum: `cmd_admin_generate_admin_cert`'s CA-key read gate denies blank too.

    MEASURED FIRST, and said plainly because it changes what these cells can prove: on
    this command the blank case was already refused ONE GUARD EARLIER — the #547a
    leaf-key guard at the top of the function reads the same variable and denies unset,
    empty and whitespace-only. Probed against the base `commands.py` and against this
    branch, a `"   "` run answers with the #547a refusal and writes nothing, both times.
    So the edit has no operator-visible effect here today; what it fixes is the gate
    itself, which as shipped treated a value of spaces as a passphrase and was one
    reordering away from handing `b"   "` to the loader — the exact truthiness shape
    #554 was filed for. `N3` pins the gate's shape so a future edit cannot quietly put
    the raw truthiness test back (the same `inspect.getsource` technique #541's suite
    uses to keep a deleted warning from coming back).
    """

    def test_n1_blank_passphrase_refuses_and_writes_nothing(self, tmp_path, monkeypatch, capsys):
        """Reachable half: a blank value gets the refusal, and no certificate is minted."""
        ca = _admin_ca(tmp_path, " test ca phrase 547 with spaces ")
        out = tmp_path / "leaf"
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "   ")

        assert cmd_admin_generate_admin_cert(_gen_args(ca, out)) == 1
        assert not out.exists(), f"a blank passphrase still produced {out}"
        err = capsys.readouterr().err
        assert "REFUSED" in err and "VENYA_ADMIN_CA_KEY_PASSPHRASE" in err

    def test_n2_real_passphrase_still_decrypts_the_ca_key(self, tmp_path, monkeypatch):
        """Positive half: the gate must not break a correctly-configured CA read."""
        phrase = " test ca phrase 547 with spaces "
        ca = _admin_ca(tmp_path, phrase)
        out = tmp_path / "leaf"
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", phrase)

        assert cmd_admin_generate_admin_cert(_gen_args(ca, out)) == 0
        assert (out / "admin.crt").exists() and (out / "admin.key").exists()
        # Spaces are content, not blankness: the untrimmed phrase is the secret on both
        # halves of this run, and the stripped form is a different secret.
        leaf = serialization.load_pem_private_key((out / "admin.key").read_bytes(), password=phrase.encode("utf-8"))
        assert leaf is not None
        with pytest.raises(ValueError):
            serialization.load_pem_private_key((out / "admin.key").read_bytes(), password=phrase.strip().encode())

    def test_n3_the_read_gate_uses_the_shared_predicate_not_raw_truthiness(self):
        """The gate-shape cell, and this branch's non-vacuity proof for the addendum.

        RED at the base `commands.py`: the read gate read the variable directly with
        `if is_encrypted and not passphrase`, so a value of spaces counted as a
        passphrase there. GREEN now: it asks the same helper the write path asks.
        """
        source = inspect.getsource(cmd_admin_generate_admin_cert)
        assert "_admin_ca_passphrase_or_none()" in source, "the CA read gate must use the shared predicate"
        assert (
            'os.environ.get("VENYA_ADMIN_CA_KEY_PASSPHRASE")' not in source
        ), "the read gate may not re-read the variable raw — that is the #554 shape"

    def test_n4_plaintext_ca_key_plus_blank_refuses_earlier_not_loads(self, tmp_path, monkeypatch):
        """The observable the addendum asked to state, measured rather than assumed.

        The server half (#554 F3) had a plaintext key at rest LOAD as unset once blank
        stopped counting as a passphrase. That consequence does NOT reach this command:
        the #547a guard refuses blank before the CA file is read, so a plaintext admin
        CA key at rest is never opened by a spaces-only value here. Pinned so the two
        halves are not mistaken for each other if the guard order ever changes.
        """
        phrase = " test ca phrase 547 with spaces "
        ca = _admin_ca(tmp_path, phrase)
        key = serialization.load_pem_private_key((ca / "admin-ca.key").read_bytes(), password=phrase.encode())
        (ca / "admin-ca.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        out = tmp_path / "leaf"
        monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "   ")

        assert cmd_admin_generate_admin_cert(_gen_args(ca, out)) == 1
        assert not out.exists()
        assert b"ENCRYPTED" not in (ca / "admin-ca.key").read_bytes(), "the refusal rewrote the CA key"
