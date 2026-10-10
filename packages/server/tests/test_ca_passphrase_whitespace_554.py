# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#554 — a whitespace-only CA passphrase reads as UNSET on the server side.

Owner ruling (2026-10-09, verbatim): *"whitespace-only passphrase should not be
acceptable."* Every CA decision in ``server/ca.py`` is a truthiness test on the
configured value, and a value of ``" "`` is truthy — so a key was written
"protected" by one space character: a well-formed encrypted PEM that protects
nothing, and the #537 write-side refusal waved it through.

The fix is in the ONE place that decides it, ``_load_passphrase()``, which all
four sites already route through (both ``initialize()`` write guards, both read
paths, and the serializer through the value it returns). No call site strips,
because a strip at each gate answers the same question four times.

**The ruled shape is DENY, not TRIM.** The operator's value is never rewritten,
so these cells pin both halves: an all-whitespace value counts as no passphrase,
and a passphrase that merely carries a leading, trailing or embedded space is
delivered to the crypto layer byte-for-byte. Trimming would have silently
changed what a legitimate passphrase is and stopped existing encrypted keys
opening — the ticket records that as a migration risk, and this file keeps the
code on the safe side of it.

Wording: nothing here invents a sentence. A whitespace-only value is now simply
"no passphrase", so the shipped, owner-approved #537 refusal fires verbatim
(checked with #537's own element tuple, imported from #537's suite so a wording
fork trips that suite too). The #541 arms — plaintext key at rest plus a REAL
configured passphrase — are untouched by this change and are pinned as still
refusing.
"""

import pytest
from cryptography.hazmat.primitives import serialization
from server.ca import (
    AdminCAManager,
    CAManager,
    _load_passphrase,
    _unencrypted_key_refusal,
)

# The SAME approved element tuple and checker #537 ships, imported not copied.
from tests.test_ca_key_write_refusal_537 import _APPROVED_ELEMENTS, _assert_approved_message

_ROOT_ENV = "VENYA_CA_KEY_PASSPHRASE"
_ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"

# Synthetic dev-only values (AGENTS.md test-password vocabulary, never real):
# a real passphrase at or above the ruled length, and blank shapes.
_REAL_PASSPHRASE = "test-ca-passphrase-554"
_PADDED_PASSPHRASE = " test ca passphrase 554 "
_BLANK_VALUES = [" ", "   ", "\t", "\n", " \t \n "]


class TestLoadPassphraseUnit:
    """The decision itself, at the single place that makes it."""

    def test_unset_reads_as_none(self, monkeypatch):
        monkeypatch.delenv(_ROOT_ENV, raising=False)
        assert _load_passphrase(_ROOT_ENV) is None

    def test_empty_reads_as_none(self, monkeypatch):
        monkeypatch.setenv(_ROOT_ENV, "")
        assert _load_passphrase(_ROOT_ENV) is None

    @pytest.mark.parametrize(
        "blank",
        _BLANK_VALUES,
        ids=["space1", "space3", "tab", "newline", "mixed"],
    )
    def test_whitespace_only_reads_as_none(self, monkeypatch, blank):
        """THE #554 defect: truthiness said a space was a passphrase."""
        monkeypatch.setenv(_ROOT_ENV, blank)
        assert _load_passphrase(_ROOT_ENV) is None, f"{blank!r} must not count as a passphrase"

    def test_real_passphrase_is_returned_as_utf8_bytes(self, monkeypatch):
        """The paired positive: the happy path is byte-for-byte what it was."""
        monkeypatch.setenv(_ROOT_ENV, _REAL_PASSPHRASE)
        assert _load_passphrase(_ROOT_ENV) == _REAL_PASSPHRASE.encode("utf-8")

    def test_value_is_never_trimmed(self, monkeypatch):
        """DENY, not TRIM: a passphrase that carries spaces as CONTENT comes back
        exactly as set — leading, trailing and embedded. Trimming here would
        silently change the secret and lock the operator out of their own key."""
        monkeypatch.setenv(_ROOT_ENV, _PADDED_PASSPHRASE)
        loaded = _load_passphrase(_ROOT_ENV)
        assert loaded == _PADDED_PASSPHRASE.encode("utf-8")
        assert loaded is not None and loaded.strip() != loaded, "the bytes must still carry the spaces"


class TestWriteRefusal554:
    """Both managers, both blank shapes: refuse with #537's words, write nothing."""

    @pytest.mark.parametrize("blank", [" ", "   ", "\t"], ids=["space1", "space3", "tab"])
    def test_root_ca_refuses_whitespace_only_and_creates_nothing(self, tmp_path, monkeypatch, blank):
        monkeypatch.setenv(_ROOT_ENV, blank)
        manager = CAManager(str(tmp_path / "ca"))

        assert not manager.ca_dir.exists(), "fixture precondition: CA dir absent"
        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        message = str(excinfo.value)
        _assert_approved_message(message, _ROOT_ENV)
        assert message == _unencrypted_key_refusal(_ROOT_ENV), "the refusal is #537's, word for word"
        # The filesystem proof: the refusal is not a message, it is an absence.
        assert not manager.ca_dir.exists(), f"a {blank!r} passphrase still created {manager.ca_dir}"
        assert not (tmp_path / "ca").exists()

    @pytest.mark.parametrize("blank", [" ", "   ", "\t"], ids=["space1", "space3", "tab"])
    def test_admin_ca_refuses_whitespace_only_and_creates_nothing(self, tmp_path, monkeypatch, blank):
        """Admin twin — same rule, and the refusal names the ADMIN variable."""
        monkeypatch.setenv(_ADMIN_ENV, blank)
        manager = AdminCAManager(tmp_path / "admin-ca")

        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        message = str(excinfo.value)
        _assert_approved_message(message, _ADMIN_ENV)
        assert _ADMIN_ENV in message
        assert not manager.ca_path.exists(), f"a {blank!r} passphrase still created {manager.ca_path}"

    def test_a_real_passphrase_still_mints_and_reloads(self, tmp_path, monkeypatch):
        """AC3's positive half: the guard must not break the correct configuration."""
        monkeypatch.setenv(_ROOT_ENV, _REAL_PASSPHRASE)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()

        key_data = manager.ca_key_path.read_bytes()
        assert b"ENCRYPTED" in key_data, "the key must still be written encrypted"
        assert key_data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        # And it loads back under the same ruled shape.
        assert manager.load_ca()[1] is not None

    def test_whitespace_padding_as_content_still_mints_and_reloads(self, tmp_path, monkeypatch):
        """The sharp negative for the TRIM reading: a value whose spaces are content
        is NOT blank, so it mints — and the key opens only with the untrimmed bytes."""
        monkeypatch.setenv(_ROOT_ENV, _PADDED_PASSPHRASE)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()

        key_data = manager.ca_key_path.read_bytes()
        assert b"ENCRYPTED" in key_data
        assert manager.load_ca()[1] is not None, "the untrimmed value must open the key it wrote"
        # The exact secret is the untrimmed bytes; a stripped form must NOT open it.
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(key_data, password=_PADDED_PASSPHRASE.strip().encode("utf-8"))


class TestReadPairing554:
    """Reads keep their pairing: blank is no longer a passphrase anywhere."""

    def test_encrypted_key_with_whitespace_only_reports_the_var_as_not_set(self, tmp_path, monkeypatch):
        """Root read: the value is unset-like, so the operator is told to set it."""
        monkeypatch.setenv(_ROOT_ENV, _REAL_PASSPHRASE)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()

        monkeypatch.setenv(_ROOT_ENV, "   ")
        with pytest.raises(RuntimeError) as excinfo:
            manager.load_ca()
        assert "is not set" in str(excinfo.value)
        assert _ROOT_ENV in str(excinfo.value)

    def test_admin_encrypted_key_with_whitespace_only_reports_the_var_as_not_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_ADMIN_ENV, _REAL_PASSPHRASE)
        manager = AdminCAManager(tmp_path / "admin-ca")
        manager.initialize()

        monkeypatch.setenv(_ADMIN_ENV, "\t")
        with pytest.raises(RuntimeError) as excinfo:
            manager._load_ca_key()
        assert "is not set" in str(excinfo.value)
        assert _ADMIN_ENV in str(excinfo.value)

    def test_plaintext_key_plus_whitespace_only_is_no_longer_a_541_refusal(self, tmp_path, monkeypatch):
        """DISCOVERED CONSEQUENCE, pinned on purpose (not a weakening — a stated outcome).

        #541 selects its refusal on ``not is_encrypted and passphrase``. A
        whitespace-only value now reads as UNSET, so that arm no longer fires and
        the legacy plaintext key loads the way an UNSET passphrase already loads
        it. The operator typed a value and got no warning; the file says so.
        The ruled fix for THIS hole is a read-side refusal for any plaintext key at
        rest, which #537/#541 deliberately left out of scope — recorded in the #554
        report rather than improvised into this changeset.
        """
        monkeypatch.setenv(_ROOT_ENV, _REAL_PASSPHRASE)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        key = manager.load_ca()[1]
        plaintext = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        manager.ca_key_path.write_bytes(plaintext)

        monkeypatch.setenv(_ROOT_ENV, "   ")
        loaded_cert, loaded_key = manager.load_ca()
        assert loaded_key is not None, "a blank value now behaves exactly like an unset one"
        assert b"ENCRYPTED" not in manager.ca_key_path.read_bytes()
        assert loaded_cert is not None

    def test_the_541_arms_are_unchanged_for_a_real_passphrase(self, tmp_path, monkeypatch):
        """Paired negative: a REAL configured passphrase against a plaintext key at
        rest still refuses with the shared approved text — #541's ruling intact."""
        monkeypatch.setenv(_ROOT_ENV, _REAL_PASSPHRASE)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()
        key = manager.load_ca()[1]
        manager.ca_key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

        with pytest.raises(RuntimeError) as excinfo:
            manager.load_ca()
        message = str(excinfo.value)
        assert message.startswith("REFUSED:")
        _assert_approved_message(message, _ROOT_ENV)
        assert tuple(element in message for element in _APPROVED_ELEMENTS) == (True,) * len(_APPROVED_ELEMENTS)
