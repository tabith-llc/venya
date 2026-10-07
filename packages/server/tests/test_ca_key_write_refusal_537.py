# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#537 ca-key-write-side-unencrypted-refusal — the write path refuses plaintext.

``CAManager.initialize`` / ``AdminCAManager.initialize`` used to log
"CA key will be stored UNENCRYPTED — set <env> in production" and write a
plaintext root CA key whenever the passphrase env var was unset, while the READ
side refused the same situation outright. The owner ruled the design:
"if there is no passphrase set, no key should be created/written to begin with."

The refusal now lands in two places:

* early in both ``initialize()`` methods, before any filesystem work, so
  "Nothing was written." is literally true — no key file and no CA directory;
* in ``_serialize_key_encrypted`` itself, as the backstop for the two current
  callers and any future one (the plaintext branch is gone).

Cells follow the ticket acceptance criteria, negative half first — the whole
point of the ticket is what gets rejected.
"""

import inspect
import re
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from server import ca as ca_module
from server.ca import (
    AdminCAManager,
    CAManager,
    _serialize_key_encrypted,
    _unencrypted_key_refusal,
)
from server.config import CASecurityConfig

_ROOT_ENV = "VENYA_CA_KEY_PASSPHRASE"
_ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
_TEST_PASSPHRASE = "test-ca-passphrase-537"

#: Every element of the owner-approved refusal text (approved as drafted).
_APPROVED_ELEMENTS = (
    "REFUSED:",
    "Nothing was written.",
    "Why it matters:",
    "To fix it:",
    "/etc/venya/venya-core.env",
    "never as a command-line",
    "Your existing CA was not modified by this refusal.",
    "docs/cert-rotation-runbook.md",
    "docs/BACKUPS.md",
)


def _assert_approved_message(message: str, passphrase_env: str) -> None:
    """Fail unless `message` carries every approved element, in order, plus steps 1/2/3.

    Used as a positive check on the real refusal and — as the paired negative —
    to prove a one-line error string cannot pass it.
    """
    for element in _APPROVED_ELEMENTS:
        assert element in message, f"refusal text is missing the approved element {element!r}"
    assert passphrase_env in message, f"refusal text must name the env var the caller reads ({passphrase_env})"
    assert f"1. Set {passphrase_env}" in message, "step 1 must name the real variable"
    steps = re.findall(r"^\s+\d\. ", message, flags=re.MULTILINE)
    assert len(steps) >= 3, f"refusal must carry at least 3 numbered repair steps, found {len(steps)}"
    assert len(message) > 300, "a short error string must not satisfy the approved refusal"


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestWriteRefusal537:
    """AC1/AC1b/AC1c — no passphrase means no key and no directory."""

    def test_ac1_root_ca_refuses_and_creates_nothing(self, tmp_path, monkeypatch):
        """AC1: env unset -> RuntimeError, and NOTHING on disk (no key, no dir).

        RED at HEAD: the old path logged a warning and wrote a plaintext key
        plus the 0700 CA directory.
        """
        monkeypatch.delenv(_ROOT_ENV, raising=False)
        manager = CAManager(str(tmp_path / "ca"))

        assert not manager.ca_dir.exists(), "fixture precondition: CA dir absent"
        assert not manager.ca_key_path.exists()

        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        assert not manager.ca_key_path.exists(), "refusal must not write a key"
        assert not manager.ca_cert_path.exists(), "refusal must not write a cert"
        assert not manager.ca_dir.exists(), "refusal must not even create the CA directory"
        assert str(excinfo.value).startswith("REFUSED:")

    def test_ac1b_empty_string_passphrase_refuses(self, tmp_path, monkeypatch):
        """AC1b: an EMPTY passphrase value counts as unset — same refusal, nothing written.

        ``_load_passphrase`` returns None on the empty string (``if passphrase:``),
        so this pins that falsiness is what the guard keys on, not key presence.
        """
        monkeypatch.setenv(_ROOT_ENV, "")
        manager = CAManager(str(tmp_path / "ca"))

        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        assert str(excinfo.value).startswith("REFUSED:")
        assert not manager.ca_dir.exists(), "empty passphrase must not create anything"
        assert not manager.ca_key_path.exists()

    def test_ac1c_admin_ca_refuses_and_creates_nothing(self, tmp_path, monkeypatch):
        """AC1c: the admin CA write path refuses the same way, naming the ADMIN var.

        RED at HEAD: plaintext admin key + the CA directory.
        """
        monkeypatch.delenv(_ADMIN_ENV, raising=False)
        manager = AdminCAManager(tmp_path / "admin-ca")

        assert not manager.ca_path.exists()
        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        message = str(excinfo.value)
        assert _ADMIN_ENV in message, "admin refusal must name the admin var"
        assert not manager.ca_key_path.exists()
        assert not manager.ca_cert_path.exists()
        assert not manager.ca_path.exists(), "refusal must not even create the admin CA directory"

    def test_serializer_backstop_refuses_null_passphrase(self):
        """Defence in depth: the serializer itself refuses a null passphrase.

        The initialize() guard is what keeps "nothing was written" honest; this
        pins that a FUTURE caller which skips the guard still cannot get
        plaintext bytes out of ``_serialize_key_encrypted``.
        """
        key = ec.generate_private_key(ec.SECP256R1())

        with pytest.raises(RuntimeError) as excinfo:
            _serialize_key_encrypted(key, None, _ROOT_ENV)

        assert str(excinfo.value).startswith("REFUSED:")
        _assert_approved_message(str(excinfo.value), _ROOT_ENV)


class TestHappyPath537:
    """AC2/AC5 — the valid configuration still mints, encrypts, and reloads."""

    def test_ac2_passphrase_set_writes_encrypted_key(self, tmp_path, monkeypatch):
        """AC2 (GREEN at HEAD too): the guard must not break the happy path.

        Key lands encrypted, reloads through the existing load path, mode 0600.
        """
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        manager = CAManager(str(tmp_path / "ca"))

        manager.initialize()

        key_bytes = manager.ca_key_path.read_bytes()
        assert b"ENCRYPTED" in key_bytes, "CA key must be encrypted at rest"
        # Stronger than a byte-grep: the plaintext form cannot even be parsed
        # without the passphrase.
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(key_bytes, password=None)
        assert _mode(manager.ca_key_path) == 0o600
        assert _mode(manager.ca_cert_path) == 0o644

        cert, private_key = manager.load_ca()
        assert cert is not None
        assert private_key is not None

    def test_ac5_installer_delivered_passphrase_never_refuses(self, tmp_path, monkeypatch, caplog):
        """AC5: the installer-driven case (passphrase present) is unaffected.

        Paired negative for "this breaks served installs": full initialize +
        reload with a zero refusal anywhere, including in the log. The value
        stands in for the one ``install-venya-core.sh`` validates non-empty into
        ``/etc/venya/venya-core.env``.
        """
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        monkeypatch.setenv(_ADMIN_ENV, "test-admin-passphrase-537")
        caplog.set_level("WARNING", logger="venya.ca")

        root = CAManager(str(tmp_path / "ca"))
        root.initialize()
        admin = AdminCAManager(tmp_path / "admin-ca")
        admin.initialize()

        assert root.load_ca()[0] is not None
        assert admin._load_ca_key() is not None
        assert b"ENCRYPTED" in root.ca_key_path.read_bytes()
        assert b"ENCRYPTED" in admin.ca_key_path.read_bytes()
        assert "REFUSED" not in caplog.text, "no refusal on the installer-shaped path"


class TestReadSideUnchanged537:
    """AC4 — the load path keeps its own refusal (behaviour untouched)."""

    def test_ac4_root_load_refuses_encrypted_key_without_passphrase(self, tmp_path, monkeypatch):
        """Encrypted key at rest + env unset -> the same load error as before #537."""
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        manager = CAManager(str(tmp_path / "ca"))
        manager.initialize()

        monkeypatch.delenv(_ROOT_ENV, raising=False)
        with pytest.raises(RuntimeError, match="CA key is encrypted but"):
            manager.load_ca()

    def test_ac4_admin_load_refuses_encrypted_key_without_passphrase(self, tmp_path, monkeypatch):
        """Admin twin of the read-side cell — same wording contract, admin var."""
        monkeypatch.setenv(_ADMIN_ENV, "test-admin-passphrase-537")
        manager = AdminCAManager(tmp_path / "admin-ca")
        manager.initialize()

        monkeypatch.delenv(_ADMIN_ENV, raising=False)
        with pytest.raises(RuntimeError, match="Admin CA key is encrypted but"):
            manager._load_ca_key()


class TestRefusalText537:
    """AC3 — the owner-approved wording, and proof that a stub cannot pass."""

    def test_ac3_message_carries_every_approved_element(self):
        """Root CA renders the approved text byte-for-byte, incl. step 1's var name."""
        message = _unencrypted_key_refusal(_ROOT_ENV)
        _assert_approved_message(message, _ROOT_ENV)
        assert message.splitlines()[0] == (
            "REFUSED: the Venya root CA key must never be stored unencrypted. Nothing was written."
        )

    def test_ac3_admin_var_is_carried_when_configured(self, tmp_path, monkeypatch):
        """AC3 paired: a configured passphrase env NAME is what the text carries.

        ``config.ca_security.key_passphrase_env`` (and the admin override) mean
        the variable is not always VENYA_CA_KEY_PASSPHRASE — the repair step must
        name the one the caller actually reads.
        """
        monkeypatch.delenv("CUSTOM_CA_PASSPHRASE", raising=False)
        manager = CAManager(str(tmp_path / "ca"), CASecurityConfig(key_passphrase_env="CUSTOM_CA_PASSPHRASE"))

        with pytest.raises(RuntimeError) as excinfo:
            manager.initialize()

        message = str(excinfo.value)
        _assert_approved_message(message, "CUSTOM_CA_PASSPHRASE")
        assert _ROOT_ENV not in message, "must not point the operator at a var this deployment does not read"

    def test_ac3_paired_negative_short_message_fails_the_element_check(self):
        """The element check rejects a stub: "error" and the bare first line both fail.

        Without this half, any one-liner that happens to contain "REFUSED:"
        would look like a compliant refusal.
        """
        for stub in ("error", "REFUSED: nothing was written", _unencrypted_key_refusal(_ROOT_ENV).splitlines()[0]):
            with pytest.raises(AssertionError):
                _assert_approved_message(stub, _ROOT_ENV)


class TestSerializerSource537:
    """AC6 — grep-level pin: the plaintext branch is gone from the serializer."""

    def test_ac6_serializer_has_no_plaintext_branch(self):
        """``NoEncryption`` must not appear in _serialize_key_encrypted's source.

        ``inspect.getsource`` pin, so a future re-introduction of a
        warn-and-continue branch fails here even before the behavioural cells do.
        """
        source = inspect.getsource(ca_module._serialize_key_encrypted)
        assert "NoEncryption" not in source, "the serializer must never emit plaintext key bytes"
        assert "BestAvailableEncryption" in source, "the encrypted path must stay in place"
        assert "logger.warning" not in source, "the warn-and-write posture is retired (#537)"

    def test_ac6_guard_reads_the_configured_var_not_the_constant(self, tmp_path, monkeypatch):
        """A configured var that IS set lets the mint through even when
        VENYA_CA_KEY_PASSPHRASE is absent — the guard keys on the caller's var
        name, exactly like the serializer and the load path do.

        A guard hardcoded to the default name would refuse real deployments that
        configure ``ca_security.key_passphrase_env`` (install-venya-core.sh does
        deliver the value under the configured name).
        """
        monkeypatch.setenv("CUSTOM_CA_PASSPHRASE", _TEST_PASSPHRASE)
        monkeypatch.delenv(_ROOT_ENV, raising=False)
        manager = CAManager(str(tmp_path / "ca"), CASecurityConfig(key_passphrase_env="CUSTOM_CA_PASSPHRASE"))

        manager.initialize()

        assert b"ENCRYPTED" in manager.ca_key_path.read_bytes()
        # The key it wrote decrypts with the CUSTOM var's value only.
        assert manager.load_ca()[1] is not None
        with pytest.raises(RuntimeError, match="CA key is encrypted but CUSTOM_CA_PASSPHRASE is not set"):
            monkeypatch.delenv("CUSTOM_CA_PASSPHRASE", raising=False)
            manager.load_ca()
