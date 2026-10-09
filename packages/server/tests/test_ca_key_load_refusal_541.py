# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#541 ca-key-load-plaintext-passphrase-refusal — the READ path refuses too.

``CAManager.load_ca`` and ``AdminCAManager._load_ca_key`` both logged
"CA key is unencrypted but passphrase is set — ignoring passphrase" and then
handed the passphrase to the loader anyway. ``load_pem_private_key`` does not
ignore anything: it raises ``TypeError: Password was given but private key is
not encrypted.``, and ``_deserialize_key`` catches only ``ValueError``, so the
``TypeError`` escaped the manager, the boot path and the health check.

The owner ruled this case (the AC2 fork, 2026-10-09): *"REFUSE LOUDLY, NO
REWRAP"* — "alpha, no customer is upgrading, so no legacy form exists to wrap."
So a legacy plaintext key at rest is not loaded, not re-wrapped, not migrated
and not silently accepted; the manager raises the refusal #537 already approved
for the write path, shared word-for-word.

Every arm of the grid runs on BOTH managers — the bug is twins, so the tests are
twins too. The paired negatives (what must still LOAD) are the deployment-
continuity half: nothing here may break a correctly-configured key.
"""

import inspect
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from server import ca as ca_module
from server.ca import (
    AdminCAManager,
    CAManager,
    _deserialize_key,
    _unencrypted_key_refusal,
)

# The SAME approved element tuple and the SAME element checker the #537 suite
# pins — imported from that suite, never copied, so a wording fork in this leg
# trips #537's own cells instead of passing quietly alongside a variant.
from tests.test_ca_key_write_refusal_537 import _APPROVED_ELEMENTS, _assert_approved_message

_ROOT_ENV = "VENYA_CA_KEY_PASSPHRASE"
_ADMIN_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
_TEST_PASSPHRASE = "test-ca-passphrase-541"
_TEST_ADMIN_PASSPHRASE = "test-admin-passphrase-541"


def _root_manager(tmp_path: Path) -> CAManager:
    """Root/executor CA manager initialized with an ENCRYPTED key on disk."""
    manager = CAManager(str(tmp_path / "ca"))
    manager.initialize()
    return manager


def _admin_manager(tmp_path: Path) -> AdminCAManager:
    """Admin CA manager initialized with an ENCRYPTED key on disk."""
    manager = AdminCAManager(tmp_path / "admin-ca")
    manager.initialize()
    return manager


def _make_key_plaintext(key_path: Path, passphrase: str) -> bytes:
    """Rewrite an encrypted key file as the LEGACY plaintext form, in place.

    This is the exact on-disk shape an older installation left behind: PKCS#8
    unencrypted PEM. Returns the plaintext bytes so a cell can hash them for the
    "the refusal did not touch my key" assertion.
    """
    key = _deserialize_key(key_path.read_bytes(), passphrase.encode("utf-8"))
    plaintext = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path.write_bytes(plaintext)
    return plaintext


class TestPlaintextKeyWithPassphraseSet541:
    """AC1 — the refusal arm, on both planes, with no TypeError escaping."""

    def test_root_load_refuses_plaintext_key_when_passphrase_is_set(self, tmp_path, monkeypatch):
        """Plaintext key at rest + env SET -> the approved refusal, not a TypeError."""
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        manager = _root_manager(tmp_path)
        key_bytes = _make_key_plaintext(manager.ca_key_path, _TEST_PASSPHRASE)

        with pytest.raises(Exception) as excinfo:
            manager.load_ca()

        # The bug class: a TypeError escaping the manager. Assert it explicitly,
        # with a message that says so if this arm ever regresses.
        assert excinfo.type is RuntimeError, f"expected the refusal, got {excinfo.type.__name__}"
        assert not isinstance(excinfo.value, TypeError), "no TypeError may escape load_ca()"
        message = str(excinfo.value)
        assert message.startswith("REFUSED:")
        _assert_approved_message(message, _ROOT_ENV)
        assert _ROOT_ENV in message, "the root refusal must name the root variable"
        assert _ADMIN_ENV not in message, "the root refusal must not name the admin variable"
        # NO REWRAP: the refusal happens before anything is read or written.
        assert manager.ca_key_path.read_bytes() == key_bytes, "the plaintext key must be untouched"
        assert b"ENCRYPTED" not in key_bytes, "fixture precondition: key really is plaintext"

    def test_admin_load_refuses_plaintext_key_when_passphrase_is_set(self, tmp_path, monkeypatch):
        """Admin twin of the refusal cell — same shared text, ADMIN variable named."""
        monkeypatch.setenv(_ADMIN_ENV, _TEST_ADMIN_PASSPHRASE)
        manager = _admin_manager(tmp_path)
        key_bytes = _make_key_plaintext(manager.ca_key_path, _TEST_ADMIN_PASSPHRASE)

        with pytest.raises(Exception) as excinfo:
            manager._load_ca_key()

        assert excinfo.type is RuntimeError, f"expected the refusal, got {excinfo.type.__name__}"
        assert not isinstance(excinfo.value, TypeError), "no TypeError may escape _load_ca_key()"
        message = str(excinfo.value)
        assert message.startswith("REFUSED:")
        _assert_approved_message(message, _ADMIN_ENV)
        assert _ADMIN_ENV in message, "the admin refusal must name the admin variable"
        assert manager.ca_key_path.read_bytes() == key_bytes, "the plaintext key must be untouched"

    def test_both_refusals_are_the_identical_shared_element_tuple(self, tmp_path, monkeypatch):
        """AC1's "one wording, shared with #537" — no load-specific variant anywhere.

        Both managers' messages are compared against the helper's own output for
        their variable, element-for-element, and each must be byte-equal to
        ``_unencrypted_key_refusal(env)`` apart from nothing at all: the fix adds
        no load-specific paragraph.
        """
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        monkeypatch.setenv(_ADMIN_ENV, _TEST_ADMIN_PASSPHRASE)

        root = _root_manager(tmp_path)
        _make_key_plaintext(root.ca_key_path, _TEST_PASSPHRASE)
        with pytest.raises(RuntimeError) as root_exc:
            root.load_ca()

        admin = _admin_manager(tmp_path)
        _make_key_plaintext(admin.ca_key_path, _TEST_ADMIN_PASSPHRASE)
        with pytest.raises(RuntimeError) as admin_exc:
            admin._load_ca_key()

        assert str(root_exc.value) == _unencrypted_key_refusal(_ROOT_ENV)
        assert str(admin_exc.value) == _unencrypted_key_refusal(_ADMIN_ENV)
        for message in (str(root_exc.value), str(admin_exc.value)):
            for element in _APPROVED_ELEMENTS:
                assert element in message, f"missing the approved element {element!r}"


class TestDeploymentContinuity541:
    """AC3's paired negatives — the three configurations that must STILL work."""

    def test_root_plaintext_key_without_passphrase_still_loads(self, tmp_path, monkeypatch):
        """Plaintext key + env UNSET -> loads (nothing new breaks an incumbent read)."""
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        manager = _root_manager(tmp_path)
        _make_key_plaintext(manager.ca_key_path, _TEST_PASSPHRASE)
        monkeypatch.delenv(_ROOT_ENV, raising=False)

        cert, private_key = manager.load_ca()

        assert cert is not None
        assert private_key is not None

    def test_admin_plaintext_key_without_passphrase_still_loads(self, tmp_path, monkeypatch):
        """Admin twin of the continuity arm."""
        monkeypatch.setenv(_ADMIN_ENV, _TEST_ADMIN_PASSPHRASE)
        manager = _admin_manager(tmp_path)
        _make_key_plaintext(manager.ca_key_path, _TEST_ADMIN_PASSPHRASE)
        monkeypatch.delenv(_ADMIN_ENV, raising=False)

        assert manager._load_ca_key() is not None

    def test_root_encrypted_key_with_passphrase_still_loads(self, tmp_path, monkeypatch):
        """The correct configuration (encrypted at rest + passphrase) is unaffected."""
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        manager = _root_manager(tmp_path)

        assert b"ENCRYPTED" in manager.ca_key_path.read_bytes()
        cert, private_key = manager.load_ca()
        assert cert is not None and private_key is not None

    def test_admin_encrypted_key_with_passphrase_still_loads(self, tmp_path, monkeypatch):
        """Admin twin of the correct-configuration arm."""
        monkeypatch.setenv(_ADMIN_ENV, _TEST_ADMIN_PASSPHRASE)
        manager = _admin_manager(tmp_path)

        assert b"ENCRYPTED" in manager.ca_key_path.read_bytes()
        assert manager._load_ca_key() is not None

    def test_root_encrypted_key_without_passphrase_keeps_the_old_message(self, tmp_path, monkeypatch):
        """Encrypted key + env UNSET -> the pre-existing arm, wording unchanged.

        This is the AC2 instruction "keep the existing raise untouched" — the
        message is still the named-variable one, NOT the #537 refusal.
        """
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        manager = _root_manager(tmp_path)
        monkeypatch.delenv(_ROOT_ENV, raising=False)

        with pytest.raises(RuntimeError, match="CA key is encrypted but") as excinfo:
            manager.load_ca()

        assert "REFUSED:" not in str(excinfo.value), "this arm keeps its own message"

    def test_admin_encrypted_key_without_passphrase_keeps_the_old_message(self, tmp_path, monkeypatch):
        """Admin twin of the unchanged-arm cell."""
        monkeypatch.setenv(_ADMIN_ENV, _TEST_ADMIN_PASSPHRASE)
        manager = _admin_manager(tmp_path)
        monkeypatch.delenv(_ADMIN_ENV, raising=False)

        with pytest.raises(RuntimeError, match="Admin CA key is encrypted but") as excinfo:
            manager._load_ca_key()

        assert "REFUSED:" not in str(excinfo.value)


class TestMisleadingLogDeleted541:
    """AC5 — the log line must match what the code does, so it is gone."""

    def test_ignoring_passphrase_string_appears_nowhere_in_ca(self):
        """Negative on the DELETION: no "ignoring passphrase" survives in ca.py.

        A leftover warning is exactly the AC5 doc-drift half — the code no longer
        ignores anything, so the sentence cannot remain anywhere in the module.
        """
        source = inspect.getsource(CAManager) + inspect.getsource(AdminCAManager)
        full = inspect.getsource(ca_module)
        assert "ignoring passphrase" not in full, "the misleading warning must be deleted at both sites"
        assert "unencrypted but passphrase is set" not in full, "no softened variant of the log either"
        # And the refusal is reachable from both managers, not just one.
        assert (
            full.count("_unencrypted_key_refusal(self._key_passphrase_env)") >= 2
        ), "both load sites must raise the shared refusal"
        assert "ignoring passphrase" not in source

    def test_load_path_does_not_log_a_warning_on_the_refusal(self, tmp_path, monkeypatch, caplog):
        """The refusal is an exception, not a warning-and-continue (caplog half).

        RED at HEAD: the old path emitted a WARNING and then raised TypeError
        from the loader, so a monitoring rule keyed on the warning fired while
        the real failure went to the traceback path.
        """
        monkeypatch.setenv(_ROOT_ENV, _TEST_PASSPHRASE)
        manager = _root_manager(tmp_path)
        _make_key_plaintext(manager.ca_key_path, _TEST_PASSPHRASE)
        caplog.set_level("WARNING", logger="venya.ca")

        with pytest.raises(RuntimeError):
            manager.load_ca()

        assert "REFUSED" not in caplog.text, "a refusal is raised, never logged as a warning"
        assert "ignoring" not in caplog.text.lower(), "nothing is ignored on this path anymore"
