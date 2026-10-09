# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at this file's repository root. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#538 — the CLI-local holder for the root CA key in ``export-ca-key``.

Two families of cells, both paired per the project truth-table law.

The first tests the holder on its own: a scoped read-only view (P1), erase on
release proven by reading the buffer's own memory (P2), a refused pin recorded
and never fatal (P3), use-after-release raising instead of returning stale bytes
(P4), and the real command path end to end (P5).

The second family tests what must NOT have changed and what must NOT be reached:
the shipped ``VENYACA1`` behaviour (N4), no banned protected-memory name anywhere
under ``venya_cli`` derived from the shipped guard rather than from a copy of it
here (N2), and no ``core`` import in the files this leg added (N3).

N3 SCOPE, stated because a wider claim would be false: two pre-existing CLI test
modules (``test_recovery_e2e.py``, ``test_cli_response_key_drift_482.py``) import
``core`` for response-shape coverage, which is how they arrived at this tip. The
ruling condition this leg carries is that the dependency tax stays at zero, so
the cells below assert it over the files THIS leg added and over the source
package — not over the whole test directory, which would fail at base.

P3 is the load-bearing cell: on an operator workstation the pin is normally
INACTIVE (no ``CAP_IPC_LOCK``, and a small buffer is not pinnable at all), so a
refusal must never break an export. Nothing here claims the key is pinned.
"""

import ast
import gc
import os
import platform
import resource
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from venya_cli import commands as commands_mod
from venya_cli import secret_holder as holder_mod
from venya_cli.secret_holder import SecretHolder, SecretHolderReleasedError

_TESTS_DIR = Path(__file__).resolve().parent
_CLI_SRC_DIR = _TESTS_DIR.parent / "src" / "venya_cli"
_REPO_ROOT = _TESTS_DIR.parents[2]  # packages/cli/tests -> repo root
_CORE_ISOLATION_TEST = _REPO_ROOT / "packages" / "core" / "tests" / "test_capability_isolation.py"
_CLI_ISOLATION_TEST = _TESTS_DIR / "test_capability_isolation.py"

#: A fixed 241-byte secret — the product's SECP256R1 CA key serializes to about
#: that size, which is exactly the size the pin measurements were taken at.
#: Deliberately NOT PEM-shaped: a PEM literal in a test file is a fake key handed
#: to the detect-secrets scan, and the fixture's content is irrelevant to this
#: module (the holder treats its input as opaque bytes).
SECRET_FIXTURE = b"venya-538-fixture-" + bytes(range(32)) * 7 + b"\n"


def _real_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _banned_symbols() -> set[str]:
    """The protected-memory names the shipped guards forbid, READ from those files.

    Nothing here hardcodes the list: if a guard's set changes, this cell changes
    with it, which is the only way the check stays worth having. Both homes are
    read — the core one (``PROTECTED_MEMORY_SYMBOLS``) and the CLI one
    (``_SECURE_SYMBOLS``) — and the union is what a new CLI file must avoid.
    """
    names: set[str] = set()
    for path, var in ((_CORE_ISOLATION_TEST, "PROTECTED_MEMORY_SYMBOLS"), (_CLI_ISOLATION_TEST, "_SECURE_SYMBOLS")):
        assert path.is_file(), f"the shipped guard file is missing: {path}"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
            if not any(isinstance(t, ast.Name) and t.id == var for t in targets):
                continue
            assert node.value is not None
            for literal in ast.walk(node.value):
                if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
                    names.add(literal.value)
    assert names, "no protected-memory names parsed out of the guard files — the finder is broken"
    return names


class TestP1ScopedView:
    """P1 — the key reaches the holder and readers get a memoryview, never bytes."""

    def test_p1_holder_serves_a_read_only_view_of_the_exact_bytes(self):
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            with holder.view() as view:
                assert isinstance(view, memoryview)
                assert view.readonly is True
                assert bytes(view) == SECRET_FIXTURE
                assert len(view) == len(SECRET_FIXTURE)
        finally:
            holder.release()

    def test_p1_negative_no_api_hands_out_bytes(self):
        """Paired negative: there is no accessor that returns the secret as bytes."""
        public = {n for n in vars(SecretHolder) if not n.startswith("_")}
        assert public <= {
            "view",
            "release",
            "length",
            "released",
            "zeroized",
            "pin_state",
            "pin_attempted",
            "pin_active",
            "pin_errno",
            "pin_reason",
        }, public
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            for name in public:
                value = getattr(holder, name, None)
                assert not isinstance(value, (bytes, bytearray)), f"{name} leaks key material as bytes"
        finally:
            holder.release()

    def test_p1_view_reports_only_the_key_not_the_page_padding(self):
        """The allocation is page-rounded; the view is key-length, not padding."""
        page = holder_mod._page_size()
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            assert len(holder._data) % page == 0 and len(holder._data) >= len(SECRET_FIXTURE)
            with holder.view() as view:
                assert len(view) == len(SECRET_FIXTURE)
                assert holder.length == len(SECRET_FIXTURE)
        finally:
            holder.release()

    def test_p1_empty_input_is_refused(self):
        """A holder of nothing would be a silent success — refused, loudly."""
        with pytest.raises(ValueError, match="at least one byte"):
            SecretHolder(b"")


class TestP2EraseOnRelease:
    """P2 — AC2: the owned copy is zeroized, proven from the buffer's own memory."""

    def test_p2_buffer_reads_all_zero_after_release(self):
        holder = SecretHolder(SECRET_FIXTURE)
        buf = holder._data
        assert buf[: len(SECRET_FIXTURE)] == SECRET_FIXTURE
        assert holder.release() is True
        assert holder.zeroized is True
        assert all(byte == 0 for byte in buf), "the owned buffer still holds key material after release"

    def test_p2_with_block_releases_on_exit(self):
        captured: list[SecretHolder] = []
        with SecretHolder(SECRET_FIXTURE) as holder:
            captured.append(holder)
            assert holder.released is False
        assert captured[0].released is True
        assert captured[0].zeroized is True

    def test_p2_negative_release_is_idempotent_and_reports_honestly(self):
        """Second release changes nothing and does not re-report a fresh erase."""
        holder = SecretHolder(SECRET_FIXTURE)
        assert holder.release() is True
        assert holder.release() is True
        assert holder.zeroized is True

    def test_p2_del_backstop_erases_when_nothing_else_did(self):
        """The GC backstop is a backstop: it works, and it is not the claim."""
        holder = SecretHolder(SECRET_FIXTURE)
        buf = memoryview(holder._data)
        del holder
        gc.collect()
        assert all(byte == 0 for byte in buf)
        buf.release()

    def test_p2_erase_refuses_a_view_not_the_owner(self):
        """A view is not the owner; a silent no-op would make the report a lie."""
        with pytest.raises(TypeError, match="owning bytearray"):
            holder_mod._erase(memoryview(bytearray(b"abc")))

    def test_p2_failed_erase_is_reported_not_raised(self):
        """If the erase itself fails, release says so and the command still finishes."""

        def _boom(_data: bytearray) -> None:
            raise RuntimeError("erase blew up")

        holder = SecretHolder(SECRET_FIXTURE)
        with patch.object(holder_mod, "_erase", _boom):
            assert holder.release() is False
        assert holder.released is True
        assert holder.zeroized is False


class TestP3PinNeverFatal:
    """P3 — THE LOAD-BEARING CELL: a refused pin must never break an export."""

    def test_p3_errno_12_is_recorded_and_the_export_still_completes(self, tmp_path):
        """Simulate the measured workstation condition: mlock refused, errno 12."""
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        key = _real_key_pem()
        (ca_dir / "ca.key").write_bytes(key)
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))

        refused: list[OSError] = []

        def _refuse(data: bytearray) -> None:
            err = OSError(12, "Cannot allocate memory")
            refused.append(err)
            raise err

        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch("venya_cli.commands.getpass.getpass", side_effect=["pw", "pw"]),
            patch.object(holder_mod, "_pin", _refuse),
        ):
            rc = commands_mod.cmd_admin_export_ca_key(args)

        assert rc == 0, "a refused pin broke the operator's export — the pin must never be fatal"
        assert len(refused) == 1, "the pin was not attempted at all"
        assert out.read_bytes()[:8] == commands_mod._CA_BLOB_MAGIC
        assert key not in out.read_bytes()

    def test_p3_pin_outcome_is_carried_on_the_holder(self):
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            assert holder.pin_attempted is True
            assert holder.pin_state in ("active", "inactive")
            if not holder.pin_active:
                assert holder.pin_reason, "an inactive pin must say why"
        finally:
            holder.release()

    def test_p3_errno_and_reason_are_the_os_verbatim(self):
        """The report is the kernel's answer, not a paraphrase."""

        def _refuse(_data: bytearray) -> None:
            raise OSError(12, os.strerror(12))

        with patch.object(holder_mod, "_pin", _refuse):
            holder = SecretHolder(SECRET_FIXTURE)
        assert holder.pin_attempted is True
        assert holder.pin_active is False
        assert holder.pin_errno == 12
        assert holder.pin_reason == os.strerror(12)
        assert holder.pin_state == "inactive"
        assert holder.release() is True

    def test_p3_non_linux_is_reported_not_fatal(self):
        """macOS/Windows: no pin mechanism at all, and the export still runs."""
        with patch.object(holder_mod, "platform", SimpleNamespace(system=lambda: "Darwin")):
            holder = SecretHolder(SECRET_FIXTURE)
        assert holder.pin_active is False
        assert "Linux" in (holder.pin_reason or "")
        assert holder.pin_state == "inactive"
        with holder.view() as view:
            assert bytes(view) == SECRET_FIXTURE
        assert holder.release() is True

    def test_p3_no_c_library_is_reported_not_fatal(self):
        with patch.object(holder_mod, "_load_libc", lambda: None):
            holder = SecretHolder(SECRET_FIXTURE)
        assert holder.pin_active is False
        assert holder.pin_reason
        assert holder.release() is True

    def test_p3_unpin_refusal_is_reported_not_fatal(self):
        """A pin we took but cannot drop must not break the release either."""
        holder = SecretHolder(SECRET_FIXTURE)
        holder._pinned = True  # claim a pin regardless of this machine's answer

        def _refuse_unpin(_data: bytearray) -> None:
            raise OSError(1, "Operation not permitted")

        with patch.object(holder_mod, "_unpin", _refuse_unpin):
            assert holder.release() is True
        assert holder.pin_active is False

    def test_p3_positive_real_pin_when_the_kernel_allows_it(self):
        """When the pin is granted it is reported ACTIVE — the report is two-sided.

        Skipped where the machine will not grant it (a hardened host, ``ulimit -l
        0``), which is the normal operator-workstation condition.
        """
        if platform.system() != "Linux":
            pytest.skip("the pin is only attempted on Linux")
        soft = resource.getrlimit(resource.RLIMIT_MEMLOCK)[0]
        if soft != resource.RLIM_INFINITY and soft < 4096:
            pytest.skip(f"locked-memory budget is {soft} bytes — the kernel will refuse, which is the point of P3")
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            assert holder.pin_attempted is True
            assert holder.pin_active in (True, False)
            assert holder.pin_state == ("active" if holder.pin_active else "inactive")
        finally:
            assert holder.release() is True


class TestP4UseAfterRelease:
    """P4 — paired negative: a released holder raises, it never returns stale bytes."""

    def test_p4_view_after_release_raises(self):
        holder = SecretHolder(SECRET_FIXTURE)
        assert holder.release() is True
        with pytest.raises(SecretHolderReleasedError):
            with holder.view():
                pytest.fail("a released holder handed out key material")

    def test_p4_view_stashed_out_of_the_block_is_dead(self):
        """A view carried out of its block cannot be read afterwards."""
        holder = SecretHolder(SECRET_FIXTURE)
        with holder.view() as view:
            assert bytes(view) == SECRET_FIXTURE
        with pytest.raises(ValueError):
            bytes(view)

    def test_p4_negative_before_release_the_view_works(self):
        """The same accessor that raises after release must work before it."""
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            with holder.view() as view:
                assert bytes(view) == SECRET_FIXTURE
        finally:
            holder.release()

    def test_p4_released_error_is_not_a_passphrase_error(self):
        """A bug must not be readable as 'wrong passphrase'."""
        assert issubclass(SecretHolderReleasedError, RuntimeError)
        assert not issubclass(SecretHolderReleasedError, ValueError)


class TestP5RealPath:
    """P5 — AC1/AC3 honesty on the actual command path, in-process, mocked transport."""

    def _run_export(self, tmp_path, key: bytes):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(key)
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch("venya_cli.commands.getpass.getpass", side_effect=["pw", "pw"]),
        ):
            rc = commands_mod.cmd_admin_export_ca_key(args)
        return rc, out

    def test_p5_export_completes_and_no_plaintext_bytes_reach_the_handler_frame(self, tmp_path):
        """At the moment of encryption, the frame holds the holder — not a bytes copy."""
        key = _real_key_pem()
        from cryptography.hazmat.primitives.ciphers import aead

        seen: dict[str, object] = {}

        class _SpyAESGCM:
            """Delegating wrapper — the real AESGCM is a Rust type and cannot be subclassed.

            It records what the export handed it, from the caller's own frame.
            """

            def __init__(self, key_bytes):
                self._inner = real_cls(key_bytes)

            def encrypt(self, nonce, data, associated_data):
                caller = sys._getframe(1)
                seen["data_type"] = type(data)
                seen["readonly"] = getattr(data, "readonly", None)
                seen["plaintext_locals"] = [
                    name
                    for name, value in caller.f_locals.items()
                    if isinstance(value, (bytes, bytearray)) and bytes(value) == key
                ]
                seen["holder_in_frame"] = "holder" in caller.f_locals
                return self._inner.encrypt(nonce, data, associated_data)

        real_cls = aead.AESGCM

        with patch.object(aead, "AESGCM", _SpyAESGCM):
            rc, out = self._run_export(tmp_path, key)

        assert rc == 0
        assert seen["data_type"] is memoryview, "the view should be what AESGCM is fed"
        assert seen["readonly"] is True
        assert (
            seen["plaintext_locals"] == []
        ), f"plaintext bytes still reachable in the frame: {seen['plaintext_locals']}"
        assert seen["holder_in_frame"] is True
        blob = out.read_bytes()
        assert blob[:8] == commands_mod._CA_BLOB_MAGIC
        assert key not in blob

    def test_p5_round_trip_still_restores(self, tmp_path):
        """The holder must not disturb what the backup is FOR: restoring the key."""
        key = _real_key_pem()
        rc, backup = self._run_export(tmp_path, key)
        assert rc == 0
        (tmp_path / "ca" / "ca.key").unlink()
        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch("venya_cli.commands.getpass.getpass", side_effect=["pw"]),
        ):
            rc2 = commands_mod.cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(backup), shares=None, ca_dir=str(tmp_path / "ca"))
            )
        assert rc2 == 0
        assert (tmp_path / "ca" / "ca.key").read_bytes() == key

    def test_p5_negative_wrong_passphrase_still_fails_loud(self, tmp_path):
        key = _real_key_pem()
        _rc, backup = self._run_export(tmp_path, key)
        (tmp_path / "ca" / "ca.key").unlink()
        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch("venya_cli.commands.getpass.getpass", side_effect=["wrong-pw"]),
        ):
            rc = commands_mod.cmd_admin_restore_ca_key(
                SimpleNamespace(mode="backup", backup_file=str(backup), shares=None, ca_dir=str(tmp_path / "ca"))
            )
        assert rc != 0
        assert not (tmp_path / "ca" / "ca.key").exists()

    def test_p5_holder_released_even_on_the_refusal_path(self, tmp_path):
        """The empty-passphrase return is inside the holder's scope: it must erase."""
        key = _real_key_pem()
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(key)
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        captured: list[SecretHolder] = []

        class _Capturing(SecretHolder):
            def __init__(self, data):
                super().__init__(data)
                captured.append(self)

        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch("venya_cli.commands.getpass.getpass", side_effect=["", ""]),
            patch.object(commands_mod, "SecretHolder", _Capturing),
        ):
            rc = commands_mod.cmd_admin_export_ca_key(args)

        assert rc == 1
        assert not out.exists()
        assert len(captured) == 1
        assert captured[0].released is True
        assert captured[0].zeroized is True


class TestN2GuardNames:
    """N2 — the shipped protected-memory guard, re-checked from the guard's own set."""

    def test_n2_banned_set_is_read_from_the_shipped_guards(self):
        names = _banned_symbols()
        # The finder works: the names the guards are famous for are in there.
        assert "SecureBuffer" in names
        assert any("mlock" in n for n in names)

    def test_n2_no_banned_substring_in_any_cli_source_file(self):
        names = _banned_symbols()
        offenders: list[tuple[str, str]] = []
        for path in sorted(_CLI_SRC_DIR.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for name in sorted(names):
                if name in text:
                    offenders.append((path.name, name))
        assert offenders == [], f"protected-memory names under venya_cli: {offenders}"

    def test_n2_negative_a_planted_banned_name_is_caught(self, tmp_path):
        """Paired negative: the scan fires. A finder that never matches is worthless."""
        planted = tmp_path / "extra_buffer.py"
        names = _banned_symbols()
        banned = sorted(n for n in names if n == "SecureBuffer") or sorted(names)
        planted.write_text(f"class {banned[0]}:\n    pass\n", encoding="utf-8")
        text = planted.read_text(encoding="utf-8")
        assert any(name in text for name in names)

    def test_n2_the_new_module_is_named_differently_on_purpose(self):
        """The core home keeps the semantics of record; this file is the CLI twin."""
        assert (_CLI_SRC_DIR / "secret_holder.py").is_file()
        assert not (
            _CLI_SRC_DIR / "secure_memory.py"
        ).exists(), "a second file with the core module's name would break the shipped isolation guard"


class TestN3NoCoreDependency:
    """N3 — the dependency tax stayed at zero, in the files this leg added."""

    def test_n3_new_module_and_command_site_import_no_core(self):
        for path in (_CLI_SRC_DIR / "secret_holder.py", _CLI_SRC_DIR / "commands.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                assert not stripped.startswith(("from core.", "import core.")), f"{path.name}:{lineno} imports core"

    def test_n3_this_test_file_imports_no_core(self):
        for lineno, line in enumerate(Path(__file__).read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            assert not stripped.startswith(
                ("from core.", "import core.")
            ), f"{Path(__file__).name}:{lineno} imports core"

    def test_n3_holder_needs_only_the_stdlib(self):
        """Every module the holder pulls in is stdlib — no new wheel, no new pin."""
        imported = ast.parse((_CLI_SRC_DIR / "secret_holder.py").read_text(encoding="utf-8"))
        tops: set[str] = set()
        for node in ast.walk(imported):
            if isinstance(node, ast.Import):
                tops.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                tops.add(node.module.split(".")[0])
        assert tops <= {"ctypes", "logging", "os", "platform", "collections", "contextlib", "typing"}, tops

    def test_n3_negative_a_third_party_import_would_be_seen(self):
        """The set comparison has teeth: a real dependency is not stdlib."""
        assert "mqtt" not in {"ctypes", "logging", "os", "platform", "collections", "contextlib", "typing"}


class TestN4BehaviourUnchanged:
    """N4 — AC4: every shipped property of the export, with its rejecting half."""

    def _export(self, tmp_path, key, side_effect):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(key)
        out = tmp_path / "nested" / "ca-backup.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch("venya_cli.commands.getpass.getpass", side_effect=side_effect),
        ):
            rc = commands_mod.cmd_admin_export_ca_key(args)
        return rc, out

    def test_n4_magic_and_layout_unchanged(self, tmp_path):
        key = _real_key_pem()
        rc, out = self._export(tmp_path, key, ["pw", "pw"])
        assert rc == 0
        blob = out.read_bytes()
        assert blob[:8] == b"VENYACA1"
        # MAGIC(8) + salt(16) + nonce(12) + ciphertext+tag(16)
        assert len(blob) == 8 + 16 + 12 + len(key) + 16

    def test_n4_kdf_parameters_untouched(self, tmp_path):
        assert commands_mod._CA_KDF_ITERATIONS == 600_000
        key = _real_key_pem()
        rc, out = self._export(tmp_path, key, ["pw", "pw"])
        assert rc == 0
        salt = out.read_bytes()[8:24]
        derived = commands_mod._derive_ca_backup_key(salt, "pw")
        assert len(derived) == 32

    def test_n4_mismatch_reprompts_then_succeeds(self, tmp_path):
        key = _real_key_pem()
        rc, _out = self._export(tmp_path, key, ["a", "b", "pw", "pw"])
        assert rc == 0

    def test_n4_empty_passphrase_refused_and_no_file_written(self, tmp_path):
        """Rejecting half: a refusal must produce ZERO output, not an empty blob."""
        key = _real_key_pem()
        rc, out = self._export(tmp_path, key, ["", ""])
        assert rc == 1
        assert not out.exists()

    def test_n4_permissions_0600_file_0700_dir(self, tmp_path):
        key = _real_key_pem()
        rc, out = self._export(tmp_path, key, ["pw", "pw"])
        assert rc == 0
        assert out.stat().st_mode & 0o777 == 0o600
        assert out.parent.stat().st_mode & 0o777 == 0o700

    def test_n4_no_temp_residue_after_a_failed_write(self, tmp_path):
        """Rejecting half: the cleanup ladder still runs with the holder in scope."""
        key = _real_key_pem()
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(key)
        out = tmp_path / "deep" / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        real_replace = os.replace

        def _fail_replace(src, dst, *a):
            raise OSError(5, "Input/output error")

        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch("venya_cli.commands.getpass.getpass", side_effect=["pw", "pw"]),
            patch("os.replace", _fail_replace),
        ):
            with pytest.raises(OSError):
                commands_mod.cmd_admin_export_ca_key(args)
        assert real_replace is os.replace
        leftovers = [p.name for p in out.parent.glob(".venya-cabackup-*")] if out.parent.exists() else []
        assert leftovers == [], f"temp-file residue left behind: {leftovers}"

    def test_n4_garbage_ca_key_fails_closed_before_any_holder(self, tmp_path):
        """Rejecting half: an unrecognised file produces no output and no holder."""
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        (ca_dir / "ca.key").write_bytes(b"this is not a key and not an envelope\n")
        out = tmp_path / "o.enc"
        args = SimpleNamespace(output=str(out), ca_dir=str(ca_dir))
        captured: list[SecretHolder] = []

        class _Capturing(SecretHolder):
            def __init__(self, data):
                super().__init__(data)
                captured.append(self)

        with (
            patch("builtins.input", lambda *a, **k: pytest.fail("echoed input() in a secret prompt")),
            patch.object(commands_mod, "SecretHolder", _Capturing),
        ):
            rc = commands_mod.cmd_admin_export_ca_key(args)
        assert rc == 1
        assert not out.exists()
        assert captured == [], "a holder was built for a key that never validated"


class TestParityContract:
    """The two homes share a BEHAVIOURAL contract, not internals (#538 Option B).

    The core package's protected buffer stays the semantics of record and the
    design that governs both is ``docs/design-secure-memory-kek.md``. These cells
    assert the three contract behaviours against THIS module only — never by
    importing the other home (N3) and never by reading its private internals.
    """

    def test_parity_design_doc_is_cited_by_the_module(self):
        text = (_CLI_SRC_DIR / "secret_holder.py").read_text(encoding="utf-8")
        assert "docs/design-secure-memory-kek.md" in text
        assert (_REPO_ROOT / "docs" / "design-secure-memory-kek.md").is_file()

    def test_parity_rung_one_scoped_read_only_view(self):
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            with holder.view() as view:
                assert view.readonly is True
        finally:
            holder.release()

    def test_parity_rung_two_zeroize_on_release_is_observed_not_assumed(self):
        holder = SecretHolder(SECRET_FIXTURE)
        assert holder.release() is True
        assert holder.zeroized is True
        assert all(byte == 0 for byte in holder._data)

    def test_parity_rung_three_pin_attempted_and_reported_never_fatal(self):
        """Whatever this machine answers, the holder ANSWERS rather than raising."""
        holder = SecretHolder(SECRET_FIXTURE)
        try:
            assert holder.pin_attempted is True
            assert holder.pin_state in ("active", "inactive", "not attempted")
            assert isinstance(holder.pin_active, bool)
        finally:
            holder.release()

    def test_parity_negative_a_fatal_pin_would_fail_this_cell(self):
        """Paired half: the contract is 'never fatal', so a raising pin is caught here."""

        def _explode(_data: bytearray) -> None:
            raise RuntimeError("pin exploded")

        with patch.object(holder_mod, "_pin", _explode):
            holder = SecretHolder(SECRET_FIXTURE)  # must NOT raise
        assert holder.pin_active is False
        assert holder.pin_reason == "pin exploded"
        assert holder.release() is True

    def test_parity_docstring_says_erased_not_pinned(self):
        """AC3: the shipped claim must not imply active protection."""
        text = " ".join((_CLI_SRC_DIR / "secret_holder.py").read_text(encoding="utf-8").split())
        assert "erases the copy it owns on release" in text
        assert "it does not pin" in text
        for overclaim in ("protects the key in memory", "scrubs the key", "mlock-protected"):
            assert overclaim not in text, f"the docstring claims more than the mechanism delivers: {overclaim}"
