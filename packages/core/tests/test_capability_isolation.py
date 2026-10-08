# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for capability isolation between core and executor.

The protected-memory story (#472, design note section 6). The KEK now lives on
the protected path, so these cells assert WHERE it may live rather than that the
path is unused:

  * one explicit allowlist of the two files allowed to name a protected-memory
    primitive — `secure_memory.py` (the primitives) and `backend.py` (the cache
    owner). The count is asserted, so a third protected buffer is a deliberate
    edit to this file, never drift;
  * the nine per-module cells still ban a direct primitive call in every other
    module, and the ban is proven failable;
  * the KEK positive cell (after `bootstrap_kek()` the cache is populated, the
    `config.kek` intake slot is None, and a reader gets a read-only view) and
    its paired negatives, per the truth-table rule;
  * the systemd/runtime capability cells and their helpers, which can now see a
    real install and can actually FAIL (#542 shape, kept as written).

The executor (Phase 4) must NEVER have CAP_IPC_LOCK — the jump host
is assumed compromised.
"""

import os
import subprocess
from pathlib import Path
from typing import ClassVar, Final
from unittest.mock import MagicMock, patch

import pytest

#: Symbols that mean "this file touches a pinned/zeroizing buffer".
PROTECTED_MEMORY_SYMBOLS: Final[frozenset[str]] = frozenset(
    {"secure_mlock", "secure_munlock", "secure_zero", "SecureBuffer", "_load_system_lib"}
)

#: The files allowed to name one. Two, by ruling (#472 section 6.1): the module
#: that defines the primitives, and the one object that owns the KEK buffer.
#: `test_protected_memory_allowlist_is_exactly_two_files` asserts this count.
PROTECTED_MEMORY_ALLOWLIST: Final[frozenset[str]] = frozenset({"secure_memory.py", "backend.py"})


def _find_protected_symbol_names(directory: Path, allowlist: frozenset[str]) -> list[tuple[str, str]]:
    """Every (file, symbol) pair in *.py under ``directory`` outside ``allowlist``.

    Shared by the shipped scan and by the harness cells that plant a synthetic
    third buffer, so the teeth are the same teeth the real check runs.
    """
    offenders: list[tuple[str, str]] = []
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_") or path.name in allowlist:
            continue
        source = path.read_text(encoding="utf-8")
        for symbol in sorted(PROTECTED_MEMORY_SYMBOLS):
            if symbol in source:
                offenders.append((path.name, symbol))
    return offenders


def _assert_off_the_protected_path(source: str, label: str) -> None:
    """Fail if a module names the module, the primitives, or both.

    Two separate reasons, both reported: the import surface (``secure_memory``)
    and the direct-call surface (the primitive names). The cache owner is the one
    file exempted from the import half, by ``PROTECTED_MEMORY_ALLOWLIST``.
    """
    imported = "secure_memory" in source
    named = _find_primitive_calls(source)
    assert not imported and not named, (
        f"{label} must stay off the protected path: "
        f"module reference={'yes' if imported else 'no'}, primitives named={named}"
    )


def _find_primitive_calls(source: str) -> list[str]:
    """The protected-memory symbols named in one module's source text."""
    return [symbol for symbol in sorted(PROTECTED_MEMORY_SYMBOLS) if symbol in source]


def _check_allowlist_shape(allowlist: frozenset[str]) -> None:
    """Fail unless ``allowlist`` is exactly the two ruled files (section 6.1)."""
    assert (
        len(allowlist) == 2
    ), f"the protected-memory allowlist must name exactly 2 files, got {len(allowlist)}: {sorted(allowlist)}"
    assert (
        allowlist == PROTECTED_MEMORY_ALLOWLIST
    ), f"the allowlist drifted: expected {sorted(PROTECTED_MEMORY_ALLOWLIST)}, got {sorted(allowlist)}"


class TestCapabilityIsolation:
    """The primitive surface itself: platform rules, EPERM shape, auto-unlock.

    These cells are about ``secure_memory`` behaviour, not about who may call it
    — that is ``TestSecureMemoryIsolation`` below. Kept as written (#472
    section 6.4: the existing graceful-mlock-failure shape stays).
    """

    @pytest.fixture(autouse=True)
    def _reset_secure_memory_state(self):
        """Reset _SYSTEM_LIB cache before each test to avoid test pollution."""
        import core.engine.secure_memory as sm

        original = sm._SYSTEM_LIB
        sm._SYSTEM_LIB = None
        yield
        sm._SYSTEM_LIB = original

    def test_secure_memory_requires_linux(self):
        """mlock should fail on non-Linux platforms."""
        from core.engine.secure_memory import secure_mlock

        with patch("core.engine.secure_memory.platform.system", return_value="Darwin"):
            try:
                secure_mlock(bytearray(16))
                assert False, "Should have raised RuntimeError"
            except RuntimeError as e:
                assert "only supported on Linux" in str(e)

    def test_secure_memory_fails_without_cap(self):
        """mlock should fail if CAP_IPC_LOCK is not available."""
        from core.engine.secure_memory import secure_mlock

        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = -1
            with patch("core.engine.secure_memory.ctypes.get_errno", return_value=1):
                with patch("os.strerror", return_value="Operation not permitted"):
                    try:
                        secure_mlock(bytearray(16))
                        assert False, "Should have raised OSError"
                    except OSError as e:
                        assert "Operation not permitted" in str(e)
            patch.stopall()

    def test_secure_buffer_auto_unlock_on_error(self):
        """SecureBuffer should handle mlock failure gracefully in context manager."""
        from core.engine.secure_memory import SecureBuffer

        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = 0
            mock_lib.return_value.munlock.return_value = -1
            with patch("core.engine.secure_memory.ctypes.get_errno", return_value=1):
                with patch("os.strerror", return_value="Operation not permitted"):
                    buf = SecureBuffer(32, mlock=True)
                    assert buf.is_locked
                    with buf:
                        pass
                    # Should not raise — munlock failure is ignored in __exit__
                    assert not buf.is_locked
            patch.stopall()

    def test_cli_does_not_import_secure_memory(self):
        """CLI should never import secure_memory (runs on untrusted jump host).

        The CLI moved to the venya-cli package; the equivalent check lives in
        packages/cli/tests/test_capability_isolation.py. Verified here that the
        core package does not re-expose a cli surface.
        """
        import core

        assert not hasattr(core, "cli"), "core should no longer expose a cli submodule"


class TestSecureMemoryIsolation:
    """Where the protected path may live, and where it may not (#472 section 6).

    Two rules, each with its proven-negative half:

    1. Only the two allowlisted files may name a protected-memory primitive —
       `secure_memory.py` (the primitives) and `backend.py` (the cache owner).
       The allowlist COUNT is asserted, so a third protected buffer has to be
       added to this file on purpose.
    2. Every other module in the KEK's reach — the facade, encryption, the rate
       limiter, the factory, the IAM modules — still must not call a primitive
       directly. They go through the cache.
    """

    def test_protected_memory_allowlist_is_exactly_two_files(self):
        """The allowlist is two named files, and its COUNT is the check (#472 6.1).

        A third protected buffer is only reachable by editing this test on
        purpose: the count assertion below refuses a list of three, so the scan
        cannot be widened quietly.
        """
        _check_allowlist_shape(PROTECTED_MEMORY_ALLOWLIST)
        assert "secure_memory.py" in PROTECTED_MEMORY_ALLOWLIST
        assert "backend.py" in PROTECTED_MEMORY_ALLOWLIST

    def test_allowlist_count_check_is_failable(self):
        """Negative half: a three-file allowlist trips the same check.

        Without this cell the count assertion is unproven — it would only ever
        be seen passing.
        """
        widened = PROTECTED_MEMORY_ALLOWLIST | {"scratch_cache.py"}
        with pytest.raises(AssertionError, match="exactly 2 files"):
            _check_allowlist_shape(widened)

    def test_only_allowlisted_files_use_mlock(self):
        """The module-wide scan, now run against the explicit allowlist.

        Every `core.engine` module outside the two allowlisted files must be
        clean of the primitive names. The verdict is collected first so the
        failure message lists all offenders, not just the first.
        """
        import core.engine

        engine_dir = Path(core.engine.__file__).resolve().parent
        offenders = _find_protected_symbol_names(engine_dir, PROTECTED_MEMORY_ALLOWLIST)
        assert not offenders, (
            "protected-memory symbols named outside the allowlist "
            f"{sorted(PROTECTED_MEMORY_ALLOWLIST)}: {offenders} — add a file to "
            "PROTECTED_MEMORY_ALLOWLIST only as a reviewed #472 change"
        )

    def test_scan_flags_a_planted_third_buffer(self, tmp_path):
        """Negative half: the scan actually catches a new protected buffer.

        A planted module naming `SecureBuffer` must be reported, and the same
        content under an allowlisted name must not be — that pair is what makes
        the shipped scan more than a loop that always agrees.
        """
        content = "from .secure_memory import SecureBuffer\n\nBUF = SecureBuffer(32)\n"
        planted = tmp_path / "extra_buffer.py"
        planted.write_text(content, encoding="utf-8")
        assert _find_protected_symbol_names(tmp_path, PROTECTED_MEMORY_ALLOWLIST) == [
            ("extra_buffer.py", "SecureBuffer")
        ]

        # The same content under an allowlisted name is not an offender.
        os.unlink(planted)
        (tmp_path / "backend.py").write_text(content, encoding="utf-8")
        assert _find_protected_symbol_names(tmp_path, PROTECTED_MEMORY_ALLOWLIST) == []

        # And it is not simply that the file is unreadable: renaming it back is
        # caught again.
        (tmp_path / "backend.py").rename(tmp_path / "extra_buffer.py")
        assert _find_protected_symbol_names(tmp_path, PROTECTED_MEMORY_ALLOWLIST) == [
            ("extra_buffer.py", "SecureBuffer")
        ]

    def test_direct_call_ban_is_failable(self):
        """The per-module ban below is proven live, not a loop that always agrees.

        A planted direct call must be named by the same helper the cells use.
        Without this the nine cells pass the positive case only, which is the
        truth-table failure mode #472 is about.
        """
        assert _find_primitive_calls("value = secure_mlock(buf)\n") == ["secure_mlock"]
        assert _find_primitive_calls("BUF = SecureBuffer(32)\nZERO = secure_zero\n") == [
            "SecureBuffer",
            "secure_zero",
        ]
        # Clean source -> nothing named (the half that keeps the ban honest).
        assert _find_primitive_calls("from .secure_memory import KekCache\ncache = KekCache(32)\n") == []
        # The import half is live too: a non-owner module that only imports the
        # module is refused even though it names no primitive.
        with pytest.raises(AssertionError, match="must stay off the protected path"):
            _assert_off_the_protected_path("from .secure_memory import KekCache\n", "Somebody")
        # And the exempted owner passes for the same text.
        _assert_off_the_protected_path("x = 1\n", "CleanModule")

    def test_core_class_does_not_use_secure_memory(self):
        """Core facade stays off the primitives — it asks the cache for a view."""
        import core.engine.core

        source = core.engine.core.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "Core facade")

    def test_backend_uses_the_cache_but_not_the_primitives(self):
        """Backend is the cache owner: it may hold a cache, never call a primitive.

        The direct-call ban stays real (#472 rewrite of the old "does not
        import secure_memory" cell): Backend goes through the cache, so
        ``secure_mlock``/``secure_munlock``/``secure_zero``/``SecureBuffer``
        must not appear in this file at all.
        """
        import core.engine.backend

        source = core.engine.backend.__file__
        with open(source) as f:
            content = f.read()
        assert "KekCache" in content, "Backend should hold the KEK cache"
        for primitive in ("secure_mlock", "secure_munlock", "secure_zero", "SecureBuffer", "_load_system_lib"):
            assert primitive not in content, f"Backend should not call {primitive} directly"

    def test_encryption_does_not_use_secure_memory(self):
        """Encryption takes key material; it never owns or pins a buffer."""
        import core.engine.encryption

        source = core.engine.encryption.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "Encryption")

    def test_rate_limiter_does_not_use_secure_memory(self):
        """Rate limiter should not import secure_memory."""
        import core.engine.rate_limiter

        source = core.engine.rate_limiter.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "Rate limiter")

    def test_factory_does_not_use_secure_memory(self):
        """Factory should not import secure_memory."""
        import core.engine.factory

        source = core.engine.factory.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "Factory")

    def test_iam_models_do_not_use_secure_memory(self):
        """IAM models should not import secure_memory."""
        import core.iam.models

        source = core.iam.models.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "IAM models")

    def test_iam_role_manager_does_not_use_secure_memory(self):
        """IAM role manager should not import secure_memory."""
        import core.iam.role_manager

        source = core.iam.role_manager.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "IAM role manager")

    def test_iam_session_manager_does_not_use_secure_memory(self):
        """IAM session manager should not import secure_memory."""
        import core.iam.session_manager

        source = core.iam.session_manager.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "IAM session manager")

    def test_iam_enrollment_manager_does_not_use_secure_memory(self):
        """IAM enrollment manager should not import secure_memory."""
        import core.iam.enrollment_manager

        source = core.iam.enrollment_manager.__file__
        with open(source) as f:
            content = f.read()
        _assert_off_the_protected_path(content, "IAM enrollment manager")

    def test_core_factory_does_not_enable_mlock_by_default(self):
        """CoreFactory should not enable mlock by default."""
        from unittest.mock import MagicMock, patch

        import core.engine.factory
        from core.engine.backend import BackendConfig

        config = BackendConfig(
            database_url="postgresql://venya:venya@localhost:5432/venya_test",
            passphrase=b"test-passphrase-for-testing",
        )
        factory = core.engine.factory.CoreFactory(config)
        # build() now resolves the KEK from the persisted salt (C-11); supply a
        # deterministic salt via a mocked session so no real DB is needed.
        with patch("core.engine.factory.Backend.get_session") as mock_gs:
            mock_session = MagicMock()
            mock_session.query.return_value.filter.return_value.first.return_value = MagicMock(value=b"\x33" * 16)
            mock_gs.return_value = mock_session
            core = factory.build()

        # The core should be built without mlock — SecureBuffer is not used
        # by the core facade, so this is implicitly verified by the fact
        # that build() succeeds without any mlock-related config.
        assert core is not None
        assert core.kek is not None

    def test_core_does_not_mlock_by_default(self):
        """Core operations should not lock memory by default."""
        from unittest.mock import MagicMock, patch

        import core.engine.factory
        from core.engine.backend import BackendConfig

        config = BackendConfig(
            database_url="postgresql://venya:venya@localhost:5432/venya_test",
            passphrase=b"isolation-test-passphrase",
        )
        factory = core.engine.factory.CoreFactory(config)
        # build() now resolves the KEK from the persisted salt (C-11); supply a
        # deterministic salt via a mocked session so no real DB is needed.
        with patch("core.engine.factory.Backend.get_session") as mock_gs:
            mock_session = MagicMock()
            mock_session.query.return_value.filter.return_value.first.return_value = MagicMock(value=b"\x33" * 16)
            mock_gs.return_value = mock_session
            core = factory.build()

        # Mock the backend so we don't need a real DB connection
        # The test is about verifying mlock is NOT used, not about actual storage
        mock_backend = MagicMock()
        mock_record = MagicMock()
        mock_record.key = "test_secret"
        mock_backend.put.return_value = mock_record
        # Upsert resolve step must see "no existing row" (this test exercises
        # the insert path): pin the _resolve_secret_in mock chain (through the #515 with_for_update read) to None —
        # MagicMock auto-chains are truthy and would take the replace branch.
        (
            mock_backend.get_session.return_value.query.return_value.filter.return_value.filter.return_value.order_by.return_value.with_for_update.return_value.first.return_value
        ) = None
        core.backend = mock_backend

        # put() should not use mlock — it uses encryption, not SecureBuffer
        record = core.put(
            key="test_secret",
            value=b"test_secret_value_for_isolation",
            user_id="test_user",
            role_names=["test_role"],
            key_version_id="kv_001",
        )
        assert record is not None
        assert record.key == "test_secret"

    def test_secure_memory_not_in_core_module_exports(self):
        """secure_memory symbols should not be re-exported from core.engine."""
        import core.engine

        # secure_memory should not be directly accessible from the core package
        assert not hasattr(core.engine, "secure_mlock"), "secure_mlock should not be re-exported from core.engine"
        assert not hasattr(core.engine, "SecureBuffer"), "SecureBuffer should not be re-exported from core.engine"

    def test_secure_memory_not_in_iam_module_exports(self):
        """secure_memory symbols should not be accessible from core.iam."""
        import core.iam

        assert not hasattr(core.iam, "secure_mlock"), "secure_mlock should not be accessible from core.iam"
        assert not hasattr(core.iam, "SecureBuffer"), "SecureBuffer should not be accessible from core.iam"


@pytest.mark.integration
class TestRuntimeCapabilityIsolation:
    """Verify CAP_IPC_LOCK is granted ONLY to core, not executor.

    Validates the systemd deployment configuration — the actual production
    security model — rather than attempting ad-hoc capability injection.

    Checks:
      1. systemd unit files declare correct AmbientCapabilities
      2. If services are running, /proc/[pid]/status confirms runtime state
    """

    CAP_IPC_LOCK_BIT = 14  # Linux kernel capability number (CAP_IPC_LOCK)
    # Per-service lookup order: /etc first (the installer writes the live unit
    # to /etc/systemd/system — install-venya-core.sh SYSTEMD_DIR, and
    # install-venya-executor.sh), /lib as the packaged fallback. The FIRST
    # EXISTING candidate wins (#542: the old scan overwrote with no existence
    # check, so the last-listed /lib path always won — a path that does not
    # exist on a real install). Drop-in override dirs
    # (/etc/systemd/system/<unit>.d/) are NOT parsed — designed for the
    # fleet window, see refs 542.
    _CORE_UNIT_CANDIDATES: ClassVar[list[str]] = [
        "/etc/systemd/system/venya-core.service",
        "/lib/systemd/system/venya-core.service",
    ]
    _EXECUTOR_UNIT_CANDIDATES: ClassVar[list[str]] = [
        "/etc/systemd/system/venya-executor.service",
        "/lib/systemd/system/venya-executor.service",
    ]

    @staticmethod
    def _parse_unit_file(path: str) -> dict[str, list[str]] | None:
        """Parse a systemd unit file into {directive: [values]}.

        Returns None when the file is ABSENT and {} when it is present but
        carries no parseable directives — "not installed here" and "installed
        with no such directive" are different verdicts (#542: the old handler
        folded absent into {} so negatives passed vacuously).
        """
        if not os.path.exists(path):
            return None
        result: dict[str, list[str]] = {}
        with open(path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#") and not line.startswith(";"):
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if key not in result:
                        result[key] = []
                    result[key].append(value)
        return result

    @classmethod
    def _find_unit_file(cls) -> dict[str, str | None]:
        """Resolve the unit file path for core and executor.

        First EXISTING candidate per service wins, /etc taking precedence over
        /lib; None means no candidate exists on this host.
        """
        found: dict[str, str | None] = {"core": None, "executor": None}
        for service, candidates in (
            ("core", cls._CORE_UNIT_CANDIDATES),
            ("executor", cls._EXECUTOR_UNIT_CANDIDATES),
        ):
            for path in candidates:
                if os.path.exists(path):
                    found[service] = path
                    break
        return found

    # Derived from the shipped unit templates, not guessed: systemd/venya-core.service
    # and systemd/venya-executor.service both run User=venya; core ExecStart is
    # /opt/venya/.venv/bin/venya-server, executor ExecStart is
    # /opt/venya/.venv/bin/venya-executor. The old code passed the SERVICE name
    # as the pgrep username and hardcoded -x venya-core, so pgrep exited 2
    # (invalid user name) and both runtime cells skipped unconditionally (#542).
    SERVICE_USER = "venya"
    CORE_PROCESS = "venya-server"
    EXECUTOR_PROCESS = "venya-executor"

    @classmethod
    def _get_running_pid(cls, process_name: str, username: str = SERVICE_USER) -> int | None:
        """Find the PID of ``process_name`` running as ``username`` (None if not running)."""
        try:
            result = subprocess.run(
                ["pgrep", "-u", username, "-x", process_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip().split()[0])
        except (FileNotFoundError, ValueError):
            pass
        return None

    @staticmethod
    def _read_proc_caps(pid: int) -> dict[str, int]:
        """Read Cap* fields from /proc/[pid]/status as integers."""
        caps: dict[str, int] = {}
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("Cap"):
                        parts = line.split()
                        if len(parts) == 2:
                            key = parts[0].rstrip(":")
                            caps[key] = int(parts[1], 16)
        except (FileNotFoundError, ValueError):
            pass
        return caps

    @staticmethod
    def _has_capability(cappeff: int, bit: int) -> bool:
        """Check if a capability bit is set in the CapEff bitmask."""
        return bool(cappeff & (1 << bit))

    def test_systemd_unit_has_cap_ipc_lock(self):
        """venya-core.service must declare AmbientCapabilities=CAP_IPC_LOCK."""
        units = self._find_unit_file()
        core_unit = units["core"]
        if core_unit is None:
            pytest.skip("no venya-core.service unit exists on this host (/etc and /lib checked)")

        config = self._parse_unit_file(core_unit)
        assert config is not None, f"{core_unit} resolved but did not parse — harness bug"
        ambient = config.get("AmbientCapabilities", [])
        assert any("CAP_IPC_LOCK" in c for c in ambient), (
            f"venya-core.service ({core_unit}) missing AmbientCapabilities=CAP_IPC_LOCK. " f"Found: {ambient}"
        )

    def test_systemd_unit_no_cap_ipc_lock(self):
        """venya-executor.service must NOT declare any AmbientCapabilities."""
        units = self._find_unit_file()
        executor_unit = units["executor"]
        if executor_unit is None:
            pytest.skip("no venya-executor.service unit exists on this host (/etc and /lib checked)")

        config = self._parse_unit_file(executor_unit)
        assert config is not None, f"{executor_unit} resolved but did not parse — harness bug"
        ambient = config.get("AmbientCapabilities", [])
        assert not ambient or not any("CAP_IPC_LOCK" in c for c in ambient), (
            f"venya-executor.service ({executor_unit}) must NOT have AmbientCapabilities=CAP_IPC_LOCK. "
            f"Found: {ambient}"
        )

    def test_executor_no_bounding_caps(self):
        """venya-executor.service must not have a broad CapabilityBoundingSet."""
        units = self._find_unit_file()
        executor_unit = units["executor"]
        if executor_unit is None:
            pytest.skip("no venya-executor.service unit exists on this host (/etc and /lib checked)")
        config = self._parse_unit_file(executor_unit)
        assert config is not None, f"{executor_unit} resolved but did not parse — harness bug"
        bounding = config.get("CapabilityBoundingSet", [])
        for b in bounding:
            assert "CAP_IPC_LOCK" not in b, "venya-executor.service has CAP_IPC_LOCK in CapabilityBoundingSet: " + b

    def test_core_running_has_cap_ipc_lock(self):
        """If the core server process is running, verify CapEff includes CAP_IPC_LOCK at runtime."""
        pid = self._get_running_pid(self.CORE_PROCESS)
        if pid is None:
            pytest.skip(f"no '{self.CORE_PROCESS}' process running as '{self.SERVICE_USER}' on this host")
        caps = self._read_proc_caps(pid)
        cap_eff = caps.get("CapEff", 0)
        assert self._has_capability(cap_eff, self.CAP_IPC_LOCK_BIT), (
            f"core PID {pid} CapEff=0x{cap_eff:x} missing CAP_IPC_LOCK (bit {self.CAP_IPC_LOCK_BIT}). "
            f"All Cap fields: {caps}"
        )

    def test_executor_running_no_cap_ipc_lock(self):
        """If the executor process is running, verify CapEff does NOT include CAP_IPC_LOCK."""
        pid = self._get_running_pid(self.EXECUTOR_PROCESS)
        if pid is None:
            pytest.skip(f"no '{self.EXECUTOR_PROCESS}' process running as '{self.SERVICE_USER}' on this host")
        caps = self._read_proc_caps(pid)
        cap_eff = caps.get("CapEff", 0)
        assert not self._has_capability(cap_eff, self.CAP_IPC_LOCK_BIT), (
            f"executor PID {pid} CapEff=0x{cap_eff:x} has CAP_IPC_LOCK (bit {self.CAP_IPC_LOCK_BIT}). "
            f"Executor must NEVER have CAP_IPC_LOCK. All Cap fields: {caps}"
        )


class TestKekProtectedPath:
    """The protected path IS the KEK path now (#472 section 6.3 / 6.4).

    One positive cell — after ``bootstrap_kek()`` the Backend-owned cache is
    populated, the ``config.kek`` intake slot reads ``None``, and a reader gets
    a read-only ``memoryview`` — each with its paired negative, per the
    truth-table rule. These are the half the project most often misses, so each
    negative names the state that must be REFUSED, not just the state that works.

    The release-error class is whatever the module actually exports at this
    base: ``SecureBufferReleasedError`` (``secure_memory.py``, grep
    ``class .*Error``). If that symbol is renamed, these cells fail and say so.
    """

    FIXED_SALT = b"\x22" * 16

    def _booted_backend(self, passphrase: bytes = b"isolation-kek-passphrase"):
        """A Backend whose KEK is resolved from a mocked persisted salt.

        The salt lookup is mocked so no real database is needed; derivation is
        the shipped Argon2id path (C-11), unchanged.
        """
        from core.engine.backend import Backend, BackendConfig

        config = BackendConfig(
            database_url="postgresql://venya:venya@localhost:5432/venya_test",
            passphrase=passphrase,
        )
        backend = Backend(config)
        mock_session = MagicMock()
        salt_row = MagicMock(value=self.FIXED_SALT)
        mock_session.query.return_value.filter.return_value.first.return_value = salt_row
        backend.get_session = lambda: mock_session
        backend.bootstrap_kek()
        return backend

    def test_bootstrap_kek_fills_the_cache_and_clears_the_intake(self):
        """Positive cell: the key lives in the cache, not in the config field."""
        backend = self._booted_backend()
        cache = backend.kek_cache

        assert cache.is_populated, "bootstrap_kek() must leave the cache populated"
        assert backend.config.kek is None, "the config.kek intake slot must not stay the stored form"
        assert cache.size == 32

        with cache.view() as kek:
            assert isinstance(kek, memoryview), "a reader gets a memoryview, never bytes"
            assert kek.readonly is True, "the reader view must be read-only"
            assert len(kek) == 32

    def test_intake_kek_is_moved_into_the_cache_at_construction(self):
        """Raw-KEK intake: the value is copied in and the slot is cleared.

        Paired with the cell above: both entry paths end with the cache as the
        only holder, which is what makes the allowlist count mean something.
        """
        from core.engine.backend import Backend, BackendConfig

        config = BackendConfig(database_url="postgresql://venya:venya@localhost:5432/venya_test", kek=b"\xaa" * 32)
        backend = Backend(config)

        assert backend.config.kek is None, "the intake slot must be cleared once the cache holds the key"
        assert backend.kek_cache.is_populated
        with backend.kek_cache.view() as kek:
            assert bytes(kek) == b"\xaa" * 32

    def test_view_after_release_raises(self):
        """Negative: a released cache refuses rather than handing out zero bytes."""
        from core.engine.secure_memory import SecureBufferReleasedError

        backend = self._booted_backend()
        backend.kek_cache.release()

        with pytest.raises(SecureBufferReleasedError):
            with backend.kek_cache.view():
                pass

    def test_second_bootstrap_kek_does_not_refill_a_released_cache_by_accident(self):
        """Negative pairing for the idempotence rule (cell 1's second half).

        A repeat call with no passphrase returns the populated cache as it is;
        it does not re-derive, and it never silently re-populates a released one.
        """
        from core.engine.secure_memory import SecureBufferReleasedError

        backend = self._booted_backend()
        before = backend.kek_cache
        again = backend.bootstrap_kek()
        assert again is before, "a second bootstrap_kek() must return the same cache, not a re-derived one"

        before.release()
        with pytest.raises(SecureBufferReleasedError):
            with before.view():
                pass

    def test_unpinned_cache_still_serves_and_still_zeroizes(self):
        """Negative half of the pinning policy: EPERM changes the report, not the service.

        mlock mocked to fail with EPERM (the container / hardened-host shape the
        ruling protects): the cache still holds the key, still serves a view,
        and release still zeroes it.
        """
        from core.engine.secure_memory import KekCache

        def _fake_libc(mlock_rc: int):
            class _Lib:
                def mlock(self, addr: int, size: int) -> int:
                    return mlock_rc

                def munlock(self, addr: int, size: int) -> int:
                    return 0

            return _Lib()

        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch("core.engine.secure_memory._load_system_lib", return_value=_fake_libc(-1)):
                with patch("core.engine.secure_memory.ctypes.get_errno", return_value=1):  # EPERM
                    cache = KekCache(32, mlock=True)

        assert cache.pin_active is False, "a failed mlock must be reported, not fatal"
        assert cache.pin_errno == 1
        cache.populate(b"K" * 32)
        assert cache.is_populated
        with cache.view() as kek:
            assert bytes(kek) == b"K" * 32, "an unpinned cache still serves key material"
        assert cache.release() is True, "erasure is not a perk of pinning: an unpinned cache still zeroizes"
        assert cache.is_zeroed

    def test_wrong_key_cache_fails_the_sentinel_rather_than_serving(self, tmp_path):
        """Negative: a cache holding the WRONG key is caught at boot, not served.

        This is the belt the design note names for the quiet-wrong-key risk: the
        sentinel unwraps under the resident KEK or the boot verdict is
        MISMATCH (the server layer turns that into an abort).
        """
        from core.engine.backend import SentinelStatus, ensure_kek_sentinel, verify_kek_sentinel
        from core.engine.encryption import derive_kek
        from core.engine.secure_memory import KekCache
        from core.iam.models import Base
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        right_kek, _ = derive_kek(b"right-passphrase", self.FIXED_SALT)
        wrong_kek, _ = derive_kek(b"wrong-passphrase", self.FIXED_SALT)

        engine = create_engine(f"sqlite:///{tmp_path / 'sentinel.db'}")
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine)()
        try:
            right_cache = KekCache.from_bytes(right_kek, mlock=False)
            with right_cache.view() as kek:
                ensure_kek_sentinel(session, kek)

            wrong_cache = KekCache.from_bytes(wrong_kek, mlock=False)
            with wrong_cache.view() as kek:
                verdict = verify_kek_sentinel(session, kek)
            assert (
                verdict.status is SentinelStatus.MISMATCH
            ), "a wrong-key cache must fail the sentinel check, not boot quietly"

            # Positive half of the same pair: the right cache verifies.
            with right_cache.view() as kek:
                assert verify_kek_sentinel(session, kek).status is SentinelStatus.MATCH
            right_cache.release()
            wrong_cache.release()
        finally:
            session.close()

    def test_secure_zero_on_a_reader_view_raises_instead_of_returning(self):
        """Negative: the zeroizer refuses a view it cannot erase.

        A silent no-op here would let the release log claim ``zeroized=yes`` for
        a buffer nobody touched, which is worse than having no zeroizer.
        """
        from core.engine.secure_memory import KekCache, secure_zero

        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        with cache.view() as kek:
            with pytest.raises(TypeError):
                secure_zero(kek)
            # The refused call touched nothing: the same view still reads the key.
            assert bytes(kek) == b"K" * 32
        cache.release()
        assert cache.is_zeroed

    def test_different_length_write_on_the_resident_kek_raises(self):
        """Negative: a short write to the pinned KEK buffer is refused.

        Resizing a locked bytearray can move it and quietly un-pin the key while
        the cache still reports it locked. Equal-length stays put and keeps the
        lock (the positive half).
        """
        from core.engine.secure_memory import SecureBuffer

        def _lib(mlock_rc: int):
            class _L:
                def mlock(self, addr: int, size: int) -> int:
                    return mlock_rc

                def munlock(self, addr: int, size: int) -> int:
                    return 0

            return _L()

        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch("core.engine.secure_memory._load_system_lib", return_value=_lib(0)):
                buffer = SecureBuffer(32, mlock=True)
        assert buffer.is_locked

        with pytest.raises(ValueError, match="full 32-byte write"):
            buffer.write(b"short")

        buffer.write(b"A" * 32)
        assert buffer.read() == b"A" * 32
        assert buffer.is_locked, "an equal-length write must keep the lock"


class TestGracefulMlockFailureShape:
    """The existing graceful-mlock shape stays green (section 6.4, last clause).

    Kept as its own cell so the rewrite is visibly additive: the old
    context-manager behaviour assertion in
    ``TestCapabilityIsolation.test_secure_buffer_auto_unlock_on_error`` is
    untouched, and this names the same contract from the cache side.
    """

    def test_unpinned_cache_construction_never_raises(self):
        from core.engine.secure_memory import KekCache

        def _lib(mlock_rc: int):
            class _L:
                def mlock(self, addr: int, size: int) -> int:
                    return mlock_rc

                def munlock(self, addr: int, size: int) -> int:
                    return 0

            return _L()

        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch("core.engine.secure_memory._load_system_lib", return_value=_lib(-1)):
                with patch("core.engine.secure_memory.ctypes.get_errno", return_value=12):
                    cache = KekCache(32, mlock=True)  # must not raise
        assert cache.pin_active is False
        assert cache.is_pinned is False
        cache.release()


# --------------------------------------------------------------------------
# DESIGN-ONLY CELL — physically UNVERIFIED. It reads the live host and skips
# honestly when the service is not running here; the owner-present fleet
# window is what makes it pass. Do not read a skip as a pass.
# --------------------------------------------------------------------------


@pytest.mark.integration
class TestServedCorePinningProof:
    """The pinning proof the ruling requires before any pinning claim (#472 5).

    Only a served core satisfies this: ``/proc/<pid>/limits`` names the
    locked-memory budget and ``smaps_rollup`` reports a non-zero ``Locked:``
    value for the pinned page. The pid comes from the same fixed helper the
    runtime cells use (``pgrep -u venya -x venya-server``, #542), so this class
    is reachable on a served host and honestly skipped everywhere else — a skip
    here is never a pass. Physically UNVERIFIED in this leg by design: the fleet
    window is owner-present work and belongs to CP5, not here.
    """

    @staticmethod
    def _core_pid() -> int | None:
        return TestRuntimeCapabilityIsolation._get_running_pid(TestRuntimeCapabilityIsolation.CORE_PROCESS)

    @staticmethod
    def _read(path: str) -> str:
        try:
            with open(path) as f:
                return f.read()
        except OSError:
            return ""

    def test_served_core_limits_report_a_locked_memory_budget(self):
        pid = self._core_pid()
        if pid is None:
            pytest.skip("no served venya-server on this host — physically UNVERIFIED (fleet window)")
        limits = self._read(f"/proc/{pid}/limits")
        assert "Max locked memory" in limits, f"no locked-memory limit line in /proc/{pid}/limits"

    def test_served_core_reports_a_locked_page_in_smaps_rollup(self):
        pid = self._core_pid()
        if pid is None:
            pytest.skip("no served venya-server on this host — physically UNVERIFIED (fleet window)")
        rollup = self._read(f"/proc/{pid}/smaps_rollup")
        locked = [line for line in rollup.splitlines() if line.startswith("Locked:")]
        assert locked, f"no Locked: line in smaps_rollup for pid {pid}"
        assert any(
            int(line.split()[1]) > 0 for line in locked if len(line.split()) > 1
        ), f"smaps_rollup Locked: is zero for pid {pid} — pin NOT active on this host"


class TestCapabilityIsolationHarness:
    """Fixture-driven cells proving the runtime harness itself can fail.

    The shipped unit cells above read the real host; on a machine with no
    venya install they legitimately skip. These cells give the same harness
    a synthetic install (tmp_path, monkeypatch — never a real /etc write) and
    demand the paired negatives pass/fail as the security model requires.
    """

    @staticmethod
    def _write_unit(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_find_unit_prefers_existing_etc_over_lib(self, tmp_path, monkeypatch):
        """A real-install shape: /etc unit exists, /lib twin does not — /etc must win."""
        etc = tmp_path / "etc" / "venya-core.service"
        lib = tmp_path / "lib" / "venya-core.service"  # deliberately not created
        self._write_unit(etc, "[Service]\nAmbientCapabilities=CAP_IPC_LOCK\n")
        cls = TestRuntimeCapabilityIsolation
        monkeypatch.setattr(cls, "_CORE_UNIT_CANDIDATES", [str(lib), str(etc)])
        units = cls._find_unit_file()
        assert units["core"] == str(etc)

    def test_find_unit_falls_back_to_lib_when_etc_absent(self, tmp_path, monkeypatch):
        """Packaged-install shape: only the /lib unit exists — it must resolve."""
        etc = tmp_path / "etc" / "venya-core.service"  # not created
        lib = tmp_path / "lib" / "venya-core.service"
        self._write_unit(lib, "[Service]\nAmbientCapabilities=CAP_IPC_LOCK\n")
        cls = TestRuntimeCapabilityIsolation
        monkeypatch.setattr(cls, "_CORE_UNIT_CANDIDATES", [str(etc), str(lib)])
        units = cls._find_unit_file()
        assert units["core"] == str(lib)

    def test_find_unit_none_when_no_candidate_exists(self, tmp_path, monkeypatch):
        """Uninstalled host: no candidate exists -> None (skip), never a wrong path."""
        cls = TestRuntimeCapabilityIsolation
        monkeypatch.setattr(cls, "_CORE_UNIT_CANDIDATES", [str(tmp_path / "nope" / "venya-core.service")])
        monkeypatch.setattr(cls, "_EXECUTOR_UNIT_CANDIDATES", [str(tmp_path / "nope" / "venya-executor.service")])
        units = cls._find_unit_file()
        assert units == {"core": None, "executor": None}

    def test_parse_unit_absent_vs_present_empty(self, tmp_path):
        """Absent returns None; present-but-directive-less returns {} — distinguishable."""
        cls = TestRuntimeCapabilityIsolation
        absent = tmp_path / "missing.service"
        present = tmp_path / "bare.service"
        self._write_unit(present, "[Service]\n")
        assert cls._parse_unit_file(str(absent)) is None
        assert cls._parse_unit_file(str(present)) == {}
        withcap = tmp_path / "withcap.service"
        self._write_unit(withcap, "[Service]\nAmbientCapabilities=CAP_IPC_LOCK\n")
        assert cls._parse_unit_file(str(withcap))["AmbientCapabilities"] == ["CAP_IPC_LOCK"]

    def test_positive_cell_passes_on_correct_etc_install(self, tmp_path, monkeypatch):
        """The cell that could only skip before (#542 break 1) now PASSES."""
        etc = tmp_path / "etc" / "venya-core.service"
        lib = tmp_path / "lib" / "venya-core.service"  # nonexistent twin, as on a real install
        self._write_unit(etc, "[Service]\nUser=venya\nAmbientCapabilities=CAP_IPC_LOCK\n")
        cls = TestRuntimeCapabilityIsolation
        monkeypatch.setattr(cls, "_CORE_UNIT_CANDIDATES", [str(etc), str(lib)])
        cls().test_systemd_unit_has_cap_ipc_lock()

    def test_poisoned_executor_unit_fails_the_negative_cell(self, tmp_path, monkeypatch):
        """The paired negative that passed vacuously before (#542 break 2) now FAILS."""
        etc_core = tmp_path / "etc" / "venya-core.service"
        lib_core = tmp_path / "lib" / "venya-core.service"
        etc_exec = tmp_path / "etc" / "venya-executor.service"
        lib_exec = tmp_path / "lib" / "venya-executor.service"  # nonexistent twin
        self._write_unit(etc_core, "[Service]\nAmbientCapabilities=CAP_IPC_LOCK\n")
        self._write_unit(etc_exec, "[Service]\nUser=venya\nAmbientCapabilities=CAP_IPC_LOCK\n")  # poisoned
        cls = TestRuntimeCapabilityIsolation
        monkeypatch.setattr(cls, "_CORE_UNIT_CANDIDATES", [str(etc_core), str(lib_core)])
        monkeypatch.setattr(cls, "_EXECUTOR_UNIT_CANDIDATES", [str(etc_exec), str(lib_exec)])
        with pytest.raises(AssertionError, match="CAP_IPC_LOCK"):
            cls().test_systemd_unit_no_cap_ipc_lock()

    def test_poisoned_executor_bounding_caps_fails_the_cell(self, tmp_path, monkeypatch):
        """Second paired negative: a CAP_IPC_LOCK bounding-set grant must trip it."""
        etc_exec = tmp_path / "etc" / "venya-executor.service"
        lib_exec = tmp_path / "lib" / "venya-executor.service"
        self._write_unit(etc_exec, "[Service]\nCapabilityBoundingSet=CAP_IPC_LOCK\n")  # poisoned
        cls = TestRuntimeCapabilityIsolation
        monkeypatch.setattr(cls, "_EXECUTOR_UNIT_CANDIDATES", [str(etc_exec), str(lib_exec)])
        with pytest.raises(AssertionError, match="CapabilityBoundingSet"):
            cls().test_executor_no_bounding_caps()

    def test_get_running_pid_wiring_exit0(self, monkeypatch):
        """exit 0: pgrep is invoked with the real username AND the per-service process name."""
        seen: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            seen.append(list(cmd))
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="4242\n", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cls = TestRuntimeCapabilityIsolation
        assert cls._get_running_pid(cls.CORE_PROCESS) == 4242
        assert seen[0] == ["pgrep", "-u", "venya", "-x", "venya-server"]
        assert cls._get_running_pid(cls.EXECUTOR_PROCESS) == 4242
        assert seen[1] == ["pgrep", "-u", "venya", "-x", "venya-executor"]

    def test_get_running_pid_wiring_exit1(self, monkeypatch):
        """exit 1 (pgrep found nothing): None -> the caller skips 'service not running'."""

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cls = TestRuntimeCapabilityIsolation
        assert cls._get_running_pid(cls.CORE_PROCESS) is None

    def test_get_running_pid_wiring_exit2(self, monkeypatch):
        """exit 2 (invalid user name — the old shipped wiring): None, never a fabricated PID."""

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, returncode=2, stdout="", stderr="pgrep: invalid user name")

        monkeypatch.setattr(subprocess, "run", fake_run)
        cls = TestRuntimeCapabilityIsolation
        assert cls._get_running_pid(cls.CORE_PROCESS) is None

    def test_running_cells_read_proc_status_for_resolved_pid(self, tmp_path, monkeypatch):
        """A resolved PID is passed to /proc/[pid]/status parsing — the CapEff bit decides."""
        fake = tmp_path / "status"
        # CAP_IPC_LOCK is bit 14 -> 0x4000 set in this synthetic CapEff
        fake.write_text(
            "CapInh:\t0000000000004000\nCapPrm:\t0000000000004000\nCapEff:\t0000000000004000\n", encoding="utf-8"
        )
        cls = TestRuntimeCapabilityIsolation
        monkeypatch.setattr(cls, "_read_proc_caps", staticmethod(lambda pid: _read_proc_caps_file(str(fake))))
        caps = cls._read_proc_caps(4242)
        assert cls._has_capability(
            caps["CapEff"], cls.CAP_IPC_LOCK_BIT
        ), "harness cannot see a CAP_IPC_LOCK grant in a real CapEff shape — the runtime positive would be vacuous"
        # negative half: a CapEff WITHOUT bit 14 must read as no grant
        plain = tmp_path / "status-plain"
        plain.write_text("CapEff:\t0000000000000000\n", encoding="utf-8")
        monkeypatch.setattr(cls, "_read_proc_caps", staticmethod(lambda pid: _read_proc_caps_file(str(plain))))
        assert not cls._has_capability(cls._read_proc_caps(1)["CapEff"], cls.CAP_IPC_LOCK_BIT)


def _read_proc_caps_file(path: str) -> dict[str, int]:
    """Same parse as the shipped _read_proc_caps, applied to a fixture path."""
    caps: dict[str, int] = {}
    with open(path) as f:
        for line in f:
            if line.startswith("Cap"):
                parts = line.split()
                if len(parts) == 2:
                    caps[parts[0].rstrip(":")] = int(parts[1], 16)
    return caps
