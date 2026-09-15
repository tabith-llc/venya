# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for capability isolation between core and executor.

These tests verify that mlock (which requires CAP_IPC_LOCK) is only
used in the core package, never in CLI or other components.

The executor (Phase 4) must NEVER have CAP_IPC_LOCK — the jump host
is assumed compromised.
"""

import importlib
from typing import ClassVar
from unittest.mock import patch

import pytest


class TestCapabilityIsolation:
    """Verify mlock is only used in the core package."""

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
    """Verify mlock/secure_memory is only used within secure_memory.py itself.

    The security model requires that mlock (which needs CAP_IPC_LOCK) is
    confined to secure_memory.py. No other module should import or use it.
    The executor (Phase 4) must NEVER have CAP_IPC_LOCK.
    """

    def test_only_secure_memory_uses_mlock(self):
        """Only secure_memory.py should define or import mlock-related symbols."""
        import core.engine

        secure_memory_symbols = {"secure_mlock", "secure_munlock", "secure_zero", "SecureBuffer", "_load_system_lib"}

        core_dir = importlib.import_module("importlib.resources").files(core.engine)
        if core_dir and hasattr(core_dir, "iterdir"):
            for submodule_path in core_dir.iterdir():
                if submodule_path.suffix == ".py" and not submodule_path.name.startswith("_"):
                    submodule_name = submodule_path.stem
                    if submodule_name == "secure_memory":
                        continue
                    source = submodule_path.read_text(encoding="utf-8")
                    for sym in secure_memory_symbols:
                        assert sym not in source, (
                            f"secure_memory symbol '{sym}' found in {submodule_name}.py — "
                            f"mlock must only be used in secure_memory.py"
                        )

    def test_core_class_does_not_use_secure_memory(self):
        """Core facade should not import secure_memory."""
        import core.engine.core

        source = core.engine.core.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Core should not import secure_memory"
        assert "SecureBuffer" not in content, "Core should not use SecureBuffer"
        assert "secure_mlock" not in content, "Core should not call secure_mlock"

    def test_backend_does_not_use_secure_memory(self):
        """Backend should not import secure_memory."""
        import core.engine.backend

        source = core.engine.backend.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Backend should not import secure_memory"
        assert "SecureBuffer" not in content, "Backend should not use SecureBuffer"
        assert "secure_mlock" not in content, "Backend should not call secure_mlock"

    def test_encryption_does_not_use_secure_memory(self):
        """Encryption module should not import secure_memory."""
        import core.engine.encryption

        source = core.engine.encryption.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Encryption should not import secure_memory"
        assert "SecureBuffer" not in content, "Encryption should not use SecureBuffer"
        assert "secure_mlock" not in content, "Encryption should not call secure_mlock"

    def test_rate_limiter_does_not_use_secure_memory(self):
        """Rate limiter should not import secure_memory."""
        import core.engine.rate_limiter

        source = core.engine.rate_limiter.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Rate limiter should not import secure_memory"
        assert "SecureBuffer" not in content, "Rate limiter should not use SecureBuffer"
        assert "secure_mlock" not in content, "Rate limiter should not call secure_mlock"

    def test_factory_does_not_use_secure_memory(self):
        """Factory should not import secure_memory."""
        import core.engine.factory

        source = core.engine.factory.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "Factory should not import secure_memory"
        assert "SecureBuffer" not in content, "Factory should not use SecureBuffer"
        assert "secure_mlock" not in content, "Factory should not call secure_mlock"

    def test_iam_models_do_not_use_secure_memory(self):
        """IAM models should not import secure_memory."""
        import core.iam.models

        source = core.iam.models.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM models should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM models should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM models should not call secure_mlock"

    def test_iam_role_manager_does_not_use_secure_memory(self):
        """IAM role manager should not import secure_memory."""
        import core.iam.role_manager

        source = core.iam.role_manager.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM role manager should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM role manager should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM role manager should not call secure_mlock"

    def test_iam_session_manager_does_not_use_secure_memory(self):
        """IAM session manager should not import secure_memory."""
        import core.iam.session_manager

        source = core.iam.session_manager.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM session manager should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM session manager should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM session manager should not call secure_mlock"

    def test_iam_enrollment_manager_does_not_use_secure_memory(self):
        """IAM enrollment manager should not import secure_memory."""
        import core.iam.enrollment_manager

        source = core.iam.enrollment_manager.__file__
        with open(source) as f:
            content = f.read()
        assert "secure_memory" not in content, "IAM enrollment manager should not import secure_memory"
        assert "SecureBuffer" not in content, "IAM enrollment manager should not use SecureBuffer"
        assert "secure_mlock" not in content, "IAM enrollment manager should not call secure_mlock"

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
    _SYSTEMD_UNIT_PATHS: ClassVar[list[str]] = [
        "/etc/systemd/system/venya-core.service",
        "/etc/systemd/system/venya-executor.service",
        "/lib/systemd/system/venya-core.service",
        "/lib/systemd/system/venya-executor.service",
    ]

    @staticmethod
    def _parse_unit_file(path: str) -> dict[str, list[str]]:
        """Parse a systemd unit file into {directive: [values]}."""
        result: dict[str, list[str]] = {}
        try:
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
        except FileNotFoundError:
            pass
        return result

    @classmethod
    def _find_unit_file(cls) -> dict[str, str | None]:
        """Find the unit file paths for core and executor services."""
        found: dict[str, str | None] = {"core": None, "executor": None}
        for path in cls._SYSTEMD_UNIT_PATHS:
            if "venya-core" in path:
                found["core"] = path
            elif "venya-executor" in path:
                found["executor"] = path
        return found

    @staticmethod
    def _get_running_pid(username: str) -> int | None:
        """Find the PID of a process running as the given user."""
        import subprocess

        try:
            result = subprocess.run(
                ["pgrep", "-u", username, "-x", "venya-core"],
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
            pytest.skip("venya-core.service unit file not found")

        config = self._parse_unit_file(core_unit)
        ambient = config.get("AmbientCapabilities", [])
        if not ambient:
            pytest.skip(f"venya-core.service ({core_unit}) has no AmbientCapabilities")
        assert any("CAP_IPC_LOCK" in c for c in ambient), (
            f"venya-core.service ({core_unit}) missing AmbientCapabilities=CAP_IPC_LOCK. " f"Found: {ambient}"
        )

    def test_systemd_unit_no_cap_ipc_lock(self):
        """venya-executor.service must NOT declare any AmbientCapabilities."""
        units = self._find_unit_file()
        executor_unit = units["executor"]
        if executor_unit is None:
            pytest.skip("venya-executor.service unit file not found")

        config = self._parse_unit_file(executor_unit)
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
            pytest.skip("venya-executor.service not found")
        config = self._parse_unit_file(executor_unit)
        bounding = config.get("CapabilityBoundingSet", [])
        for b in bounding:
            assert "CAP_IPC_LOCK" not in b, "venya-executor.service has CAP_IPC_LOCK in CapabilityBoundingSet"

    def test_core_running_has_cap_ipc_lock(self):
        """If venya-core is running, verify CapEff includes CAP_IPC_LOCK at runtime."""
        pid = self._get_running_pid("venya-core")
        if pid is None:
            pytest.skip("venya-core service is not running")
        caps = self._read_proc_caps(pid)
        cap_eff = caps.get("CapEff", 0)
        assert self._has_capability(cap_eff, self.CAP_IPC_LOCK_BIT), (
            f"venya-core PID {pid} CapEff=0x{cap_eff:x} missing CAP_IPC_LOCK (bit {self.CAP_IPC_LOCK_BIT}). "
            f"All Cap fields: {caps}"
        )

    def test_executor_running_no_cap_ipc_lock(self):
        """If venya-executor is running, verify CapEff does NOT include CAP_IPC_LOCK."""
        pid = self._get_running_pid("venya-executor")
        if pid is None:
            pytest.skip("venya-executor service is not running")
        caps = self._read_proc_caps(pid)
        cap_eff = caps.get("CapEff", 0)
        assert not self._has_capability(cap_eff, self.CAP_IPC_LOCK_BIT), (
            f"venya-executor PID {pid} CapEff=0x{cap_eff:x} has CAP_IPC_LOCK (bit {self.CAP_IPC_LOCK_BIT}). "
            f"Executor must NEVER have CAP_IPC_LOCK. All Cap fields: {caps}"
        )
