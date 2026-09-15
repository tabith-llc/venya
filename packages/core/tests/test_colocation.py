# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for co-location isolation: cross-user permission enforcement.

Verifies that when core and executor run on the same host, their data
directories are properly isolated via file permissions (chmod 700).

Tests require venya-core and venya-executor system users to exist.
Some operations (chown, runuser) require root/sudo or full paths.
"""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

_RUNUSER = "/usr/sbin/runuser"
_SUDO_PASS = "nopomo"


def _sudo(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a command with sudo."""
    return subprocess.run(
        ["sudo", "-S", "--"] + cmd,
        input=(_SUDO_PASS + "\n").encode(),
        capture_output=True,
        timeout=10,
        check=False,
    )


def _run_as_user(username: str, cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a command as the given user via sudo -u."""
    return subprocess.run(
        ["sudo", "-S", "-u", username, "--"] + cmd,
        input=(_SUDO_PASS + "\n").encode(),
        capture_output=True,
        timeout=10,
        check=False,
    )


@pytest.mark.integration
class TestCoLocationIsolation:
    """Verify cross-user isolation when running on same host."""

    CORE_USER = "venya-core"
    EXECUTOR_USER = "venya-executor"

    @staticmethod
    def _check_user_exists(username: str) -> bool:
        """Check if a system user exists."""
        try:
            result = subprocess.run(
                ["id", username],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    @pytest.fixture(autouse=True)
    def _skip_if_users_missing(self):
        """Skip all tests in this class if users don't exist."""
        if not self._check_user_exists(self.CORE_USER):
            pytest.skip(f"{self.CORE_USER} user not found")
        if not self._check_user_exists(self.EXECUTOR_USER):
            pytest.skip(f"{self.EXECUTOR_USER} user not found")

    def _get_uid_gid(self, username: str) -> tuple[int, int]:
        """Get UID and GID for a user."""
        uid = int(subprocess.run(["id", "-u", username], capture_output=True, text=True, check=False).stdout.strip())
        gid = int(subprocess.run(["id", "-g", username], capture_output=True, text=True, check=False).stdout.strip())
        return uid, gid

    def test_core_dir_inaccessible_by_executor(self):
        """venya-executor user must NOT read venya-core data directory."""
        tmpdir = tempfile.mkdtemp()
        test_dir = Path(tmpdir) / "core_data"
        test_dir.mkdir()
        test_file = test_dir / "secret.db"
        test_file.write_bytes(b"encrypted blob")

        core_uid, core_gid = self._get_uid_gid(self.CORE_USER)
        _executor_uid, _executor_gid = self._get_uid_gid(self.EXECUTOR_USER)

        # Set ownership to venya-core and permissions to 700
        result_chown = _sudo(["chown", "-R", f"{core_uid}:{core_gid}", str(test_dir)])
        assert result_chown.returncode == 0, f"chown failed: {result_chown.stderr.decode()}"
        result_chmod = _sudo(["chmod", "700", str(test_dir)])
        assert result_chmod.returncode == 0, f"chmod failed: {result_chmod.stderr.decode()}"

        # Verify permissions
        stat = os.stat(test_dir)
        assert stat.st_uid == core_uid
        assert stat.st_gid == core_gid
        assert oct(stat.st_mode)[-3:] == "700"

        # Try to read as executor
        result = _run_as_user(self.EXECUTOR_USER, ["cat", str(test_file)])
        assert result.returncode != 0, f"executor ({self.EXECUTOR_USER}) should not read core dir (mode 700)"

        # Cleanup
        _sudo(["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(test_dir)])
        _sudo(["chmod", "755", str(test_dir)])
        subprocess.run(["rm", "-rf", tmpdir], check=False)

    def test_executor_dir_inaccessible_by_core(self):
        """venya-core user must NOT read venya-executor data directory."""
        tmpdir = tempfile.mkdtemp()
        test_dir = Path(tmpdir) / "executor_data"
        test_dir.mkdir()
        test_file = test_dir / "config.toml"
        test_file.write_text("executor_config")

        _core_uid, _core_gid = self._get_uid_gid(self.CORE_USER)
        executor_uid, executor_gid = self._get_uid_gid(self.EXECUTOR_USER)

        result_chown = _sudo(["chown", "-R", f"{executor_uid}:{executor_gid}", str(test_dir)])
        assert result_chown.returncode == 0, f"chown failed: {result_chown.stderr.decode()}"
        result_chmod = _sudo(["chmod", "700", str(test_dir)])
        assert result_chmod.returncode == 0, f"chmod failed: {result_chmod.stderr.decode()}"

        # Try to read as core
        result = _run_as_user(self.CORE_USER, ["cat", str(test_file)])
        assert result.returncode != 0, f"core ({self.CORE_USER}) should not read executor dir (mode 700)"

        # Cleanup
        _sudo(["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(test_dir)])
        _sudo(["chmod", "755", str(test_dir)])
        subprocess.run(["rm", "-rf", tmpdir], check=False)

    def test_core_dir_executable_by_core(self):
        """venya-core user MUST be able to access its own data directory."""
        tmpdir = tempfile.mkdtemp()
        # Make temp dir traversable by all users
        _sudo(["chmod", "755", tmpdir])
        test_dir = Path(tmpdir) / "core_data"
        test_dir.mkdir()
        test_file = test_dir / "secret.db"
        test_file.write_bytes(b"encrypted blob")

        core_uid, core_gid = self._get_uid_gid(self.CORE_USER)

        result_chown = _sudo(["chown", "-R", f"{core_uid}:{core_gid}", str(test_dir)])
        assert result_chown.returncode == 0, f"chown failed: {result_chown.stderr.decode()}"
        result_chmod = _sudo(["chmod", "700", str(test_dir)])
        assert result_chmod.returncode == 0, f"chmod failed: {result_chmod.stderr.decode()}"

        # Verify core can read
        result = _run_as_user(self.CORE_USER, ["cat", str(test_file)])
        assert result.returncode == 0, "core user must access its own dir"
        assert result.stdout == b"encrypted blob"

        # Cleanup
        _sudo(["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(test_dir)])
        _sudo(["chmod", "755", str(test_dir)])
        subprocess.run(["rm", "-rf", tmpdir], check=False)

    def test_executor_dir_executable_by_executor(self):
        """venya-executor user MUST be able to access its own data directory."""
        tmpdir = tempfile.mkdtemp()
        # Make temp dir traversable by all users
        _sudo(["chmod", "755", tmpdir])
        test_dir = Path(tmpdir) / "executor_data"
        test_dir.mkdir()
        test_file = test_dir / "config.toml"
        test_file.write_text("executor_config")

        executor_uid, executor_gid = self._get_uid_gid(self.EXECUTOR_USER)

        result_chown = _sudo(["chown", "-R", f"{executor_uid}:{executor_gid}", str(test_dir)])
        assert result_chown.returncode == 0, f"chown failed: {result_chown.stderr.decode()}"
        result_chmod = _sudo(["chmod", "700", str(test_dir)])
        assert result_chmod.returncode == 0, f"chmod failed: {result_chmod.stderr.decode()}"

        # Verify executor can read
        result = _run_as_user(self.EXECUTOR_USER, ["cat", str(test_file)])
        assert result.returncode == 0, "executor user must access its own dir"
        assert result.stdout == b"executor_config"

        # Cleanup
        _sudo(["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(test_dir)])
        _sudo(["chmod", "755", str(test_dir)])
        subprocess.run(["rm", "-rf", tmpdir], check=False)
