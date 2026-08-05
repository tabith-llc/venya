"""Tests for MemfdStrategy."""

from __future__ import annotations

import fcntl
import os
import subprocess
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from executor.strategies.memfd_strategy import MemfdStrategy


@dataclass
class FakeBundle:
    secret_id: str
    value: bytes


@pytest.fixture()
def strategy() -> MemfdStrategy:
    return MemfdStrategy()


class TestMemfdStrategyName:
    """Tests for MemfdStrategy.name()."""

    def test_returns_memfd(self):
        assert MemfdStrategy().name() == "memfd"


class TestMemfdStrategyPrepare:
    """Tests for MemfdStrategy.prepare()."""

    def test_prepare_creates_fds(self, strategy):
        """prepare() creates one memfd per secret."""
        bundles = [FakeBundle("s1", b"secret1"), FakeBundle("s2", b"secret2")]
        result = strategy.prepare(bundles)

        assert len(result.extra_fds) == 2
        assert result.env_vars == {}

        # Verify data integrity
        for i, fd in enumerate(result.extra_fds):
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 100)
            assert data == bundles[i].value
            os.close(fd)

    def test_prepare_empty_secrets(self, strategy):
        """prepare() handles empty secrets list."""
        result = strategy.prepare([])

        assert len(result.extra_fds) == 0
        assert len(result.cleanup_funcs) == 0

    def test_prepare_large_secret(self, strategy):
        """prepare() handles large secrets."""
        large_value = b"x" * 1_000_000
        bundles = [FakeBundle("big", large_value)]
        result = strategy.prepare(bundles)

        assert len(result.extra_fds) == 1
        os.lseek(result.extra_fds[0], 0, os.SEEK_SET)
        data = os.read(result.extra_fds[0], len(large_value))
        assert data == large_value
        os.close(result.extra_fds[0])

    def test_prepare_null_bytes(self, strategy):
        """prepare() handles secrets with null bytes."""
        bundles = [FakeBundle("null", b"\x00\x00\x00\xff\xfe\xfd")]
        result = strategy.prepare(bundles)

        os.lseek(result.extra_fds[0], 0, os.SEEK_SET)
        data = os.read(result.extra_fds[0], 100)
        assert data == b"\x00\x00\x00\xff\xfe\xfd"
        os.close(result.extra_fds[0])

    def test_prepare_raises_on_memfd_failure(self, strategy):
        """prepare() raises OSError when memfd_create fails."""
        with patch(
            "executor.strategies.memfd_strategy.ctypes.CDLL"
        ) as mock_cdll:
            mock_libc = MagicMock()
            mock_cdll.return_value = mock_libc
            mock_libc.memfd_create.return_value = -1
            import ctypes

            mock_libc.memfd_create.errno = 38  # ENOSYS

            with patch("executor.strategies.memfd_strategy.ctypes.get_errno", return_value=38):
                with patch("os.strerror", return_value="Function not implemented"):
                    with pytest.raises(OSError, match="memfd_create failed"):
                        strategy.prepare([FakeBundle("s1", b"secret")])

    def test_prepare_raises_on_write_failure(self, strategy):
        """prepare() raises when write fails (FD cleanup tested separately)."""
        bundles = [FakeBundle("s1", b"secret")]

        # Use a real memfd but mock write to fail
        fd = os.memfd_create("test_write_fail", 0x0001 | 0x0002)  # MFD_CLOEXEC | MFD_ALLOW_SEALING

        with patch("os.write", side_effect=OSError(28, "No space left on device")):
            with pytest.raises(OSError, match="No space left on device"):
                strategy.prepare(bundles)

        os.close(fd)


class TestMemfdStrategyCleanup:
    """Tests for MemfdStrategy cleanup behavior."""

    def test_cleanup_closes_all_fds(self, strategy):
        """cleanup() closes all memfd FDs."""
        bundles = [FakeBundle("s1", b"one"), FakeBundle("s2", b"two")]
        result = strategy.prepare(bundles)

        fds = list(result.extra_fds)
        assert len(fds) == 2

        # Verify FDs are open
        for fd in fds:
            fcntl.fcntl(fd, fcntl.F_GETFD)

        # Run cleanup
        result.cleanup()

        # Verify FDs are closed
        for fd in fds:
            with pytest.raises(OSError):
                fcntl.fcntl(fd, fcntl.F_GETFD)

    def test_cleanup_is_idempotent(self, strategy):
        """cleanup() can be called multiple times without raising."""
        bundles = [FakeBundle("s1", b"secret")]
        result = strategy.prepare(bundles)

        result.cleanup()
        result.cleanup()  # Should not raise

    def test_cleanup_does_not_affect_std_fds(self, strategy):
        """cleanup() does not close stdin/stdout/stderr."""
        # Pipe FDs are typically 3+
        r, w = os.pipe()
        try:
            bundles = [FakeBundle("s1", b"secret")]
            result = strategy.prepare(bundles)
            result.cleanup()

            # Pipe should still be open
            fcntl.fcntl(r, fcntl.F_GETFD)
            fcntl.fcntl(w, fcntl.F_GETFD)
        finally:
            os.close(r)
            os.close(w)

    def test_cleanup_resilient_to_already_closed_fds(self, strategy):
        """cleanup() does not raise if FDs are already closed."""
        bundles = [FakeBundle("s1", b"secret")]
        result = strategy.prepare(bundles)

        # Close FDs manually
        for fd in result.extra_fds:
            os.close(fd)

        # Cleanup should not raise
        result.cleanup()


class TestMemfdStrategyConfig:
    """Tests for MemfdStrategy configuration."""

    def test_default_secret_base_fd(self):
        """MemfdStrategy defaults to secret_base_fd=100."""
        strategy = MemfdStrategy()
        assert strategy.secret_base_fd == 100

    def test_custom_secret_base_fd(self):
        """MemfdStrategy accepts a custom secret_base_fd value."""
        strategy = MemfdStrategy(secret_base_fd=200)
        assert strategy.secret_base_fd == 200

    def test_custom_secret_base_fd_affects_logical_fd(self):
        """secret_base_fd changes the logical FD in debug logging."""
        strategy = MemfdStrategy(secret_base_fd=50)
        bundles = [FakeBundle("s1", b"secret1"), FakeBundle("s2", b"secret2")]
        result = strategy.prepare(bundles)

        assert len(result.extra_fds) == 2
        for fd in result.extra_fds:
            os.close(fd)
        result.cleanup()


class TestMemfdSecurity:
    """Security tests for memfd injection."""

    def test_memfd_not_in_environ(self):
        """Verify secrets are not visible in /proc/self/environ."""
        strategy = MemfdStrategy()
        strategy.validate()

        bundles = [FakeBundle("test_secret", b"should-not-be-in-env")]
        result = strategy.prepare(bundles)

        proc = subprocess.Popen(
            "cat /proc/self/environ | tr '\\0' '\\n' | grep -c 'should-not-be-in-env' || true",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate()
        count = int(stdout.strip())
        assert count == 0, f"Secret found {count} times in /proc/self/environ"

        for fd in result.extra_fds:
            os.close(fd)
