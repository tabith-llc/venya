# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for secure memory: mlock, secure_zero, and SecureBuffer."""

import ctypes
from unittest.mock import patch

import pytest
from core.engine.secure_memory import (
    SecureBuffer,
    secure_mlock,
    secure_munlock,
    secure_zero,
)


class TestSecureZero:
    """Tests for secure_zero."""

    def test_zeros_bytearray(self):
        data = bytearray([1, 2, 3, 4, 5])
        secure_zero(data)
        assert data == bytearray(5)

    def test_zeros_empty_bytearray(self):
        data = bytearray()
        secure_zero(data)
        assert data == bytearray()

    def test_does_not_alter_memoryview(self):
        """secure_zero on memoryview returns early (no-op)."""
        original = bytearray([1, 2, 3])
        mv = memoryview(original)
        # memoryview path returns early — it's a no-op
        secure_zero(mv)
        # Original bytearray is unchanged
        assert original == bytearray([1, 2, 3])

    def test_zeros_large_buffer(self):
        data = bytearray(range(256)) * 100
        secure_zero(data)
        assert all(b == 0 for b in data)


class TestSecureBuffer:
    """Tests for SecureBuffer."""

    def test_create_buffer(self):
        buf = SecureBuffer(32)
        assert buf.size == 32
        assert len(buf) == 32
        assert not buf.is_locked
        assert not buf.is_zeroed

    def test_create_zeroed_buffer(self):
        buf = SecureBuffer(16)
        # New buffer should be all zeros
        assert buf.read() == b"\x00" * 16

    def test_create_negative_size_raises(self):
        with pytest.raises(ValueError, match="positive"):
            SecureBuffer(0)

        with pytest.raises(ValueError, match="positive"):
            SecureBuffer(-1)

    def test_write_and_read(self):
        buf = SecureBuffer(16)
        buf.write(b"hello world")
        assert buf.read(0, 11) == b"hello world"

    def test_write_oob_raises(self):
        buf = SecureBuffer(5)
        with pytest.raises(ValueError, match="exceeds"):
            buf.write(b"too long")

    def test_write_partial(self):
        buf = SecureBuffer(10)
        buf.write(b"hello", offset=3)
        assert buf.read(3, 5) == b"hello"
        # Bytes before offset are still zero
        assert buf.read(0, 3) == b"\x00\x00\x00"

    def test_clear_zeros_buffer(self):
        buf = SecureBuffer(16)
        buf.write(b"secret data")
        buf.clear()
        assert buf.is_zeroed
        assert buf.read() == b"\x00" * 16

    def test_write_after_clear(self):
        buf = SecureBuffer(16)
        buf.write(b"first")
        buf.clear()
        assert buf.is_zeroed
        buf.write(b"second")
        assert not buf.is_zeroed

    def test_context_manager_clears(self):
        buf = SecureBuffer(16)
        buf.write(b"secret")
        with buf:
            pass
        # After exiting context, buffer should be cleared
        # Note: __exit__ clears the buffer
        assert buf.is_zeroed

    def test_item_access(self):
        buf = SecureBuffer(5)
        buf.write(b"abcde")
        assert buf[0] == ord("a")
        assert buf[4] == ord("e")
        buf[0] = ord("X")
        assert buf[0] == ord("X")

    def test_read_slice(self):
        buf = SecureBuffer(10)
        buf.write(b"0123456789")
        assert buf.read(2, 4) == b"2345"

    def test_read_full(self):
        buf = SecureBuffer(8)
        buf.write(b"abcdefgh")
        assert buf.read() == b"abcdefgh"

    def test_read_with_length_none(self):
        buf = SecureBuffer(8)
        buf.write(b"abcdefgh")
        assert buf.read(0, None) == b"abcdefgh"


class TestSecureMlock:
    """Tests for mlock functionality."""

    def test_mlock_not_available_on_non_linux(self):
        with patch("core.engine.secure_memory.platform.system", return_value="Darwin"):
            with pytest.raises(RuntimeError, match="only supported on Linux"):
                secure_mlock(bytearray(16))

    def test_mlock_empty_raises(self):
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with pytest.raises(ValueError, match="empty"):
                secure_mlock(bytearray())

    def test_mlock_not_found_library(self):
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch("core.engine.secure_memory._load_system_lib", return_value=None):
                with pytest.raises(RuntimeError, match="Cannot find system C library"):
                    secure_mlock(bytearray(16))

    def test_mlock_no_permission(self):
        """Test that mlock failure raises OSError with correct message."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = -1
            with patch("core.engine.secure_memory.ctypes.get_errno", return_value=1):
                with patch("os.strerror", return_value="Operation not permitted"):
                    with pytest.raises(OSError, match="Operation not permitted"):
                        secure_mlock(bytearray(16))
            patch.stopall()

    def test_mlock_succeeds_with_cap(self):
        """Test mlock succeeds when CAP_IPC_LOCK is available."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = 0
            data = bytearray(32)
            secure_mlock(data)
            expected_ptr = ctypes.addressof(ctypes.c_char.from_buffer(data))
            mock_lib.return_value.mlock.assert_called_once_with(expected_ptr, 32)
            patch.stopall()

    def test_munlock_succeeds(self):
        """Test munlock succeeds."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.munlock.return_value = 0
            data = bytearray(32)
            secure_munlock(data)
            expected_ptr = ctypes.addressof(ctypes.c_char.from_buffer(data))
            mock_lib.return_value.munlock.assert_called_once_with(expected_ptr, 32)
            patch.stopall()

    def test_munlock_non_linux_is_noop(self):
        with patch("core.engine.secure_memory.platform.system", return_value="Darwin"):
            data = bytearray(32)
            # Should not raise
            secure_munlock(data)


class TestSecureBufferMlock:
    """Tests for SecureBuffer with mlock enabled."""

    def test_buffer_with_mlock(self):
        """Test that SecureBuffer sets _locked=True when mlock succeeds."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = 0
            buf = SecureBuffer(32, mlock=True)
            assert buf.is_locked
            buf.clear()
            del buf
            patch.stopall()

    def test_buffer_mlock_failure(self):
        """Test that mlock failure raises through __init__."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = -1
            with patch("core.engine.secure_memory.ctypes.get_errno", return_value=1):
                with patch("os.strerror", return_value="Operation not permitted"):
                    with pytest.raises(OSError):
                        SecureBuffer(32, mlock=True)
            patch.stopall()

    def test_context_manager_unlocks(self):
        """Test that context manager unlocks buffer on exit."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = 0
            mock_lib.return_value.munlock.return_value = 0
            buf = SecureBuffer(32, mlock=True)
            assert buf.is_locked
            with buf:
                pass
            assert not buf.is_locked
            patch.stopall()

    def test_del_unlocks(self):
        """Test that __del__ unlocks and clears."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            mock_lib = patch("core.engine.secure_memory._load_system_lib").start()
            mock_lib.return_value.mlock.return_value = 0
            mock_lib.return_value.munlock.return_value = 0
            buf = SecureBuffer(32, mlock=True)
            assert buf.is_locked
            # __del__ only unlocks if not already zeroed
            # Write some data but don't clear
            buf.write(b"secret")
            assert not buf.is_zeroed
            buf.__del__()
            assert not buf.is_locked
            assert buf.is_zeroed
            patch.stopall()


class TestSecureBufferAutoZero:
    """Tests for auto-zero behavior."""

    def test_context_manager_auto_clears(self):
        """Buffer is cleared when exiting context."""
        buf = SecureBuffer(16)
        buf.write(b"secret")
        assert not buf.is_zeroed
        with buf:
            pass
        assert buf.is_zeroed

    def test_explicit_clear_then_exit(self):
        """If already cleared, __exit__ doesn't re-zero."""
        buf = SecureBuffer(16)
        buf.write(b"secret")
        buf.clear()
        assert buf.is_zeroed
        with buf:
            pass
        assert buf.is_zeroed

    def test_del_auto_clears(self):
        """Buffer is cleared on __del__ if not already zeroed."""
        buf = SecureBuffer(16)
        buf.write(b"secret")
        assert not buf.is_zeroed
        buf.__del__()
        # After __del__, the buffer should be zeroed
        assert buf.is_zeroed
