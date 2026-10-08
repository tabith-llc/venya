# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for secure memory: mlock, secure_zero, SecureBuffer, and the KEK cache."""

import ctypes
from unittest.mock import patch

import pytest
from core.engine.secure_memory import (
    KekCache,
    SecureBuffer,
    SecureBufferReleasedError,
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

    def test_memoryview_raises_instead_of_no_op(self):
        """secure_zero on a memoryview raises TypeError — it must not quietly do nothing.

        The old behavior (return without touching the buffer) made a release
        log that says "zeroized" a lie. A view is not the owner of the memory;
        the caller passes the bytearray. (refs 472)
        """
        original = bytearray([1, 2, 3])
        mv = memoryview(original)
        with pytest.raises(TypeError, match="owning bytearray"):
            secure_zero(mv)
        # The buffer was not touched by the refused call.
        assert original == bytearray([1, 2, 3])
        mv.release()

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
            # Write some data but don't clear. A locked buffer takes a
            # full-size write (#472: never resize a pinned buffer).
            buf.write(b"s" * 32)
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


def _fake_libc(mlock_rc: int = 0, munlock_rc: int = 0) -> object:
    """A stand-in C library: mlock/munlock return the given codes."""

    class _Lib:
        def mlock(self, addr: int, size: int) -> int:
            return mlock_rc

        def munlock(self, addr: int, size: int) -> int:
            return munlock_rc

    return _Lib()


class TestKekCacheView:
    """The reader contract: one scoped read-only view (#472, test-plan cell 2)."""

    def test_view_yields_read_only_memoryview(self):
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        with cache.view() as kek:
            assert isinstance(kek, memoryview)
            assert kek.readonly is True
            assert len(kek) == 32
            assert bytes(kek) == b"K" * 32

    def test_view_never_hands_out_bytes_or_the_buffer(self):
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        with cache.view() as kek:
            assert not isinstance(kek, bytes)
            assert not isinstance(kek, SecureBuffer)

    def test_round_trip_through_the_view_equals_the_bytes_result(self):
        """wrap/unwrap with a read-only view produce exactly the bytes-key result."""
        from core.engine.encryption import unwrap_key, wrap_key

        key = b"R" * 32
        plaintext_key = b"D" * 32
        cache = KekCache.from_bytes(key, mlock=False)
        with cache.view() as kek:
            wrapped = wrap_key(kek, plaintext_key)
        assert len(wrapped) == 40
        # Cross-check both directions: bytes-wrapped unwraps under the view and
        # view-wrapped unwraps under the bytes key.
        with cache.view() as kek:
            assert unwrap_key(kek, wrap_key(key, plaintext_key)) == plaintext_key
        assert unwrap_key(key, wrapped) == plaintext_key

    def test_view_after_release_raises(self):
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        cache.release()
        with pytest.raises(SecureBufferReleasedError):
            with cache.view():
                pass

    def test_view_before_populate_raises(self):
        """An unpopulated cache raises rather than handing out zero bytes."""
        cache = KekCache(32, mlock=False)
        with pytest.raises(SecureBufferReleasedError):
            with cache.view():
                pass

    def test_assigning_through_the_view_raises(self):
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        with pytest.raises(TypeError):
            with cache.view() as kek:
                kek[0] = 0

    def test_views_are_not_stashable(self):
        """A view outlives its block only as an unusable object."""
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        with cache.view() as kek:
            stashed = kek
        with pytest.raises(ValueError, match="released memoryview"):
            bytes(stashed)

    def test_release_is_idempotent(self):
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        assert cache.release() is True
        assert cache.release() is True

    def test_populate_after_release_refuses(self):
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        cache.release()
        with pytest.raises(ValueError, match="released"):
            cache.populate(b"J" * 32)

    def test_populate_wrong_size_refuses(self):
        cache = KekCache(32, mlock=False)
        with pytest.raises(ValueError, match="exactly 32"):
            cache.populate(b"short")


class TestKekCacheRelease:
    """Release zeroes and reports the attempt, nothing more (cell 3)."""

    def test_release_zeroes_and_reports(self, caplog):
        cache = KekCache.from_bytes(b"erase-me-please-32-bytes-here!!!", mlock=False)
        with caplog.at_level("INFO", logger="core.engine.secure_memory"):
            assert cache.release() is True
        assert cache.is_zeroed is True
        line = cache_release_line(caplog)
        assert "zeroized=yes" in line
        assert "munlock=not locked" in line

    def test_secure_zero_failure_does_not_report_zeroized(self, caplog):
        """The negative half: a failed erase must not be logged as done."""
        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        with patch("core.engine.secure_memory.secure_zero", side_effect=RuntimeError("boom")):
            with caplog.at_level("INFO", logger="core.engine.secure_memory"):
                assert cache.release() is False
        assert cache.is_zeroed is False
        line = cache_release_line(caplog)
        assert "zeroized=no" in line
        assert "zeroized=yes" not in line

    def test_release_never_logs_key_material(self, caplog):
        secret = b"NEVER-LOG-THIS-KEY-MATERIAL-PAD!"  # 32 bytes
        cache = KekCache.from_bytes(secret, mlock=False)
        with caplog.at_level("INFO", logger="core.engine.secure_memory"):
            cache.release()
        assert secret.decode() not in caplog.text
        assert "NEVER-LOG" not in caplog.text

    def test_munlock_failure_is_reported_not_raised(self, caplog):
        """A buffer that cannot be unlocked still releases quietly."""
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch(
                "core.engine.secure_memory._load_system_lib", return_value=_fake_libc(mlock_rc=0, munlock_rc=-1)
            ):
                with patch("core.engine.secure_memory.ctypes.get_errno", return_value=1):
                    cache = KekCache(32, mlock=True)
                    assert cache.pin_active is True
                    cache.populate(b"K" * 32)
                    with caplog.at_level("INFO", logger="core.engine.secure_memory"):
                        assert cache.release() is True
        line = cache_release_line(caplog)
        assert "zeroized=yes" in line
        assert "munlock=failed" in line


class TestKekCachePinning:
    """Pinning is attempted and reported, never fatal (cells 5 and 6)."""

    def test_mlock_failure_is_not_fatal_and_names_errno(self, caplog):
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch("core.engine.secure_memory._load_system_lib", return_value=_fake_libc(mlock_rc=-1)):
                with patch("core.engine.secure_memory.ctypes.get_errno", return_value=1):
                    with caplog.at_level("INFO", logger="core.engine.secure_memory"):
                        cache = KekCache(32, mlock=True)
        assert cache.pin_active is False
        assert cache.pin_errno == 1
        # ...and the unpinned cache still serves.
        cache.populate(b"K" * 32)
        with cache.view() as kek:
            assert bytes(kek) == b"K" * 32
        line = cache_pin_line(caplog)
        assert "pin=inactive" in line
        assert "errno=1" in line
        assert "NOT pinned" in line

    def test_non_linux_mlock_is_reported_not_fatal(self, caplog):
        with patch("core.engine.secure_memory.platform.system", return_value="Darwin"):
            with caplog.at_level("INFO", logger="core.engine.secure_memory"):
                cache = KekCache(32, mlock=True)
        assert cache.pin_active is False
        assert "pin=inactive" in cache_pin_line(caplog)
        cache.populate(b"K" * 32)
        with cache.view() as kek:
            assert len(kek) == 32

    def test_pin_success_reports_active_with_page_rounded_cost(self, caplog):
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch("core.engine.secure_memory._load_system_lib", return_value=_fake_libc()):
                with caplog.at_level("INFO", logger="core.engine.secure_memory"):
                    cache = KekCache(32, mlock=True)
        assert cache.pin_active is True
        assert cache.is_pinned is True
        line = cache_pin_line(caplog)
        assert "pin=active" in line
        assert "mlock 32 bytes" in line
        assert "page-rounded to 4 KiB" in line
        assert "budget" in line
        cache.release()

    def test_wrap_key_under_an_empty_cache_raises_not_envelope(self):
        """The zero-KEK trap: a released cache must never produce an envelope."""
        from core.engine.encryption import wrap_key

        cache = KekCache.from_bytes(b"K" * 32, mlock=False)
        cache.release()
        with pytest.raises(SecureBufferReleasedError):
            with cache.view() as kek:
                wrap_key(kek, b"D" * 32)


class TestSecureBufferLockedWrite:
    """Never resize a pinned buffer (cell 7)."""

    def _locked_buffer(self) -> SecureBuffer:
        with patch("core.engine.secure_memory.platform.system", return_value="Linux"):
            with patch("core.engine.secure_memory._load_system_lib", return_value=_fake_libc()):
                buf = SecureBuffer(32, mlock=True)
        assert buf.is_locked
        return buf

    def test_different_length_write_on_locked_buffer_raises(self):
        buf = self._locked_buffer()
        with pytest.raises(ValueError, match="full 32-byte write"):
            buf.write(b"short")
        with pytest.raises(ValueError, match="full 32-byte write"):
            buf.write(b"x" * 16, offset=0)

    def test_equal_length_write_keeps_address_and_lock(self):
        buf = self._locked_buffer()
        addr_before = ctypes.addressof(ctypes.c_char.from_buffer(buf._data))
        buf.write(b"A" * 32)
        addr_after = ctypes.addressof(ctypes.c_char.from_buffer(buf._data))
        assert buf.is_locked
        assert addr_after == addr_before, "an equal-length write moved the pinned buffer"
        assert buf.read() == b"A" * 32


def cache_pin_line(caplog) -> str:
    """The single kek-cache pin line from the captured log."""
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("kek cache: pin=")]
    assert len(lines) == 1, f"expected exactly one pin line, got {lines}"
    return lines[0]


def cache_release_line(caplog) -> str:
    """The single kek-cache release line from the captured log."""
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("kek cache: released")]
    assert len(lines) == 1, f"expected exactly one release line, got {lines}"
    return lines[0]
