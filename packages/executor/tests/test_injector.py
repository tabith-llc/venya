"""Tests for credential injection (sentinels, FD injection, FD whitelisting)."""

import base64
import fcntl
import os
import re
import stat
import tempfile
from pathlib import Path

from executor.injector import (
    SentinelRegistry,
    inject_via_fifo,
    inject_via_file,
    inject_via_memfd,
    parse_sentinels,
    scan_open_fds,
    set_cloexec,
    strip_sentinel,
    verify_fd_whitelist,
    wrap_with_sentinel,
)

# ---------------------------------------------------------------------------
# SentinelRegistry
# ---------------------------------------------------------------------------


class TestSentinelRegistry:
    """Tests for SentinelRegistry."""

    def test_register_and_get(self):
        reg = SentinelRegistry(session_id="s1")
        reg.register("db-password", "a1b2c3d4")

        assert reg.get_secret_id("a1b2c3d4") == "db-password"

    def test_register_overwrites_same_hash(self):
        reg = SentinelRegistry(session_id="s1")
        reg.register("secret-a", "hash1")
        reg.register("secret-b", "hash1")

        assert reg.get_secret_id("hash1") == "secret-b"

    def test_get_nonexistent_hash(self):
        reg = SentinelRegistry(session_id="s1")
        assert reg.get_secret_id("nonexistent") is None

    def test_get_session_hashes(self):
        reg = SentinelRegistry(session_id="s1")
        reg.register("s1", "hash1")
        reg.register("s2", "hash2")
        reg.register("s3", "hash3")

        hashes = reg.get_session_hashes()
        assert hashes == {"hash1", "hash2", "hash3"}

    def test_get_session_hashes_empty(self):
        reg = SentinelRegistry(session_id="s1")
        assert reg.get_session_hashes() == set()

    def test_clear(self):
        reg = SentinelRegistry(session_id="s1")
        reg.register("s1", "hash1")
        reg.register("s2", "hash2")
        reg.clear()

        assert reg.get_session_hashes() == set()
        assert reg.get_secret_id("hash1") is None

    def test_clear_does_not_affect_other_sessions(self):
        """Clear only affects this registry instance."""
        reg1 = SentinelRegistry(session_id="s1")
        reg2 = SentinelRegistry(session_id="s2")
        reg1.register("s1", "hash1")
        reg2.register("s2", "hash2")

        reg1.clear()
        assert reg2.get_secret_id("hash2") == "s2"


# ---------------------------------------------------------------------------
# wrap_with_sentinel / strip_sentinel
# ---------------------------------------------------------------------------


class TestSentinelWrapping:
    """Tests for sentinel wrapping and stripping."""

    def test_round_trip_simple(self):
        original = b"my-secret-password"
        wrapped = wrap_with_sentinel("db-password", original)
        stripped = strip_sentinel(wrapped)

        assert stripped == original

    def test_round_trip_binary(self):
        original = b"\x00\x01\x02\xff\xfe\xfd"
        wrapped = wrap_with_sentinel("binary-secret", original)
        stripped = strip_sentinel(wrapped)

        assert stripped == original

    def test_round_trip_empty(self):
        original = b""
        wrapped = wrap_with_sentinel("empty-secret", original)
        stripped = strip_sentinel(wrapped)

        assert stripped == original

    def test_round_trip_long(self):
        original = b"A" * 10000
        wrapped = wrap_with_sentinel("long-secret", original)
        stripped = strip_sentinel(wrapped)

        assert stripped == original

    def test_sentinel_format(self):
        wrapped = wrap_with_sentinel("test-secret", b"value")

        # Should match [VENYA:{8-char-hex}]base64[/VENYA]
        assert re.match(rb"\[VENYA:[a-f0-9]{8}\]", wrapped)
        assert wrapped.endswith(b"[/VENYA]")

    def test_sentinel_hash_is_sha256_prefix(self):
        secret_id = "my-db-password"
        wrapped = wrap_with_sentinel(secret_id, b"value")

        import hashlib

        expected_hash = hashlib.sha256(secret_id.encode()).hexdigest()[:8]

        assert f"[VENYA:{expected_hash}]".encode() in wrapped

    def test_wrapped_contains_base64(self):
        original = b"test-value"
        wrapped = wrap_with_sentinel("s1", original)

        base64.b64decode(wrapped.split(b"[VENYA:")[1].split(b"]")[0])
        # The part between [VENYA:hash] and [/VENYA] is base64
        match = re.search(rb"\[VENYA:[a-f0-9]{8}\](.*?)\[/VENYA\]", wrapped)
        assert match
        assert base64.b64decode(match.group(1)) == original

    def test_strip_non_wrapped_returns_original(self):
        data = b"not wrapped at all"
        result = strip_sentinel(data)

        assert result == data

    def test_strip_missing_suffix_returns_original(self):
        data = b"[VENYA:a1b2c3d4]base64data"
        result = strip_sentinel(data)

        assert result == data

    def test_strip_missing_prefix_returns_original(self):
        data = b"base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_strip_invalid_hash_returns_original(self):
        data = b"[VENYA:INVALID]base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data


# ---------------------------------------------------------------------------
# parse_sentinels
# ---------------------------------------------------------------------------


class TestParseSentinels:
    """Tests for parse_sentinels()."""

    def test_parse_single_sentinel(self):
        wrapped = wrap_with_sentinel("s1", b"secret-value")
        results = parse_sentinels(wrapped)

        assert len(results) == 1
        hash_prefix, decoded = results[0]
        assert len(hash_prefix) == 8
        assert decoded == b"secret-value"

    def test_parse_multiple_sentinels(self):
        data = wrap_with_sentinel("s1", b"secret-one") + b" " + wrap_with_sentinel("s2", b"secret-two")
        results = parse_sentinels(data)

        assert len(results) == 2
        assert results[0][1] == b"secret-one"
        assert results[1][1] == b"secret-two"

    def test_parse_no_sentinels(self):
        results = parse_sentinels(b"no sentinels here")
        assert results == []

    def test_parse_empty_data(self):
        results = parse_sentinels(b"")
        assert results == []

    def test_parse_sentinel_with_padding(self):
        """Sentinel with base64 padding (=) is correctly decoded."""
        original = b"ab"  # 2 bytes → base64 "YWI=" (with padding)
        wrapped = wrap_with_sentinel("pad-test", original)
        results = parse_sentinels(wrapped)

        assert len(results) == 1
        assert results[0][1] == original

    def test_sentinel_with_trailing_text(self):
        """Sentinel followed by non-sentinel text is correctly parsed."""
        wrapped = wrap_with_sentinel("s1", b"secret")
        data = wrapped + b" -- end of injection"
        results = parse_sentinels(data)

        assert len(results) == 1
        assert results[0][1] == b"secret"

    def test_sentinel_with_leading_text(self):
        """Sentinel preceded by text is correctly parsed."""
        wrapped = wrap_with_sentinel("s1", b"secret")
        data = b"INJECT:" + wrapped
        results = parse_sentinels(data)

        assert len(results) == 1
        assert results[0][1] == b"secret"

    def test_sentinels_back_to_back_no_separator(self):
        """Two sentinels concatenated without separator are parsed separately."""
        w1 = wrap_with_sentinel("s1", b"alpha")
        w2 = wrap_with_sentinel("s2", b"beta")
        data = w1 + w2
        results = parse_sentinels(data)

        assert len(results) == 2
        assert results[0][1] == b"alpha"
        assert results[1][1] == b"beta"

    def test_sentinel_with_special_base64_chars(self):
        """Secrets that produce + and / in base64 are handled."""
        # b'\xff\xfe' encodes to b"/w4=" in base64
        original = b"\xff\xfe"
        wrapped = wrap_with_sentinel("special-b64", original)
        stripped = strip_sentinel(wrapped)

        assert stripped == original

    def test_sentinel_hash_prefix_is_consistent(self):
        """The hash prefix is deterministic for a given secret_id."""
        wrapped1 = wrap_with_sentinel("same-id", b"val1")
        wrapped2 = wrap_with_sentinel("same-id", b"val2")

        prefix1 = re.search(rb"\[VENYA:([a-f0-9]{8})\]", wrapped1).group(1)
        prefix2 = re.search(rb"\[VENYA:([a-f0-9]{8})\]", wrapped2).group(1)

        assert prefix1 == prefix2

    def test_sentinel_different_ids_different_hashes(self):
        """Different secret_ids produce different hash prefixes."""
        wrapped1 = wrap_with_sentinel("id-a", b"val")
        wrapped2 = wrap_with_sentinel("id-b", b"val")

        prefix1 = re.search(rb"\[VENYA:([a-f0-9]{8})\]", wrapped1).group(1)
        prefix2 = re.search(rb"\[VENYA:([a-f0-9]{8})\]", wrapped2).group(1)

        assert prefix1 != prefix2

    def test_sentinel_contains_only_valid_base64(self):
        """The data portion between sentinels contains only valid base64 chars."""
        import string

        valid_b64_chars = set(string.ascii_letters + string.digits + "+/=")
        wrapped = wrap_with_sentinel("charset-test", b"any content \x00\xff\xfe")
        match = re.search(rb"\[VENYA:[a-f0-9]{8}\](.*?)\[/VENYA\]", wrapped)
        assert match
        data = match.group(1)
        assert all(chr(b) in valid_b64_chars for b in data)

    def test_sentinel_format_is_valid(self):
        """Full sentinel format matches expected pattern."""
        wrapped = wrap_with_sentinel("test-secret", b"value")
        full_pattern = re.compile(rb"\[VENYA:[a-f0-9]{8}\][A-Za-z0-9+/=]*\[/VENYA\]")
        assert full_pattern.fullmatch(wrapped)


class TestSentinelValidation:
    """Tests for sentinel hash validation."""

    def test_validate_known_hash(self):
        """Known hash returns True."""
        reg = SentinelRegistry(session_id="s1")
        reg.register("my-secret", "a1b2c3d4")

        assert reg.validate_hash("a1b2c3d4") is True

    def test_validate_unknown_hash(self):
        """Unknown hash returns False."""
        reg = SentinelRegistry(session_id="s1")
        reg.register("my-secret", "a1b2c3d4")

        assert reg.validate_hash("deadbeef") is False

    def test_validate_empty_registry(self):
        """All hashes are unknown in empty registry."""
        reg = SentinelRegistry(session_id="s1")

        assert reg.validate_hash("anyhash") is False

    def test_validate_after_clear(self):
        """Hashes are unknown after registry is cleared."""
        reg = SentinelRegistry(session_id="s1")
        reg.register("my-secret", "a1b2c3d4")
        reg.clear()

        assert reg.validate_hash("a1b2c3d4") is False

    def test_validate_multiple_hashes(self):
        """Multiple registered hashes can all be validated."""
        reg = SentinelRegistry(session_id="s1")
        reg.register("s1", "hash1")
        reg.register("s2", "hash2")
        reg.register("s3", "hash3")

        assert reg.validate_hash("hash1") is True
        assert reg.validate_hash("hash2") is True
        assert reg.validate_hash("hash3") is True
        assert reg.validate_hash("hash4") is False


class TestSentinelEdgeCases:
    """Edge case tests for sentinel wrapping and stripping."""

    def test_secret_containing_sentinel_like_string(self):
        """A secret that contains '[VENYA:' before base64 encoding is safe."""
        # The secret contains a sentinel-like string, but after base64 encoding
        # the bracket characters are encoded and cannot match the sentinel pattern
        original = b"prefix [VENYA:abc12345] middle [/VENYA] suffix"
        wrapped = wrap_with_sentinel("tricky", original)
        stripped = strip_sentinel(wrapped)

        assert stripped == original

    def test_secret_that_is_exact_sentinel_pattern(self):
        """A secret that IS the sentinel pattern itself."""
        original = b"[VENYA:abcdef01]data[/VENYA]"
        wrapped = wrap_with_sentinel("self-ref", original)
        stripped = strip_sentinel(wrapped)

        assert stripped == original

    def test_empty_hash_prefix_rejected(self):
        """Sentinel with empty hash prefix is not matched."""
        data = b"[VENYA:]base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_short_hash_prefix_rejected(self):
        """Sentinel with hash shorter than 8 chars is not matched."""
        data = b"[VENYA:abc1]base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_long_hash_prefix_rejected(self):
        """Sentinel with hash longer than 8 chars is not matched."""
        data = b"[VENYA:abcdef012]base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_uppercase_hash_prefix_rejected(self):
        """Sentinel with uppercase hex is not matched (lowercase only)."""
        data = b"[VENYA:ABCDEF01]base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_non_hex_hash_rejected(self):
        """Sentinel with non-hex characters is not matched."""
        data = b"[VENYA:GGGGGGGG]base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_missing_closing_bracket_prefix(self):
        """Sentinel missing closing bracket of prefix is not matched."""
        data = b"[VENYA:abcdef01base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_missing_opening_bracket_prefix(self):
        """Sentinel missing opening bracket of prefix is not matched."""
        data = b"VENYA:abcdef01]base64data[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_extra_characters_before_sentinel(self):
        """Sentinel preceded by other characters is still found by search()."""
        import base64

        valid_b64 = base64.b64encode(b"test").decode()
        data = b"X[VENYA:abcdef01]" + valid_b64.encode() + b"[/VENYA]"
        result = strip_sentinel(data)

        assert result == b"test"

    def test_single_sentinel_in_large_buffer(self):
        """Single sentinel correctly extracted from large buffer."""
        wrapped = wrap_with_sentinel("s1", b"target-secret")
        prefix = b"X" * 10000
        suffix = b"Y" * 10000
        data = prefix + wrapped + suffix
        stripped = strip_sentinel(data)

        assert stripped == b"target-secret"

    def test_strip_preserves_non_sentinel_data(self):
        """Non-sentinel data is preserved when no sentinel found."""
        data = b"some process output with [brackets] and [/tags]"
        result = strip_sentinel(data)

        assert result == data

    def test_parse_sentinels_empty_results_for_no_sentinels(self):
        """parse_sentinels returns empty list for data without sentinels."""
        data = b"just plain text with [VENYA: prefix but no closing"
        results = parse_sentinels(data)

        assert results == []

    def test_strip_sentinel_with_only_prefix(self):
        """Sentinel with only prefix (no data, no suffix) is not matched."""
        data = b"[VENYA:abcdef01]"
        result = strip_sentinel(data)

        assert result == data

    def test_strip_sentinel_with_only_suffix(self):
        """Sentinel with only suffix (no prefix, no data) is not matched."""
        data = b"[/VENYA]"
        result = strip_sentinel(data)

        assert result == data

    def test_strip_sentinel_reverse_order(self):
        """Closing tag before opening tag is not matched."""
        data = b"[/VENYA]base64data[VENYA:abcdef01]"
        result = strip_sentinel(data)

        assert result == data


# ---------------------------------------------------------------------------
# inject_via_file
# ---------------------------------------------------------------------------


class TestInjectViaFile:
    """Tests for tmpfs file injection."""

    def test_file_created(self, tmp_path: Path):
        injection = inject_via_file(b"secret-data", str(tmp_path))

        assert os.path.exists(injection.injection_path)

    def test_file_permissions(self, tmp_path: Path):
        injection = inject_via_file(b"secret-data", str(tmp_path))

        file_stat = os.stat(injection.injection_path)
        mode = stat.S_IMODE(file_stat.st_mode)
        assert mode == 0o400

    def test_file_content(self, tmp_path: Path):
        injection = inject_via_file(b"secret-content", str(tmp_path))

        content = Path(injection.injection_path).read_bytes()
        assert content == b"secret-content"

    def test_file_name_pattern(self, tmp_path: Path):
        injection = inject_via_file(b"data", str(tmp_path))

        assert injection.injection_path.startswith(str(tmp_path) + "/venya_")
        assert injection.injection_path.endswith(".secret")

    def test_multiple_injections_different_files(self, tmp_path: Path):
        i1 = inject_via_file(b"secret-1", str(tmp_path))
        i2 = inject_via_file(b"secret-2", str(tmp_path))

        assert i1.injection_path != i2.injection_path
        assert Path(i1.injection_path).read_bytes() == b"secret-1"
        assert Path(i2.injection_path).read_bytes() == b"secret-2"

    def test_creates_directory_if_missing(self, tmp_path: Path):
        secret_dir = tmp_path / "new-secrets-dir"

        injection = inject_via_file(b"data", str(secret_dir))

        assert secret_dir.exists()
        assert os.path.exists(injection.injection_path)

    def test_injection_path_format(self, tmp_path: Path):
        injection = inject_via_file(b"data", str(tmp_path))

        assert injection.secret_id == ""
        assert injection.sentinel_hash == ""
        assert isinstance(injection.injection_path, str)


# ---------------------------------------------------------------------------
# inject_via_memfd
# ---------------------------------------------------------------------------


class TestInjectViaMemfd:
    """Tests for memfd injection."""

    def test_memfd_available_on_linux(self):
        """memfd_create should be available on Linux."""
        fd, injection = inject_via_memfd(b"test-secret")

        try:
            assert fd >= 0
            assert "memfd:" in injection.injection_path
            assert injection.secret_id == ""

            # Verify data was written
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 1024)
            assert data == b"test-secret"
        finally:
            os.close(fd)

    def test_memfd_data_integrity(self):
        """Data written to memfd is intact."""
        original = b"\x00\x01\x02\x03\x04\x05\xff\xfe\xfd"
        fd, _ = inject_via_memfd(original)

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, len(original)) == original
        finally:
            os.close(fd)

    def test_memfd_empty_data(self):
        """Empty secret can be injected via memfd."""
        fd, _ = inject_via_memfd(b"")

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, 1) == b""
        finally:
            os.close(fd)

    def test_memfd_large_data(self):
        """Large secret can be injected via memfd."""
        original = b"A" * 100000
        fd, _ = inject_via_memfd(original)

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, len(original)) == original
        finally:
            os.close(fd)


# ---------------------------------------------------------------------------
# inject_via_fifo
# ---------------------------------------------------------------------------


class TestInjectViaFifo:
    """Tests for FIFO injection."""

    def test_fifo_created(self, tmp_path: Path):
        fifo_path = str(tmp_path / "test.fifo")

        inject_via_fifo(fifo_path, b"secret-data")

        assert os.path.exists(fifo_path)
        assert stat.S_ISFIFO(os.stat(fifo_path).st_mode)

    def test_fifo_permissions(self, tmp_path: Path):
        fifo_path = str(tmp_path / "test.fifo")

        inject_via_fifo(fifo_path, b"data")

        mode = stat.S_IMODE(os.stat(fifo_path).st_mode)
        assert mode == 0o600

    def test_fifo_content_readable(self, tmp_path: Path):
        fifo_path = str(tmp_path / "test.fifo")
        secret = b"fifo-secret-content"

        inject_via_fifo(fifo_path, secret)

        # Give the background thread a moment to write
        import time

        time.sleep(0.2)

        with open(fifo_path, "rb") as f:
            data = f.read()
        assert data == secret

    def test_fifo_overwrites_existing(self, tmp_path: Path):
        fifo_path = str(tmp_path / "test.fifo")

        # Create a regular file first
        Path(fifo_path).write_bytes(b"old-content")
        assert not stat.S_ISFIFO(os.stat(fifo_path).st_mode)

        inject_via_fifo(fifo_path, b"new-secret")

        assert stat.S_ISFIFO(os.stat(fifo_path).st_mode)

    def test_fifo_injection_path(self, tmp_path: Path):
        fifo_path = str(tmp_path / "test.fifo")

        injection = inject_via_fifo(fifo_path, b"data")

        assert injection.injection_path == fifo_path


# ---------------------------------------------------------------------------
# verify_fd_whitelist
# ---------------------------------------------------------------------------


class TestVerifyFdWhitelist:
    """Tests for FD whitelist verification."""

    def test_only_default_fds_allowed(self):
        """Only FDs 0, 1, 2 — no unexpected."""
        unexpected = verify_fd_whitelist({0, 1, 2})
        assert unexpected == []

    def test_extra_allowed_fds(self):
        """Extra allowed FDs are not flagged."""
        unexpected = verify_fd_whitelist({0, 1, 2, 3, 4}, allowed_fds={3, 4})
        assert unexpected == []

    def test_unexpected_fd_detected(self):
        """FD 5 without annotation is flagged."""
        unexpected = verify_fd_whitelist({0, 1, 2, 5})
        assert unexpected == [5]

    def test_multiple_unexpected_fds(self):
        """Multiple unexpected FDs are all reported, sorted."""
        unexpected = verify_fd_whitelist({0, 1, 2, 5, 7, 3})
        assert unexpected == [3, 5, 7]

    def test_allowed_fds_merges_with_defaults(self):
        """allowed_fds is combined with {0, 1, 2}."""
        unexpected = verify_fd_whitelist({0, 1, 2, 10, 11}, allowed_fds={10})
        assert unexpected == [11]

    def test_none_allowed_fds(self):
        """None allowed_fds defaults to only 0, 1, 2."""
        unexpected = verify_fd_whitelist({0, 1, 2, 3}, None)
        assert unexpected == [3]

    def test_empty_fds(self):
        """No open FDs — nothing unexpected."""
        unexpected = verify_fd_whitelist(set())
        assert unexpected == []

    def test_unsorted_output(self):
        """Unexpected FDs are returned sorted."""
        unexpected = verify_fd_whitelist({0, 1, 2, 99, 3, 50})
        assert unexpected == [3, 50, 99]


# ---------------------------------------------------------------------------
# scan_open_fds
# ---------------------------------------------------------------------------


class TestScanOpenFds:
    """Tests for scan_open_fds()."""

    def test_current_process_has_fds(self):
        """Current process should have at least 0, 1, 2."""
        fds = scan_open_fds()
        assert 0 in fds
        assert 1 in fds
        assert 2 in fds

    def test_returns_set(self):
        fds = scan_open_fds()
        assert isinstance(fds, set)
        assert all(isinstance(fd, int) for fd in fds)

    def test_nonexistent_pid(self):
        """Non-existent PID returns empty set."""
        fds = scan_open_fds(pid=999999)
        assert fds == set()

    def test_specific_pid(self, tmp_path: Path):
        """Can scan a specific PID."""
        import subprocess

        # Run a simple process
        proc = subprocess.Popen(["sleep", "5"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            fds = scan_open_fds(pid=proc.pid)
            assert isinstance(fds, set)
            # sleep shouldn't have many FDs open
        finally:
            proc.terminate()
            proc.wait()


# ---------------------------------------------------------------------------
# set_cloexec
# ---------------------------------------------------------------------------


class TestSetCloexec:
    """Tests for set_cloexec()."""

    def test_sets_cloexec_on_fd(self, tmp_path: Path):
        """FD_CLOEXEC flag is set on the file descriptor."""
        fd, _path = tempfile.mkstemp(dir=str(tmp_path))
        try:
            set_cloexec(fd)

            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            assert flags & fcntl.FD_CLOEXEC

        finally:
            os.close(fd)

    def test_does_not_affect_other_flags(self, tmp_path: Path):
        """Other FD flags are preserved."""
        fd, _ = tempfile.mkstemp(dir=str(tmp_path))
        try:
            # Set a specific flag first
            fcntl.fcntl(fd, fcntl.F_SETFD, 0)  # Reset
            original_flags = fcntl.fcntl(fd, fcntl.F_GETFD)

            set_cloexec(fd)
            new_flags = fcntl.fcntl(fd, fcntl.F_GETFD)

            # CLOEXEC should be set, other bits should be unchanged
            assert new_flags & fcntl.FD_CLOEXEC
            assert new_flags & ~fcntl.FD_CLOEXEC == original_flags & ~fcntl.FD_CLOEXEC

        finally:
            os.close(fd)

    def test_cloexec_prevents_inheritance(self, tmp_path: Path):
        """CLOEXEC flag prevents FD from being inherited by child process."""
        import subprocess

        fd, _ = tempfile.mkstemp(dir=str(tmp_path))
        try:
            set_cloexec(fd)

            # Use subprocess instead of fork for better portability
            result = subprocess.run(
                ["python3", "-c", f"import fcntl; fcntl.fcntl({fd}, fcntl.F_GETFL)"],
                capture_output=True,
                check=False,
            )
            # CLOEXEC should cause EBADF when child tries to use the FD
            assert result.returncode != 0
            assert b"[Errno 9]" in result.stderr or b"Bad file descriptor" in result.stderr
        finally:
            os.close(fd)
