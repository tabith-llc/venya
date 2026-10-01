# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket executor-daemon-umask0-key-write-window (#316).

Pre-fix: daemonize ran os.umask(0) and key/token writes were
write_bytes-then-chmod — the private key existed WORLD-WRITABLE between the
create and the chmod on every boot and rotation. Fix pins here:

1. daemonize sets umask 0o077, not 0 (no implicit-mode creation is ever
   group/other-permissive);
2. secret writes land via _atomic_write — final mode AT CREATE
   (os.open O_CREAT|O_EXCL) then os.replace; the target never exists at any
   other mode, and pre-existing garbage at the deterministic temp name
   fails loud without disturbing the target;
3. freshly created key / cert / config files are never group-/world-
   accessible, even under an adversarial umask(0).
"""

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from executor.daemon import _atomic_write, _daemonize_detach


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class TestDaemonizeUmask:
    def test_daemonize_sets_umask_077(self):
        """#316: the detach path must call os.umask(0o077), never 0.
        Both forks are stubbed to return 0 (the child leg) so the whole
        sequence runs in-process; every other side-effect syscall is mocked."""
        with (
            patch("executor.daemon.os.fork", return_value=0),
            patch("executor.daemon.os.setsid"),
            patch("executor.daemon.os.umask") as umask,
            patch("executor.daemon.os.chdir"),
            patch("executor.daemon.os.open", return_value=3),
            patch("executor.daemon.os.dup2"),
            patch("executor.daemon.os.close"),
        ):
            _daemonize_detach()
        umask.assert_called_once_with(0o077)


class TestAtomicWrite:
    def test_normal_write_content_and_mode(self, tmp_path: Path):
        """Positive half of the pair: plain write succeeds, bytes identical,
        final mode exactly as requested."""
        target = tmp_path / "thing.pem"
        _atomic_write(target, b"secret-bytes\n", 0o600)
        assert target.read_bytes() == b"secret-bytes\n"
        assert _mode(target) == 0o600

    def test_mode_0644_cert_lands_despite_umask_077(self, tmp_path: Path):
        old = os.umask(0o077)
        try:
            target = tmp_path / "executor.crt"
            _atomic_write(target, b"CERT", 0o644)
            assert _mode(target) == 0o644  # chmod path, not umask-derived
        finally:
            os.umask(old)

    def test_pre_existing_garbage_at_temp_name_fails_loud(self, tmp_path: Path):
        """Negative half: attacker/stale garbage at <target>.tmp aborts the
        write; the garbage and any existing target are untouched."""
        target = tmp_path / "executor.key"
        _atomic_write(target, b"GOOD", 0o600)
        garbage = tmp_path / "executor.key.tmp"
        garbage.write_bytes(b"ATTACKER")
        with pytest.raises(FileExistsError):
            _atomic_write(target, b"NEW", 0o600)
        assert garbage.read_bytes() == b"ATTACKER"  # never consumed as our temp
        assert target.read_bytes() == b"GOOD"  # identity on disk unchanged

    def test_write_failure_leaves_no_temp_residue(self, tmp_path: Path):
        """Corrupt-write path still cleans up the temp (paired: normal write
        above leaves none). Failure is provoked naturally: a non-empty
        DIRECTORY sits at the target name, so os.replace(file -> dir) ENOTDIR
        and the write aborts."""
        target = tmp_path / "executor.key"
        target.mkdir()
        (target / "occupied").write_bytes(b"x")  # non-empty: replace must fail
        with pytest.raises(OSError):
            _atomic_write(target, b"KEY", 0o600)
        assert (target / "occupied").exists()  # nothing consumed
        assert not (tmp_path / "executor.key.tmp").exists()  # temp unlinked

    def test_readonly_target_refused_before_temp_created(self, tmp_path: Path):
        """erofs contract preserved: an existing target we cannot write is
        refused loudly and no replacement silently slides under it."""
        target = tmp_path / "executor.crt"
        target.write_bytes(b"OLD")
        target.chmod(0o400)
        try:
            with pytest.raises(PermissionError):
                _atomic_write(target, b"NEW", 0o644)
            assert target.read_bytes() == b"OLD"
            assert not (tmp_path / "executor.crt.tmp").exists()
        finally:
            target.chmod(0o600)


class TestSecretWriteModes:
    """The umask-0 window: pre-fix, key files existed 0666 (world-writable)
    between write_bytes and chmod. Post-fix the mode lands at CREATE — prove
    it under the adversarial umask(0) the pre-fix daemonize set."""

    @pytest.fixture()
    def zero_umask(self):
        old = os.umask(0)
        yield
        os.umask(old)

    def test_register_key_and_cert_modes_no_world_access(self, zero_umask, tmp_path: Path):
        """Freshly created key/config files are NOT world-readable/writable
        after the fix (stat-asserted), even with umask 0."""
        from executor.config import ExecutorConfig, MtlsConfig
        from executor.daemon import CertificateManager
        from tests.test_daemon import _make_ca_pair, _make_executor_cert, _make_mock_response

        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")
        mock_response = _make_mock_response(executor_cert, ca_cert, executor_cert.serial_number)

        config = ExecutorConfig(
            server_url="https://example.com",
            executor_id="test-executor",
            dns_resolver="192.0.2.53",
            mtls=MtlsConfig(
                ca_cert=str(tmp_path / "ca.crt"),
                cert=str(tmp_path / "executor.crt"),
                key=str(tmp_path / "executor.key"),
            ),
        )
        cm = CertificateManager(config)
        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response
            cm.register("test-executor")

        assert _mode(cm.key_path) == 0o600
        assert _mode(cm.cert_path) == 0o644
        # the mode is not umask-born: nothing group/other-WRITABLE anywhere
        for p in (cm.key_path, cm.cert_path, cm.ca_cert_path):
            assert not _mode(p) & 0o022, f"{p} is group/world-writable: {oct(_mode(p))}"

    def test_config_save_file_is_0600_not_world_readable(self, zero_umask, tmp_path: Path):
        """save_file lands the credential-bearing toml 0600 even under umask 0."""
        from executor.config import ExecutorConfig

        cfg = ExecutorConfig(server_url="https://example.com", executor_id="test-exec")
        config_file = tmp_path / "executor.toml"
        cfg.save_file(config_file)
        assert _mode(config_file) == 0o600
        import tomllib

        with open(config_file, "rb") as f:
            assert tomllib.load(f)["server_url"] == "https://example.com"

    def test_token_clear_rewrites_config_0600(self, zero_umask, tmp_path: Path):
        """The [bootstrap]-clear rewrite never re-lands the toml world-accessible."""
        import tomllib

        from executor.config import BootstrapConfig, ExecutorConfig
        from executor.daemon import ExecutorDaemon

        config_file = tmp_path / "executor.toml"
        config_file.write_text(
            'server_url = "https://venya-core"\nexecutor_id = "test-executor"\n\n'
            '[bootstrap]\nenrollment_token = "enrl_exec_toml_legacy"\n'
        )
        config = ExecutorConfig(
            server_url="https://example.com",
            executor_id="test-executor",
            dns_resolver="192.0.2.53",
            bootstrap=BootstrapConfig(enrollment_token="enrl_exec_toml_legacy"),
            config_path=config_file,
        )
        daemon = ExecutorDaemon(config)
        daemon._bootstrap_token_path = tmp_path / "bootstrap-token"
        config_file.chmod(0o600)

        daemon._clear_bootstrap_token()

        assert _mode(config_file) == 0o600
        with open(config_file, "rb") as f:
            assert "bootstrap" not in tomllib.load(f)
