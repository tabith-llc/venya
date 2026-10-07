# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket atomic-write-deterministic-tmp-no-reclaim (#478).

Pre-fix: _atomic_write built the temp name DETERMINISTICALLY (<path>.tmp,
O_CREAT|O_EXCL). A kill between os.open and os.replace — the systemd stop
SIGKILL, an OOM kill, a Restart=always bounce — left <target>.tmp on disk and
every later write to that target raised FileExistsError forever: register()
mapped it to the fatal "mint a fresh token and reinstall", rotate() and the
config/token writes failed the same way, and nothing swept the residue.

Fix pinned here:
1. mkstemp-unique temp names — a stale file can no longer block a new write
   (the single-publish os.replace keeps the no-interleave property O_EXCL was
   bought for);
2. boot-time sweep of stale *.tmp older than _STALE_TMP_MAX_AGE_SECONDS,
   scoped to the executor's own directories (fresh temps of live writers are
   NEVER reclaimed);
3. Physical cell (kill-window simulation on a fleet VM): DO-NOT-RUN until an
   owner-present fleet lane per the leg spec — designed in the report.
"""

import os
import stat
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.config import AuditForwarderConfig, CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import (
    _STALE_TMP_MAX_AGE_SECONDS,
    ExecutorDaemon,
    _atomic_write,
    sweep_stale_tmp_files,
)


def _make_stale(path: Path, age_seconds: float = _STALE_TMP_MAX_AGE_SECONDS + 600, content: bytes = b"stale") -> Path:
    path.write_bytes(content)
    old = time.time() - age_seconds
    os.utime(path, (old, old))
    return path


class TestUniqueTempNoWedge:
    """AC1/AC3: one killed write must not wedge the target."""

    def test_legacy_stale_tmp_does_not_block_new_write(self, tmp_path: Path):
        target = tmp_path / "executor.key"
        target.write_bytes(b"GOOD")
        _make_stale(tmp_path / "executor.key.tmp")
        _atomic_write(target, b"NEW", 0o600)  # at base: FileExistsError
        assert target.read_bytes() == b"NEW"

    def test_repeated_writes_after_stale_residue(self, tmp_path: Path):
        """The wedge was permanent — prove a whole sequence of writes lands."""
        target = tmp_path / "executor.toml"
        _make_stale(tmp_path / "executor.toml.tmp")
        for i in range(5):
            _atomic_write(target, f"payload-{i}".encode(), 0o600)
        assert target.read_bytes() == b"payload-4"


class TestNoInterleavePreserved:
    """AC4 paired negative: the atomicity O_EXCL was bought for survives —
    concurrent writers to the SAME target never interleave, and no temp of any
    name is left behind on the success path."""

    def test_concurrent_writers_publish_whole_payloads(self, tmp_path: Path):
        target = tmp_path / "shared.bin"
        payload_a = b"A" * 4096
        payload_b = b"B" * 4096
        barrier = threading.Barrier(2)
        results: list[Exception] = []

        def writer(payload: bytes) -> None:
            try:
                barrier.wait(timeout=5)
                _atomic_write(target, payload, 0o600)
            except Exception as exc:  # pragma: no cover — only collected
                results.append(exc)

        threads = [threading.Thread(target=writer, args=(p,)) for p in (payload_a, payload_b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not results, f"writers raised: {results}"
        final = target.read_bytes()
        assert final in (payload_a, payload_b), "target holds a MIX of both payloads — interleave"
        assert not list(tmp_path.glob("*.tmp")), "no temp residue after success"


class TestBootSweep:
    """AC2: stale *.tmp older than the bound is reclaimed, scoped to the
    directories the caller names; the fresh temp of a live writer is NOT."""

    def test_stale_removed_fresh_kept(self, tmp_path: Path):
        stale = _make_stale(tmp_path / "executor.crt.old.tmp")
        fresh = tmp_path / "executor.crt.live.tmp"  # a live writer's in-flight temp
        fresh.write_bytes(b"in-flight")
        other = tmp_path / "executor.crt"  # non-.tmp never touched
        other.write_bytes(b"CERT")
        stale_dir = tmp_path / "dir-shaped.tmp"  # never a directory victim
        stale_dir.mkdir()
        os.utime(stale_dir, (time.time() - 7200, time.time() - 7200))

        removed = sweep_stale_tmp_files([tmp_path])

        assert removed == 1
        assert not stale.exists()
        assert fresh.exists() and fresh.read_bytes() == b"in-flight"
        assert other.exists()
        assert stale_dir.is_dir()

    def test_unreadable_directory_skipped_quietly(self, tmp_path: Path):
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o000)
        try:
            assert sweep_stale_tmp_files([locked, tmp_path / "does-not-exist"]) == 0
        finally:
            locked.chmod(0o755)

    def test_duplicate_dirs_swept_once(self, tmp_path: Path):
        _make_stale(tmp_path / "a.tmp")
        assert sweep_stale_tmp_files([tmp_path, tmp_path, str(tmp_path)]) == 1


class TestDaemonReclaimScope:
    """_reclaim_stale_tmp is the single source of the sweep SCOPE: identity
    dirs, config dir, bootstrap-token dir, and the configured spool dir — and
    nothing outside them."""

    def _daemon(self, tmp_path: Path) -> ExecutorDaemon:
        identity = tmp_path / "identity"
        identity.mkdir()
        (tmp_path / "audit").mkdir()
        config = ExecutorConfig(
            server_url="https://test-server.local",
            executor_id="test-executor",
            dns_resolver="192.0.2.53",
            relay_client_ids=["core-relay"],
            mtls=MtlsConfig(
                ca_cert=str(identity / "ca.crt"),
                cert=str(identity / "executor.crt"),
                key=str(identity / "executor.key"),
            ),
            cert_rotation=CertificateRotationConfig(rotate_before_days=3),
            audit=AuditForwarderConfig(spool_path=str(tmp_path / "audit" / "spool.jsonl")),
        )
        daemon = ExecutorDaemon(config)
        daemon._config_path = tmp_path / "executor.toml"
        daemon._bootstrap_token_path = tmp_path / "bootstrap-token"
        return daemon

    def test_sweeps_only_executors_own_dirs(self, tmp_path: Path):
        daemon = self._daemon(tmp_path)
        stale = {
            daemon._config_path.parent / "executor.toml.tmp",
            daemon._bootstrap_token_path.parent / "bootstrap-token.tmp",
            Path(daemon.config.mtls.cert).parent / "executor.crt.tmp",
            tmp_path / "audit" / "spool.jsonl.old.tmp",
        }
        for p in stale:
            _make_stale(p)
        outside = tmp_path / "somewhere-else"
        outside.mkdir()
        untouchable = _make_stale(outside / "not-mine.tmp")

        removed = daemon._reclaim_stale_tmp()

        assert removed == 4
        assert all(not p.exists() for p in stale)
        assert untouchable.exists(), "sweep is scoped — never walks outside the executor's dirs"

    def test_fresh_temps_in_own_dirs_survive(self, tmp_path: Path):
        daemon = self._daemon(tmp_path)
        live = Path(daemon.config.mtls.key).parent / "executor.key.live.tmp"
        live.write_bytes(b"in-flight")

        assert daemon._reclaim_stale_tmp() == 0
        assert live.exists()

    def test_start_sweeps_before_registration_writes(self, tmp_path: Path):
        """Boot-path sequence cell: the reclaim lands BEFORE register(), so the
        first write of the boot can no longer be wedged by a stale residue
        (at base this order did not exist at all — nothing swept)."""
        daemon = self._daemon(tmp_path)
        stale = _make_stale(Path(daemon.config.mtls.cert).parent / "executor.crt.tmp")
        daemon.cert_manager = MagicMock()
        daemon.reaper = MagicMock()
        sentinel = RuntimeError("register reached")
        daemon.cert_manager.register.side_effect = sentinel
        with (
            patch("executor.daemon.require_supported_sbx", return_value="0.46.0"),
            patch("executor.daemon.sweep_workspace_base", return_value=0),
        ):
            with pytest.raises(RuntimeError) as exc:
                daemon.start()
        assert exc.value is sentinel
        assert not stale.exists(), "stale tmp must be reclaimed before register is attempted"


@pytest.mark.parametrize("umask", [0o077, 0o022])
def test_final_mode_pinned_through_mkstemp(umask, tmp_path: Path):
    """mkstemp always creates 0600; the fchmod pin must still land the exact
    final mode requested (the #316 contract, now through the unique-name
    path) under both house umasks."""
    old = os.umask(umask)
    try:
        cert = tmp_path / "executor.crt"
        key = tmp_path / "executor.key"
        _atomic_write(cert, b"CERT", 0o644)
        _atomic_write(key, b"KEY", 0o600)
        assert stat.S_IMODE(os.stat(cert).st_mode) == 0o644
        assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    finally:
        os.umask(old)
