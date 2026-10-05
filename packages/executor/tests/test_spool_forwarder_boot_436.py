# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the boot-time audit spool forwarder (ticket
audit-spool-forwarder-session-lifetime, #436 ruling (a)).

The forwarder thread lives inside AuditLogger, which historically existed
ONLY per command session — an idle executor never drained its backlog.
Truth table: boot with a configured sink + non-empty spool and ZERO
sessions → a forward attempt happens (positive); empty spool → no
transport churn (paired negative); no configured sink → no boot forwarder
is constructed at all (guard negative).
"""

import logging
from compression import zstd
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.config import AuditForwarderConfig, ExecutorConfig, MtlsConfig
from executor.daemon import BOOT_FORWARDER_SESSION_ID, ExecutorDaemon
from tests.test_audit import make_cert_pair

SPOOL_LINE = '{"event_type":"command_executed","session_id":"sess-real-7","command":"echo hi"}\n'


def _config(tmp_path: Path, *, remote_url: str | None, spool_path: Path | None) -> ExecutorConfig:
    cert, key = make_cert_pair(tmp_path)
    return ExecutorConfig(
        server_url="https://test-server.local",
        executor_id="test-executor",
        relay_client_ids=["core-relay"],
        dns_resolver="192.0.2.53",
        config_path=tmp_path / "executor.toml",
        pid_file=str(tmp_path / "venya-executor.pid"),
        mtls=MtlsConfig(ca_cert=str(tmp_path / "ca.crt"), cert=cert, key=key),
        audit=AuditForwarderConfig(
            remote_url=remote_url,
            # #436 validator half: remote_url requires ca_cert_path; the
            # transport is mocked so the PEM just needs to load.
            ca_cert_path=cert if remote_url else None,
            spool_path=str(spool_path) if spool_path else None,
            max_buffer_size=100,
            max_batch_lines=50,
            retry_base_delay=0.1,
            retry_max_delay=0.2,
            max_retries=3,
        ),
    )


def _started_daemon(tmp_path: Path, *, remote_url: str | None, spool_path: Path | None):
    """Run daemon.start() to completion with the network siblings mocked and
    the REAL AuditLogger boot path armed. _main_loop returns at once; stop()
    is mocked so the test drives the drain deterministically via flush()."""
    d = ExecutorDaemon(_config(tmp_path, remote_url=remote_url, spool_path=spool_path))
    d._bootstrap_token_path = tmp_path / "bootstrap-token"
    d.cert_manager = MagicMock()
    d.cert_manager.last_command_policy = None
    d._create_mtls_client = MagicMock(return_value=MagicMock())
    d.reaper = MagicMock()
    d.relay = MagicMock()
    d.relay.active = True
    d._write_pidfile = MagicMock()
    d._main_loop = MagicMock()
    d.stop = MagicMock()
    d.create_executor = MagicMock()  # sessions must never be needed for the drain
    with (
        patch("executor.daemon.require_supported_sbx", return_value="v0.46.0"),
        patch("executor.daemon.sweep_workspace_base", return_value=0),
    ):
        d.start()
    return d


class TestBootForwarder:
    def test_boot_arms_forwarder_with_nonempty_spool_and_zero_sessions(self, tmp_path: Path):
        """POSITIVE: daemon start with a non-empty spool and no session →
        the boot-time forwarder drains it (forward attempt observed)."""
        spool = tmp_path / "spool.jsonl"
        spool.write_text(SPOOL_LINE)
        d = _started_daemon(tmp_path, remote_url="https://core.local:8443/audit/ingest", spool_path=spool)
        try:
            assert d.audit_boot_forwarder is not None
            assert d.audit_boot_forwarder._session_id == BOOT_FORWARDER_SESSION_ID
            d.create_executor.assert_not_called()  # zero sessions
            with patch("executor.audit.httpx2.Client") as MockClient:
                resp = MagicMock(status_code=200)
                client = MagicMock()
                client.post.return_value = resp
                client.__enter__ = MagicMock(return_value=client)
                client.__exit__ = MagicMock(return_value=False)
                MockClient.return_value = client
                d.audit_boot_forwarder.flush()
                client.post.assert_called_once()
                assert "sess-real-7" in zstd.decompress(client.post.call_args[1]["content"]).decode()
            assert spool.read_text() == ""  # accepted batch removed
        finally:
            d.audit_boot_forwarder.shutdown()

    def test_boot_forwarder_empty_spool_no_transport_churn(self, tmp_path: Path):
        """PAIRED NEGATIVE: same boot, EMPTY spool (tmp path, never created
        by hand) → the drain runs but the transport is NEVER touched (no
        client, no POST, no churn)."""
        d = _started_daemon(
            tmp_path, remote_url="https://core.local:8443/audit/ingest", spool_path=tmp_path / "spool-empty.jsonl"
        )
        spool = Path(d.config.audit.spool_path)
        try:
            assert d.audit_boot_forwarder is not None
            d.create_executor.assert_not_called()
            with patch("executor.audit.httpx2.Client") as MockClient:
                d.audit_boot_forwarder.flush()
                MockClient.assert_not_called()
            assert spool.read_text() == ""
        finally:
            d.audit_boot_forwarder.shutdown()

    def test_unconfigured_sink_boots_no_forwarder(self, tmp_path: Path):
        """GUARD NEGATIVE: remote_url unset → no boot forwarder constructed
        (nothing to deliver to; per-session behavior stays untouched)."""
        d = _started_daemon(tmp_path, remote_url=None, spool_path=None)
        assert d.audit_boot_forwarder is None
        d.create_executor.assert_not_called()

    def test_boot_forwarder_logs_armed_line_once(self, tmp_path: Path, caplog):
        spool = tmp_path / "spool.jsonl"
        spool.write_text(SPOOL_LINE)
        with caplog.at_level(logging.INFO, logger="venya.executor.daemon"):
            d = _started_daemon(tmp_path, remote_url="https://core.local:8443/audit/ingest", spool_path=spool)
        try:
            assert caplog.messages.count("Audit spool forwarder booted (session-less drain armed)") == 1
        finally:
            d.audit_boot_forwarder.shutdown()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
