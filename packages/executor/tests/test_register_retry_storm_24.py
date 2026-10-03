# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#24 truth table: register permanent-vs-transient classification + unit pacing.

Positive halves: 401/403/404 -> one loud named stop (no retry, no sleep);
429 -> in-process retry honoring Retry-After; 5xx -> exponential backoff.
Paired negatives: plain 400 still propagates raw (no over-conversion), TLS-keyword
ConnectError stays single-shot, and the vendored unit declares restart pacing.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import CertificateManager

REPO_ROOT = Path(__file__).resolve().parents[3]


def _config(tmp_path: Path) -> ExecutorConfig:
    return ExecutorConfig(
        server_url="https://example.com",
        executor_id="test-executor",
        dns_resolver="192.0.2.53",
        mtls=MtlsConfig(
            ca_cert=str(tmp_path / "ca.crt"),
            cert=str(tmp_path / "executor.crt"),
            key=str(tmp_path / "executor.key"),
        ),
        cert_rotation=CertificateRotationConfig(rotate_before_days=3),
    )


def _enter(mock_client_cls):
    mock_client_cls.return_value.__enter__.return_value = mock_client_cls.return_value
    return mock_client_cls.return_value


def _status_error(status_code: int, detail: str, headers: dict | None = None) -> httpx2.HTTPStatusError:
    resp = MagicMock(spec=httpx2.Response)
    resp.status_code = status_code
    resp.json.return_value = {"detail": detail}
    resp.text = detail
    resp.headers = headers if headers is not None else {}
    exc = httpx2.HTTPStatusError(f"{status_code}", request=MagicMock(), response=resp)
    resp.raise_for_status.side_effect = exc
    return exc


def _patched_register(mock_client_cls, config: ExecutorConfig):
    """Register under patched keypair/CSR — existing test_daemon.py mock idiom:
    the context-managed client IS mock_client_cls.return_value."""
    mock_client_cls.return_value.__enter__.return_value = mock_client_cls.return_value
    with (
        patch("executor.daemon._generate_ecdsa_p256_keypair"),
        patch("executor.daemon._create_csr", return_value=b"CSR"),
    ):
        CertificateManager(config).register("test-executor")


@pytest.fixture()
def config(tmp_path: Path) -> ExecutorConfig:
    return _config(tmp_path)


@pytest.mark.parametrize("status_code", [401, 403, 404])
def test_register_permanent_rejection_stops_loud_single_attempt(config, status_code):
    """#24 positive: 401/403/404 -> named stop (the helper logger.errors the SAME
    message), ONE POST attempt, zero sleeps; message names the status AND the
    server's reason (the 429-mask fix)."""
    err = _status_error(status_code, "Executor revoked")
    with (
        patch("executor.daemon.httpx2.Client") as MockClient,
        patch("executor.daemon.time.sleep") as mock_sleep,
    ):
        _enter(MockClient).post.return_value.raise_for_status.side_effect = err
        with pytest.raises(RuntimeError, match="permanently rejected") as ei:
            _patched_register(MockClient, config)
    assert MockClient.return_value.post.call_count == 1
    mock_sleep.assert_not_called()
    msg = str(ei.value)
    assert f"HTTP {status_code}" in msg
    assert "Executor revoked" in msg


def test_register_429_retries_honoring_retry_after(config):
    """#24 positive: 429 with Retry-After -> transient path; waits the server's
    window (never shorter than the limiter), up to the attempt budget, final raise raw."""
    err = _status_error(429, "Too Many Requests", headers={"Retry-After": "2"})
    with (
        patch("executor.daemon.httpx2.Client") as MockClient,
        patch("executor.daemon.time.sleep") as mock_sleep,
    ):
        _enter(MockClient).post.return_value.raise_for_status.side_effect = err
        with pytest.raises(httpx2.HTTPStatusError):
            _patched_register(MockClient, config)
    assert MockClient.return_value.post.call_count == 4
    assert [c.args[0] for c in mock_sleep.call_args_list] == [2.0, 2.0, 2.0]


def test_register_503_backoff_exponential(config):
    """#24 positive: 5xx without Retry-After -> 5/10/20s exponential, final raise raw."""
    err = _status_error(503, "nginx is down")
    with (
        patch("executor.daemon.httpx2.Client") as MockClient,
        patch("executor.daemon.time.sleep") as mock_sleep,
    ):
        _enter(MockClient).post.return_value.raise_for_status.side_effect = err
        with pytest.raises(httpx2.HTTPStatusError):
            _patched_register(MockClient, config)
    assert MockClient.return_value.post.call_count == 4
    assert [c.args[0] for c in mock_sleep.call_args_list] == [5.0, 10.0, 20.0]


def test_register_plain_400_still_raw_paired_negative(config):
    """Paired negative: a non-token 400 is NOT reclassified — it propagates raw
    exactly once (#369-pinned behavior; no over-conversion)."""
    err = _status_error(400, "Invalid payload")
    with (
        patch("executor.daemon.httpx2.Client") as MockClient,
        patch("executor.daemon.time.sleep") as mock_sleep,
    ):
        _enter(MockClient).post.return_value.raise_for_status.side_effect = err
        with pytest.raises(httpx2.HTTPStatusError):
            _patched_register(MockClient, config)
    assert MockClient.return_value.post.call_count == 1
    mock_sleep.assert_not_called()


def test_register_tls_connect_error_single_shot_paired_negative(config):
    """Paired negative: TLS-keyword ConnectError stays single-shot RuntimeError
    (configuration fault — retrying cannot change the outcome)."""
    with (
        patch("executor.daemon.httpx2.Client") as MockClient,
        patch("executor.daemon.time.sleep") as mock_sleep,
    ):
        _enter(MockClient).post.side_effect = httpx2.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")
        with pytest.raises(RuntimeError, match="TLS verification error"):
            _patched_register(MockClient, config)
    assert MockClient.return_value.post.call_count == 1
    mock_sleep.assert_not_called()


def test_executor_unit_declares_restart_pacing():
    """#24 half (a): the vendored unit must carry RestartSec + StartLimit keys so
    an exhausted-retry boot parks in failed state instead of storming the
    register limiter at the 100 ms default."""
    text = (REPO_ROOT / "systemd" / "venya-executor.service").read_text()
    assert "RestartSec=5s" in text
    assert "StartLimitIntervalSec=300" in text
    assert "StartLimitBurst=5" in text
    assert "Restart=always" in text
