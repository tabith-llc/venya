# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Truth-table tests for the guarded expiry-clock tz relabel (#465).

Pre-fix, both parse sites in ``executor/daemon.py`` did
``datetime.fromisoformat(data["not_after"]).replace(tzinfo=UTC)`` — an
UNCONDITIONAL relabel that re-stamps any parsed value as UTC. Today's producers
emit ``+00:00`` so it is a no-op; the ticket files the LATENT class, because a
serialization change would silently shift the expiry clock that rotation timing
consumes.

Ruled shape (lead, from the ticket ACs):
1. Relabel ONLY when ``tzinfo is None`` — mirroring the server-side guarded form
   at ``routes/executors.py:1247-1248``.
2. Naive input is REJECTED (fail-closed outranks tidy) — no silent stamping.
3. A non-UTC AWARE input is PRESERVED with its own offset — never converted.

Every rejection here is paired with the half that must still be accepted, and
the ``+00:00`` producer shape is pinned to the SAME instant as before the fix.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import httpx2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from executor.config import CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import CertificateManager, _expiry_clock_with_tz

# Reuse the real-crypto register/rotate harness from the daemon test home so the
# cells here exercise the same code path as the existing end-to-end cells.
from tests.test_daemon import (
    _make_ca_pair,
    _make_executor_cert,
    _make_mock_response,
)


@pytest.fixture()
def ca_dir(tmp_path: Path) -> Path:
    d = tmp_path / "ca"
    d.mkdir()
    d.chmod(0o700)
    ca_key, ca_cert = _make_ca_pair()
    (d / "ca.key").write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (d / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return d


@pytest.fixture()
def manager(ca_dir: Path, tmp_path: Path) -> CertificateManager:
    """A CertificateManager with a stand-in client, patched per cell."""
    cfg = ExecutorConfig(
        server_url="https://example.com",
        executor_id="test-executor",
        mtls=MtlsConfig(
            ca_cert=str(ca_dir / "ca.crt"),
            cert=str(tmp_path / "executor.crt"),
            key=str(tmp_path / "executor.key"),
        ),
        cert_rotation=CertificateRotationConfig(rotate_before_days=3),
    )
    mgr = CertificateManager(cfg)
    mgr.client = httpx2.Client(base_url="https://example.com", verify=False)
    return mgr


# --------------------------------------------------------------------------
# AC 3 + AC 2: helper-level truth table (aware preserved / naive rejected)
# --------------------------------------------------------------------------


class TestExpiryClockHelperPreservesAwareOffsets:
    """Non-UTC aware input keeps its offset — never converted, never relabelled."""

    def test_plus_two_offset_is_preserved_not_relabelled(self):
        parsed = _expiry_clock_with_tz("2026-11-02T15:30:00+02:00", where="register")

        assert parsed.utcoffset() == timedelta(hours=2)
        assert parsed.tzinfo is not None
        # The wall-clock fields stay exactly as the server sent them.
        assert parsed.isoformat() == "2026-11-02T15:30:00+02:00"

    def test_negative_offset_is_preserved(self):
        """Paired half: the rule is offset-preserving in both directions."""
        parsed = _expiry_clock_with_tz("2026-11-02T15:30:00-05:00", where="rotate")

        assert parsed.utcoffset() == timedelta(hours=-5)
        assert parsed.isoformat() == "2026-11-02T15:30:00-05:00"

    def test_zulu_input_stays_aware_utc(self):
        """A trailing 'Z' is aware too — no relabel needed, offset is zero."""
        parsed = _expiry_clock_with_tz("2026-11-02T15:30:00Z", where="register")

        assert parsed.utcoffset() == timedelta(0)


class TestExpiryClockHelperRejectsNaive:
    """Naive input is refused through the named RuntimeError path (ruled: REJECT)."""

    def test_naive_input_rejected_with_named_error_path(self):
        with pytest.raises(RuntimeError) as exc_info:
            _expiry_clock_with_tz("2026-11-02T15:30:00", where="register")

        # Assert the REFUSAL, not merely that something raised: it names the
        # missing timezone, the offending value, and the parse site.
        msg = str(exc_info.value)
        assert "no timezone information" in msg
        assert "2026-11-02T15:30:00" in msg
        assert "register" in msg

    def test_naive_input_is_never_silently_stamped(self):
        """The pre-fix failure mode: naive → silently labelled UTC. Now refused."""
        with pytest.raises(RuntimeError):
            _expiry_clock_with_tz("2026-11-02T15:30:00", where="rotate")

    def test_where_names_the_site_in_the_refusal(self):
        """rotate site reports itself, so the loud failure is diagnosable."""
        with pytest.raises(RuntimeError, match="rotate"):
            _expiry_clock_with_tz("2026-11-02T15:30:00", where="rotate")


class TestExpiryClockProducerParity:
    """Paired negative (AC 3): today's +00:00 output yields the SAME instant."""

    def test_plus_zero_yields_same_instant_as_the_old_unconditional_relabel(self):
        value = "2026-11-02T15:30:00+00:00"

        guarded = _expiry_clock_with_tz(value, where="register")
        pre_fix = datetime.fromisoformat(value).replace(tzinfo=UTC)

        assert guarded == pre_fix
        assert guarded.utcoffset() == timedelta(0)


# --------------------------------------------------------------------------
# Both parse sites, end to end: register + rotate each get their own cells.
# --------------------------------------------------------------------------


def _response_with_not_after(ca_key, ca_cert, not_after: str) -> httpx2.Response:
    """A successful server response whose not_after is an exact wire string."""
    executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")
    mock_response = _make_mock_response(executor_cert, ca_cert, executor_cert.serial_number)
    payload = dict(mock_response.json.return_value)
    payload["not_after"] = not_after
    mock_response.json.return_value = payload
    return mock_response


class TestRegisterParseSite:
    """Site 1 — ``register()`` (daemon.py, the register handler)."""

    def test_register_preserves_plus_two_offset_expiry(self, manager: CertificateManager):
        ca_key, ca_cert = _make_ca_pair()
        mock_response = _response_with_not_after(ca_key, ca_cert, "2026-11-02T15:30:00+02:00")

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response
            manager.register("test-executor")

        assert manager.not_after is not None
        assert manager.not_after.utcoffset() == timedelta(hours=2)

    def test_register_rejects_naive_expiry_loudly(self, manager: CertificateManager):
        ca_key, ca_cert = _make_ca_pair()
        mock_response = _response_with_not_after(ca_key, ca_cert, "2026-11-02T15:30:00")

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response

            with pytest.raises(RuntimeError, match="no timezone information"):
                manager.register("test-executor")

    def test_register_keeps_producer_plus_zero_instant(self, manager: CertificateManager):
        """The live producer shape: register still lands the same aware UTC instant."""
        ca_key, ca_cert = _make_ca_pair()
        executor_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")
        producer_value = executor_cert.not_valid_after_utc.isoformat()
        assert producer_value.endswith("+00:00")  # the serialization the ticket assumes

        mock_response = _response_with_not_after(ca_key, ca_cert, producer_value)

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response
            manager.register("test-executor")

        assert manager.not_after == executor_cert.not_valid_after_utc


class TestRotateParseSite:
    """Site 2 — ``rotate()`` (daemon.py, the rotate handler).

    The parse site runs AFTER the disk writes, so the incumbent identity is
    seeded the way the existing rotation cells do (same CA root on disk as in
    the response, per #500).
    """

    def _seed(self, mgr: CertificateManager, ca_key, ca_cert) -> None:
        Path(mgr.ca_cert_path).write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        Path(mgr.cert_path).write_bytes(
            _make_executor_cert(ca_key, ca_cert, "test-executor", validity_days=30).public_bytes(
                serialization.Encoding.PEM
            )
        )
        Path(mgr.key_path).write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def test_rotate_preserves_plus_two_offset_expiry(self, manager: CertificateManager, ca_dir: Path):
        ca_key, ca_cert = _make_ca_pair()
        self._seed(manager, ca_key, ca_cert)
        mock_response = _response_with_not_after(ca_key, ca_cert, "2026-11-02T15:30:00+02:00")

        with patch.object(manager.client, "post", return_value=mock_response):
            manager.rotate()

        assert manager.not_after is not None
        assert manager.not_after.utcoffset() == timedelta(hours=2)

    def test_rotate_rejects_naive_expiry_loudly(self, manager: CertificateManager, ca_dir: Path):
        ca_key, ca_cert = _make_ca_pair()
        self._seed(manager, ca_key, ca_cert)
        mock_response = _response_with_not_after(ca_key, ca_cert, "2026-11-02T15:30:00")

        with patch.object(manager.client, "post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="no timezone information"):
                manager.rotate()
