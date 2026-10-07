# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket interrupted-rotation-leaves-mismatched-cert-key-pair (#480).

Pre-fix: rotate() wrote cert and key with two independent replaces; a kill
between them left NEW cert beside OLD key. The boot presence gate passed the
pair, _create_mtls_client then died on ssl.load_cert_chain (key values
mismatch) -> SystemExit(1) -> Restart=always crash-loop parked in failed.
Nothing re-minted; only a human on the host could recover.

Fix pinned here:
1. register()'s presence gate now REQUIRES the pair to actually match
   (_cert_key_pair_matches); a mismatched or unparseable pair falls through
   to the registration path — RE-ENROLLMENT ATTEMPTED, chosen behavior under
   acceptance criterion 2 — instead of booting a broken pair.
2. rotate() replaces KEY first, CERT second (commit point), CA last — the
   new cert never lands ahead of its key.
3. Paired negatives: a healthy pair still skips re-enrollment exactly as
   before (#361 semantics preserved).
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import executor.daemon as daemon_mod
from executor.daemon import CertificateManager, _cert_key_pair_matches
from tests.test_daemon import (
    _make_ca_pair,
    _make_executor_cert,
    _make_executor_keypair_and_cert,
    _make_mock_response,
    _seed_paired_identity,
)

_PEM = serialization.Encoding.PEM
_PKCS8 = serialization.PrivateFormat.PKCS8
_NOENC = serialization.NoEncryption()


def _write_pair(cm: CertificateManager, cert: x509.Certificate, key) -> None:
    Path(cm.cert_path).write_bytes(cert.public_bytes(_PEM))
    Path(cm.key_path).write_bytes(key.private_bytes(encoding=_PEM, format=_PKCS8, encryption_algorithm=_NOENC))


class TestCertKeyPairMatches:
    def test_healthy_pair_returns_true(self, tmp_path: Path):
        ca_key, ca_cert = _make_ca_pair()
        key, cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "exec-a")
        c = tmp_path / "exec.crt"
        k = tmp_path / "exec.key"
        c.write_bytes(cert.public_bytes(_PEM))
        k.write_bytes(key.private_bytes(encoding=_PEM, format=_PKCS8, encryption_algorithm=_NOENC))
        assert _cert_key_pair_matches(c, k) is True

    def test_mismatched_pair_returns_false(self, tmp_path: Path):
        """The #480 shape: cert signed for keypair A sitting beside key B."""
        ca_key, ca_cert = _make_ca_pair()
        _key_a, cert_a = _make_executor_keypair_and_cert(ca_key, ca_cert, "exec-a")
        key_b, _cert_b = _make_executor_keypair_and_cert(ca_key, ca_cert, "exec-a")
        c = tmp_path / "exec.crt"
        k = tmp_path / "exec.key"
        c.write_bytes(cert_a.public_bytes(_PEM))
        k.write_bytes(key_b.private_bytes(encoding=_PEM, format=_PKCS8, encryption_algorithm=_NOENC))
        assert _cert_key_pair_matches(c, k) is False

    def test_unparseable_material_returns_false(self, tmp_path: Path):
        """Half-written PEM from the same kill window is the same recovery class."""
        c = tmp_path / "exec.crt"
        k = tmp_path / "exec.key"
        c.write_bytes(b"-----BEGIN CERTIFICATE-----\nTRUNCATED")
        k.write_bytes(b"not a key")
        assert _cert_key_pair_matches(c, k) is False

    def test_missing_file_returns_false(self, tmp_path: Path):
        assert _cert_key_pair_matches(tmp_path / "nope.crt", tmp_path / "nope.key") is False


class TestRegisterMismatchedPairRecovers:
    """AC3: a mismatched pair on disk must NOT pass the presence gate quietly.
    The boot path attempts re-enrollment (register POST) instead of skipping;
    no zero-recovery SystemExit class outcome is reachable from here."""

    def _mismatched_seed(self, cert_manager: CertificateManager):
        ca_key, ca_cert = _make_ca_pair()
        _key_a, cert_a = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        key_b = ec.generate_private_key(ec.SECP256R1())
        _write_pair(cert_manager, cert_a, key_b)
        return ca_key, ca_cert

    def test_register_with_mismatched_pair_attempts_reenroll(self, cert_manager: CertificateManager):
        ca_key, ca_cert = self._mismatched_seed(cert_manager)
        # A rotated-style cert for a fresh keypair — what the (mocked) server
        # hands back for the new CSR.
        _new_key, new_cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        mock_response = _make_mock_response(new_cert, ca_cert, new_cert.serial_number)

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response
            cert_manager.register("test-executor")  # must NOT raise

        posted_urls = [c[0][0] for c in MockClient.return_value.post.call_args_list]
        assert any(
            "/executors/register" in u for u in posted_urls
        ), "mismatched pair must fall through to the re-enrollment POST, not skip"
        assert not any(
            "/api/v1/heartbeat" in u for u in posted_urls
        ), "the ghost probe sits BEHIND the pair check; an unusable pair must not probe"

    def test_register_with_unparseable_pair_attempts_reenroll(self, cert_manager: CertificateManager):
        """Half-written PEM (kill during the write itself) takes the same path."""
        Path(cert_manager.cert_path).write_bytes(b"-----BEGIN CERTIFICATE-----\nTRUNCATED\n")
        Path(cert_manager.key_path).write_bytes(b"-----BEGIN PRIVATE KEY-----\nHALF\n")
        ca_key, ca_cert = _make_ca_pair()
        new_cert = _make_executor_cert(ca_key, ca_cert, "test-executor")
        mock_response = _make_mock_response(new_cert, ca_cert, new_cert.serial_number)

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = mock_response
            cert_manager.register("test-executor")

        assert any(
            "/executors/register" in c[0][0] for c in MockClient.return_value.post.call_args_list
        ), "unparseable pair must not pass the presence gate"

    def test_mismatched_pair_without_token_raises_actionable_not_systemexit(self, cert_manager: CertificateManager):
        """Re-enrollment is ATTEMPTED (AC3's 'zero recovery attempt' is dead);
        the server's permanent reject surfaces as the named RuntimeError class
        (#24 _permanent_rejection_error), never a silent SystemExit before any
        recovery POST."""
        self._mismatched_seed(cert_manager)
        deny = MagicMock(spec=daemon_mod.httpx2.Response)
        deny.status_code = 401
        err = daemon_mod.httpx2.HTTPStatusError("401 Unauthorized", request=MagicMock(), response=deny)
        deny.raise_for_status.side_effect = err

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = deny
            with pytest.raises(RuntimeError, match="permanently rejected") as ei:
                cert_manager.register("test-executor")

        assert not isinstance(ei.value, SystemExit)
        msg = str(ei.value)
        assert "venya admin executor-enroll" in msg, "error must name the operator re-enroll path"


class TestHealthyPairSemanticsPreserved:
    """AC4 paired negative: the #361 skip-and-probe path is UNTOUCHED for a
    genuinely paired cert+key (presence + pair match -> probe -> skip)."""

    def test_healthy_pair_skips_and_probes(self, cert_manager: CertificateManager):
        ca_key, ca_cert = _make_ca_pair()
        _seed_paired_identity(cert_manager, ca_key, ca_cert)

        ok = MagicMock(spec=daemon_mod.httpx2.Response)
        ok.status_code = 200
        ok.json.return_value = {"revoked": False, "new_cert_required": False}

        with patch("executor.daemon.httpx2.Client") as MockClient:
            MockClient.return_value.__enter__.return_value = MockClient.return_value
            MockClient.return_value.post.return_value = ok
            cert_manager.register("test-executor")

        posted_urls = [c[0][0] for c in MockClient.return_value.post.call_args_list]
        assert any("/api/v1/heartbeat" in u for u in posted_urls)
        assert not any("/executors/register" in u for u in posted_urls)


class TestRotateWriteOrder:
    """AC1: the trio replaces in key -> cert -> CA order; the new cert never
    lands before the key it pairs with."""

    def test_rotate_lands_key_before_cert(self, cert_manager: CertificateManager):
        ca_key, ca_cert = _make_ca_pair()
        Path(cert_manager.ca_cert_path).write_bytes(ca_cert.public_bytes(_PEM))
        _seed_paired_identity(cert_manager, ca_key, ca_cert)

        new_key, new_cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        mock_response = _make_mock_response(new_cert, ca_cert, new_cert.serial_number)

        order: list[str] = []
        real_atomic_write = daemon_mod._atomic_write

        def spy(path, payload, mode):
            order.append(Path(str(path)).name)
            return real_atomic_write(path, payload, mode)

        with (
            # rotate() mints its own keypair internally; pin it to the key the
            # mock server's cert is signed for, so the landed trio is a REAL
            # pair and the end-state check below tests product behavior, not
            # mock shape.
            patch.object(daemon_mod, "_generate_ecdsa_p256_keypair", return_value=new_key),
            patch.object(cert_manager.client, "post", return_value=mock_response),
            patch.object(daemon_mod, "_atomic_write", side_effect=spy),
        ):
            cert_manager.rotate()

        assert order == [Path(cert_manager.key_path).name, Path(cert_manager.cert_path).name, "ca.crt"], order
        # End state: the replaced trio is a genuinely matching pair on disk.
        assert _cert_key_pair_matches(cert_manager.cert_path, cert_manager.key_path) is True
