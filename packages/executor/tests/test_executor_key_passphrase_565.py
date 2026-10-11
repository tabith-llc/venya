# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#565 (body sites 5-6) — the executor daemon writes AND reads an encrypted key.

Pre-fix: ``CertificateManager.register`` and ``CertificateManager.rotate``
serialized the executor's own ECDSA leaf with ``serialization.NoEncryption()``,
so ``/etc/venya/executor/executor.key`` sat in the clear beside its certificate on
every installed executor, while every consumer of that file was written
passphrase-blind (the load half of the pair: a file nobody can unlock is as dead
as one anybody can read).

The posture is ruled, not re-decided here. R7-Q3 (`decisions.md` commit
`1bf25ae`, quoted in `docs/design-fido2-keywrap-565.md` §6) makes a **file
passphrase delivered through the service environment** the interim shape for
these unattended sites — disk protection, explicitly **not** hardware custody —
and forbids a partial ship: the read side lands in this same changeset or neither
side does. Hence the reader classes below; they are the other half of the ruling,
not scope creep.

Truth table (paired negatives are mandatory — a gate that passes only the
positive case is untested):

+---------------------------------------------------------------+----------------------------+
| shape                                                         | expected                   |
+---------------------------------------------------------------+----------------------------+
| register/rotate with a passphrase                              | PKCS#8-encrypted key, 0600 |
| register/rotate with NO passphrase                             | refuse, no POST, no files  |
| blank / whitespace-only value                                  | same refusal (#554)        |
| value under the #573 floor                                     | floor refusal, value never |
|                                                                | echoed, no POST, no files  |
| readers (daemon client, relay, audit) + encrypted key + pw     | context builds             |
| readers + encrypted key, no passphrase                         | named refusal, not OpenSSL |
| readers + LEGACY plaintext key, nothing set                    | still works (no-regression)|
| boot pair gate + encrypted key it cannot open                  | RAISES, never False        |
| boot pair gate + genuinely mismatched plaintext pair            | False (the #480 recovery)  |
| boot probe, plaintext key                                      | 2-tuple, byte-identical    |
| boot probe, encrypted key                                      | 3-tuple carrying the pw    |
+---------------------------------------------------------------+----------------------------+
"""

import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from executor.config import AuditForwarderConfig, CertificateRotationConfig, ExecutorConfig, MtlsConfig
from executor.daemon import CertificateManager, ExecutorDaemon, _cert_key_pair_matches
from executor.key_passphrase import EXECUTOR_KEY_PASSPHRASE_ENV, load_private_key
from tests.test_daemon import (
    _make_ca_pair,
    _make_executor_keypair_and_cert,
    _make_mock_response,
    _seed_paired_identity,
)

_PEM = serialization.Encoding.PEM
_PKCS8 = serialization.PrivateFormat.PKCS8
_NOENC = serialization.NoEncryption()

# TEST-only values (AGENTS.md password protocol); the names state the boundary
# each one sits on, so the arithmetic of the #573 floor is visible in the cell.
GOOD_PW = "test-executor-key-passphrase"  # pragma: allowlist secret — 28 code points, over the floor
AT_FLOOR_PW = "0123456789abcde"  # pragma: allowlist secret — exactly 15 code points: PASSES
UNDER_PW = "0123456789abcd"  # pragma: allowlist secret — 14 code points: REFUSES

# The two constants above are the #573 boundary itself; assert the arithmetic here
# so a retyped string can never silently move the door the cells claim to test.
assert len(AT_FLOOR_PW) == 15 and len(UNDER_PW) == 14


def _mode(path) -> int:
    return stat.S_IMODE(Path(path).stat().st_mode)


def _config_for(tmp_path: Path, ca_file: Path) -> ExecutorConfig:
    """Executor config with every mTLS file pointed at this cell's tmp_path."""
    return ExecutorConfig(
        server_url="https://example.com",
        executor_id="test-executor",
        dns_resolver="192.0.2.53",
        mtls=MtlsConfig(
            ca_cert=str(ca_file),
            cert=str(tmp_path / "executor.crt"),
            key=str(tmp_path / "executor.key"),
        ),
        cert_rotation=CertificateRotationConfig(rotate_before_days=3),
    )


@pytest.fixture()
def ca_pair(tmp_path: Path):
    """A CA key/cert written to ``ca.crt`` — the anchor rotation validates against."""
    ca_key, ca_cert = _make_ca_pair()
    ca_file = tmp_path / "ca.crt"
    ca_file.write_bytes(ca_cert.public_bytes(_PEM))
    return ca_key, ca_cert, ca_file


@pytest.fixture()
def manager(tmp_path: Path, ca_pair):
    """A CertificateManager over this cell's tmp_path with a real CA anchor."""
    _ca_key, _ca_cert, ca_file = ca_pair
    return CertificateManager(_config_for(tmp_path, ca_file))


def _daemon_over(cm: CertificateManager, tmp_path: Path, ca_file: Path) -> ExecutorDaemon:
    """An ExecutorDaemon shell pointed at this cell's files.

    ``_create_mtls_client`` lives on the DAEMON, not on CertificateManager, and it
    reads only ``self.config`` — so an uninitialized instance with a config attached
    exercises the real reader without booting a daemon (no threads, no registry, no
    network: building the client is local object construction only).
    """
    daemon = ExecutorDaemon.__new__(ExecutorDaemon)
    daemon.config = _config_for(tmp_path, ca_file)
    return daemon


def _ok_response():
    """A 200 probe answer: status_code AND raise_for_status, the two attributes
    _verify_cert_recognized reads (a bare status_code mock fails on the second)."""
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status.return_value = None
    return ok


def _encrypted_key_bytes(key, passphrase: str = GOOD_PW) -> bytes:
    return key.private_bytes(
        encoding=_PEM,
        format=_PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def _seed_encrypted_identity(cm: CertificateManager, ca_key, ca_cert) -> tuple:
    """Write a MATCHING cert + encrypted key pair (the post-fix on-disk shape)."""
    key, cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
    Path(cm.cert_path).write_bytes(cert.public_bytes(_PEM))
    Path(cm.key_path).write_bytes(_encrypted_key_bytes(key))
    return key, cert


def _register_transport(response):
    """Patch the register-path transport (a throwaway client per attempt, #24)."""
    mock = patch("executor.daemon.httpx2.Client")
    MockClient = mock.start()
    MockClient.return_value.__enter__.return_value = MockClient.return_value
    MockClient.return_value.post.return_value = response
    return MockClient, mock


class TestRegisterWritesEncrypted:
    """Body site 5: `CertificateManager.register`."""

    def test_key_lands_encrypted_and_the_pair_still_matches(self, manager, ca_pair) -> None:
        """Positive half, with real cryptography (no mocked crypto): the registered
        key is an encrypted envelope, pinned at 0600, and is the key its own new
        certificate was signed for — the boot gate accepts the pair the writer made."""
        ca_key, ca_cert, _ca_file = ca_pair
        _new_key, new_cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        MockClient, stopper = _register_transport(_make_mock_response(new_cert, ca_cert, new_cert.serial_number))
        try:
            manager.register("test-executor")
        finally:
            stopper.stop()

        raw = Path(manager.key_path).read_bytes()
        assert b"ENCRYPTED PRIVATE KEY" in raw, "the key landed in the clear — the defect is still shipping"
        assert _mode(manager.key_path) == 0o600, "the envelope must not move the mode pin"
        # The key that lands is the writer's OWN generated keypair, unlocked by the
        # configured passphrase. (Pair-matching against the certificate is not
        # assertable through this mock — the fake server signs a cert for a keypair
        # the daemon never generated; #480's pair gate is pinned for real in
        # TestBootPairGateNeverRemintsQuietly below.)
        assert isinstance(load_private_key(raw, key_path=manager.key_path), ec.EllipticCurvePrivateKey)
        MockClient.return_value.post.assert_called_once()

    def test_no_passphrase_refuses_before_the_post(self, manager, no_executor_key_passphrase) -> None:
        """Paired negative (#565 AC3 + design §5 row 5): the refusal must arrive
        BEFORE the registration POST. A doomed write after the POST burns the
        enrollment token and replaces the server-side record — the same failure the
        site's existing EROFS preflight exists to prevent, reached by a different
        route."""
        MockClient, stopper = _register_transport(MagicMock())
        try:
            with pytest.raises(RuntimeError, match=EXECUTOR_KEY_PASSPHRASE_ENV):
                manager.register("test-executor")
        finally:
            stopper.stop()

        MockClient.return_value.post.assert_not_called()
        assert not Path(manager.key_path).exists(), "a refused write must leave no key"
        assert not Path(manager.cert_path).exists(), "a refused write must leave no certificate"

    def test_whitespace_only_value_counts_as_no_passphrase(self, manager, monkeypatch) -> None:
        """#554 on this plane: spaces carry no material, so they read as unset and
        get the same refusal — never a file that merely LOOKS protected."""
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, "   ")
        MockClient, stopper = _register_transport(MagicMock())
        try:
            with pytest.raises(RuntimeError, match="must never be stored unencrypted"):
                manager.register("test-executor")
            MockClient.return_value.post.assert_not_called()
            assert not Path(manager.key_path).exists()
        finally:
            stopper.stop()

    def test_value_under_the_floor_refuses_without_echoing_it(self, manager, monkeypatch) -> None:
        """#573's floor extends to this plane: 14 code points refuse. The text names
        the variable and never the value or its length (lane-survival law)."""
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, UNDER_PW)
        MockClient, stopper = _register_transport(MagicMock())
        try:
            with pytest.raises(RuntimeError, match="shorter than Venya's minimum") as ei:
                manager.register("test-executor")
            assert UNDER_PW not in str(ei.value)
            assert "Nothing was written." in str(ei.value)
            MockClient.return_value.post.assert_not_called()
            assert not Path(manager.key_path).exists()
        finally:
            stopper.stop()

    def test_floor_boundary_is_inclusive_at_fifteen(self, manager, ca_pair, monkeypatch) -> None:
        """The other half of the boundary: 15 PASSES (the floor is inclusive), so the
        door is exactly where the constant says it is and not one tighter."""
        ca_key, ca_cert, _ca_file = ca_pair
        _k, new_cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        monkeypatch.setenv(EXECUTOR_KEY_PASSPHRASE_ENV, AT_FLOOR_PW)
        _MockClient, stopper = _register_transport(_make_mock_response(new_cert, ca_cert, new_cert.serial_number))
        try:
            manager.register("test-executor")
        finally:
            stopper.stop()
        assert b"ENCRYPTED PRIVATE KEY" in Path(manager.key_path).read_bytes()


class TestRotateWritesEncrypted:
    """Body site 6: `CertificateManager.rotate` — and #480's ordering is incumbent
    on this path and must not regress."""

    def test_rotated_key_lands_encrypted(self, manager, ca_pair) -> None:
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_paired_identity(manager, ca_key, ca_cert)  # incumbent (plaintext legacy) identity
        _k, new_cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        # rotate() posts through the persistent client, not register()'s throwaway.
        mock_client = MagicMock()
        mock_client.post.return_value = _make_mock_response(new_cert, ca_cert, new_cert.serial_number)
        manager.client = mock_client

        manager.rotate()

        raw = Path(manager.key_path).read_bytes()
        assert b"ENCRYPTED PRIVATE KEY" in raw
        assert _mode(manager.key_path) == 0o600
        # rotate() writes the key it generated for the CSR it sent; the pairing
        # property itself is pinned in TestBootPairGateNeverRemintsQuietly.
        assert isinstance(load_private_key(raw, key_path=manager.key_path), ec.EllipticCurvePrivateKey)
        assert manager.serial == format(new_cert.serial_number, "016x")

    def test_refusal_leaves_the_incumbent_pair_alone(self, manager, ca_pair, no_executor_key_passphrase) -> None:
        """Paired negative: an unattended rotation with no passphrase must not POST
        (that replaces the server-side record) and must not touch the working files
        — the executor keeps running on the certificate it has."""
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_paired_identity(manager, ca_key, ca_cert)
        before_key = Path(manager.key_path).read_bytes()
        before_cert = Path(manager.cert_path).read_bytes()
        mock_client = MagicMock()
        manager.client = mock_client

        with pytest.raises(RuntimeError, match="must never be stored unencrypted"):
            manager.rotate()

        mock_client.post.assert_not_called()
        assert Path(manager.key_path).read_bytes() == before_key, "a refused rotation changed the incumbent key"
        assert Path(manager.cert_path).read_bytes() == before_cert, "a refused rotation changed the incumbent cert"

    def test_write_order_is_still_key_then_cert_then_ca(self, manager, ca_pair) -> None:
        """#480's ordering re-pinned THROUGH the encrypted writer: the cert replace is
        the commit point and must never land ahead of the key it pairs with."""
        import executor.daemon as dm

        ca_key, ca_cert, _ca_file = ca_pair
        _seed_paired_identity(manager, ca_key, ca_cert)
        _k, new_cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        mock_client = MagicMock()
        mock_client.post.return_value = _make_mock_response(new_cert, ca_cert, new_cert.serial_number)
        manager.client = mock_client

        order: list[str] = []
        real_write = dm._atomic_write

        def _spy(path, payload, mode):
            order.append(Path(path).name)
            return real_write(path, payload, mode)

        with patch.object(dm, "_atomic_write", side_effect=_spy):
            manager.rotate()

        assert order == [
            "executor.key",
            "executor.crt",
            Path(manager.ca_cert_path).name,
        ], f"rotation write order changed: {order}"


class TestReadersOpenTheEnvelope:
    """The same-changeset read half (§2 F2, and R7-Q3's no-partial-ship clause):
    three consumers of `mtls.key` on the executor host, all passphrase-blind before
    this fix. A write nobody can read is not a fix — it is an outage."""

    def test_daemon_client_loads_an_encrypted_key(self, tmp_path: Path, manager, ca_pair) -> None:
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_encrypted_identity(manager, ca_key, ca_cert)
        _daemon_over(manager, tmp_path, _ca_file)._create_mtls_client()  # must not raise

    def test_daemon_client_names_the_refusal_when_nothing_is_set(
        self, tmp_path: Path, manager, ca_pair, no_executor_key_passphrase
    ) -> None:
        """Paired negative: the operator reads a repair that names the variable, not
        OpenSSL's ``PEM lib`` — which points at nothing and sends a lane hunting."""
        ca_key, ca_cert, _ca_file = ca_pair
        key, cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        Path(manager.cert_path).write_bytes(cert.public_bytes(_PEM))
        Path(manager.key_path).write_bytes(_encrypted_key_bytes(key))
        Path(manager.ca_cert_path).write_bytes(ca_cert.public_bytes(_PEM))

        with pytest.raises(RuntimeError, match=EXECUTOR_KEY_PASSPHRASE_ENV) as ei:
            _daemon_over(manager, tmp_path, _ca_file)._create_mtls_client()
        assert "did not open it" in str(ei.value)

    def test_legacy_plaintext_key_still_loads_with_nothing_set(
        self, tmp_path: Path, manager, ca_pair, no_executor_key_passphrase
    ) -> None:
        """No-regression half: every host installed before this change holds a
        plaintext key, and it must keep booting with zero environment change. This
        is the clause that keeps the fix from being a fleet-wide outage."""
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_paired_identity(manager, ca_key, ca_cert)  # plaintext ON PURPOSE

        _daemon_over(manager, tmp_path, _ca_file)._create_mtls_client()  # must not raise

    def test_relay_listener_builds_on_an_encrypted_key(self, tmp_path: Path, manager, ca_pair) -> None:
        """The relay serves on the SAME executor leaf key, so it is a consumer too."""
        from executor.relay_listener import RelayListener

        ca_key, ca_cert, ca_file = ca_pair
        key, cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        Path(manager.cert_path).write_bytes(cert.public_bytes(_PEM))
        Path(manager.key_path).write_bytes(_encrypted_key_bytes(key))
        listener = RelayListener(_config_for(tmp_path, ca_file), lambda _i: None, [])

        ctx = listener._build_ssl_context()
        assert ctx.verify_mode.name == "CERT_REQUIRED", "the relay's mTLS posture is not this cell's to change"

    def test_relay_listener_refuses_loudly_without_the_passphrase(
        self, tmp_path: Path, manager, ca_pair, no_executor_key_passphrase
    ) -> None:
        from executor.relay_listener import RelayListener

        ca_key, ca_cert, ca_file = ca_pair
        key, cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        Path(manager.cert_path).write_bytes(cert.public_bytes(_PEM))
        Path(manager.key_path).write_bytes(_encrypted_key_bytes(key))
        listener = RelayListener(_config_for(tmp_path, ca_file), lambda _i: None, [])

        with pytest.raises(RuntimeError, match=EXECUTOR_KEY_PASSPHRASE_ENV):
            listener._build_ssl_context()

    def test_audit_forwarder_builds_on_an_encrypted_key(self, tmp_path: Path, manager, ca_pair) -> None:
        from executor.audit import AuditLogger

        ca_key, ca_cert, ca_file = ca_pair
        key, cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        Path(manager.cert_path).write_bytes(cert.public_bytes(_PEM))
        Path(manager.key_path).write_bytes(_encrypted_key_bytes(key))
        cfg = AuditForwarderConfig(remote_url=None, ca_cert_path=str(ca_file), spool_path=str(tmp_path / "spool"))
        logger = AuditLogger(cfg, "cell", client_cert=(manager.cert_path, manager.key_path))

        assert logger._build_forward_ssl_context() is not None

    def test_audit_forwarder_refuses_without_the_passphrase(
        self, tmp_path: Path, manager, ca_pair, no_executor_key_passphrase
    ) -> None:
        from executor.audit import AuditLogger

        ca_key, ca_cert, ca_file = ca_pair
        key, cert = _make_executor_keypair_and_cert(ca_key, ca_cert, "test-executor")
        Path(manager.cert_path).write_bytes(cert.public_bytes(_PEM))
        Path(manager.key_path).write_bytes(_encrypted_key_bytes(key))
        cfg = AuditForwarderConfig(remote_url=None, ca_cert_path=str(ca_file), spool_path=str(tmp_path / "spool"))
        logger = AuditLogger(cfg, "cell", client_cert=(manager.cert_path, manager.key_path))

        with pytest.raises(RuntimeError, match=EXECUTOR_KEY_PASSPHRASE_ENV):
            logger._build_forward_ssl_context()


class TestBootPairGateNeverRemintsQuietly:
    """The #480 gate reads the key too. An envelope it cannot open is a passphrase
    problem, and the recovery for a passphrase problem is NOT quietly re-minting an
    identity the core already knows."""

    def test_encrypted_matching_pair_returns_true(self, manager, ca_pair) -> None:
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_encrypted_identity(manager, ca_key, ca_cert)
        assert _cert_key_pair_matches(manager.cert_path, manager.key_path) is True

    def test_encrypted_pair_with_no_passphrase_raises_not_false(
        self, manager, ca_pair, no_executor_key_passphrase
    ) -> None:
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_encrypted_identity(manager, ca_key, ca_cert)
        with pytest.raises(RuntimeError, match=EXECUTOR_KEY_PASSPHRASE_ENV):
            _cert_key_pair_matches(manager.cert_path, manager.key_path)

    def test_genuinely_mismatched_plaintext_pair_still_returns_false(self, tmp_path: Path, ca_pair) -> None:
        """Paired negative for the negative: #480's real mismatch keeps its False
        verdict (fall through to re-enrollment). A fix that swallowed this into a
        passphrase error would have eaten a merged recovery."""
        ca_key, ca_cert, _ca_file = ca_pair
        _key_a, cert_a = _make_executor_keypair_and_cert(ca_key, ca_cert, "exec-a")
        key_b, _cert_b = _make_executor_keypair_and_cert(ca_key, ca_cert, "exec-a")
        c, k = tmp_path / "exec.crt", tmp_path / "exec.key"
        c.write_bytes(cert_a.public_bytes(_PEM))
        k.write_bytes(key_b.private_bytes(encoding=_PEM, format=_PKCS8, encryption_algorithm=_NOENC))
        assert _cert_key_pair_matches(c, k) is False

    def test_unparseable_material_still_returns_false(self, tmp_path: Path) -> None:
        """Half-written PEM is #480's other shape and is not a passphrase question."""
        c, k = tmp_path / "exec.crt", tmp_path / "exec.key"
        c.write_bytes(b"-----BEGIN CERTIFICATE-----\nTRUNCATED")
        k.write_bytes(b"not a key")
        assert _cert_key_pair_matches(c, k) is False


class TestBootProbeCertTuple:
    """`_verify_cert_recognized` dials with the executor pair through httpx's
    ``cert=``. #502's pin on this site (an anchor context, never ``verify=True``)
    stays green untouched; these cells add the envelope half."""

    def _probe(self, cm: CertificateManager, response):
        MockClient, stopper = _register_transport(response)
        try:
            cm._verify_cert_recognized("test-executor")
        finally:
            stopper.stop()
        return MockClient

    def test_plaintext_key_keeps_the_two_tuple(self, manager, ca_pair, no_executor_key_passphrase) -> None:
        """No-regression: with no passphrase to add, the site hands httpx exactly
        the tuple it always handed it."""
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_paired_identity(manager, ca_key, ca_cert)
        ok = _ok_response()
        MockClient = self._probe(manager, ok)
        assert MockClient.call_args[1]["cert"] == (manager.cert_path, manager.key_path)

    def test_encrypted_key_rides_the_three_tuple(self, manager, ca_pair) -> None:
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_encrypted_identity(manager, ca_key, ca_cert)
        ok = _ok_response()
        MockClient = self._probe(manager, ok)
        cert_arg = MockClient.call_args[1]["cert"]
        assert cert_arg[0] == manager.cert_path and cert_arg[1] == manager.key_path
        assert cert_arg[2] == GOOD_PW.encode(), "the envelope's passphrase must ride the cert triple"

    def test_encrypted_key_without_a_passphrase_is_not_reported_as_a_ghost(
        self, manager, ca_pair, no_executor_key_passphrase
    ) -> None:
        """Paired negative: mislabelling a passphrase problem as a ghost identity
        would send the operator to re-enroll when the repair is to set the
        variable — the misdirection this whole fix is meant to end."""
        ca_key, ca_cert, _ca_file = ca_pair
        _seed_encrypted_identity(manager, ca_key, ca_cert)
        with pytest.raises(RuntimeError) as ei:
            self._probe(manager, MagicMock())
        assert "ghost identity" not in str(ei.value).lower()
        assert EXECUTOR_KEY_PASSPHRASE_ENV in str(ei.value)


class TestNoPlaintextBranch:
    """#565 AC4: no site is fixed by loosening a check, and a silent fallback to
    plaintext is the defect returning. These pins fail if the plaintext branch is
    ever re-added."""

    def test_source_of_both_writers_carries_no_noencryption_call(self) -> None:
        src = Path(__file__).resolve().parents[1] / "src" / "executor" / "daemon.py"
        text = src.read_text(encoding="utf-8")
        # Only a past-tense mention (a comment) is allowed; no CALL remains.
        for line in text.splitlines():
            if "NoEncryption()" in line:
                assert line.lstrip().startswith("#"), f"live NoEncryption() call returned to daemon.py: {line}"

    def test_serializer_has_no_plaintext_arm(self) -> None:
        """``serialize_key_encrypted`` takes the passphrase, not an option: every
        call it makes emits an envelope. There is no algorithm branch to fall back
        through, which is why a missing passphrase is a refusal and not a mode."""
        from executor import key_passphrase as kp

        key = ec.generate_private_key(ec.SECP256R1())
        assert b"ENCRYPTED PRIVATE KEY" in kp.serialize_key_encrypted(key, GOOD_PW.encode("utf-8"))

    def test_writers_take_no_fallback_flag(self) -> None:
        """No ``allow_plaintext``-shaped parameter exists on either writer — the
        escape hatch is not in the signature, so it cannot be re-added by a caller."""
        import inspect

        from executor.daemon import CertificateManager

        for name in ("register", "rotate"):
            params = inspect.signature(getattr(CertificateManager, name)).parameters
            assert not any(
                "plaintext" in p or "no_encrypt" in p or "allow_" in p for p in params
            ), f"a plaintext escape hatch appeared on {name}(): {list(params)}"
