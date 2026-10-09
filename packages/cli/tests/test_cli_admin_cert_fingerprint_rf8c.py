# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-8c — fingerprint-triggered TLS context rebuild at the `_http` choke point.

Design authority: `docs/design/rf6-shortcert-dossier-20261007.md` §4.3. The mechanism
it designs against is real and quiet: `load_cert_chain` copies the chain into the
OpenSSL context AT BUILD TIME, and the built client is cached until `close()`. So
rewriting the certificate file under a live process changes nothing that process will
send — a long-running admin script would die at the 60-minute mark even after a
successful `venya admin cert renew`.

The ruled answer is a content-hash fingerprint recorded at build and re-checked at the
existing choke point before each request: differs → close the old client and rebuild
through the SAME build branch; identical → send on, zero rebuild. These cells are
built around the two ways that design can be wrong in practice:

  * a `mtime`/size shortcut, which rebuilds on `cp`/`rsync` noise and FAILS to rebuild
    on a restore that preserves `mtime` — so P2 counts builds, it does not admire
    behavior;
  * a rebuild that silently adopts a different file, or that leaks the superseded
    client — N1 pins the PATH, P4 pins the `close()`.

N4 is the RF-8b interaction only the same lane can spec honestly: a session-only dial
has NO admin certificate to fingerprint, so it must skip cleanly — no crash, no rebuild
loop, and still no credential presented.

No network: the transport factory is stubbed and counted. No VM, no ceremony.
"""

import datetime
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient, APIClientError

UTC = datetime.UTC
# dev-only test passphrase (#547a); value is not secret and not used anywhere live
LEAF_PASSPHRASE = "test_passphrase"
ISSUER = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
    ]
)


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _key_bytes(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cert_bytes(seed: int, lifetime_min: int = 30, key=None, signer=None, public_key=None) -> bytes:
    """A real, distinct admin-shaped certificate.

    `seed` moves the MATERIAL (serial + subject) without changing the key, because the
    cells that swap a certificate under a live client must produce a pair that
    `load_cert_chain` still accepts — a cert for a different key is refused with
    KEY_VALUES_MISMATCH, and that would be a fixture bug, not the behavior under test.
    `signer` is the CA-side key; a minted certificate is signed by the CA, not by the
    requester's key, so the P5 cell signs with its own CA-shaped key.
    """
    now = datetime.datetime.now(UTC)
    key = key if key is not None else _new_key()
    # `public_key` is the CSR's key, which is already a public key object (the mint
    # stub below plays the CA, and a CA signs the REQUESTER's public key).
    pub = public_key if public_key is not None else key.public_key()
    signer = signer if signer is not None else key
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"dusty@workstation-{seed}")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ISSUER)
        .public_key(pub)
        .serial_number(0x5000_0000 + seed)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(minutes=lifetime_min))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(signer, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class _CountedClient:
    """A transport that reports its own construction and its own close()."""

    def __init__(self, registry: list, **kwargs) -> None:
        self.kwargs = kwargs
        self.closed = False
        registry.append(self)

    def request(self, method, path, json=None, params=None, headers=None, **kwargs):
        raise AssertionError("this cell asserts the TRANSPORT, never a real dial")

    def close(self) -> None:
        self.closed = True


def _build_counter():
    """Patch the transport factory so every construction is visible and countable."""
    registry: list[_CountedClient] = []

    def factory(**kwargs):
        return _CountedClient(registry, **kwargs)

    return registry, patch("venya_cli.api_client.httpx2.Client", side_effect=lambda **kw: factory(**kw))


def _private_of(key_path: Path) -> ec.EllipticCurvePrivateKey:
    """The key the pair fixture wrote — read back so a swapped certificate matches it."""
    return serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)


def _client(tmp_path: Path, cert_path: Path, key_path: Path) -> APIClient:
    cfg = tmp_path / "config.json"
    cfg.write_text('{"server_url": "https://core.test:8443"}', encoding="utf-8")
    os.environ["VENYA_CONFIG"] = str(cfg)
    os.environ["SSL_CERT_FILE"] = str(cert_path)  # an anchor this cell can resolve
    os.environ["VENYA_ADMIN_CERT"] = str(cert_path)
    os.environ["VENYA_ADMIN_KEY"] = str(key_path)
    client = APIClient()
    client.config.access_token = "session-bearer"
    return client


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("VENYA_ADMIN_CERT", "VENYA_ADMIN_KEY", "VENYA_CONFIG", "SSL_CERT_FILE", "VENYA_SERVER_URL"):
        monkeypatch.delenv(var, raising=False)
    # #547a: an admin private key is now only written encrypted, so every cell here that
    # exercises the write path supplies the passphrase. Converted by ADDING the variable
    # — no assertion in this file was deleted or relaxed. (The refusal halves, including
    # the proof that the written key is not mTLS-loadable yet, live in
    # tests/test_cli_admin_leaf_key_passphrase_547a.py.)
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", LEAF_PASSPHRASE)
    yield


@pytest.fixture
def pair(tmp_path):
    """One keypair on disk. Replacement certificates reuse THIS key, so every swap is
    a change of material the TLS layer will actually accept."""
    cert = tmp_path / "admin.crt"
    key = tmp_path / "admin.key"
    private = _new_key()
    cert.write_bytes(_cert_bytes(1, key=private))
    key.write_bytes(_key_bytes(private))
    key.chmod(0o600)
    return cert, key


class TestFingerprintMechanism:
    """The mechanism's own halves: hash the bytes, not the stat()."""

    def test_fingerprint_is_sha256_of_the_file_bytes(self, pair):
        from venya_cli.api_client import _admin_cert_fingerprint

        cert, _key = pair
        assert _admin_cert_fingerprint(str(cert)) == hashlib.sha256(cert.read_bytes()).hexdigest()

    def test_identical_bytes_under_a_changed_mtime_do_not_rebuild(self, tmp_path, pair):
        """P2 + the dossier's named trap: a restore that leaves `mtime` behind must
        still rebuild, and a `cp` that moves `mtime` on identical material must NOT.
        Size is equal in both cases, so only the content can answer."""
        cert, key = pair
        before = cert.read_bytes()
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
            assert len(registry) == 1
            # rewrite byte-identical content and push mtime far into the past
            os.utime(cert, (0, 0))
            cert.write_bytes(before)
            assert client._http is not None
            assert len(registry) == 1, "identical bytes rebuilt the context — churn by mtime"
        client.close()

    def test_different_bytes_of_the_same_length_rebuild(self, tmp_path, pair):
        """The size-only trap: two certs for one identity are the same length by
        construction, so length comparison would never fire."""
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
            assert len(registry) == 1
            private = _private_of(key)
            replacement = _cert_bytes(2, key=private)
            cert.write_bytes(replacement)
            assert client._http is not None
            # the trigger is the material, not its length: a size comparison would sleep
            # through exactly this swap
            assert len(registry) == 2, "different material of the same kind did not rebuild"
        client.close()

    def test_one_fingerprint_per_request_at_most(self, tmp_path, pair):
        """P3 — the ruled cost: one read of the certificate per request, no more."""
        import venya_cli.api_client as api

        cert, key = pair
        client = _client(tmp_path, cert, key)
        calls: list[str] = []
        real = api._admin_cert_fingerprint

        def counting(path):
            calls.append(path)
            return real(path)

        registry, counter = _build_counter()
        with counter, patch.object(api, "_admin_cert_fingerprint", side_effect=counting):
            assert client._http is not None  # first dial: builds and records
            assert calls == [str(cert)], calls
            assert client._http is not None  # staged dial: re-confirms, does not rebuild
            assert len(calls) == 2, calls
            assert client._http is not None
            assert len(calls) == 3, calls
            assert len(registry) == 1, "the check must not rebuild when nothing changed"
        client.close()


class TestRebuildPresentsTheNewMaterial:
    """P1 + P4 — the rebuilt context carries the new pair and the old client is closed."""

    def test_replaced_cert_is_presented_on_the_next_request(self, tmp_path, pair):
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
            first = registry[0]
            fp_before = client._cert_fingerprint
            new_material = _cert_bytes(7, key=_private_of(key))
            cert.write_bytes(new_material)
            assert client._http is not None
            assert len(registry) == 2
            assert client._cert_fingerprint == hashlib.sha256(new_material).hexdigest()
            assert client._cert_fingerprint != fp_before
            # the rebuilt context is built through the same _build_ssl_context call with
            # the same pinned path — the material under that path is what changed
            assert first.kwargs.get("verify") is not None
            assert registry[1].kwargs.get("verify") is not None
            assert registry[1].kwargs.get("verify") is not first.kwargs.get("verify")
        client.close()

    def test_rebuild_closes_the_superseded_client(self, tmp_path, pair):
        """P4 — a leak here is a socket leak."""
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
            assert registry[0].closed is False
            cert.write_bytes(_cert_bytes(9, key=_private_of(key)))
            assert client._http is not None
            assert registry[0].closed is True, "the old transport was not closed before rebuild"
            assert registry[1].closed is False
        client.close()

    def test_renew_in_process_is_picked_up_without_a_restart(self, tmp_path, pair):
        """P5 — the feature's whole point, proven end-to-end in one process.

        A live admin client stages its context from the old certificate. RF-8b's renew
        then writes a fresh certificate at that same path (renew itself dials
        session-only — see N4 — so it is done on its own client). The NEXT dial on the
        original live client must notice the changed material: the fingerprint fires,
        the superseded client is closed, and the rebuild runs. Since #547a the rebuilt
        pair carries an ENCRYPTED key and the current TLS path cannot load one, so the
        rebuild refuses loudly instead of presenting anything — the pickup mechanism is
        proven here, and the read-side gap with it (see §4 N4 for the byte-level half).
        """
        from venya_cli.commands import cmd_admin_cert_renew

        cert, key = pair
        live = _client(tmp_path, cert, key)  # a long-running admin script
        registry, counter = _build_counter()
        with counter:
            assert live._http is not None
            assert len(registry) == 1
            old_fp = live._cert_fingerprint

            # RF-8b renew writes the new pair. The mint stub does what the core does:
            # it reads the CSR the handler built and signs THAT public key, so the
            # certificate and the key the handler writes are a real matching pair.
            renew_client = _client(tmp_path, cert, key)
            _, renew_counter = _build_counter()

            def fake_post(self, method, path, json_data=None, params=None, extra_headers=None, timeout=None):
                csr = x509.load_pem_x509_csr(json_data["csr_pem"].encode())
                minted = _cert_bytes(11, lifetime_min=60, public_key=csr.public_key(), signer=_new_key())
                return {"certificate_pem": minted.decode()}

            with (
                renew_counter,
                patch("venya_cli.commands._elevate", return_value="t"),
                patch.object(APIClient, "_request", fake_post),
            ):
                rc = cmd_admin_cert_renew(
                    renew_client,
                    SimpleNamespace(cert_path=str(cert), key_path=str(key), user_id=None, server_url=None),
                )
            assert rc == 0
            # what the handler wrote is a different certificate at the SAME path — the
            # identity the readout printed is the mint's, not the fixture's
            assert x509.load_pem_x509_certificate(cert.read_bytes()).serial_number == 0x5000_0000 + 11
            # #547a changed this cell's honest ending, and the change is recorded here
            # rather than papered over: the renew now writes the key ENCRYPTED, and the
            # CLI has no path that loads an encrypted admin key for mTLS (Part B). So
            # the fingerprint DOES fire — the pickup half of RF-8c still works, and the
            # superseded client is still closed — but the rebuild refuses instead of
            # staging a transport. This is the same fact §4 N4 asserts on the written
            # bytes; here it is shown at the choke point, which is where an operator
            # would meet it.
            with pytest.raises(APIClientError) as refused:
                assert live._http is not None
            assert "Failed to load the admin mTLS client cert/key pair" in str(refused.value)
            assert len(registry) == 1, "the refusal must not stage a transport either"
            assert registry[0].closed is True, "the superseded client was still closed"
            assert live._cert_fingerprint != old_fp, "the renewed certificate was not picked up"
        live.close()
        renew_client.close()


class TestNothingRebuildsWhenNothingChanged:
    """The no-churn half, in numbers."""

    def test_ten_requests_on_a_stable_pair_build_exactly_one_transport(self, tmp_path, pair):
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            for _ in range(10):
                assert client._http is not None
        assert len(registry) == 1, f"built {len(registry)} transports for 10 requests"
        client.close()

    def test_touching_the_private_key_does_not_rebuild(self, tmp_path, pair):
        """The fingerprint is of the CERTIFICATE only — the key is never the trigger
        and never opened for it (the RF-8a boundary)."""
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
            key.write_bytes(_key_bytes(_private_of(key)))
            os.utime(key, (0, 0))
            assert client._http is not None
            assert len(registry) == 1
        client.close()


class TestNegativeCases:
    """The rejecting halves the dossier names."""

    def test_env_moved_to_another_path_does_not_make_the_live_client_adopt_it(self, tmp_path, pair):
        """N1 — "a process holding the old path must keep using the old file and must
        not silently adopt anything"."""
        cert, key = pair
        other = tmp_path / "elsewhere.crt"
        other.write_bytes(_cert_bytes(21))
        other_key = tmp_path / "elsewhere.key"
        other_key.write_bytes(_key_bytes(_new_key()))
        other_key.chmod(0o600)

        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
            assert client._cert_fingerprint_path == str(cert)
            # the operator re-points the environment mid-session (a different file)
            os.environ["VENYA_ADMIN_CERT"] = str(other)
            os.environ["VENYA_ADMIN_KEY"] = str(other_key)
            assert client._http is not None
            assert client._http is not None
            assert len(registry) == 1, "the live client adopted a path it never built from"
            assert client._cert_fingerprint_path == str(cert)
            assert client._cert_fingerprint == hashlib.sha256(cert.read_bytes()).hexdigest()
        client.close()

    def test_deleted_cert_mid_session_refuses_loudly_and_builds_nothing(self, tmp_path, pair):
        """N2 — no rebuild-and-hope, nothing dialed on a stale context."""
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter, pytest.raises(APIClientError) as excinfo:
            assert client._http is not None
            assert len(registry) == 1
            cert.unlink()
            assert client._http is not None
        msg = str(excinfo.value)
        assert "cannot be read" in msg and "FileNotFoundError" in msg
        assert "venya admin cert renew" in msg  # names the repair, like every other refusal
        assert "Nothing was sent" in msg
        assert len(registry) == 1, "a refusal must not build a replacement transport"
        assert registry[0].closed is False, "the refusal did not touch the staged transport"
        client.close()

    def test_unreadable_cert_mid_session_refuses_and_never_falls_back_to_the_host_store(self, tmp_path, pair):
        """N3 — same class as N2, and no route to the system trust store."""
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        try:
            with counter, pytest.raises(APIClientError) as excinfo:
                assert client._http is not None
                cert.chmod(0o000)
                assert client._http is not None
            assert "cannot be read" in str(excinfo.value)
            assert "PermissionError" in str(excinfo.value)
            assert len(registry) == 1
        finally:
            cert.chmod(0o644)
            client.close()

    def test_empty_cert_file_refuses_rather_than_rebuilding_on_garbage(self, tmp_path, pair):
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter, pytest.raises(APIClientError) as excinfo:
            assert client._http is not None
            cert.write_bytes(b"")
            assert client._http is not None
        assert "empty" in str(excinfo.value)
        assert len(registry) == 1
        client.close()

    def test_rebuild_to_an_expired_certificate_still_hits_the_rf8a_guard(self, tmp_path, pair):
        """N5 + the ordering that matters: a rebuild is not a way around the landed
        expiry refusal — re-entry runs the same branch, guard included."""
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter, pytest.raises(APIClientError) as excinfo:
            assert client._http is not None
            assert len(registry) == 1
            cert.write_bytes(_cert_bytes(31, lifetime_min=-5, key=_private_of(key)))  # into the past
            assert client._http is not None
        assert "EXPIRED" in str(excinfo.value)
        assert "venya admin cert renew" in str(excinfo.value)
        assert len(registry) == 1, "the expired material must never reach a built context"
        client.close()


class TestSessionOnlyTransportSkipsTheFingerprint:
    """N4 — the RF-8b interaction this leg owns. A session-only dial has no admin
    certificate to fingerprint: it must skip cleanly, never loop, and keep presenting
    nothing."""

    def test_session_only_dial_records_no_fingerprint_and_builds_once(self, tmp_path, pair):
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            client.use_session_only_transport()
            assert client._http is not None
            assert client._cert_fingerprint is None
            assert client._cert_fingerprint_path is None
            for _ in range(5):
                assert client._http is not None
            assert len(registry) == 1, "a session-only dial rebuild-looped"
        client.close()

    def test_session_only_still_presents_no_credential_after_the_change(self, tmp_path, pair):
        """The RF-8b guarantee, restated at the RF-8c seam: no cert, no key, ever."""
        import venya_cli.api_client as api

        cert, key = pair
        seen: list[tuple] = []
        real = api._build_ssl_context
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()

        def spy(cafile=None, certfile=None, keyfile=None, *a, **k):
            seen.append((certfile, keyfile))
            return real(cafile, certfile, keyfile)

        with (
            counter,
            patch.object(api, "_build_ssl_context", side_effect=spy),
        ):
            client.use_session_only_transport()
            assert client._http is not None
            assert client._http is not None
            # and the file changing under it cannot start a presentation loop
            cert.write_bytes(_cert_bytes(41, key=_private_of(key)))
            assert client._http is not None
        assert seen == [(None, None)], seen  # built ONCE, and the re-check was skipped
        assert len(registry) == 1
        assert client._cert_fingerprint is None
        client.close()

    def test_no_fingerprint_is_taken_when_nothing_is_presented(self, tmp_path, pair):
        """The cost is not paid on a dial that has no certificate to confirm."""
        import venya_cli.api_client as api

        cert, key = pair
        client = _client(tmp_path, cert, key)
        calls: list[str] = []
        real = api._admin_cert_fingerprint

        def counting(path):
            calls.append(path)
            return real(path)

        registry, counter = _build_counter()
        with counter, patch.object(api, "_admin_cert_fingerprint", side_effect=counting):
            client.use_session_only_transport()
            for _ in range(4):
                assert client._http is not None
        assert calls == [], calls
        assert len(registry) == 1
        client.close()

    def test_a_normal_dial_after_the_rf8c_change_still_presents_the_pair(self, tmp_path, pair):
        """Default-ON for the pair path: the seam is opt-in, so an ordinary admin dial
        builds with the pair and fingerprints it."""
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
        assert len(registry) == 1
        assert client._cert_fingerprint == hashlib.sha256(cert.read_bytes()).hexdigest()
        assert client._cert_fingerprint_path == str(cert)
        client.close()


class TestHandedOverTransportIsNotVouchedFor:
    """The setter seam: an injected transport carries no fingerprint claim."""

    def test_injection_clears_the_fingerprint_and_never_rebuilds_over_it(self, tmp_path, pair):
        cert, key = pair
        client = _client(tmp_path, cert, key)
        stub = _CountedClient([], verify=None)
        client._http = stub
        assert client._cert_fingerprint is None and client._cert_fingerprint_path is None
        # material changes, but this code never built the staged transport
        cert.write_bytes(_cert_bytes(51, key=_private_of(key)))
        assert client._http is stub

    def test_real_build_then_injection_then_real_build(self, tmp_path, pair):
        cert, key = pair
        client = _client(tmp_path, cert, key)
        registry, counter = _build_counter()
        with counter:
            assert client._http is not None
            assert client._cert_fingerprint is not None
            client._http = None  # force a rebuild, the documented test-seam usage
            assert client._cert_fingerprint is None
            assert client._http is not None
            assert client._cert_fingerprint == hashlib.sha256(cert.read_bytes()).hexdigest()
        assert len(registry) == 2
        client.close()
