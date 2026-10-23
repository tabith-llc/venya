# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#531 audit-forwarder-dial-falls-back-to-host-store — the split, pinned by mechanism.

Owner ruling 2026-10-07 (note 3971355264) split the three internal dials:

* SITE 1 (defect, tightened) — ``executor.audit.AuditLogger._build_forward_ssl_context``
  ended in ``else: ctx.load_default_certs()``, so an executor whose
  ``audit.ca_cert_path`` never landed dialed the audit sink against the HOST
  trust store: a forwarded audit row was not provably addressed to our core.
* SITE 2 (defect, tightened) — ``executor.daemon.ExecutorDaemon._create_mtls_client``
  built on ``ssl.create_default_context()`` and then only ADDED the Venya anchor
  (``load_verify_locations`` adds, it never replaces), so the executor's own
  control-channel dial accepted any publicly-issued certificate for the core
  hostname.
* SITE 3 (STANDS, ruled posture) — ``executor.daemon.CertificateManager._server_ssl_context``
  keeps the OS store on purpose: it serves customer bring-your-own-certificate
  leaves. Record, no behaviour change — and a guard cell so a later sweep cannot
  silently "fix" it.

The trust set is pinned by REAL handshakes (threaded TLS server on
127.0.0.1:0, no fleet, no outbound network) and by the PROHIBITION SHAPE
(``load_default_certs`` rigged to explode, asserted never reached). Anchor
COUNTS are never used: this build's default context reports
``get_ca_certs() == 0`` / ``cert_store_stats() == 0`` while the store is live —
the counting trap is documented in #530/#531 and a count cell would pass by
lying. The host trust store is stood in for by ``SSL_CERT_FILE``, which
``set_default_verify_paths()`` (and therefore ``load_default_certs()``) honors.
"""

import ast
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Self
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from executor.audit import AuditLogger
from executor.config import AuditForwarderConfig, ExecutorConfig, MtlsConfig
from executor.daemon import CertificateManager, ExecutorDaemon
from tests.test_audit import make_cert_pair, read_spool

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "executor"

# ---------------------------------------------------------------------------
# PKI: a Venya-shaped CA (the product anchor) and a foreign CA (the stand-in
# for whatever the HOST store happens to trust). Both minted in the shipped
# root's shape — BC + KeyUsage + SKI — because VERIFY_X509_STRICT, which
# create_default_context() set at HEAD and site 2 sets explicitly now, rejects
# a chain whose CA carries no SKI when the leaf asserts an AKI.
# ---------------------------------------------------------------------------

_NOT_BEFORE = datetime.now(UTC) - timedelta(days=1)
_NOT_AFTER = datetime.now(UTC) + timedelta(days=30)


def _ca(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _server_leaf(
    ca_key: ec.EllipticCurvePrivateKey, ca_cert: x509.Certificate, hostname: str = "localhost"
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _write(dir_: Path, name: str, cert: x509.Certificate, key=None) -> tuple[str, str]:
    """PEM a cert (and, for pairs, its key) to disk; returns (cert_path, key_path)."""
    cert_path = dir_ / f"{name}.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = dir_ / f"{name}.key"
    if key is not None:
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return str(cert_path), str(key_path)


# ---------------------------------------------------------------------------
# Real TLS sink — one server material set per instance, POSTs counted.
# ---------------------------------------------------------------------------


class _CountingHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        self.server.hits += 1  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self) -> None:
        self.server.hits += 1  # type: ignore[attr-defined]
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # silence the test server
        return


class _TlsSink:
    """Threaded HTTPS server on 127.0.0.1:0 presenting ONE server material set."""

    def __init__(self, cert_file: str, key_file: str) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
        self._httpd.hits = 0
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    @property
    def url(self) -> str:
        return f"https://localhost:{self._httpd.server_address[1]}/ingest"

    @property
    def hits(self) -> int:
        return self._httpd.hits

    def __exit__(self, *_exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def pki(tmp_path: Path):
    """On-disk Venya CA + foreign CA, a leaf per CA, and a matching client pair."""
    venya_key, venya_cert = _ca("Venya Test CA 531")
    foreign_key, foreign_cert = _ca("Example Public Root CA 531")
    v_srv_key, v_srv = _server_leaf(venya_key, venya_cert)
    f_srv_key, f_srv = _server_leaf(foreign_key, foreign_cert)
    cli_key, cli_cert = _server_leaf(venya_key, venya_cert, hostname="test-executor")

    class _Pki:
        venya_ca, foreign_ca = (
            _write(tmp_path, "venya-ca", venya_cert)[0],
            _write(tmp_path, "foreign-ca", foreign_cert)[0],
        )
        venya_srv, venya_srv_key = _write(tmp_path, "srv-venya", v_srv, v_srv_key)
        foreign_srv, foreign_srv_key = _write(tmp_path, "srv-foreign", f_srv, f_srv_key)
        client_cert, client_key = _write(tmp_path, "executor", cli_cert, cli_key)

    return _Pki


def _no_host_store(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Prohibition shape: rig ANY host-store load to explode, return the spy."""
    spy = MagicMock(
        name="load_default_certs",
        side_effect=AssertionError("load_default_certs() reached — the dial fell back to the host store (#531)"),
    )
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", spy)
    return spy


def _ssl_error_chain(exc: BaseException) -> str:
    """Flatten an exception chain to text — httpx2 wraps the ssl failure."""
    parts = []
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        parts.append(f"{type(exc).__name__}: {exc}")
        exc = exc.__cause__ or exc.__context__
    return " | ".join(parts)


def _forwarder(config: AuditForwarderConfig, cert_pair: tuple[str, str]) -> AuditLogger:
    """A forwarder whose background thread is already stopped (the test drives it)."""
    log = AuditLogger(config, session_id="s531", client_cert=cert_pair)
    log._shutdown = True
    log._wakeup.set()
    log._forwarder.join(timeout=2.0)
    log._shutdown = False
    return log


# ---------------------------------------------------------------------------
# SITE 1 — the audit forwarder: anchor configured = Venya only; no anchor = REFUSE
# ---------------------------------------------------------------------------


class TestSite1AuditForwarderAnchor:
    def test_forward_drains_to_a_venya_signed_sink(self, tmp_path: Path, pki, monkeypatch):
        """AC3 (no availability regression): the real POST path still works,
        and the prohibition spy proves the host store was never consulted."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        spy = _no_host_store(monkeypatch)
        cert_pair = make_cert_pair(tmp_path)
        with _TlsSink(pki.venya_srv, pki.venya_srv_key) as sink:
            cfg = AuditForwarderConfig(
                remote_url=sink.url,
                ca_cert_path=pki.venya_ca,
                spool_path=str(tmp_path / "spool.jsonl"),
                max_batch_lines=10,
            )
            log = _forwarder(cfg, cert_pair)
            try:
                log.emit("credential_injected", strategy="memfd")
                assert log._forward_once() is True
                assert sink.hits == 1, "the Venya-CA-signed sink was not reached"
                assert read_spool(tmp_path) == [], "the accepted batch left the spool"
            finally:
                log.shutdown()
        spy.assert_not_called()

    def test_forward_refuses_a_host_store_only_sink(self, tmp_path: Path, pki, monkeypatch):
        """Paired negative (trust set == the anchor, not the host store): the
        SAME hostname served by a CA that sits in the host store only is
        REFUSED, the line stays spooled, and nothing crosses the network."""
        foreign_ca_file = pki.foreign_ca
        monkeypatch.setenv("SSL_CERT_FILE", foreign_ca_file)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        cert_pair = make_cert_pair(tmp_path)
        with _TlsSink(pki.foreign_srv, pki.foreign_srv_key) as sink:
            cfg = AuditForwarderConfig(
                remote_url=sink.url,
                ca_cert_path=pki.venya_ca,
                spool_path=str(tmp_path / "spool.jsonl"),
                max_batch_lines=10,
            )
            log = _forwarder(cfg, cert_pair)
            try:
                log.emit("credential_injected", strategy="memfd")
                assert log._forward_once() is False
                assert sink.hits == 0, "the request reached a sink the anchor does not vouch for"
                assert len(read_spool(tmp_path)) == 1, "a refused forward keeps the audit line"
            finally:
                log.shutdown()

    def test_no_anchor_never_dials_on_the_host_store(self, tmp_path: Path, pki, monkeypatch):
        """RED-then-GREEN at site 1, against a live server: HEAD's
        ``else: load_default_certs()`` accepted this sink (the foreign leaf is in
        the host store via SSL_CERT_FILE). Now the dial is refused outright."""
        monkeypatch.setenv("SSL_CERT_FILE", pki.foreign_ca)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        spy = _no_host_store(monkeypatch)
        cert_pair = make_cert_pair(tmp_path)
        with _TlsSink(pki.foreign_srv, pki.foreign_srv_key) as sink:
            # No anchor at all, exactly the shape the config validator refuses:
            # constructed without remote_url, then remote_url lands by mutation.
            cfg = AuditForwarderConfig(spool_path=str(tmp_path / "spool.jsonl"), max_batch_lines=10)
            cfg.remote_url = sink.url
            log = _forwarder(cfg, cert_pair)
            try:
                log.emit("credential_injected", strategy="memfd")
                assert log._forward_once() is False
                assert sink.hits == 0, "a no-anchor forwarder crossed the network on host trust"
                assert len(read_spool(tmp_path)) == 1
            finally:
                log.shutdown()
        spy.assert_not_called()

    def test_refusal_names_the_anchor_and_the_repair(self, tmp_path: Path, pki, caplog):
        """The operator gets a named, one-line reason — not a raw traceback."""
        cfg = AuditForwarderConfig(spool_path=str(tmp_path / "spool.jsonl"), max_batch_lines=10)
        cfg.remote_url = "https://sink.invalid/audit"  # validator bypassed by mutation
        log = _forwarder(cfg, make_cert_pair(tmp_path))
        try:
            log.emit("credential_injected", strategy="memfd")
            with pytest.raises(RuntimeError) as excinfo:
                log._build_forward_ssl_context()  # must raise, never fall back
            assert "audit.ca_cert_path" in str(excinfo.value)
            assert "host trust store" in str(excinfo.value)
            assert "spooled" in str(excinfo.value), "the refusal says what happens to the events"
            # The refusal is one loud line per cycle through the existing handler.
            with caplog.at_level("WARNING", logger="venya.executor.audit"):
                assert log._forward_once() is False
            assert "no trust anchor" in caplog.text
            assert len(read_spool(tmp_path)) == 1
        finally:
            log.shutdown()


# ---------------------------------------------------------------------------
# SITE 2 — the executor control-channel dial: the Venya anchor ONLY
# ---------------------------------------------------------------------------


def _daemon(server_url: str, pki, tmp_path: Path) -> ExecutorDaemon:
    cfg = ExecutorConfig(
        server_url=server_url,
        executor_id="test-executor",
        mtls=MtlsConfig(cert=pki.client_cert, key=pki.client_key, ca_cert=pki.venya_ca),
        audit=AuditForwarderConfig(spool_path=str(tmp_path / "unused-spool.jsonl")),
    )
    return ExecutorDaemon(cfg)


class TestSite2MtlsDialAnchor:
    def test_dial_verifies_a_venya_signed_core(self, tmp_path: Path, pki, monkeypatch):
        """AC3 positive: the heartbeat dial still reaches a Venya-CA core."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        spy = _no_host_store(monkeypatch)
        with _TlsSink(pki.venya_srv, pki.venya_srv_key) as sink:
            d = _daemon(sink.url.rsplit("/", 1)[0], pki, tmp_path)
            client = d._create_mtls_client()
            with client:
                resp = client.get("/api/v1/heartbeat")
            assert resp.status_code == 200
            assert sink.hits == 1
        spy.assert_not_called()

    def test_dial_refuses_a_host_store_signed_core(self, tmp_path: Path, pki, monkeypatch):
        """Paired negative, RED at HEAD: create_default_context() loaded the
        host store and load_verify_locations() only ADDED our anchor, so this
        publicly-signed leaf for the same hostname validated."""
        monkeypatch.setenv("SSL_CERT_FILE", pki.foreign_ca)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        with _TlsSink(pki.foreign_srv, pki.foreign_srv_key) as sink:
            d = _daemon(sink.url.rsplit("/", 1)[0], pki, tmp_path)
            client = d._create_mtls_client()
            with client, pytest.raises(httpx2.TransportError) as excinfo:
                client.get("/api/v1/heartbeat")
            assert sink.hits == 0, "the control channel dialed a host-trusted impostor"
            assert "unable to get local issuer certificate" in _ssl_error_chain(excinfo.value)

    def test_dial_never_loads_the_host_store(self, tmp_path: Path, pki, monkeypatch):
        """Prohibition shape on the builder itself (no socket): the context
        production must not reach load_default_certs() — ever."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        spy = _no_host_store(monkeypatch)
        d = _daemon("https://localhost:1", pki, tmp_path)
        with patch("executor.daemon.httpx2.Client") as client_cls:
            d._create_mtls_client()
        verify = client_cls.call_args.kwargs["verify"]
        assert isinstance(verify, ssl.SSLContext)
        assert verify.verify_mode is ssl.CERT_REQUIRED
        assert verify.check_hostname is True
        assert verify.verify_flags & ssl.VERIFY_X509_STRICT
        assert verify.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
        spy.assert_not_called()

    def test_missing_material_still_refuses_by_name(self, tmp_path: Path, pki, monkeypatch, caplog):
        """AC5 / fail-loud kept: unusable material is the named startup
        refusal, not a fall-through to the host store."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        spy = _no_host_store(monkeypatch)
        d = _daemon("https://localhost:1", pki, tmp_path)
        d.config.mtls = MtlsConfig(
            cert=str(tmp_path / "gone.crt"),
            key=str(tmp_path / "gone.key"),
            ca_cert=pki.venya_ca,
        )
        with pytest.raises(RuntimeError, match="mTLS material unusable"):
            d._create_mtls_client()
        assert "mTLS material unusable" in caplog.text
        spy.assert_not_called()

    def test_unusable_anchor_is_a_named_refusal_not_the_host_store(self, tmp_path: Path, pki, monkeypatch, caplog):
        """The paired half: a CA file that exists but is not a certificate
        must refuse loudly (AC5) instead of quietly validating on host trust."""
        monkeypatch.setenv("SSL_CERT_FILE", pki.foreign_ca)
        bad = tmp_path / "bad-ca.crt"
        bad.write_text("not a pem\n", encoding="utf-8")
        spy = _no_host_store(monkeypatch)
        d = _daemon("https://localhost:1", pki, tmp_path)
        d.config.mtls = MtlsConfig(cert=pki.client_cert, key=pki.client_key, ca_cert=str(bad))
        with pytest.raises(RuntimeError, match="mTLS material unusable"):
            d._create_mtls_client()
        spy.assert_not_called()


# ---------------------------------------------------------------------------
# SITE 3 — the ruled posture: the OS store stays loaded HERE, on purpose
# ---------------------------------------------------------------------------


class TestSite3RuledPostureStands:
    """_server_ssl_context is the one dial the owner ruled to KEEP the system
    store (customer bring-your-own-certificate leaves). These cells exist so a
    later sweep cannot silently 'tighten' the ruled posture."""

    def _manager(self, pki, tmp_path: Path, ca_bundle: str | None) -> CertificateManager:
        cfg = ExecutorConfig(
            server_url="https://localhost:1",
            executor_id="test-executor",
            ca_bundle=ca_bundle,
            mtls=MtlsConfig(cert=pki.client_cert, key=pki.client_key, ca_cert=pki.venya_ca),
        )
        return CertificateManager(cfg)

    def test_server_context_still_loads_the_default_store(self, tmp_path: Path, pki, monkeypatch):
        """The posture pinned POSITIVELY: create_default_context() runs, and the
        spy calls through instead of exploding (the opposite of the tightened
        sites) so the anchor add still happens."""
        monkeypatch.setenv("SSL_CERT_FILE", pki.foreign_ca)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        real = ssl.SSLContext.load_default_certs

        calls: list[str] = []

        def _spy(self, *a, **k):  # call through — this store load is the point
            calls.append("default-store")
            return real(self, *a, **k)

        monkeypatch.setattr(ssl.SSLContext, "load_default_certs", _spy)
        cm = self._manager(pki, tmp_path, ca_bundle=None)
        ctx = cm._server_ssl_context()
        assert calls == ["default-store"], "site 3 lost the ruled host-store posture"
        assert isinstance(ctx, ssl.SSLContext)

    def test_server_context_accepts_a_host_store_signed_core(self, tmp_path: Path, pki, monkeypatch):
        """The consequence of the posture, by handshake: a core whose leaf a
        host already trusts keeps verifying at this site (register + probe)."""
        monkeypatch.setenv("SSL_CERT_FILE", pki.foreign_ca)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        with _TlsSink(pki.foreign_srv, pki.foreign_srv_key) as sink:
            cm = self._manager(pki, tmp_path, ca_bundle=None)
            with httpx2.Client(base_url=sink.url.rsplit("/", 1)[0], verify=cm._server_ssl_context()) as client:
                cm.client = client
                assert client.get("/api/v1/ping").status_code == 200
            assert sink.hits == 1

    def test_ruling_is_recorded_at_the_construction_site(self, pki, tmp_path: Path):
        """AC4: a ruled posture is a RECORD — the ruling, the date and the
        ticket must be readable in the source beside the call."""
        src = (SRC_ROOT / "daemon.py").read_text(encoding="utf-8")
        block = src[src.index("def _server_ssl_context") : src.index("def register(")]
        assert "RULED POSTURE" in block
        assert "2026-10-07" in block
        assert "#531" in block
        assert "bring-your-own-certificate" in block
        assert "RULUED" not in src, "the typo'd ruling word shipped"


# ---------------------------------------------------------------------------
# Static sweep — the tightened sites have no host-store call site left
# ---------------------------------------------------------------------------


def _call_names(py_file: Path) -> list[str]:
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name in {"load_default_certs", "create_default_context", "set_default_verify_paths"}:
                names.append(name)
    return names


class TestTrustStoreSweep:
    def test_audit_module_has_no_host_store_call_site(self):
        """Site 1's fallback is gone, not merely bypassed in tests."""
        assert "load_default_certs" not in _call_names(SRC_ROOT / "audit.py")

    def test_daemon_keeps_exactly_one_default_trust_site(self):
        """Site 3 (the ruled posture) is the ONLY create_default_context left in
        daemon.py; site 2 no longer contributes one, and no new dial appeared."""
        names = _call_names(SRC_ROOT / "daemon.py")
        assert names.count("create_default_context") == 1, f"unexpected default-trust dials: {names}"
        assert names.count("load_default_certs") == 0

    def test_mtls_dial_source_has_no_default_context_call(self):
        """AST-scoped to the method itself (a docstring mention is not a call
        site, and the sweep cannot be satisfied by a comment) — and site 3's
        sanctioned construction lives in a different FunctionDef."""
        tree = ast.parse((SRC_ROOT / "daemon.py").read_text(encoding="utf-8"), filename="daemon.py")

        def _calls_in(name: str) -> list[str]:
            fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
            found = []
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    func = node.func
                    ident = getattr(func, "attr", None) or getattr(func, "id", None)
                    if ident in {"create_default_context", "load_default_certs", "set_default_verify_paths"}:
                        found.append(ident)
            return found

        assert _calls_in("_create_mtls_client") == [], "site 2 reverted to the host store"
        assert _calls_in("_server_ssl_context") == ["create_default_context"], "site 3 posture moved unrecorded"
