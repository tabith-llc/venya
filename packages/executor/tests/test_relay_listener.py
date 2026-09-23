# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the executor-side mTLS relay listener (B0.1 / B0.2 / B0.3).

Stand up a real ``http.server`` + ``ssl.SSLContext`` listener on an ephemeral
port with a real ``cryptography`` PKI, drive it with real mTLS ``httpx2``
clients, and assert the TLS + identity + payload contract.

No Docker, no sandboxes: the execution engine is a stub injected through the
``executor_factory`` seam, which proves B0.2 *wiring* (handler -> engine, bytes
normalization, result formatting). The physical engine is re-validated at C1.

Failure-mode matrix (the plan's "immediate 503 on any failure"):
  - no client cert            -> TLS handshake fails (no HTTP)
  - client cert wrong CA      -> TLS handshake fails (no HTTP)
  - known CA, unknown CN      -> 403 (B0.3)
  - allowed CN, bad payload   -> 400
  - allowed CN, engine error  -> 503
  - empty relay_client_ids    -> listener never binds (fail-closed)
"""

import json
import socket
import ssl
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from executor.config import ExecutorConfig, MtlsConfig
from executor.executor import CommandResult
from executor.relay_listener import (
    MAX_RELAY_BODY_BYTES,
    RELAY_READ_TIMEOUT_SECONDS,
    ExecuteHandler,
    RelayListener,
)

ALLOWED = "core-allowed"
SERVER_CN = "relay-srv"

# --- PKI helpers (self-contained; full control over CN and private keys) ---


def _not_window():
    now = datetime.now(UTC)
    return now, now + timedelta(days=1)


def _ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Relay Test CA"),
        ]
    )
    nb, na = _not_window()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
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
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    server_auth: bool = False,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    eku = [ExtendedKeyUsageOID.SERVER_AUTH if server_auth else ExtendedKeyUsageOID.CLIENT_AUTH]
    nb, na = _not_window()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
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
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def _write_dir(cert: x509.Certificate, key: ec.EllipticCurvePrivateKey, tmp_path, base: str) -> tuple[str, str]:
    cert_path = tmp_path / f"{base}.crt"
    key_path = tmp_path / f"{base}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return str(cert_path), str(key_path)


def _write_cert_only(cert: x509.Certificate, tmp_path, base: str) -> str:
    path = tmp_path / f"{base}.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


# --- HTTP + engine test doubles ---


def _client(ca_crt: str, cert: tuple[str, str] | None = None) -> httpx2.Client:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(ca_crt)
    if cert:
        ctx.load_cert_chain(cert[0], cert[1])
    return httpx2.Client(verify=ctx, timeout=10.0)


class _FakeExec:
    """Stand-in for Executor: records the call, returns a canned result or raises."""

    def __init__(self, result: CommandResult | None = None, exc: BaseException | None = None):
        self._result = result
        self._exc = exc
        self.command: str | None = None
        self.secrets: object = None
        self.env_vars: object = "UNSET"
        self.askpass_helper: object = "UNSET"

    def execute(
        self,
        command: str,
        secrets: list,
        env_vars: list | None = None,
        askpass_helper: bool = False,
    ) -> CommandResult:
        self.command = command
        self.secrets = secrets
        self.env_vars = env_vars
        self.askpass_helper = askpass_helper
        if self._exc is not None:
            raise self._exc
        assert self._result is not None
        return self._result


def _factory(exec_obj: _FakeExec, sessions: list):
    def _make(session_id: str) -> _FakeExec:
        sessions.append(session_id)
        return exec_obj

    return _make


def _start(config, factory, allowed, host="127.0.0.1", port=0) -> RelayListener:
    listener = RelayListener(config, factory, allowed, host=host, port=port)
    listener.start()
    assert listener.active is True, "listener failed to start"
    return listener


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    try:
        return s.getsockname()[1]
    finally:
        s.close()


def _ok_result(stdout: bytes = b"hello", masked: list[str] | None = None) -> CommandResult:
    return CommandResult(command="echo hi", exit_code=0, stdout=stdout, stderr=b"", masked_secret_ids=masked or [])


# --- Fixtures + launcher ---


@pytest.fixture()
def pk(tmp_path) -> SimpleNamespace:
    """Build a full PKI and return cert paths + a configured ExecutorConfig."""
    a_key, a_cert = _ca()  # the CA the executor trusts for relaying clients
    b_key, b_cert = _ca()  # a *different* CA (for the wrong-CA rejection)

    srv_cert, srv_key = _leaf(a_key, a_cert, SERVER_CN, server_auth=True)  # executor leaf
    c_ok_cert, c_ok_key = _leaf(a_key, a_cert, ALLOWED)  # allowed client
    c_ban_cert, c_ban_key = _leaf(a_key, a_cert, "disallowed-exec")  # CA-valid, CN not allowed
    c_case_cert, c_case_key = _leaf(a_key, a_cert, ALLOWED.upper())  # CN differs only by case
    c_foreign_cert, c_foreign_key = _leaf(b_key, b_cert, ALLOWED)  # same CN, wrong CA

    ca_a_crt = _write_cert_only(a_cert, tmp_path, "ca-a")
    srv = _write_dir(srv_cert, srv_key, tmp_path, "srv")
    c_ok = _write_dir(c_ok_cert, c_ok_key, tmp_path, "c-ok")
    c_ban = _write_dir(c_ban_cert, c_ban_key, tmp_path, "c-ban")
    c_case = _write_dir(c_case_cert, c_case_key, tmp_path, "c-case")
    c_foreign = _write_dir(c_foreign_cert, c_foreign_key, tmp_path, "c-foreign")

    config = ExecutorConfig(
        server_url="https://core.test",
        executor_id="relay-test",
        relay_client_ids=[ALLOWED],
        mtls=MtlsConfig(ca_cert=ca_a_crt, cert=srv[0], key=srv[1]),
    )

    return SimpleNamespace(ca_a=ca_a_crt, c_ok=c_ok, c_ban=c_ban, c_case=c_case, c_foreign=c_foreign, config=config)


@pytest.fixture()
def started(pk):
    """A running listener (allowed client ready) with its engine stub + capture list."""
    fake = _FakeExec(result=_ok_result(stdout=b"hello", masked=["a"]))
    sessions: list = []
    listener = _start(pk.config, _factory(fake, sessions), [ALLOWED])
    yield listener, pk, fake, sessions
    listener.stop()


def _url(listener: RelayListener) -> str:
    return f"https://127.0.0.1:{listener.port}/execute"


# --- Tests ---


class TestRelayListener:
    def test_valid_mtls_request_returns_result(self, started):
        listener, pk, fake, sessions = started
        payload = {
            "session_id": "s1",
            "command": "echo hi",
            "secrets": [{"secret_id": 7, "wrapped_value": "[VENYA:deadbeef]aaa[/VENYA]"}],
        }
        with _client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(_url(listener), json=payload)

        assert resp.status_code == 200
        data = resp.json()
        assert data["exit_code"] == 0
        assert data["stdout"] == "hello"
        assert data["masked_count"] == 1
        # B0.2 wiring: engine got the right command, session id, and BYTES
        assert sessions == ["s1"]
        assert fake.command == "echo hi"
        assert fake.secrets[0]["secret_id"] == 7
        assert fake.secrets[0]["wrapped_value"] == b"[VENYA:deadbeef]aaa[/VENYA]"

    def test_no_cert_rejected_then_server_recovers(self, started):
        listener, pk, _fake, _sessions = started
        # No client certificate -> the CERT_REQUIRED handshake must fail.
        with _client(pk.ca_a, None) as client:
            with pytest.raises(httpx2.RequestError):
                client.post(_url(listener), json={"session_id": "x", "command": "true"})
        # A bad peer must not wedge the listener: the next valid request still works.
        with _client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(_url(listener), json={"session_id": "x", "command": "true"})
        assert resp.status_code == 200

    def test_wrong_ca_rejected(self, started):
        listener, pk, _fake, _sessions = started
        # Client cert signed by a CA the executor does not trust.
        with _client(pk.ca_a, pk.c_foreign) as client:
            with pytest.raises(httpx2.RequestError):
                client.post(_url(listener), json={"session_id": "x", "command": "true"})

    def test_unknown_identity_rejected(self, started):
        listener, pk, _fake, _sessions = started
        # Valid CA, but CN is not in relay_client_ids -> clean 403 (B0.3).
        with _client(pk.ca_a, pk.c_ban) as client:
            resp = client.post(_url(listener), json={"session_id": "x", "command": "true"})
        assert resp.status_code == 403

    def test_cn_comparison_is_case_sensitive(self, started):
        # The allow-list is an exact-match security gate: a CN that differs from
        # "core-allowed" only by case must be rejected, so a later "helpful"
        # normalization PR cannot silently widen the set.
        listener, pk, _fake, _sessions = started
        with _client(pk.ca_a, pk.c_case) as client:
            resp = client.post(_url(listener), json={"session_id": "x", "command": "true"})
        assert resp.status_code == 403

    def test_malformed_body_rejected(self, started):
        listener, pk, _fake, _sessions = started
        # Invalid JSON syntax.
        with _client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(_url(listener), content=b"{not valid json", headers={"Content-Type": "application/json"})
        assert resp.status_code == 400
        # Valid JSON, but the required "command" field is missing.
        with _client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(_url(listener), json={"session_id": "x"})
        assert resp.status_code == 400

    def test_engine_failure_returns_503(self, pk):
        # Simulate a sandbox/subprocess timeout surfacing as an engine exception.
        fake = _FakeExec(exc=TimeoutError("subprocess timed out"))
        sessions: list = []
        listener = _start(pk.config, _factory(fake, sessions), [ALLOWED])
        try:
            with _client(pk.ca_a, pk.c_ok) as client:
                resp = client.post(_url(listener), json={"session_id": "x", "command": "sleep 300"})
        finally:
            listener.stop()
        assert resp.status_code == 503

    def test_wrong_path_returns_404(self, started):
        listener, pk, _fake, _sessions = started
        with _client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(f"https://127.0.0.1:{listener.port}/nope", json={})
        assert resp.status_code == 404

    def test_empty_allowlist_does_not_bind(self, pk):
        # Fail-closed: an empty relay_client_ids means the listener never binds,
        # i.e. "no bind" (connection refused) -- not "starts and 403s everything".
        port = _free_port()
        listener = RelayListener(pk.config, lambda _sid: None, allowed_client_ids=[], host="127.0.0.1", port=port)
        listener.start()
        try:
            assert listener.active is False
            with pytest.raises(ConnectionRefusedError):
                socket.create_connection(("127.0.0.1", port), timeout=2)
        finally:
            listener.stop()


# --- Body cap + read timeout (ticket relay-listener-body-cap-and-timeout) ---


def _raw_exchange(
    listener: RelayListener,
    pk,
    request: bytes,
    *,
    client_timeout: float = 5.0,
    dribble_chunks: int = 0,
    dribble_interval: float = 0.0,
) -> tuple[int, bytes, float]:
    """Drive the listener over a raw TLS socket with the ALLOWED client cert.

    mTLS identity is real (pk.c_ok) — auth is satisfied, never bypassed; only
    the HTTP framing is hand-rolled so malformed/hostile Content-Length shapes
    can be sent verbatim. Reads to EOF (handler is HTTP/1.0, closes after
    every response). Returns (status_code_or_-1, response_bytes, elapsed_s).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(pk.ca_a)
    ctx.load_cert_chain(*pk.c_ok)
    start = time.monotonic()
    with socket.create_connection(("127.0.0.1", listener.port), timeout=client_timeout) as sock:
        with ctx.wrap_socket(sock) as tls:
            tls.settimeout(client_timeout)
            if dribble_chunks > 1:
                size = max(1, len(request) // dribble_chunks)
                for i in range(0, len(request), size):
                    tls.sendall(request[i : i + size])
                    time.sleep(dribble_interval)
            else:
                tls.sendall(request)
            resp = b""
            while True:
                try:
                    part = tls.recv(65536)
                except TimeoutError:
                    break
                if not part:
                    break
                resp += part
    elapsed = time.monotonic() - start
    status = int(resp.split(b" ", 2)[1]) if resp.startswith(b"HTTP/") else -1
    return status, resp, elapsed


def _post(content_length: str, body: bytes = b"") -> bytes:
    return f"POST /execute HTTP/1.0\r\nContent-Length: {content_length}\r\n\r\n".encode() + body


class TestRelayBodyCapAndTimeout:
    """Cap + inactivity-timeout truth table. Boundary contract: CL == cap is
    ACCEPTED (rejection is strictly `>`); every reject is bounded and happens
    BEFORE any body read/allocation; the timeout is per-recv inactivity, so a
    slow-but-steady stream of any duration still succeeds."""

    def test_timeout_contract_constant(self):
        assert ExecuteHandler.timeout == RELAY_READ_TIMEOUT_SECONDS == 30.0

    def test_cl_at_cap_accepted(self, started):
        """Boundary (inclusive): a valid JSON body of EXACTLY the cap → 200."""
        listener, pk, _fake, sessions = started
        overhead = len(json.dumps({"session_id": "s1", "command": "", "secrets": []}).encode())
        body = json.dumps(
            {"session_id": "s1", "command": "A" * (MAX_RELAY_BODY_BYTES - overhead), "secrets": []}
        ).encode()
        assert len(body) == MAX_RELAY_BODY_BYTES
        with _client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(_url(listener), content=body, headers={"Content-Type": "application/json"})
        assert resp.status_code == 200
        assert sessions == ["s1"]

    def test_cl_over_cap_rejected_413_before_read(self, started):
        """cap+1 → 413 immediately, body never demanded, engine never invoked."""
        listener, pk, fake, sessions = started
        status, _resp, elapsed = _raw_exchange(listener, pk, _post(str(MAX_RELAY_BODY_BYTES + 1)))
        assert status == 413
        assert elapsed < 2.0  # did not wait for the (never sent) body
        assert sessions == []
        assert fake.command is None

    def test_cl_absurd_rejected_413(self, started):
        """10**30 → 413 fast; Python ints don't overflow, cap check precedes read."""
        listener, pk, fake, sessions = started
        status, _resp, elapsed = _raw_exchange(listener, pk, _post(str(10**30)))
        assert status == 413
        assert elapsed < 2.0
        assert sessions == []
        assert fake.command is None

    def test_cl_negative_rejected_400_not_hang(self, started):
        """Negative CL → 400. Regression pin: read(-5) meant read-until-EOF."""
        listener, pk, _fake, _sessions = started
        status, _resp, elapsed = _raw_exchange(listener, pk, _post("-5"))
        assert status == 400
        assert elapsed < 2.0

    def test_cl_non_integer_rejected_400(self, started):
        listener, pk, _fake, _sessions = started
        status, _resp, _elapsed = _raw_exchange(listener, pk, _post("1e3"))
        assert status == 400

    def test_cl_missing_rejected_400(self, started):
        """No Content-Length → zero-length read → malformed JSON → clean 400."""
        listener, pk, _fake, _sessions = started
        status, _resp, elapsed = _raw_exchange(listener, pk, b"POST /execute HTTP/1.0\r\n\r\n")
        assert status == 400
        assert elapsed < 2.0

    def test_chunked_not_decoded_rejected_400(self, started):
        """Documented fixed-length protocol: chunked framing is never parsed
        (BaseHTTPRequestHandler has no chunked decoder) → 400, no hang."""
        listener, pk, _fake, _sessions = started
        req = (
            b"POST /execute HTTP/1.0\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b'1a\r\n{"session_id":"s","comma\r\n0\r\n\r\n'
        )
        status, _resp, elapsed = _raw_exchange(listener, pk, req)
        assert status == 400
        assert elapsed < 2.0

    def test_mid_request_silence_closes_within_timeout(self, started, monkeypatch):
        """Header + partial body then silence: the inactivity timeout frees the
        handler (connection closed, no response) well inside the bound — not
        held until SBX_TIMEOUT."""
        listener, pk, _fake, _sessions = started
        monkeypatch.setattr(ExecuteHandler, "timeout", 1.0)
        status, resp, elapsed = _raw_exchange(listener, pk, _post("100", b'{"session_id"'), client_timeout=5.0)
        assert status == -1 and resp == b""  # closed with no HTTP response
        assert elapsed < 3.0

    def test_dribble_slow_but_steady_succeeds(self, started, monkeypatch):
        """Inverse pin: the clock is per-recv INACTIVITY, not total duration —
        a request stretched past the timeout in small steady chunks succeeds."""
        listener, pk, _fake, sessions = started
        monkeypatch.setattr(ExecuteHandler, "timeout", 1.0)
        body = json.dumps({"session_id": "s1", "command": "echo hi", "secrets": []}).encode()
        req = _post(str(len(body)), body)
        status, _resp, elapsed = _raw_exchange(
            listener, pk, req, client_timeout=10.0, dribble_chunks=8, dribble_interval=0.4
        )
        assert status == 200
        assert elapsed >= 2.0  # genuinely spanned more than the 1.0s timeout
        assert sessions == ["s1"]

    def test_valid_request_still_200(self, started):
        """Guardrail must not touch the legitimate path (acceptance #3)."""
        listener, pk, _fake, sessions = started
        with _client(pk.ca_a, pk.c_ok) as client:
            resp = client.post(_url(listener), json={"session_id": "s1", "command": "true", "secrets": []})
        assert resp.status_code == 200
        assert sessions == ["s1"]


# --- env/askpass wire pass-through (ticket secret-shape-env-injection) -------


def test_env_and_askpass_pass_through_to_engine(started):
    """The listener forwards env specs + the askpass flag untouched — it never
    resolves plaintext (that happens in execute() against the bundles)."""
    listener, pk, fake, _sessions = started
    body = json.dumps(
        {
            "session_id": "s-env",
            "command": "printenv TOKEN",
            "secrets": [{"secret_id": 7, "wrapped_value": "[VENYA:abcd1234]cHc=[/VENYA]"}],
            "env": [{"var_name": "TOKEN", "secret_id": 7}],
            "askpass_helper": True,
        }
    ).encode()
    with _client(pk.ca_a, pk.c_ok) as client:
        resp = client.post(_url(listener), content=body, headers={"Content-Type": "application/json"})
    assert resp.status_code == 200
    assert fake.command == "printenv TOKEN"
    assert fake.secrets[0]["secret_id"] == 7
    assert fake.env_vars == [{"var_name": "TOKEN", "secret_id": 7, "literal_value": None}]
    assert fake.askpass_helper is True


def test_old_wire_payload_reaches_engine_without_env(started):
    """Compat direction 2: an OLD server's payload (no env/askpass keys)
    reaches execute() as env_vars=None / askpass_helper=False."""
    listener, pk, fake, _sessions = started
    body = json.dumps({"session_id": "s-old", "command": "echo hi", "secrets": []}).encode()
    with _client(pk.ca_a, pk.c_ok) as client:
        resp = client.post(_url(listener), content=body, headers={"Content-Type": "application/json"})
    assert resp.status_code == 200
    assert fake.env_vars is None
    assert fake.askpass_helper is False
