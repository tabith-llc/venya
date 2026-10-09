# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Trust-anchor tests for the executor-registration dial (ticket #536).

The defect: ``APIClient.register_executor()`` builds its OWN ``httpx2.Client``
(not the gated ``_http`` seam), and its trust choice had three branches —

    if tls_verify and ca_bundle:  verify_param = str(ca_bundle)   # anchored
    elif tls_verify:              verify_param = True             # HOST STORE
    else:                         verify_param = tls_verify

``verify=True`` is httpx asking OpenSSL for the WORKSTATION system trust store,
so the POST that carries the CSR *and* the enrollment token — the call that hands
a new executor its identity — was verified against the host store whenever no
bundle was handed to it. A publicly-issued certificate for a name-confused core
would have passed silently. That is the same trust-set defect #501 closed on the
server relay, #530 closed on the bearer dial and #533 closed on the FIDO2
ceremony dial; this file closes it on the last remaining CLI dial.

The shape is inherited, not re-litigated (owner batch 2026-10-09: "PINNED-CA-ONLY
ABSOLUTE, NO EXCEPTIONS"): the anchor-or-refuse path is the module's own shared
helpers — ``_resolve_tls_anchor``, ``_anchor_refusal_text`` and
``_build_ssl_context`` — so this dial gets the ONE wording with an honest
transport noun, not a fourth variant.

Truth table (AC5 — every branch of ``verify_param`` gets a cell):
  * negative: verification on, no anchor resolvable -> REFUSE, and the proof is
    PROHIBITION SHAPE: ``httpx2.Client`` is never constructed, and
    ``ssl.SSLContext.load_default_certs`` is rigged to explode and is never
    reached. An anchor-COUNT assertion would be a lying cell on this build
    (``create_default_context()`` reports ``get_ca_certs() == 0`` while the host
    store is live — the #533 lead-verified hazard, do not re-derive).
  * positive: an anchor resolves -> the dial receives an ``ssl.SSLContext``
    carrying ONLY that file (never a bare ``True``), and a caller-supplied
    ``ca_bundle`` keeps the exact behavior it had before this ticket.
  * the ``VENYA_TLS_VERIFY=false`` knob is NOT an anchor override and stays the
    operator's explicit choice, warning intact (#530 ruling, AC4).
  * gate order: with BOTH problems present (plaintext URL and no anchor), the
    https scheme gate (#521/#545) still fires first.
"""

from __future__ import annotations

import ast
import datetime
import logging
import ssl
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient, APIClientError, _anchor_refusal_text

TICKET_ID = "cli-register-executor-dial-falls-back-to-host-store"


def _make_ca(tmp_path: Path, name: str, filename: str | None = None) -> Path:
    """Self-signed CA-shaped PEM — these cells exercise anchor loading, not handshakes."""
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    path = tmp_path / (filename or f"{name}.crt")
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _anchor_cns(ctx: ssl.SSLContext) -> set[str]:
    """Common names of the anchors actually loaded into ctx."""
    names: set[str] = set()
    for cert in ctx.get_ca_certs():
        for rdn in cert["subject"]:
            for attr, value in rdn:
                if attr == "commonName":
                    names.add(value)
    return names


def _no_host_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prohibition shape: make ANY host-store load explode."""

    def _boom(*_a, **_k):
        raise AssertionError("load_default_certs() was reached — the registration dial fell back to the host store")

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", _boom)


def _register_response() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 201
    resp.content = b'{"executor_id": "test-1"}'
    resp.json.return_value = {
        "executor_id": "test-1",
        "cert_pem": "-----BEGIN CERTIFICATE-----",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----",
        "serial_number": "01:23",
        "not_after": "2026-09-01T00:00:00+00:00",
    }
    resp.raise_for_status.return_value = None
    return resp


def _mock_client_cls() -> tuple[MagicMock, list[dict], list[str]]:
    """A patched ``api_client.httpx2.Client`` that RECORDS every construction.

    Returns ``(mock_cls, built_kwargs, posted_urls)``. ``built_kwargs == []`` is
    the no-socket evidence AC1 asks for on this path: the refusal must land
    before ANY client exists, which is stronger than "no POST".
    """
    built: list[dict] = []
    posted: list[str] = []
    inner = MagicMock()
    inner.__enter__.return_value = inner
    inner.__exit__.return_value = False
    resp = _register_response()

    def _post(url, *a, **k):
        posted.append(str(url))
        return resp

    inner.post = MagicMock(side_effect=_post)

    def _ctor(*args, **kwargs):
        built.append(dict(kwargs))
        return inner

    cls = MagicMock(side_effect=_ctor)
    return cls, built, posted


def _client(tmp_path: Path, server_url: str = "https://core.example.com") -> APIClient:
    """A real APIClient with a temp config file (config-dir CA at tmp_path/ca.crt)."""
    config_file = tmp_path / "config.json"
    config_file.write_text(f'{{"server_url": "{server_url}"}}')
    client = APIClient(config_file=config_file)
    # Any accidental ride on the bearer seam must be loud, never silent.
    client._http = MagicMock()
    return client


# ---------------------------------------------------------------------------
# Negative half — verification on, no anchor: refuse and dial NOTHING
# ---------------------------------------------------------------------------


class TestNoAnchorRefuses:
    def test_absent_anchor_refuses_and_constructs_no_transport(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """RED at base: with no bundle handed and no config-dir CA this dial passed
        ``verify=True`` — the host system store — on the POST carrying the CSR and
        the enrollment token."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client(tmp_path)  # tmp_path/ca.crt deliberately NOT created
        cls, built, posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                client.register_executor("test-1", "CSR_PEM", enrollment_token="enrl_exec_abc123")
        # The proof: no transport was ever constructed, so nothing was sent.
        assert built == []
        assert posted == []
        cls.assert_not_called()

    def test_refusal_is_the_shared_wording_with_the_registration_transport(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """AC6: one wording, not a fourth. The text equals what the shared builder
        produces for this transport noun, byte for byte."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client(tmp_path)
        cls, _built, _posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError) as excinfo:
                client.register_executor("test-1", "CSR_PEM")
        anchor, searched = client._resolve_tls_anchor()
        assert anchor is None
        assert str(excinfo.value) == _anchor_refusal_text(searched, transport="registration POST")
        assert "registration POST" in str(excinfo.value)
        # The bearer dial's wording is the same text with its own noun — the
        # builder is shared, only the transport name differs.
        bearer = _anchor_refusal_text(searched)
        assert str(excinfo.value).replace("registration POST", "token-bearing call") == bearer

    def test_refusal_names_what_was_searched_and_the_repair(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """The sentence must be actionable: the path searched and `venya setup`."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client(tmp_path)
        cls, _built, _posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError) as excinfo:
                client.register_executor("test-1", "CSR_PEM")
        msg = str(excinfo.value)
        assert str(client.config.ca_path) in msg
        assert "venya setup" in msg
        assert "SSL_CERT_FILE" in msg

    def test_env_opt_in_pointing_at_nothing_still_refuses(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """A named-but-missing bundle is not a silent host-store dial; the #439
        corrupt/unreadable wrap answers, and no transport is constructed."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        missing = tmp_path / "nope.crt"
        monkeypatch.setenv("SSL_CERT_FILE", str(missing))
        client = _client(tmp_path)
        cls, built, _posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="could not be loaded as a certificate"):
                client.register_executor("test-1", "CSR_PEM")
        assert built == []


# ---------------------------------------------------------------------------
# Positive half — an anchor resolves: the dial proceeds, anchored
# ---------------------------------------------------------------------------


class TestAnchoredRegister:
    def test_setup_installed_config_ca_reaches_the_dial_as_a_context(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """No ``ca_bundle`` argument, but the `venya setup` CA exists: the call
        proceeds and the transport gets a context carrying ONLY that anchor."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        ca = _make_ca(tmp_path, "venya-register-root-536", filename="ca.crt")
        assert ca == tmp_path / "ca.crt"
        client = _client(tmp_path)
        cls, built, posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            result = client.register_executor("test-1", "CSR_PEM")
        assert result["executor_id"] == "test-1"
        assert len(built) == 1
        verify = built[0]["verify"]
        assert isinstance(verify, ssl.SSLContext)
        assert verify.verify_mode == ssl.CERT_REQUIRED
        assert verify.check_hostname is True
        assert _anchor_cns(verify) == {"venya-register-root-536"}
        assert posted == ["https://core.example.com/api/v1/executors/register"]

    def test_ssl_cert_file_opt_in_carries_the_dial(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """A public-CA-served core stays reachable — by the operator NAMING a
        bundle, which then becomes the anchor (never a hint that the host store
        may be used)."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        bundle = _make_ca(tmp_path, "public-bundle-536")
        monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
        client = _client(tmp_path)  # no config-dir ca.crt: the opt-in alone carries it
        cls, built, _posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            client.register_executor("test-1", "CSR_PEM")
        verify = built[0]["verify"]
        assert isinstance(verify, ssl.SSLContext)
        assert _anchor_cns(verify) == {"public-bundle-536"}

    def test_explicit_ca_bundle_argument_behavior_unchanged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """AC5 positive: the branch that was already anchored is untouched — a
        caller-supplied bundle is still handed over as that file, and no anchor
        resolution happens ahead of it."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client(tmp_path)
        bundle = _make_ca(tmp_path, "caller-bundle-536")
        cls, built, posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            client.register_executor("test-1", "CSR_PEM", ca_bundle=str(bundle))
        assert len(built) == 1
        assert built[0]["verify"] == str(bundle)
        assert posted == ["https://core.example.com/api/v1/executors/register"]


# ---------------------------------------------------------------------------
# The operator knobs keep their exact meaning (AC4 — do not "improve" these)
# ---------------------------------------------------------------------------


class TestOperatorKnobsUnchanged:
    def test_tls_verify_false_still_honored_and_still_warned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog
    ):
        """The explicit insecure choice is not an anchor override and was not made
        stricter here: ``verify=False`` reaches the transport and the warning logs."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        client = _client(tmp_path)  # no anchor on disk — the choice is honored anyway
        cls, built, posted = _mock_client_cls()
        with caplog.at_level(logging.WARNING, logger="venya_cli.api_client"):
            with patch("venya_cli.api_client.httpx2.Client", cls):
                client.register_executor("test-1", "CSR_PEM")
        assert built[0]["verify"] is False
        assert posted  # the dial went through
        assert any("VENYA_TLS_VERIFY=false" in rec.getMessage() for rec in caplog.records)

    def test_invalid_env_value_still_raises_the_named_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """A typo in the knob is a loud failure, unchanged by this ticket."""
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("VENYA_TLS_VERIFY", "maybe")
        client = _client(tmp_path)
        cls, built, _posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="Invalid VENYA_TLS_VERIFY value"):
                client.register_executor("test-1", "CSR_PEM")
        assert built == []

    def test_true_env_value_is_the_anchored_path_not_a_host_store_dial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """``VENYA_TLS_VERIFY=true`` means "verify", which since #536 means "anchor
        or refuse" — it must not resurrect the bare ``verify=True``."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("VENYA_TLS_VERIFY", "true")
        client = _client(tmp_path)  # no anchor present
        cls, built, _posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                client.register_executor("test-1", "CSR_PEM")
        assert built == []


# ---------------------------------------------------------------------------
# Gate order — the scheme check still fires FIRST (AC5 pairing)
# ---------------------------------------------------------------------------


class TestSchemeGateStillFirst:
    def test_plaintext_url_and_no_anchor_gives_the_scheme_refusal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Both problems at once: the #521/#545 https gate answers, not the anchor
        refusal — and still no transport exists."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client(tmp_path)
        cls, built, posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError) as excinfo:
                client.register_executor("test-1", "CSR_PEM", server_url="http://core-1")
        msg = str(excinfo.value)
        assert "server URL must be https://" in msg
        assert "no Venya TLS trust anchor" not in msg
        assert built == []
        assert posted == []

    def test_plaintext_url_with_a_good_anchor_still_refuses_on_scheme(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The order does not depend on the anchor state: an anchored host with a
        plaintext URL is refused by the scheme gate alone."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        bundle = _make_ca(tmp_path, "scheme-order-536")
        monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
        client = _client(tmp_path)
        cls, built, _posted = _mock_client_cls()
        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="server URL must be https://"):
                client.register_executor("test-1", "CSR_PEM", server_url="http://core-1")
        assert built == []


# ---------------------------------------------------------------------------
# Static pins — the fallback is removed, not merely bypassed in tests (AC1)
# ---------------------------------------------------------------------------


class TestStaticPins:
    def test_no_verify_true_assignment_reachable_in_register_executor(self):
        """AC1 static half, AST form (the mechanism this repo uses to pin static
        facts — see the #530/#533 sweep pins).

        AST rather than text on purpose: the explanatory comment inside this
        branch quotes the old ``verify=True`` wording, so a substring check
        would be defeated by its own prose. Here the question is whether any
        statement assigns a literal ``True`` to ``verify_param``.
        """
        import inspect

        from venya_cli import api_client as mod

        tree = ast.parse(textwrap.dedent(inspect.getsource(mod.APIClient.register_executor)))
        literal_true_assigns = [
            node.targets[0].id
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        ]
        assert "verify_param" not in literal_true_assigns, "a bare verify_param = True host-store path survived (#536)"
        # Every construction still goes through the single local knob.
        src = inspect.getsource(mod.APIClient.register_executor)
        assert "verify=verify_param" in src

    def test_register_executor_routes_through_the_shared_helpers(self):
        """AC6: shared builder, not a fourth way — the dial calls the module's own
        resolver, refusal text and TLS-context builder."""
        import inspect

        from venya_cli import api_client as mod

        src = inspect.getsource(mod.APIClient.register_executor)
        assert "_resolve_tls_anchor()" in src
        assert "_anchor_refusal_text(" in src
        assert "_build_ssl_context(" in src

    def test_module_has_no_load_default_certs_call_site(self):
        """The prohibition symbol stays out of the module (the #530/#533 pin,
        re-run here because this dial is the one that changed)."""
        import re

        from venya_cli import api_client as mod

        src = Path(mod.__file__).read_text()
        assert not re.search(r"\.load_default_certs\(", src), "a load_default_certs() call site survived (#536)"

    def test_docstring_names_this_dial_and_matches_the_code(self):
        """AC5 paired doc: the module used to claim only ``_request()`` and
        ``_post_raw()`` never fall back, which left this dial answering the trust
        question differently. The text now says what the code does."""
        import inspect

        from venya_cli import api_client as mod

        doc = inspect.getsource(mod.APIClient.register_executor)
        assert "never fall back" in doc
        assert "#536" in doc
        assert "register_executor()" in doc
        assert "host system trust store" in doc
        # The paired negative: the old sentence claimed only the two shared seams
        # never fall back, which left this dial answering differently. The text
        # now speaks for this call, and the code matches it.
        assert "neither does this dial" in doc
