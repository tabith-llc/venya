# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Trust-anchor tests for the CLI bearer dial (ticket cli-bearer-dial-falls-back-to-host-store #530).

The defect: ``_build_ssl_context`` ended in ``else: ctx.load_default_certs()``, so a
workstation with a server URL but no Venya anchor (missing or stale config-dir
``ca.crt`` — the documented state after any core reinstall, which is why
``venya setup <core>`` exists) dialed the HOST system store. A token-bearing
request aimed at a name-confused host could then be satisfied by any
publicly-issued certificate for that name. #501 closed the same trust-set defect
on the server->executor relay; this is the workstation half.

Truth table (paired negative is the standing rule):
  * no anchor -> REFUSE, and prove it by PROHIBITION SHAPE: ``load_default_certs``
    is rigged to explode and must never be reached. An anchor-COUNT assertion
    would be a lying cell on this build — ``ssl.create_default_context()``
    reports ``get_ca_certs() == 0`` and ``cert_store_stats() == 0`` while the
    store is live (lead-verified hazard, do not re-derive).
  * anchor configured -> the ONLY CA in the context is the Venya root, with
    CERT_REQUIRED + check_hostname still on.
  * ``SSL_CERT_FILE`` still wins (the explicit operator opt-in for a
    public-CA-served core: they NAME the bundle, the code never guesses it).
  * the refusal lands BEFORE any HTTP client is constructed, and constructing an
    anchor-less client is still allowed — ``venya setup`` is the repair and
    ``run_command()`` builds the client before it dispatches.
"""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from venya_cli.api_client import APIClient, APIClientError, _build_ssl_context


def _make_ca(tmp_path: Path, name: str) -> Path:
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
    path = tmp_path / f"{name}.crt"
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
        raise AssertionError("load_default_certs() was reached — the dial fell back to the host store (#530)")

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", _boom)


class TestNoAnchorRefuses:
    """AC1 — no anchor resolvable: refuse, and never touch the host store."""

    def test_builder_refuses_when_no_anchor(self, monkeypatch: pytest.MonkeyPatch):
        _no_host_store(monkeypatch)
        with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
            _build_ssl_context(cafile=None, certfile=None, keyfile=None)

    def test_builder_refusal_names_the_repair(self, monkeypatch: pytest.MonkeyPatch):
        """The operator must be told how to fix it, not just that it failed."""
        _no_host_store(monkeypatch)
        with pytest.raises(APIClientError) as excinfo:
            _build_ssl_context(cafile=None, certfile=None, keyfile=None)
        text = str(excinfo.value)
        assert "venya setup <core>" in text
        assert "SSL_CERT_FILE" in text
        assert "system trust store" in text  # says what it will NOT do

    def test_dial_refuses_before_any_http_client_exists(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """AC1's exact shape: with no anchor the bearer path does NOT dial.

        No anchor + a normal server URL -> touching the transport raises, and
        httpx2.Client was never constructed, so no token can leave the box.
        """
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        with patch("venya_cli.api_client.httpx2.Client") as mock_client_cls:
            client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                _ = client._http
            mock_client_cls.assert_not_called()
            # And a real request cannot sneak past the seam either.
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                client.get("/api/v1/secrets")
            mock_client_cls.assert_not_called()

    def test_construction_without_anchor_is_allowed_for_the_repair(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """`venya setup` is the repair the refusal names.

        run_command() builds an APIClient for EVERY command before dispatch
        (commands.py, the `client = APIClient(server_url=server_url)` line), so a
        construction-time raise would make the repair unreachable on exactly the
        anchor-less host that needs it. Construction succeeds; the DIAL refuses.
        """
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        with patch("venya_cli.api_client.httpx2.Client"):
            client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
            assert client.config.server_url == "https://venya-core-1"
            client.close()  # nothing was built -> nothing to close, no raise

    def test_searched_paths_are_named_in_the_refusal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """#439 precedent: name the missing file, not just 'TLS failed'."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        cfg = tmp_path / "nested" / "config.json"
        with patch("venya_cli.api_client.httpx2.Client"):
            client = APIClient(server_url="https://venya-core-1", config_file=cfg)
            with pytest.raises(APIClientError) as excinfo:
                _ = client._http
        assert str((tmp_path / "nested" / "ca.crt").resolve()) in str(excinfo.value) or "ca.crt" in str(excinfo.value)
        client.close()


class TestAnchorConfiguredAccepts:
    """AC2 paired positive — an anchor is honored, and it is the ONLY one."""

    def test_anchored_context_carries_only_the_venya_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        _no_host_store(monkeypatch)  # still un-reached: the anchor path never loads it
        ca = _make_ca(tmp_path, "venya-root-530")
        ctx = _build_ssl_context(cafile=str(ca), certfile=None, keyfile=None)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        assert _anchor_cns(ctx) == {"venya-root-530"}

    def test_dial_with_setup_ca_builds_the_transport(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Accept half: config-dir ca.crt present -> the bearer path builds."""
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        ca = _make_ca(tmp_path, "venya-root-accept")
        (tmp_path / "ca.crt").write_bytes(ca.read_bytes())
        with patch("venya_cli.api_client.httpx2.Client") as mock_client_cls:
            client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
            _ = client._http
            mock_client_cls.assert_called_once()
            assert isinstance(mock_client_cls.call_args.kwargs["verify"], ssl.SSLContext)
        client.close()

    def test_ssl_cert_file_is_the_explicit_public_ca_opt_in(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """A public-CA-served core stays reachable — by the operator NAMING a bundle.

        This is the AC3 fork resolution recorded as a cell: the fork is
        (a) refuse always with SSL_CERT_FILE as the explicit opt-in, NOT
        (b) a new auto-trust-the-host-store mode. The env var is honored
        unchanged.
        """
        _no_host_store(monkeypatch)
        bundle = _make_ca(tmp_path, "public-bundle")
        monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
        ctx = _build_ssl_context(cafile=str(bundle), certfile=None, keyfile=None)
        assert _anchor_cns(ctx) == {"public-bundle"}

    def test_tls_verify_knob_not_consulted_on_the_bearer_dial(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """AC3: VENYA_TLS_VERIFY=false is NOT an anchor override.

        It means "distrust this certificate over https" on the register/heartbeat
        paths; on the bearer path it must neither re-open plaintext nor supply a
        missing anchor. With the knob set and no anchor, the dial still refuses.
        """
        _no_host_store(monkeypatch)
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        with patch("venya_cli.api_client.httpx2.Client") as mock_client_cls:
            client = APIClient(server_url="https://venya-core-1", config_file=tmp_path / "config.json")
            with pytest.raises(APIClientError, match="no Venya TLS trust anchor"):
                _ = client._http
            mock_client_cls.assert_not_called()
        client.close()

    def test_corrupt_anchor_still_lands_the_439_message(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Regression guard: the #530 restructure did not swallow ticket 439's wrap.

        Present-but-not-a-certificate must read differently from absent.
        """
        _no_host_store(monkeypatch)
        bad = tmp_path / "bad-ca.crt"
        bad.write_text("not a certificate\n")
        with pytest.raises(APIClientError, match="could not be loaded as a certificate"):
            _build_ssl_context(cafile=str(bad), certfile=None, keyfile=None)


class TestHostStoreSymbolGone:
    """Static pin: the fallback branch is removed, not merely bypassed in tests."""

    def test_api_client_module_never_calls_load_default_certs(self):
        """No CALL SITE left in the module (the word may appear in prose).

        Matches the invoked form only, so the docstring that explains what was
        removed does not defeat the pin.
        """
        import re

        import venya_cli.api_client as mod

        src = Path(mod.__file__).read_text()
        assert not re.search(r"\.load_default_certs\(", src), "a load_default_certs() call site survived (#530)"

    def test_register_executor_host_store_shape_pinned_for_the_sweep(self):
        """AC4 sweep fact, pinned statically (no socket is dialed by this cell).

        ``register_executor()`` builds its OWN httpx2.Client and, when no
        ``--ca-bundle`` was handed it, passes the bare bool ``verify=True`` —
        which is httpx asking OpenSSL for the HOST store. Same class as #530, on
        the registration POST. AC4 says sweep and report, do not silently fix, so
        this cell pins today's shape; a change becomes visible instead of quiet.
        """
        import inspect

        import venya_cli.api_client as mod

        body = inspect.getsource(mod.APIClient.register_executor)
        assert "verify_param = True" in body
        assert "verify=verify_param" in body
