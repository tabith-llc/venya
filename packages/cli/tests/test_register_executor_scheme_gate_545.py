# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#545 pins — ``register_executor``'s raw dial carries the scheme gate INSIDE the transport.

Every ordinary API request is gated at one chokepoint, the ``_http`` property
builder (#521 site 1). ``register_executor`` is the exception: it composes a URL
and dials it on a RAW ``httpx2.Client``, so until this leg the only guard on
that path lived upstream in ``commands.py``. That is one door owning the rule
for every caller except one — and the ``or self.config.server_url`` fallback
means a STORED plaintext value (config files written before #509/#497 landed)
reaches the socket the moment a new caller forgets to guard first.

Truth table, both halves:
  * negatives refuse with the SHARED ``_https_refusal`` wording and prove the
    transport is never even constructed (class-level call count, not merely an
    exception type — a raise that happened after the socket opened is not a pass);
  * the ``VENYA_TLS_VERIFY=false`` knob does not re-open plaintext on this path
    either (the scheme check precedes the knob read);
  * positives keep the #508-hardened flow byte-for-byte: https register, stored
    https fallback, and the ``--ca-bundle`` verify precedence all unchanged.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from venya_cli.api_client import APIClient, APIClientError
from venya_cli.commands import _https_refusal

TICKET = "api-client-register-executor-raw-dial-missing-scheme-gate"
SITE = "the executor registration POST"
DETAIL = "this POST carries the CSR and the enrollment token"
REGISTER_PATH = "/api/v1/executors/register"
PAYLOAD = {
    "executor_id": "test-1",
    "cert_pem": "-----BEGIN CERTIFICATE-----",
    "ca_cert_pem": "-----BEGIN CERTIFICATE-----",
    "serial_number": "01:23",
    "not_after": "2026-09-01T00:00:00+00:00",
}


def _client_with_config(server_url: str | None) -> APIClient:
    """A real APIClient whose config.json carries ``server_url`` (or is empty).

    Same house shape as the #508 suite. The scheme gate lives on the raw dial,
    so the bearer ``_http`` seam is irrelevant here; injecting a stub keeps any
    accidental ride on that property loud instead of silent.
    """
    config_file = Path(tempfile.mktemp(suffix=".json"))
    config_file.write_text(json.dumps({"server_url": server_url} if server_url else {}))
    client = APIClient(config_file=config_file)
    client._http = MagicMock()
    return client


def _mock_client_cls(payload: dict):
    """A patched ``api_client.httpx2.Client`` class that answers with ``payload``.

    Returns (MockClass, built_urls) — ``built_urls`` records every
    ``httpx2.Client(...)`` construction (what a transport existing looks like),
    and the inner ``post`` records the urls it was handed. ``built_urls == []``
    is the no-socket evidence AC2 asks for: stronger than "no POST", because
    on this path refusal must land before ANY client exists.
    """
    resp = MagicMock()
    resp.status_code = 201
    resp.content = json.dumps(payload).encode()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None

    built: list[dict] = []
    posted: list[str] = []
    inner = MagicMock()
    inner.__enter__.return_value = inner
    inner.__exit__.return_value = False

    def _post(url, *a, **k):
        posted.append(str(url))
        return resp

    inner.post = MagicMock(side_effect=_post)

    def _ctor(*args, **kwargs):
        built.append(dict(kwargs))
        return inner

    cls = MagicMock(side_effect=_ctor)
    cls.posted = posted
    cls.inner = inner
    return cls, built


# ---------------------------------------------------------------------------
# AC2 — the negatives: refuse, and no transport ever exists
# ---------------------------------------------------------------------------


class TestRawDialRefusesPlaintext:
    def test_http_arg_refuses_and_no_client_is_ever_constructed(self):
        """RED at base: the composed URL went straight to a raw client. Now the
        gate lives between the composition and the socket."""
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="must be https://") as excinfo:
                client.register_executor("test-1", "CSR_PEM", server_url="http://core-1")
            assert cls.posted == [], "a POST left for a plaintext destination"
        assert built == [], f"transport was constructed before refusing: {built}"
        assert f"got 'http://core-1{REGISTER_PATH}'" in str(excinfo.value)

    def test_stored_plaintext_fallback_refuses(self):
        """The ``or self.config.server_url`` half: NO server_url argument, a
        plaintext value STORED in config.json (the pre-#509/#497 shape) refuses
        identically — the fallback is no longer a way past the guard."""
        client = _client_with_config("http://core.example.com")
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError) as excinfo:
                client.register_executor("test-1", "CSR_PEM")
            assert cls.posted == []
        assert built == []
        assert "must be https://" in str(excinfo.value)

    @pytest.mark.parametrize("scheme", ["HTTP://", "HttPs://", "ftp://", "ws://"])
    def test_only_lowercase_https_composes_past_the_gate(self, scheme: str):
        """Case-sensitivity matches the ``_http`` gate: the check is against the
        lowercase ``https://`` literal, so a mixed-case ``HTTP://`` (which httpx2
        case-folds into a real plaintext dial) and every other scheme refuse."""
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="must be https://"):
                client.register_executor("test-1", "CSR_PEM", server_url=f"{scheme}core-1")
            assert cls.posted == []
        assert built == []

    def test_schemeless_host_refuses_at_the_transport(self):
        """A bare host reaches this door only when the CALLER normalized it;
        the transport itself never guesses. Composition yields
        ``venya-core/api/v1/...`` — no scheme, refused fail-closed."""
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="must be https://"):
                client.register_executor("test-1", "CSR_PEM", server_url="venya-core-1")
            assert cls.posted == []
        assert built == []

    def test_mock_is_not_a_url(self):
        """isinstance habit (same shape as the ``_http`` gate and the #508
        caller guard): a MagicMock answers every attribute, and its f-string
        repr composes to something that is not an https URL — refuse."""
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="must be https://"):
                client.register_executor("test-1", "CSR_PEM", server_url=MagicMock())
            assert cls.posted == []
        assert built == []

    def test_refusal_text_is_the_shared_helper_string_not_a_variant(self):
        """AC1 "same helper, one wording": the raised message EQUALS the string
        ``_https_refusal`` builds for this site — no hand-copied variant."""
        client = _client_with_config(None)
        cls, _built = _mock_client_cls(PAYLOAD)
        expected = _https_refusal(f"http://core-1{REGISTER_PATH}", site=SITE, ticket=TICKET, detail=DETAIL)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError) as excinfo:
                client.register_executor("test-1", "CSR_PEM", server_url="http://core-1")

        assert str(excinfo.value) == expected
        assert TICKET in str(excinfo.value)
        assert "Plaintext http is not supported" in str(excinfo.value)


class TestKnobDoesNotReopenPlaintext:
    def test_tls_verify_false_still_refuses_http(self, monkeypatch):
        """The scheme check runs BEFORE the knob is read: turning verification
        off means "distrust this certificate over https", never "no TLS"
        (#506 ruling) — it must not become a way back to http on this path."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError, match="must be https://"):
                client.register_executor("test-1", "CSR_PEM", server_url="http://core-1")
            assert cls.posted == []
        assert built == []

    def test_tls_verify_false_still_allows_https(self, monkeypatch):
        """Paired: the knob keeps its ruled meaning on the https branch —
        verify=False, same fixed 30s, POST goes out."""
        monkeypatch.setenv("VENYA_TLS_VERIFY", "false")
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            result = client.register_executor("test-1", "CSR_PEM", server_url="https://core-1")

        assert result["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert built == [{"verify": False, "timeout": 30}]
        assert cls.posted == [f"https://core-1{REGISTER_PATH}"]


# ---------------------------------------------------------------------------
# AC3 — the positives: the #508-hardened flow is unchanged
# ---------------------------------------------------------------------------


class TestRegisterStillWorks:
    def test_https_arg_still_registers(self, monkeypatch):
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            result = client.register_executor("test-1", "CSR_PEM", server_url="https://core-1")

        assert result == PAYLOAD
        assert built == [{"verify": True, "timeout": 30}]
        assert cls.posted == [f"https://core-1{REGISTER_PATH}"]

    def test_stored_https_fallback_still_registers(self, monkeypatch):
        """The same fallback the negative half exercises: with a STORED https
        value and no argument, registration rides through untouched."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client_with_config("https://core.example.com")
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            result = client.register_executor("test-1", "CSR_PEM")

        assert result == PAYLOAD
        assert built == [{"verify": True, "timeout": 30}]
        assert cls.posted == [f"https://core.example.com{REGISTER_PATH}"]

    def test_ca_bundle_verify_precedence_unchanged(self, monkeypatch):
        """#508 ordering pin, positive side: tls_verify AND ca_bundle ⇒ the
        bundle path rides as verify=, exactly as before this leg."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            client.register_executor("test-1", "CSR_PEM", server_url="https://core-1", ca_bundle="/tmp/ca-545.crt")

        assert built == [{"verify": "/tmp/ca-545.crt", "timeout": 30}]

    def test_enrollment_token_still_travels_over_https(self, monkeypatch):
        """The secret that makes this POST sensitive is still delivered on the
        gated path: payload carries the token, only after the scheme passed."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client_with_config(None)
        cls, _built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            client.register_executor(
                "test-1", "CSR_PEM", enrollment_token="enrl_exec_abc123", server_url="https://core-1"
            )

        inner_post = cls.inner
        call_json = inner_post.post.call_args.kwargs["json"]
        assert call_json["enrollment_token"] == "enrl_exec_abc123"

    def test_bad_executor_id_still_refuses_locally_before_the_gate(self, monkeypatch):
        """Ordering boundary: the identity check precedes URL composition (it
        rewrites executor_id into the payload); a bad id must fail with its own
        message, never with the scheme refusal."""
        monkeypatch.delenv("VENYA_TLS_VERIFY", raising=False)
        client = _client_with_config(None)
        cls, built = _mock_client_cls(PAYLOAD)

        with patch("venya_cli.api_client.httpx2.Client", cls):
            with pytest.raises(APIClientError) as excinfo:
                client.register_executor("not/valid!", "CSR_PEM", server_url="https://core-1")

        assert "must be https://" not in str(excinfo.value)
        assert built == []


# ---------------------------------------------------------------------------
# Static pins — the gate lives in the transport, not only at the caller
# ---------------------------------------------------------------------------


class TestGateLivesInsideTheTransport:
    def test_register_executor_body_carries_the_check(self):
        import inspect

        from venya_cli import api_client as mod

        body = inspect.getsource(mod.APIClient.register_executor)
        assert 'url.startswith("https://")' in body
        assert "_https_refusal" in body
        assert TICKET in body

    def test_deferred_import_shape_matches_the_http_gate(self):
        """The commands.py back-import must stay deferred — a module-level
        import here would be a cycle (commands imports api_client at its top)."""
        from venya_cli import api_client as mod

        assert "_https_refusal" not in dir(mod)
