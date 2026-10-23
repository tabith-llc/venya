# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#633 — a name that does not resolve is not reported as a connection failure.

The workstation CLI dialed a core name with no `hosts` entry and printed
``cannot fetch CA certificate from ...: [Errno 11001] getaddrinfo failed``, which
aims the operator at routing and DNS instead of the one local line that is
missing. The fault and the fix are both local; the behaviour (refuse, write
nothing, return 1, say re-run) was already right and is pinned here as unchanged.

The merge condition is the TRUTH TABLE, both halves:

POSITIVE  — a cause chain carrying ``socket.gaierror`` gets a sentence that names
            the host, says the name did not resolve on this workstation, points at
            the hosts file / name service, and never leads with fetch or
            connection wording.
NEGATIVE  — refused, timed out, handshake-failed, and a bare ConnectError keep
            their existing wording and say NOTHING about name resolution.
MECHANISM — classification is by exception CLASS on the cause chain, so an
            exception whose TEXT mentions the resolver with no gaierror under it
            stays a connection fault, and a gaierror with no recognizable text
            still becomes the name sentence. No errno number is hard-coded: the
            Windows and POSIX renderings are both exercised.

The strongest cell patches ``socket.getaddrinfo`` and lets httpx2 build its own
chain, so what is asserted is the real production shape (ConnectError ->
httpcore ConnectError -> socket.gaierror), not a hand-built impression of it.
"""

import socket
import ssl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from venya_cli import commands as commands_mod
from venya_cli.api_client import APIClient, APIClientError
from venya_cli.fido2_client import Fido2Auth, Fido2ClientError
from venya_cli.name_resolution import (
    dial_failure_text,
    find_name_resolution_cause,
    host_from_url,
    name_resolution_text,
)

HOST = "venya-core-3"
URL = f"https://{HOST}"


# --- chain builders -----------------------------------------------------------


def _gaierror_chain(errno: int = -2, text: str = "Name or service not known") -> httpx2.ConnectError:
    """A ConnectError whose cause chain ends in socket.gaierror (two links, as shipped).

    Built in the shape httpx2 raises it (verified against the real library in
    TestRealLibraryChain): ConnectError -> NetworkError -> socket.gaierror.
    """
    bottom = socket.gaierror(errno, text)
    middle = httpx2.NetworkError(f"[Errno {errno}] {text}")
    middle.__cause__ = bottom
    outer = httpx2.ConnectError(str(middle))
    outer.__cause__ = middle
    return outer


def _refused_chain(text: str = "Connection refused") -> httpx2.ConnectError:
    """A resolvable host with nothing answering: ConnectError over ConnectionRefusedError."""
    bottom = ConnectionRefusedError(111, text)
    outer = httpx2.ConnectError(text)
    outer.__cause__ = bottom
    return outer


def _handshake_chain() -> httpx2.ConnectError:
    """A dial that reached the core and failed TLS verification."""
    err = ssl.SSLCertVerificationError("certificate verify failed")
    outer = httpx2.ConnectError(str(err))
    outer.__cause__ = err
    return outer


def _connect_timeout_chain(text: str = "timed out") -> httpx2.ConnectTimeout:
    """A dial that resolved the name and then waited too long.

    This one matters at cmd_setup specifically: it catches the broad
    ``httpx2.HTTPError``, and ConnectTimeout is an HTTPError but NOT a
    ConnectError, so a timeout lands in the same handler the name fault does. The
    two must still read differently.
    """
    bottom = TimeoutError(text)
    outer = httpx2.ConnectTimeout(text)
    outer.__cause__ = bottom
    return outer


# --- the shared classifier ----------------------------------------------------


class TestClassifierMechanism:
    """AC4 — classification by cause CLASS, never by searching exception text."""

    def test_finds_gaierror_through_the_wrapping_layers(self):
        """Positive: the gaierror two levels down is still the cause, not the text."""
        chain = _gaierror_chain()
        assert isinstance(find_name_resolution_cause(chain), socket.gaierror)

    def test_refused_is_not_a_name_fault(self):
        """Negative half of AC4: a ConnectionRefusedError under a ConnectError is a
        real network fault and must not classify as name resolution."""
        assert find_name_resolution_cause(_refused_chain()) is None

    def test_handshake_is_not_a_name_fault(self):
        assert find_name_resolution_cause(_handshake_chain()) is None

    def test_bare_connect_error_is_not_a_name_fault(self):
        """The shape the pre-existing tests already raise (no cause at all)."""
        assert find_name_resolution_cause(httpx2.ConnectError("no route to host")) is None

    def test_text_naming_the_resolver_without_a_gaierror_is_still_a_connection_fault(self):
        """AC4 paired negative: the OLD mechanism (keyword search of error text) would
        call this a name fault. The class walk must not — nothing under it resolved
        or failed to resolve, so it keeps the connection wording."""
        decoy = httpx2.ConnectError("[Errno -2] Name or service not known")
        assert find_name_resolution_cause(decoy) is None
        assert name_resolution_text(decoy, url=URL) == ""
        assert dial_failure_text(decoy, url=URL, default="Connection failed: boom") == "Connection failed: boom"

    def test_gaierror_with_unfamiliar_text_is_still_the_name_fault(self):
        """AC4 other half: a gaierror whose rendering carries no keywords is still
        classified by its class. A text-matcher would miss this one."""
        odd = socket.gaierror(999_999, "")
        outer = httpx2.ConnectError("")
        outer.__cause__ = odd
        assert find_name_resolution_cause(outer) is odd
        assert HOST in name_resolution_text(outer, url=URL)

    def test_cyclic_cause_chain_terminates(self):
        """A __cause__ that points back at itself must not hang the CLI on an error path."""
        outer = httpx2.ConnectError("boom")
        inner = httpx2.NetworkError("boom")
        outer.__cause__ = inner
        inner.__cause__ = outer
        assert find_name_resolution_cause(outer) is None

    def test_no_errno_number_is_hard_coded(self):
        """AC4 — the shipped classifier reads no errno value. 11001 is Windows-only and
        both renderings may change upstream, so a pinned number is the defect returning."""
        src = (Path(commands_mod.__file__).parent / "name_resolution.py").read_text()
        assert "11001" not in src
        assert "EAI_" not in src


class TestHostExtraction:
    """The host must be named whatever shape the operator typed at the prompt."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https://venya-core-3", "venya-core-3"),
            (f"https://{HOST}/.well-known/venya-ca.crt", HOST),
            ("venya-core-1", "venya-core-1"),
            ("http://localhost:8000", "localhost"),
            ("https://[fd00::21]:8443/p", "fd00::21"),
            ("https://core.example/", "core.example"),
        ],
    )
    def test_shapes(self, value, expected):
        assert host_from_url(value) == expected

    @pytest.mark.parametrize("value", [None, "", "   ", "https:///", 42])
    def test_unusable_values_yield_no_host(self, value):
        assert host_from_url(value) is None

    def test_host_can_come_from_the_wrapped_request(self):
        """A caller that passes no URL still gets the name: httpx2 carries the request."""
        req = httpx2.Request("GET", f"{URL}/api/v1/ping")
        exc = httpx2.ConnectError("boom", request=req)
        exc.__cause__ = socket.gaierror(-2, "Name or service not known")
        assert HOST in name_resolution_text(exc)


class TestWordingContract:
    """AC1/AC2/AC3 at the text level, both halves of the table."""

    def test_name_fault_text(self):
        text = name_resolution_text(_gaierror_chain(), url=URL)
        assert HOST in text
        assert "did not resolve" in text
        assert "this workstation" in text
        assert "hosts file" in text
        assert "name service" in text
        # AC1(c): must not lead with fetch/connection wording
        assert not text.lower().startswith(("connection", "fetch", "cannot fetch"))
        assert "cannot fetch" not in text
        assert "connection failed" not in text.lower()

    def test_windows_rendering_gets_the_same_sentence(self):
        """The reported fault: Windows renders the same failure as errno 11001. The
        wording must not depend on the platform's text."""
        text = name_resolution_text(_gaierror_chain(11001, "getaddrinfo failed"), url=URL)
        assert HOST in text
        assert "did not resolve" in text

    @pytest.mark.parametrize(
        "exc",
        [
            _refused_chain(),
            _handshake_chain(),
            _connect_timeout_chain(),
            httpx2.ConnectError("Connection refused"),
            httpx2.ConnectError("[Errno 111] Connection refused"),
        ],
        ids=["refused-cause", "handshake-cause", "connect-timeout-cause", "bare-refused-text", "errno-refused-text"],
    )
    def test_non_name_faults_never_mention_name_resolution(self, exc):
        """AC2/AC3 — the distinction half. These faults say nothing about resolution,
        so the two classes are separable from the text alone."""
        text = dial_failure_text(exc, url=URL, default=f"Connection failed: {exc}")
        assert "resolve" not in text
        assert "hosts" not in text
        assert text == f"Connection failed: {exc}"


# --- the sites, as the operator sees them -------------------------------------


def _setup_args(corename: str = HOST) -> SimpleNamespace:
    return SimpleNamespace(corename=corename, ca_sha256=None)


class TestSetupCommand:
    """AC1 — cmd_setup, the workstation's first remote read, in both classes."""

    def test_unresolvable_names_the_host_and_the_local_fix(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", side_effect=_gaierror_chain()):
            rc = commands_mod.cmd_setup(client, _setup_args())
        err = capsys.readouterr().err
        assert rc == 1
        assert HOST in err
        assert "did not resolve" in err
        assert "hosts file" in err
        # AC1(c) — the fetch sentence is gone from this class entirely.
        assert "cannot fetch" not in err
        # retry line is accurate and stays (behaviour unchanged).
        assert "re-run" in err

    def test_refused_keeps_the_fetch_wording(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        """Paired negative on the SAME call site: the door is answered and the fault is
        remote, so the fetch sentence is the true statement and name wording must not
        appear."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", side_effect=_refused_chain()):
            rc = commands_mod.cmd_setup(client, _setup_args())
        err = capsys.readouterr().err
        assert rc == 1
        assert "cannot fetch CA certificate" in err
        assert "resolve" not in err
        assert "hosts" not in err

    def test_connect_timeout_keeps_the_fetch_wording(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        """The spec's named negative, and the sharpest one here: this handler catches
        the broad HTTPError, so a connect timeout reaches the SAME except block as the
        name fault. It must keep fetch wording and say nothing about resolution —
        otherwise the two classes are not separable from the text and AC2 fails."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", side_effect=_connect_timeout_chain()):
            rc = commands_mod.cmd_setup(client, _setup_args())
        err = capsys.readouterr().err
        assert rc == 1
        assert "cannot fetch CA certificate" in err
        assert "resolve" not in err
        assert "hosts" not in err

    def test_nothing_written_and_no_state_in_the_name_case(self, tmp_path: Path, capsys: pytest.CaptureFixture):
        """AC1 — rc 1 and write-nothing are unchanged by the wording fix."""
        client = APIClient(config_file=tmp_path / "config.json")
        with patch("venya_cli.commands.httpx2.get", side_effect=_gaierror_chain()):
            rc = commands_mod.cmd_setup(client, _setup_args())
        assert rc == 1
        assert not client.config.ca_path.exists()
        assert client.config.server_url == URL

    def test_two_fault_classes_produce_different_text(self):
        """AC2 stated directly: the two faults are told apart from the text alone —
        same host, same call site, different cause."""
        name_text = name_resolution_text(_gaierror_chain(), url=URL)
        refused_text = dial_failure_text(_refused_chain(), url=URL, default=f"Connection failed: {_refused_chain()}")
        assert name_text != refused_text
        assert "hosts file" in name_text
        assert "hosts file" not in refused_text
        assert "Connection failed" in refused_text


def _bearer_dial(client: APIClient) -> None:
    """One bearer-bearing dial through the client's cached httpx object."""
    client._request("GET", "/api/v1/secrets")


def _auth_dial(client: APIClient) -> None:
    """The auth-endpoint POST — same seam, different helper."""
    client._post_raw("/api/v1/auth", {})


# Both helpers dial through the same client object's .request() — that is the seam.
_DIAL_FUNCS = [_bearer_dial, _auth_dial]
_DIAL_IDS = ["bearer-dial", "auth-dial"]


class TestBearerAndAuthDials:
    """AC5 — api_client's three renderers, both halves at each.

    ``server_url`` is set on the client config first, because the default config
    value is a localhost URL and this class asserts which host gets named.
    """

    def _client(self, tmp_path: Path) -> APIClient:
        client = APIClient(config_file=tmp_path / "config.json")
        client.config.server_url = URL
        return client

    @pytest.mark.parametrize("dial", _DIAL_FUNCS, ids=_DIAL_IDS)
    def test_unresolvable_names_the_host(self, tmp_path: Path, dial):
        client = self._client(tmp_path)
        http = MagicMock()
        http.request.side_effect = _gaierror_chain()
        client._http = http
        with pytest.raises(APIClientError) as excinfo:
            dial(client)
        text = str(excinfo.value)
        assert HOST in text
        assert "did not resolve" in text
        assert "Connection failed" not in text
        client.close()

    @pytest.mark.parametrize("dial", _DIAL_FUNCS, ids=_DIAL_IDS)
    def test_refused_keeps_connection_wording(self, tmp_path: Path, dial):
        client = self._client(tmp_path)
        http = MagicMock()
        http.request.side_effect = _refused_chain()
        client._http = http
        with pytest.raises(APIClientError) as excinfo:
            dial(client)
        text = str(excinfo.value)
        assert "Connection failed" in text
        assert "resolve" not in text
        assert "hosts" not in text
        client.close()

    def test_register_dial_names_the_host(self, tmp_path: Path, venya_tls_anchor_536):
        """Site api_client register POST — the TLS keyword branch above it must not
        swallow a resolver fault (its text carries none of those keywords)."""
        client = self._client(tmp_path)
        try:
            with patch("venya_cli.api_client.httpx2.Client") as mock_client:
                mock_client.return_value.__enter__.return_value = mock_client.return_value
                mock_client.return_value.post.side_effect = _gaierror_chain()
                with pytest.raises(APIClientError) as excinfo:
                    client.register_executor("exec-1", "CSR_PEM")
            text = str(excinfo.value)
            assert "did not resolve" in text
            assert "TLS verification error" not in text
        finally:
            client.close()

    def test_register_dial_refused_keeps_its_class(self, tmp_path: Path, venya_tls_anchor_536):
        client = self._client(tmp_path)
        try:
            with patch("venya_cli.api_client.httpx2.Client") as mock_client:
                mock_client.return_value.__enter__.return_value = mock_client.return_value
                mock_client.return_value.post.side_effect = _refused_chain()
                with pytest.raises(APIClientError) as excinfo:
                    client.register_executor("exec-1", "CSR_PEM")
            text = str(excinfo.value)
            assert "Connection failed" in text
            assert "resolve" not in text
        finally:
            client.close()


class TestCeremonyDials:
    """AC5 — the two Fido2Auth renderers. Their existing TLS hint must survive for the
    faults it describes, and must not be appended to a resolver fault."""

    def _auth(self) -> Fido2Auth:
        auth = Fido2Auth(server_url=URL)
        auth._anchor = "ca-file-unused"
        return auth

    def test_unresolvable_names_the_host(self):
        auth = self._auth()
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client, patch.object(
            Fido2Auth, "_dial_verify", return_value=MagicMock()
        ):
            mock_client.return_value.__enter__.return_value = mock_client.return_value
            mock_client.return_value.get.side_effect = _gaierror_chain()
            with pytest.raises(Fido2ClientError) as excinfo:
                auth._get("/api/v1/ping")
        text = str(excinfo.value)
        assert HOST in text
        assert "did not resolve" in text
        assert "TLS trust check" not in text

    def test_post_unresolvable_names_the_host(self):
        auth = self._auth()
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client, patch.object(
            Fido2Auth, "_dial_verify", return_value=MagicMock()
        ):
            mock_client.return_value.__enter__.return_value = mock_client.return_value
            mock_client.return_value.post.side_effect = _gaierror_chain()
            with pytest.raises(Fido2ClientError) as excinfo:
                auth._post("/api/v1/ping", {})
        assert HOST in str(excinfo.value)

    def test_refused_keeps_connection_wording(self):
        auth = self._auth()
        with patch("venya_cli.fido2_client.httpx2.Client") as mock_client, patch.object(
            Fido2Auth, "_dial_verify", return_value=MagicMock()
        ):
            mock_client.return_value.__enter__.return_value = mock_client.return_value
            mock_client.return_value.get.side_effect = _refused_chain()
            with pytest.raises(Fido2ClientError) as excinfo:
                auth._get("/api/v1/ping")
        text = str(excinfo.value)
        assert "Connection failed" in text
        assert "resolve" not in text


class TestRevocationReadSite:
    """AC5 — commands._verify_register_auth's renderer, both halves.

    The TLS anchor is supplied by the house fixture because this site builds a real
    SSLContext before it dials; without one the cell would end at the #507 anchor
    refusal and never reach the handler under test.
    """

    def _client(self, tmp_path: Path) -> APIClient:
        client = APIClient(config_file=tmp_path / "config.json")
        client.config.server_url = URL
        return client

    def _dial(self, tmp_path: Path, anchor, exc):
        client = self._client(tmp_path)
        with patch("venya_cli.commands.httpx2.Client") as mock_client:
            mock_client.return_value.__enter__.return_value = mock_client.return_value
            mock_client.return_value.get.side_effect = exc
            with pytest.raises(APIClientError) as excinfo:
                commands_mod._verify_register_auth(client, URL, str(anchor))
        return str(excinfo.value)

    def test_unresolvable_names_the_host(self, tmp_path: Path, venya_tls_anchor_536):
        text = self._dial(tmp_path, venya_tls_anchor_536.path, _gaierror_chain())
        assert HOST in text
        assert "did not resolve" in text
        assert "Connection failed" not in text

    def test_refused_keeps_connection_wording(self, tmp_path: Path, venya_tls_anchor_536):
        text = self._dial(tmp_path, venya_tls_anchor_536.path, _refused_chain())
        assert "Connection failed" in text
        assert "resolve" not in text


class TestRealLibraryChain:
    """The mechanism claim, not a hand-built impression of it.

    ``socket.getaddrinfo`` is patched to fail the way a missing name fails, and httpx2
    builds the chain itself. No DNS is consulted and no socket is opened: this is the
    production exception shape reaching the production classifier.
    """

    def test_httpx2_generated_chain_is_the_name_fault(self, monkeypatch):
        def fake_getaddrinfo(*args, **kwargs):
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(httpx2.HTTPError) as excinfo:
            httpx2.get(f"{URL}/.well-known/venya-ca.crt", verify=False, timeout=5.0)
        chain = excinfo.value
        assert isinstance(chain, httpx2.ConnectError)
        assert isinstance(find_name_resolution_cause(chain), socket.gaierror)
        text = name_resolution_text(chain, url=f"{URL}/.well-known/venya-ca.crt")
        assert HOST in text and "did not resolve" in text

    def test_cmd_setup_on_the_real_chain(self, tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture):
        def fake_getaddrinfo(*args, **kwargs):
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        client = APIClient(config_file=tmp_path / "config.json")
        rc = commands_mod.cmd_setup(client, _setup_args())
        err = capsys.readouterr().err
        assert rc == 1
        assert HOST in err and "did not resolve" in err and "cannot fetch" not in err

    def test_a_real_refusal_on_a_reachable_address_keeps_the_fetch_wording(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ):
        """Positive control on the real chain cell above, and the honest form of the
        timeout/refusal negative: nothing is mocked here. The CLI dials loopback port 1,
        which no listener holds, so a real transport fault of the NON-resolver class
        reaches the real handler.

        The assertion is deliberately one-sided: whether the host refuses or stalls, the
        result must not be the name-resolution sentence. Both of those are connection
        faults and both must read as connection faults — which is exactly what AC2 asks
        for, and it cannot be satisfied by a fixture that only tries one of them.
        """
        client = APIClient(config_file=tmp_path / "config.json")
        rc = commands_mod.cmd_setup(client, _setup_args("127.0.0.1:1"))
        err = capsys.readouterr().err
        assert rc == 1
        assert "did not resolve" not in err
        assert "hosts file" not in err
        assert "setup incomplete" in err
