# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the FIDO2 client (fido2_client.py).

Verifies that Fido2Client is instantiated correctly with fido2 2.x API.
"""

from typing import ClassVar
from unittest.mock import MagicMock, patch

import httpx2
import pytest
from venya_cli.fido2_client import Fido2Auth, Fido2ClientError, Fido2NotFoundError


class TestFido2ClientInstantiation:
    """Test that Fido2Client is used correctly (fido2 2.x API)."""

    @patch("venya_cli.fido2_client.httpx2")
    @patch("venya_cli.fido2_client.list_devices")
    @patch("venya_cli.fido2_client.Fido2Client")
    @patch("venya_cli.fido2_client.DefaultClientDataCollector")
    def test_get_credential_uses_fido2_client(
        self,
        mock_collector_cls,
        mock_fido2_client_cls,
        mock_list_devices,
        mock_httpx2,
    ):
        """_get_credential creates Fido2Client with device and collector."""
        mock_list_devices.return_value = ["fake_device"]
        mock_collector = MagicMock()
        mock_collector_cls.return_value = mock_collector
        mock_client_instance = MagicMock()
        mock_fido2_client_cls.return_value = mock_client_instance

        auth = Fido2Auth(server_url="https://venya-core-1")
        # _build_registration_options returns a mock options object
        options = auth._build_registration_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp": {"name": "Venya"},
                "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
            }
        )

        auth._get_credential(options, timeout=10.0)

        # Verify Fido2Client was instantiated with device and collector
        mock_fido2_client_cls.assert_called_once()
        call_args = mock_fido2_client_cls.call_args
        assert call_args[0][0] == "fake_device"  # device
        assert call_args[0][1] is mock_collector  # collector

    @patch("venya_cli.fido2_client.httpx2")
    @patch("venya_cli.fido2_client.list_devices")
    @patch("venya_cli.fido2_client.Fido2Client")
    @patch("venya_cli.fido2_client.DefaultClientDataCollector")
    @patch("venya_cli.fido2_client.Ctap2")
    def test_get_assertion_uses_fido2_client_for_uv_key(
        self,
        mock_ctap2_cls,
        mock_collector_cls,
        mock_fido2_client_cls,
        mock_list_devices,
        mock_httpx2,
    ):
        """_get_assertion uses Fido2Client when key advertises uv:true."""
        mock_list_devices.return_value = ["fake_device"]
        mock_ctap2 = MagicMock()
        mock_ctap2_cls.return_value = mock_ctap2
        mock_ctap2.info.options = {"uv": True, "up": True, "rk": True}
        mock_ctap2.info.pin_uv_protocols = [1]
        mock_collector = MagicMock()
        mock_collector_cls.return_value = mock_collector
        mock_client_instance = MagicMock()
        mock_fido2_client_cls.return_value = mock_client_instance

        auth = Fido2Auth(server_url="https://venya-core-1")
        options = auth._build_request_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp_id": "venya-core-1",
                "timeout": 60000,
            }
        )

        auth._get_assertion(options, timeout=10.0)

        mock_fido2_client_cls.assert_called_once()
        call_args = mock_fido2_client_cls.call_args
        assert call_args[0][0] == "fake_device"
        assert call_args[0][1] is mock_collector
        mock_ctap2_cls.assert_called_once()
        mock_ctap2_cls.assert_called_with("fake_device")

    @patch("venya_cli.fido2_client.list_devices")
    def test_no_devices_raises_fido2_not_found(self, mock_list_devices):
        """_get_credential raises Fido2NotFoundError when no devices."""
        mock_list_devices.return_value = []
        auth = Fido2Auth(server_url="https://venya-core-1")
        options = auth._build_registration_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp": {"name": "Venya"},
                "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
            }
        )

        try:
            auth._get_credential(options, timeout=10.0)
            assert False, "Expected Fido2NotFoundError"
        except Fido2NotFoundError:
            pass


class TestBuildRequestOptions:
    """Test that _build_request_options forces user_verification=REQUIRED."""

    def test_forces_required_despite_discouraged_hint(self):
        """Server hint 'discouraged' is overridden to REQUIRED."""
        auth = Fido2Auth(server_url="https://venya-core-1")
        options = auth._build_request_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp_id": "venya-core-1",
                "timeout": 60000,
                "user_verification": "discouraged",
                "allow_credentials": [{"type": "public-key", "id": "YWJj"}],
            }
        )
        from fido2.webauthn import UserVerificationRequirement

        assert options.public_key.user_verification == UserVerificationRequirement.REQUIRED


class TestAuthenticateErrorHandling:
    """Test that authenticate() handles ClientError and CtapError correctly."""

    @patch.object(Fido2Auth, "_get_assertion")
    @patch.object(Fido2Auth, "_post")
    def test_configuration_unsupported_produces_actionable_message(self, mock_post, mock_get):
        """ClientError(CONFIGURATION_UNSUPPORTED) → Fido2ClientError with 'set a PIN' message."""
        from fido2.client import ClientError
        from venya_cli.fido2_client import Fido2ClientError

        mock_post.side_effect = [
            {
                "challenge_id": "ch1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "allow_credentials": [{"type": "public-key", "id": "YWJj"}],
                    "rp_id": "venya-core-1",
                    "timeout": 60000,
                },
            },
            {"user_id": "admin", "session_token": "tok", "credential_id": "c1"},
        ]
        mock_get.side_effect = ClientError.ERR.CONFIGURATION_UNSUPPORTED("User verification not configured/supported")

        auth = Fido2Auth(server_url="https://venya-core-1")
        try:
            auth.authenticate(user_id="admin")
            assert False, "Expected Fido2ClientError"
        except Fido2ClientError as exc:
            assert "PIN" in str(exc)

    @patch.object(Fido2Auth, "_get_assertion")
    @patch.object(Fido2Auth, "_post")
    def test_wrapped_pin_invalid_retries_three_times_then_fails(self, mock_post, mock_get):
        """ClientError wrapping CtapError(PIN_INVALID) → unwrap → retry fires 3× → 'PIN incorrect after 3'."""
        from fido2.client import ClientError
        from fido2.ctap import CtapError
        from venya_cli.fido2_client import Fido2ClientError

        mock_post.side_effect = [
            {
                "challenge_id": "ch1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "allow_credentials": [{"type": "public-key", "id": "YWJj"}],
                    "rp_id": "venya-core-1",
                    "timeout": 60000,
                },
            },
            {"user_id": "admin", "session_token": "tok", "credential_id": "c1"},
        ]
        wrapped = ClientError.ERR.BAD_REQUEST(CtapError(CtapError.ERR.PIN_INVALID))
        mock_get.side_effect = [wrapped, wrapped, wrapped]

        auth = Fido2Auth(server_url="https://venya-core-1")
        try:
            auth.authenticate(user_id="admin")
            assert False, "Expected Fido2ClientError"
        except Fido2ClientError as exc:
            assert "PIN incorrect after 3" in str(exc)
        assert mock_get.call_count == 3

    @patch.object(Fido2Auth, "_get_assertion")
    @patch.object(Fido2Auth, "_post")
    def test_bare_ctap_error_no_retry(self, mock_post, mock_get):
        """Raw CtapError(TIMEOUT) → no retry, called 1×, re-raises as CtapError."""
        from fido2.ctap import CtapError

        mock_post.side_effect = [
            {
                "challenge_id": "ch1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "allow_credentials": [{"type": "public-key", "id": "YWJj"}],
                    "rp_id": "venya-core-1",
                    "timeout": 60000,
                },
            },
            {"user_id": "admin", "session_token": "tok", "credential_id": "c1"},
        ]
        mock_get.side_effect = CtapError(CtapError.ERR.TIMEOUT)

        auth = Fido2Auth(server_url="https://venya-core-1")
        try:
            auth.authenticate(user_id="admin")
            assert False, "Expected CtapError"
        except CtapError:
            pass
        assert mock_get.call_count == 1

    @patch.object(Fido2Auth, "_get_assertion")
    @patch.object(Fido2Auth, "_post")
    def test_wrapped_ctap_error_reunwrapped_no_retry(self, mock_post, mock_get):
        """ClientError wrapping CtapError(TIMEOUT) → unwrap → re-raises as CtapError, not wrapper.

        This is the line that fails under a bare raise: without the unwrap + raise e,
        the caller receives the ClientError wrapper instead of the actual CtapError.
        """
        from fido2.client import ClientError
        from fido2.ctap import CtapError

        mock_post.side_effect = [
            {
                "challenge_id": "ch1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "allow_credentials": [{"type": "public-key", "id": "YWJj"}],
                    "rp_id": "venya-core-1",
                    "timeout": 60000,
                },
            },
            {"user_id": "admin", "session_token": "tok", "credential_id": "c1"},
        ]
        wrapped = ClientError.ERR.BAD_REQUEST(CtapError(CtapError.ERR.TIMEOUT))
        mock_get.side_effect = wrapped

        auth = Fido2Auth(server_url="https://venya-core-1")
        try:
            auth.authenticate(user_id="admin")
            assert False, "Expected CtapError"
        except CtapError:
            pass
        except ClientError:
            assert False, "Should have unwrapped to CtapError, not re-raised ClientError wrapper"
        assert mock_get.call_count == 1


class TestPinOnlyKeyDispatch:
    """Test that clientPin-only keys use direct Ctap2.get_assertion."""

    @patch("venya_cli.fido2_client.httpx2")
    @patch("venya_cli.fido2_client.list_devices")
    @patch("venya_cli.fido2_client.Fido2Client")
    @patch("venya_cli.fido2_client.DefaultClientDataCollector")
    @patch("venya_cli.fido2_client.Ctap2")
    @patch("venya_cli.fido2_client.ClientPin")
    @patch("venya_cli.fido2_client.CliInteraction")
    def test_pin_only_key_uses_direct_ctap2_assertion(
        self,
        mock_interaction_cls,
        mock_clientpin_cls,
        mock_ctap2_cls,
        mock_collector_cls,
        mock_fido2_client_cls,
        mock_list_devices,
        mock_httpx2,
    ):
        """clientPin:true, no uv → Ctap2.get_assertion called with pin_uv_param set and no options."""
        mock_list_devices.return_value = ["fake_device"]
        mock_ctap2 = MagicMock()
        mock_ctap2_cls.return_value = mock_ctap2
        mock_ctap2.info.options = {"clientPin": True, "up": True, "rk": True}
        mock_ctap2.info.pin_uv_protocols = [1]
        mock_response = MagicMock()
        mock_ctap2.get_assertion.return_value = mock_response
        mock_collector = MagicMock()
        mock_collector_cls.return_value = mock_collector
        mock_collector.collect_client_data.return_value = (MagicMock(), "venya-core-1")
        mock_collector.collect_client_data.return_value[0].hash = b"x" * 32
        mock_clientpin = MagicMock()
        mock_clientpin_cls.return_value = mock_clientpin
        mock_clientpin.get_pin_token.return_value = b"\x00" * 32
        mock_interaction = MagicMock()
        mock_interaction_cls.return_value = mock_interaction
        mock_interaction.request_pin.return_value = "1234"
        mock_interaction.prompt_up = MagicMock()

        # Mock protocol — the loop accesses proto.VERSION for the check,
        # then calls proto() for the instance with .authenticate/.VERSION.
        class MockProtocol:
            VERSION = 1

            def authenticate(self, token, message):
                return b"\xaa" * 16

        mock_clientpin_cls.PROTOCOLS = [MockProtocol]

        auth = Fido2Auth(server_url="https://venya-core-1")
        options = auth._build_request_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp_id": "venya-core-1",
                "timeout": 60000,
                "allow_credentials": [{"type": "public-key", "id": "YWJj"}],
            }
        )

        result = auth._get_assertion(options, timeout=10.0)

        # Verify Ctap2 was created and info read
        mock_ctap2_cls.assert_called_once()
        # Verify Fido2Client was NOT called (not a UV key)
        mock_fido2_client_cls.assert_not_called()
        # Verify Ctap2.get_assertion was called with pin_uv_param and no options
        mock_ctap2.get_assertion.assert_called_once()
        call_kwargs = mock_ctap2.get_assertion.call_args.kwargs
        assert call_kwargs.get("pin_uv_param") == b"\xaa" * 16
        assert call_kwargs.get("pin_uv_protocol") == 1
        assert "options" not in call_kwargs
        # Verify the result is an AssertionSelection
        from fido2.client import AssertionSelection

        assert isinstance(result, AssertionSelection)

    @patch("venya_cli.fido2_client.httpx2")
    @patch.object(Fido2Auth, "_get_assertion")
    @patch.object(Fido2Auth, "_post")
    def test_wrapped_pin_invalid_retries_three_times_through_new_path(
        self,
        mock_post,
        mock_get,
        mock_httpx2,
    ):
        """CtapError(PIN_INVALID) → retry fires 3× → 'PIN incorrect after 3'.

        The retry loop in authenticate() catches CtapError from the new
        direct path (Ctap2.get_assertion raises raw CtapError).
        """
        from fido2.client import ClientError
        from fido2.ctap import CtapError
        from venya_cli.fido2_client import Fido2ClientError

        mock_post.side_effect = [
            {
                "challenge_id": "ch1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "allow_credentials": [{"type": "public-key", "id": "YWJj"}],
                    "rp_id": "venya-core-1",
                    "timeout": 60000,
                },
            },
            {"user_id": "admin", "session_token": "tok", "credential_id": "c1"},
        ]
        wrapped = ClientError.ERR.BAD_REQUEST(CtapError(CtapError.ERR.PIN_INVALID))
        mock_get.side_effect = [wrapped, wrapped, wrapped]

        auth = Fido2Auth(server_url="https://venya-core-1")
        try:
            auth.authenticate(user_id="admin")
            assert False, "Expected Fido2ClientError"
        except Fido2ClientError as exc:
            assert "PIN incorrect after 3" in str(exc)
        assert mock_get.call_count == 3


class TestFormatAssertionResponse:
    """Test _format_assertion_response with real AssertionSelection (latent bug fix)."""

    def test_format_assertion_response_uses_real_api(self):
        """_format_assertion_response works with a real AssertionSelection, not just mocks.

        AssertionSelection has no .assertions or .client_data attributes;
        the formatter must use .get_assertions()[0] and .get_response(0).response.client_data.
        """
        from fido2.client import AssertionSelection
        from fido2.webauthn import AuthenticatorData, CollectedClientData

        client_data = CollectedClientData.create(
            type=CollectedClientData.TYPE.GET,
            challenge=b"test-challenge",
            origin="https://venya-core-1",
        )

        # Build a real AuthenticatorData (32 bytes rp_id_hash + 1 byte flags + 4 bytes counter)
        rp_id_hash = b"\0" * 32
        auth_data = AuthenticatorData.create(rp_id_hash, 0x01, 1)

        class FakeAssertion:
            credential: ClassVar[dict] = {"id": b"cred-id", "type": "public-key"}
            signature = b"signature-bytes"
            user = None

        FakeAssertion.auth_data = auth_data
        sel = AssertionSelection(client_data, [FakeAssertion()])

        auth = Fido2Auth(server_url="https://venya-core-1")
        result = auth._format_assertion_response(sel)

        assert result["type"] == "public-key"
        assert result["id"] == "Y3JlZC1pZA=="  # padded standard base64 — server b64decode rejects unpadded (f71d4c5)
        assert "rawId" in result
        assert "signature" in result["response"]
        assert "clientDataJSON" in result["response"]
        assert "authenticatorData" in result["response"]
        assert result["clientExtensionResults"] == {}


class TestPostErrorDetailPropagation:
    """_post must carry the server's JSON `detail` into Fido2ClientError.

    Regression (F2 physical, cli-409): cmd_init pattern-matches
    'already initialized' / 'pending enrollment' against the error text,
    but _post dropped the response body — f71d4c5 removed the parsing on
    a wrong hypothesis ("Incorrect padding" originated in _b64std_encode;
    json.loads cannot raise it). Earlier unit tests fed pattern-bearing
    strings directly to the matcher and stayed green while the parse layer
    between exception and matcher was dead. These tests construct real
    httpx2 Responses and let the real raise_for_status()/handler run.
    """

    @staticmethod
    def _response(status: int, body: bytes, content_type: str):
        request = httpx2.Request("POST", "https://venya-core-2/api/v1/init")
        return httpx2.Response(status, content=body, headers={"content-type": content_type}, request=request)

    def _post_and_catch(self, resp):
        with patch("httpx2.Client.post", return_value=resp):
            auth = Fido2Auth(server_url="https://venya-core-2")
            with pytest.raises(Fido2ClientError) as ei:
                auth._post("/api/v1/init", {})
        return str(ei.value)

    def test_409_already_initialized_detail_reaches_message(self):
        resp = self._response(
            409,
            b'{"detail":"Core already initialized with admin \'admin1\'. Cannot re-initialize."}',
            "application/json",
        )
        msg = self._post_and_catch(resp)
        # cmd_init matcher contract (server wording: routes/init.py:171)
        assert "already initialized" in msg.lower()
        assert "developer.mozilla.org" not in msg

    def test_409_pending_enrollment_detail_reaches_message(self):
        resp = self._response(
            409,
            b'{"detail":"A pending enrollment exists for \'admin1\'. Reset required."}',
            "application/json",
        )
        msg = self._post_and_catch(resp)
        # cmd_init matcher contract (server wording: routes/init.py:183)
        assert "pending enrollment" in msg.lower()

    def test_non_json_error_body_falls_back_to_status_text(self):
        resp = self._response(500, b"<html>Internal Server Error</html>", "text/html")
        msg = self._post_and_catch(resp)
        assert "500" in msg  # httpx status text fallback, no crash

    def test_non_string_detail_does_not_crash(self):
        resp = self._response(
            422,
            b'{"detail":[{"loc":["body","user_id"],"msg":"field required"}]}',
            "application/json",
        )
        msg = self._post_and_catch(resp)
        assert msg  # non-empty, Fido2ClientError (not TypeError/AttributeError)


class TestWindowsClientFactory:
    """Truth table for _make_webauthn_client (ticket windows-fido2-requires-elevation).

    win32 routes to the platform WebAuthn API (WindowsClient) with NO device
    enumeration (raw HID enumeration is admin-only since Windows 10 1903 and a
    pre-check would emit a false "No FIDO2 devices found" for standard users).
    When the platform API is unavailable there is deliberately NO raw-path
    fallback — a fallback would reproduce the silent admin-only failure.
    Non-win32 behavior must be byte-identical to before the factory existed.
    """

    @staticmethod
    def _install_fake_windows_client(monkeypatch, available=True):
        import sys
        from types import SimpleNamespace

        wc_cls = MagicMock(name="WindowsClientClass")
        wc_cls.is_available.return_value = available
        wc_instance = MagicMock(name="WindowsClientInstance")
        wc_cls.return_value = wc_instance
        monkeypatch.setitem(sys.modules, "fido2.client.windows", SimpleNamespace(WindowsClient=wc_cls))
        return wc_cls, wc_instance

    @staticmethod
    def _reg_options(auth):
        return auth._build_registration_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp": {"name": "Venya"},
                "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
            }
        )

    @staticmethod
    def _req_options(auth):
        return auth._build_request_options(
            {"challenge": "dGVzdC1jaGFsbGVuZ2U=", "rp_id": "venya-core-1", "timeout": 60000}
        )

    def test_win32_available_returns_windows_client_without_enumeration(self, monkeypatch):
        """POSITIVE: win32 + platform API available -> WindowsClient(collector); list_devices never called."""
        from venya_cli.fido2_client import _make_webauthn_client

        monkeypatch.setattr("sys.platform", "win32")
        wc_cls, wc_instance = self._install_fake_windows_client(monkeypatch, available=True)
        collector = MagicMock(name="collector")
        with patch("venya_cli.fido2_client.list_devices") as mock_list, patch(
            "venya_cli.fido2_client.Fido2Client"
        ) as mock_raw:
            result = _make_webauthn_client(collector)
        assert result is wc_instance
        wc_cls.assert_called_once_with(collector)
        mock_list.assert_not_called()
        mock_raw.assert_not_called()

    def test_win32_unavailable_raises_explicit_error_no_raw_fallback(self, monkeypatch):
        """NEGATIVE (the pinned truth-table case): win32 + is_available() False ->
        explicit Fido2ClientError, and NO fallback to the raw path — list_devices
        and Fido2Client must not be touched."""
        from venya_cli.fido2_client import _make_webauthn_client

        monkeypatch.setattr("sys.platform", "win32")
        self._install_fake_windows_client(monkeypatch, available=False)
        with patch("venya_cli.fido2_client.list_devices") as mock_list, patch(
            "venya_cli.fido2_client.Fido2Client"
        ) as mock_raw:
            with pytest.raises(Fido2ClientError) as exc_info:
                _make_webauthn_client(MagicMock(name="collector"))
        assert "1903" in str(exc_info.value)
        mock_list.assert_not_called()
        mock_raw.assert_not_called()

    def test_non_win32_enumerates_and_builds_raw_client(self, monkeypatch):
        """POSITIVE: non-win32 + device present -> Fido2Client(device, collector, user_interaction=...)."""
        from venya_cli.fido2_client import _make_webauthn_client

        monkeypatch.setattr("sys.platform", "linux")
        collector = MagicMock(name="collector")
        with patch("venya_cli.fido2_client.list_devices", return_value=["fake_device"]) as mock_list, patch(
            "venya_cli.fido2_client.Fido2Client"
        ) as mock_raw:
            result = _make_webauthn_client(collector)
        mock_list.assert_called_once()
        assert result is mock_raw.return_value
        args = mock_raw.call_args
        assert args[0][0] == "fake_device"
        assert args[0][1] is collector
        assert args[1]["user_interaction"] is not None

    def test_non_win32_no_devices_raises_not_found(self, monkeypatch):
        """NEGATIVE: non-win32 + empty enumeration -> Fido2NotFoundError."""
        from venya_cli.fido2_client import _make_webauthn_client

        monkeypatch.setattr("sys.platform", "linux")
        with patch("venya_cli.fido2_client.list_devices", return_value=[]):
            with pytest.raises(Fido2NotFoundError):
                _make_webauthn_client(MagicMock(name="collector"))


class TestWindowsCeremonyDispatch:
    """win32 ceremony routing: both ceremony sites go through WindowsClient and
    never touch raw enumeration, raw Ctap2, or the clientPin-only fallbacks."""

    def test_get_assertion_win32_uses_windows_client_only(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        _wc_cls, wc_instance = TestWindowsClientFactory._install_fake_windows_client(monkeypatch)
        auth = Fido2Auth(server_url="https://venya-core-1")
        options = TestWindowsClientFactory._req_options(auth)
        with patch("venya_cli.fido2_client.list_devices") as mock_list, patch(
            "venya_cli.fido2_client.Ctap2"
        ) as mock_ctap2, patch("venya_cli.fido2_client.Fido2Client") as mock_raw:
            result = auth._get_assertion(options, timeout=10.0)
        assert result is wc_instance.get_assertion.return_value
        wc_instance.get_assertion.assert_called_once_with(options.public_key)
        mock_list.assert_not_called()
        mock_ctap2.assert_not_called()
        mock_raw.assert_not_called()

    def test_get_credential_win32_uses_windows_client_only(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        _wc_cls, wc_instance = TestWindowsClientFactory._install_fake_windows_client(monkeypatch)
        auth = Fido2Auth(server_url="https://venya-core-1")
        options = TestWindowsClientFactory._reg_options(auth)
        with patch("venya_cli.fido2_client.list_devices") as mock_list, patch(
            "venya_cli.fido2_client.Ctap2"
        ) as mock_ctap2:
            result = auth._get_credential(options, timeout=10.0)
        assert result is wc_instance.make_credential.return_value
        wc_instance.make_credential.assert_called_once_with(options.public_key)
        mock_list.assert_not_called()
        mock_ctap2.assert_not_called()

    def test_get_credential_win32_client_error_propagates_without_pin_fallback(self, monkeypatch):
        """NEGATIVE: on win32 a ClientError from the platform API must propagate —
        the raw-Ctap2 clientPin fallback is admin-only and must not be attempted."""
        from fido2.client import ClientError

        monkeypatch.setattr("sys.platform", "win32")
        _wc_cls, wc_instance = TestWindowsClientFactory._install_fake_windows_client(monkeypatch)
        wc_instance.make_credential.side_effect = ClientError.ERR.OTHER_ERROR(ValueError("platform boom"))
        auth = Fido2Auth(server_url="https://venya-core-1")
        options = TestWindowsClientFactory._reg_options(auth)
        with patch("venya_cli.fido2_client.list_devices") as mock_list, patch(
            "venya_cli.fido2_client.Ctap2"
        ) as mock_ctap2:
            with pytest.raises(ClientError):
                auth._get_credential(options, timeout=10.0)
        mock_list.assert_not_called()
        mock_ctap2.assert_not_called()


class TestNormalizerRpShape:
    """Truth table for normalize_webauthn_options rp_id derivation.

    The server emits TWO wire shapes: /auth/login/start passes the raw manager
    options through ("rpId" scalar), while /auth/elevate/challenge and the
    browser routes run challenge_to_browser_options, which folds rpId into an
    "rp": {"id", "name"} object and DROPS the scalar. Pre-fix the normalizer
    only read the scalar, so elevation built request options with rp_id=None —
    on Windows the platform API got a NULL pwszRpId and failed
    NTE_INVALID_PARAMETER (0x80090027); found physically on win11 (venyastd,
    `venya credential remove 1`).
    """

    def test_raw_login_shape_keeps_rp_id_scalar(self):
        auth = Fido2Auth(server_url="https://venya-core-1")
        norm = auth.normalize_webauthn_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rpId": "venya-core-1",
                "timeout": 60000,
                "userVerification": "discouraged",
                "allowCredentials": [{"type": "public-key", "id": "YWJj"}],
            }
        )
        assert norm["rp_id"] == "venya-core-1"
        assert norm["allow_credentials"][0]["id"] == b"abc"

    def test_browser_elevation_shape_derives_rp_id_from_rp_object(self):
        auth = Fido2Auth(server_url="https://venya-core-1")
        norm = auth.normalize_webauthn_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U",
                "rp": {"id": "venya-core-1", "name": "Venya"},
                "timeout": 60000,
                "userVerification": "discouraged",
                "allowCredentials": [{"type": "public-key", "id": "YWJj"}],
            }
        )
        assert norm["rp_id"] == "venya-core-1"
        assert norm["rp"] == {"id": "venya-core-1", "name": "Venya"}

    def test_browser_shape_without_rp_id_stays_absent(self):
        """NEGATIVE half: rp object with no usable id must NOT invent an rp_id."""
        auth = Fido2Auth(server_url="https://venya-core-1")
        norm = auth.normalize_webauthn_options({"challenge": "dGVzdC1jaGFsbGVuZ2U=", "rp": {"name": "Venya"}})
        assert "rp_id" not in norm

    def test_build_request_options_from_elevation_shape(self):
        """End-to-end through the assertion options builder: rp_id must land on
        the PublicKeyCredentialRequestOptions the ceremony consumes."""
        auth = Fido2Auth(server_url="https://venya-core-1")
        req = auth._build_request_options(
            {
                "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                "rp": {"id": "venya-core-1", "name": "Venya"},
                "timeout": 60000,
                "allowCredentials": [{"type": "public-key", "id": "YWJj"}],
            }
        )
        assert req.public_key.rp_id == "venya-core-1"
