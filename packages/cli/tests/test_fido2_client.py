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
    @patch("venya_cli.fido2_client.Ctap2")
    def test_get_credential_uses_fido2_client_for_uv_key(
        self,
        mock_ctap2_cls,
        mock_collector_cls,
        mock_fido2_client_cls,
        mock_list_devices,
        mock_httpx2,
    ):
        """_get_credential uses the high-level Fido2Client for a key with built-in
        uv (info.options['uv'] truthy). Paired negative to
        test_get_credential_pin_only_key_dispatches_to_raw_path below.

        Updated for Fix 1 (init-pin-invalid-after-installation-reset):
        _get_credential now info-dispatches like _get_assertion, so the
        high-level path is reached only for uv keys — Ctap2 must be mocked.
        """
        mock_list_devices.return_value = ["fake_device"]
        mock_ctap2 = MagicMock()
        mock_ctap2_cls.return_value = mock_ctap2
        mock_ctap2.info.options = {"uv": True, "up": True, "rk": True}
        mock_collector = MagicMock()
        mock_collector_cls.return_value = mock_collector
        mock_client_instance = MagicMock()
        mock_fido2_client_cls.return_value = mock_client_instance

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

        auth._get_credential(options, timeout=10.0)

        # uv key → high-level Fido2Client(device, collector, user_interaction=…)
        mock_fido2_client_cls.assert_called_once()
        call_args = mock_fido2_client_cls.call_args
        assert call_args[0][0] == "fake_device"  # device
        assert call_args[0][1] is mock_collector  # collector
        mock_ctap2_cls.assert_called_once_with("fake_device")

    @patch("venya_cli.fido2_client.httpx2")
    @patch.object(Fido2Auth, "_get_credential_pin_only")
    @patch("venya_cli.fido2_client.list_devices")
    @patch("venya_cli.fido2_client.Fido2Client")
    @patch("venya_cli.fido2_client.DefaultClientDataCollector")
    @patch("venya_cli.fido2_client.Ctap2")
    def test_get_credential_pin_only_key_dispatches_to_raw_path(
        self,
        mock_ctap2_cls,
        mock_collector_cls,
        mock_fido2_client_cls,
        mock_list_devices,
        mock_pin_only,
        mock_httpx2,
    ):
        """Fix 1 (init-pin-invalid-after-installation-reset): a clientPin-only key
        (clientPin:true, NO built-in uv — the makeCredUvNotRqd TrustKey-class shape
        that returned off-spec 0x31) is dispatched STRAIGHT to the raw
        _get_credential_pin_only path. The high-level Fido2Client.make_credential
        (which mishandles such keys and burns a PIN-retry per failure) is NOT used.
        Mirror of TestPinOnlyKeyDispatch for the assertion/login path.
        """
        mock_list_devices.return_value = ["fake_device"]
        mock_ctap2 = MagicMock()
        mock_ctap2_cls.return_value = mock_ctap2
        mock_ctap2.info.options = {"clientPin": True, "up": True, "rk": True}  # no uv
        mock_collector_cls.return_value = MagicMock()
        sentinel = MagicMock()
        mock_pin_only.return_value = sentinel

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

        result = auth._get_credential(options, timeout=10.0)

        assert result is sentinel
        mock_pin_only.assert_called_once()
        # raw path received the Ctap2 instance built from the enumerated device
        assert mock_pin_only.call_args[0][0] is mock_ctap2
        # high-level path NOT used for a clientPin-only key
        mock_fido2_client_cls.assert_not_called()

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


class TestRegisterErrorHandling:
    """Fix 2 (init-pin-invalid-after-installation-reset): register() must unwrap
    ClientError→CtapError exactly like authenticate() does. da2c09a restored the
    unwrap for the assertion twin; register() was missed, so a high-level
    make_credential ClientError(PIN_INVALID) escaped as a raw tuple with no retry
    — the 'Initialization failed: (<ERR.BAD_REQUEST: 2>, CtapError(0x31)>)' the
    ticket captured. These mirror TestAuthenticateErrorHandling."""

    @patch.object(Fido2Auth, "_get_credential")
    @patch.object(Fido2Auth, "_post")
    def test_wrapped_pin_invalid_retries_three_times_then_fails(self, mock_post, mock_get_cred):
        """ClientError(CtapError PIN_INVALID) → unwrap → retry 3× → 'PIN incorrect after 3'."""
        from fido2.client import ClientError
        from fido2.ctap import CtapError
        from venya_cli.fido2_client import Fido2ClientError

        mock_post.side_effect = [
            {
                "challenge_id": "ch1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "alice", "displayName": "alice"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        ]
        wrapped = ClientError.ERR.BAD_REQUEST(CtapError(CtapError.ERR.PIN_INVALID))
        mock_get_cred.side_effect = [wrapped, wrapped, wrapped]

        auth = Fido2Auth(server_url="https://venya-core-1")
        try:
            auth.register(user_id="alice")
            assert False, "Expected Fido2ClientError"
        except Fido2ClientError as exc:
            assert "PIN incorrect after 3" in str(exc)
        assert mock_get_cred.call_count == 3

    @patch.object(Fido2Auth, "_get_credential")
    @patch.object(Fido2Auth, "_post")
    def test_bare_non_pin_ctap_error_no_retry(self, mock_post, mock_get_cred):
        """PAIRED NEGATIVE: a non-PIN CtapError is NOT retried (exactly 1 call)
        and re-raises as CtapError — not swallowed, not infinite-looped."""
        from fido2.ctap import CtapError

        mock_post.side_effect = [
            {
                "challenge_id": "ch1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "alice", "displayName": "alice"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        ]
        mock_get_cred.side_effect = CtapError(CtapError.ERR.TIMEOUT)

        auth = Fido2Auth(server_url="https://venya-core-1")
        try:
            auth.register(user_id="alice")
            assert False, "Expected CtapError"
        except CtapError:
            pass
        assert mock_get_cred.call_count == 1


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
            with pytest.raises(Fido2ClientError) as exc_info:
                auth._get_credential(options, timeout=10.0)
        # translated, not raw: operators must never see "(<ERR.OTHER_ERROR: 1>, ...)"
        assert "Windows WebAuthn error" in str(exc_info.value)
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


class TestWindowsErrorTranslation:
    """Truth table for _translate_windows_error (operator-facing accuracy).

    Mapped HRESULTs get pinned messages; unmapped codes keep the OS's own text
    plus the HRESULT (accurate, never invented); non-OSError causes fall back
    to the exception text. Evidence-driven list: NTE_EXISTS observed physically
    on win11 (`credential add` with an already-registered key, 2026-09-19)."""

    @staticmethod
    def _client_error(cause):
        from fido2.client import ClientError

        return ClientError.ERR.OTHER_ERROR(cause)

    @staticmethod
    def _win_oserror(strerror, winerror):
        """Model a WINDOWS OSError: .winerror exists only on Windows (on POSIX
        the value rides in .args and the attribute is absent), so unit tests on
        Linux must model the shape the translator sees in production. The
        physical win11 acceptance run covers the real OSError end-to-end."""
        from types import SimpleNamespace

        return SimpleNamespace(winerror=winerror, strerror=strerror)

    def test_mapped_nte_exists_gets_duplicate_message(self):
        from venya_cli.fido2_client import _translate_windows_error

        err = _translate_windows_error(self._client_error(self._win_oserror("Object already exists", -2146893809)))
        assert isinstance(err, Fido2ClientError)
        assert "already registered" in str(err)
        assert "HRESULT" not in str(err)  # pinned message, not raw dump

    def test_unmapped_hresult_keeps_os_text_and_code(self):
        from venya_cli.fido2_client import _translate_windows_error

        err = _translate_windows_error(self._client_error(self._win_oserror("The parameter is incorrect", -2146893785)))
        text = str(err)
        assert "Windows WebAuthn error" in text
        assert "The parameter is incorrect" in text  # OS text preserved verbatim
        assert "0x80090027" in text  # unsigned HRESULT for support lookup

    def test_non_oserror_cause_falls_back_to_exception_text(self):
        from venya_cli.fido2_client import _translate_windows_error

        err = _translate_windows_error(self._client_error(ValueError("platform boom")))
        assert "Windows WebAuthn error" in str(err)

    def test_get_assertion_win32_translates_platform_error(self, monkeypatch):
        """Integration: the assertion site surfaces the translated error, and
        still never touches raw enumeration or Ctap2."""
        monkeypatch.setattr("sys.platform", "win32")
        _wc_cls, wc_instance = TestWindowsClientFactory._install_fake_windows_client(monkeypatch)
        wc_instance.get_assertion.side_effect = self._client_error(
            self._win_oserror("Object already exists", -2146893809)
        )
        auth = Fido2Auth(server_url="https://venya-core-1")
        options = TestWindowsClientFactory._req_options(auth)
        with patch("venya_cli.fido2_client.list_devices") as mock_list, patch(
            "venya_cli.fido2_client.Ctap2"
        ) as mock_ctap2:
            with pytest.raises(Fido2ClientError) as exc_info:
                auth._get_assertion(options, timeout=10.0)
        assert "already registered" in str(exc_info.value)
        mock_list.assert_not_called()
        mock_ctap2.assert_not_called()


class TestWrapAttestationResponse:
    """_wrap_attestation_response must read the REAL fido2 2.x AttestationResponse.

    Ticket fido2-pin-only-attestation-attributeerror: the clientPin-only
    registration path (_get_credential_pin_only) wrapped ctap2.make_credential's
    raw AttestationResponse by reading response.credential_id /
    response.attestation_object -- attributes that DO NOT EXIST on fido2 2.x
    AttestationResponse (it exposes fmt/auth_data/att_stmt). -> AttributeError on
    the primary Linux/macOS enrollment path for clientPin keys (TrustKey T120,
    YubiKey). The assertion twin (_format_assertion_response) was already fixed;
    this is the attestation twin. Masked because no test drove the real device
    shape (mocks carried the imagined attributes). Real library objects here.
    """

    def test_sources_credential_id_and_attestation_object_from_real_shape(self):
        from types import SimpleNamespace

        from cryptography.hazmat.primitives.asymmetric import ec
        from fido2.cose import ES256
        from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

        cred_id = b"\xaa" * 32
        priv = ec.generate_private_key(ec.SECP256R1())
        cose = ES256.from_cryptography_key(priv.public_key())
        cred_data = AttestedCredentialData.create(b"\x00" * 16, cred_id, cose)
        auth_data = AuthenticatorData.create(
            b"\x11" * 32,
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
            0,
            credential_data=cred_data,
        )
        # Mimic the real AttestationResponse container: fmt/auth_data/att_stmt ONLY.
        response = SimpleNamespace(fmt="packed", auth_data=auth_data, att_stmt={})

        # Bug premise: the real shape has NO .credential_id/.attestation_object --
        # exactly what the pre-fix code read -> AttributeError.
        assert not hasattr(response, "credential_id")
        assert not hasattr(response, "attestation_object")

        wrapper = Fido2Auth._wrap_attestation_response(response, client_data=b"cd")
        ar = wrapper.auth_response
        assert ar.credential_id == cred_id  # bytes, from auth_data.credential_data
        assert bytes(ar.attestation_object) == bytes(AttestationObject.create("packed", auth_data, {}))
        assert ar.client_data == b"cd"
        assert wrapper.transports is None
