"""Tests for the FIDO2 client (fido2_client.py).

Verifies that Fido2Client is instantiated correctly with fido2 2.x API.
"""

from typing import ClassVar
from unittest.mock import MagicMock, patch

from core.cli.fido2_client import Fido2Auth, Fido2NotFoundError


class TestFido2ClientInstantiation:
    """Test that Fido2Client is used correctly (fido2 2.x API)."""

    @patch("core.cli.fido2_client.httpx2")
    @patch("core.cli.fido2_client.list_devices")
    @patch("core.cli.fido2_client.Fido2Client")
    @patch("core.cli.fido2_client.DefaultClientDataCollector")
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

    @patch("core.cli.fido2_client.httpx2")
    @patch("core.cli.fido2_client.list_devices")
    @patch("core.cli.fido2_client.Fido2Client")
    @patch("core.cli.fido2_client.DefaultClientDataCollector")
    @patch("core.cli.fido2_client.Ctap2")
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

    @patch("core.cli.fido2_client.list_devices")
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
        from core.cli.fido2_client import Fido2ClientError
        from fido2.client import ClientError

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
        from core.cli.fido2_client import Fido2ClientError
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

    @patch("core.cli.fido2_client.httpx2")
    @patch("core.cli.fido2_client.list_devices")
    @patch("core.cli.fido2_client.Fido2Client")
    @patch("core.cli.fido2_client.DefaultClientDataCollector")
    @patch("core.cli.fido2_client.Ctap2")
    @patch("core.cli.fido2_client.ClientPin")
    @patch("core.cli.fido2_client.CliInteraction")
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

    @patch("core.cli.fido2_client.httpx2")
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
        from core.cli.fido2_client import Fido2ClientError
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
