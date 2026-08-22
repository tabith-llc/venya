"""Tests for CLI enroll start and complete commands."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import httpx2
from core.cli.api_client import APIClient
from core.cli.commands import cmd_enroll_complete, cmd_enroll_start


def _make_mock_response(status_code=200, json_data=None):
    """Create a mock httpx.Response."""
    mock = MagicMock(spec=httpx2.Response)
    mock.status_code = status_code
    if json_data is not None:
        mock.json.return_value = json_data
        mock.content = json.dumps(json_data).encode()
    else:
        mock.content = b""
        mock.json.return_value = {}
    return mock


def _make_client(mock_http=None):
    """Create an APIClient with a mocked HTTP client."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        f.write(b"{}")
        config_file = Path(f.name)

    client = APIClient(config_file=config_file)
    if mock_http:
        client._http = mock_http
    return client, config_file


# ---------------------------------------------------------------------------
# cmd_enroll_start tests
# ---------------------------------------------------------------------------


class TestEnrollStart:
    """Tests for venya enroll start command."""

    def test_enroll_start_success(self):
        """Enroll start succeeds and prints challenge_id."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "challenge_id": "enroll_chal_123",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll_abc"
        args.json = False

        result = cmd_enroll_start(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/v1/enroll/browser/start"
        assert call_args[1]["json"] == {"enrollment_token": "tok_enroll_abc"}
        client.close()
        config_file.unlink()

    def test_enroll_start_json_output(self):
        """Enroll start with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "challenge_id": "enroll_chal_456",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll_xyz"
        args.json = True

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_enroll_start(client, args)

        assert result == 0
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["challenge_id"] == "enroll_chal_456"
        assert "options" in parsed
        client.close()
        config_file.unlink()

    def test_enroll_start_400_invalid_token(self):
        """Enroll start with invalid token returns 400."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Enrollment token is invalid"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "invalid_token"
        args.json = False

        result = cmd_enroll_start(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_enroll_start_400_token_expired(self):
        """Enroll start with expired token returns 400."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Enrollment token has expired"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "expired_token"
        args.json = False

        result = cmd_enroll_start(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_enroll_start_400_token_consumed(self):
        """Enroll start with consumed token returns 400."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Enrollment token already consumed"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "consumed_token"
        args.json = False

        result = cmd_enroll_start(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_enroll_start_network_error(self):
        """Enroll start with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll"
        args.json = False

        result = cmd_enroll_start(client, args)
        assert result == 1
        client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# cmd_enroll_complete tests
# ---------------------------------------------------------------------------


class TestEnrollComplete:
    """Tests for venya enroll complete command."""

    def test_enroll_complete_success(self):
        """Enroll complete succeeds and prints status, user_id, credential_id."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "status": "ok",
                "user_id": "jsmith",
                "credential_id": "cred_enrolled_789",
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll_abc"
        args.challenge_id = "enroll_chal_123"
        args.response = json.dumps(
            {
                "id": "cred_id",
                "rawId": "cmVkX2lk",
                "response": {
                    "clientDataJSON": "Y2xpZW50IGRhdGE=",
                    "authenticatorData": "YXV0aCBkYXRh",
                    "attestationObject": "YXR0ZXN0YXRpb24=",
                },
                "type": "public-key",
                "clientExtensionResults": {},
            }
        )
        args.label = "YubiKey"
        args.json = False

        result = cmd_enroll_complete(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/v1/enroll/browser/complete"
        payload = call_args[1]["json"]
        assert payload["enrollment_token"] == "tok_enroll_abc"
        assert payload["challenge_id"] == "enroll_chal_123"
        assert payload["label"] == "YubiKey"
        client.close()
        config_file.unlink()

    def test_enroll_complete_json_output(self):
        """Enroll complete with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "status": "ok",
                "user_id": "jsmith",
                "credential_id": "cred_enrolled_789",
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll_abc"
        args.challenge_id = "enroll_chal_123"
        args.response = json.dumps(
            {
                "id": "cred_id",
                "rawId": "cmVkX2lk",
                "response": {
                    "clientDataJSON": "Y2xpZW50IGRhdGE=",
                    "authenticatorData": "YXV0aCBkYXRh",
                    "attestationObject": "YXR0ZXN0YXRpb24=",
                },
                "type": "public-key",
                "clientExtensionResults": {},
            }
        )
        args.label = None
        args.json = True

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_enroll_complete(client, args)

        assert result == 0
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert parsed["status"] == "ok"
        assert parsed["user_id"] == "jsmith"
        assert parsed["credential_id"] == "cred_enrolled_789"
        client.close()
        config_file.unlink()

    def test_enroll_complete_without_label(self):
        """Enroll complete without optional label omits it from payload."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "status": "ok",
                "user_id": "jsmith",
                "credential_id": "cred_enrolled_789",
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll_abc"
        args.challenge_id = "enroll_chal_123"
        args.response = json.dumps(
            {
                "id": "cred_id",
                "rawId": "cmVkX2lk",
                "response": {
                    "clientDataJSON": "Y2xpZW50IGRhdGE=",
                    "authenticatorData": "YXV0aCBkYXRh",
                    "attestationObject": "YXR0ZXN0YXRpb24=",
                },
                "type": "public-key",
                "clientExtensionResults": {},
            }
        )
        args.label = None
        args.json = False

        result = cmd_enroll_complete(client, args)
        assert result == 0

        call_args = mock_http.request.call_args
        payload = call_args[1]["json"]
        assert "label" not in payload
        client.close()
        config_file.unlink()

    def test_enroll_complete_400_invalid_token(self):
        """Enroll complete with invalid token returns 400."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Enrollment token is invalid"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "invalid_token"
        args.challenge_id = "enroll_chal_123"
        args.response = json.dumps({"id": "cred_id", "response": {}})
        args.label = None
        args.json = False

        result = cmd_enroll_complete(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_enroll_complete_400_bad_challenge(self):
        """Enroll complete with bad challenge/response returns 400."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Invalid WebAuthn challenge or response"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll"
        args.challenge_id = "bad_chal"
        args.response = json.dumps({"id": "cred_id", "response": {}})
        args.label = None
        args.json = False

        result = cmd_enroll_complete(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_enroll_complete_invalid_json_response(self):
        """Enroll complete with invalid JSON response returns 1."""
        client, config_file = _make_client()
        MagicMock()

        args = MagicMock()
        args.token = "tok_enroll"
        args.challenge_id = "enroll_chal_123"
        args.response = "not valid json {{{"
        args.label = None
        args.json = False

        result = cmd_enroll_complete(client, args)
        assert result == 1
        client.close()
        config_file.unlink()

    def test_enroll_complete_network_error(self):
        """Enroll complete with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.token = "tok_enroll"
        args.challenge_id = "enroll_chal_123"
        args.response = json.dumps({"id": "cred_id", "response": {}})
        args.label = None
        args.json = False

        result = cmd_enroll_complete(client, args)
        assert result == 1
        client.close()
        config_file.unlink()
