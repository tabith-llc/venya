# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for CLI credential list, add, and remove commands."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx2
from venya_cli.api_client import APIClient, APIClientError
from venya_cli.commands import cmd_credential_add, cmd_credential_list, cmd_credential_remove


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
# cmd_credential_list tests
# ---------------------------------------------------------------------------


class TestCredentialList:
    """Tests for venya credential list command."""

    def test_list_credentials_success(self):
        """List credentials shows table with all columns."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "credentials": [
                    {
                        "id": 1,
                        "label": "YubiKey 1",
                        "created_at": "2025-01-01T00:00:00",
                        "last_used_at": "2025-01-15T10:30:00",
                    },
                    {
                        "id": 2,
                        "label": None,
                        "created_at": "2025-02-01T00:00:00",
                        "last_used_at": None,
                    },
                ]
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.json = False

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_credential_list(client, args)
        assert result == 0
        table = f.getvalue()
        # Regression: int DB ids (the real server shape) must render, not raise
        # TypeError in the len() width pass ("object of type 'int' has no len()")
        assert "1" in table and "YubiKey 1" in table

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "GET"
        assert call_args[0][1] == "/api/v1/credentials"
        client.close()
        config_file.unlink()

    def test_list_credentials_json_output(self):
        """List credentials with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={
                "credentials": [
                    {
                        "id": 1,
                        "label": "YubiKey 1",
                        "created_at": "2025-01-01T00:00:00",
                        "last_used_at": "2025-01-15T10:30:00",
                    },
                ]
            },
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.json = True

        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            result = cmd_credential_list(client, args)

        assert result == 0
        output = f.getvalue()
        parsed = json.loads(output.strip())
        assert "credentials" in parsed
        assert len(parsed["credentials"]) == 1
        assert parsed["credentials"][0]["label"] == "YubiKey 1"
        client.close()
        config_file.unlink()

    def test_list_credentials_empty(self):
        """List credentials with no credentials prints message."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"credentials": []},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        args = MagicMock()
        args.json = False

        result = cmd_credential_list(client, args)
        assert result == 0
        client.close()
        config_file.unlink()

    def test_list_credentials_network_error(self):
        """List credentials with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        args = MagicMock()
        args.json = False

        result = cmd_credential_list(client, args)
        assert result == 1
        client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# cmd_credential_add tests
# ---------------------------------------------------------------------------


class TestCredentialAdd:
    """Tests for venya credential add command."""

    def _make_mock_credential(self):
        """Create a mock credential in the REAL fido2 2.x RegistrationResponse
        shape (.id/.raw_id + .response) that Fido2Client/WindowsClient
        make_credential actually returns.

        The legacy CredentialSelection shape (.auth_response) this replaced is
        never produced by the pinned library — the old MagicMock encoded that
        lie and masked an AttributeError in cmd_credential_add's formatter
        (ticket: windows-fido2-requires-elevation, latent cross-platform bug).
        SimpleNamespace, not MagicMock: hasattr() must discriminate branches.
        """
        from types import SimpleNamespace

        client_data = SimpleNamespace(
            type="webauthn.create",
            challenge=b"test-challenge",
            origin="https://localhost",
            cross_origin=False,
        )
        response = SimpleNamespace(
            attestation_object=b"attestation_bytes",
            client_data=client_data,
            transports=None,
        )
        return SimpleNamespace(id=None, raw_id=b"cred_id_bytes", response=response)

    def test_add_credential_success(self):
        """Add credential succeeds through elevation + registration flow."""
        client, config_file = _make_client()
        mock_http = MagicMock()

        # Credential add start response
        start_resp = _make_mock_response(
            status_code=200,
            json_data={
                "challenge_id": "cred_chal_456",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        )
        start_resp.raise_for_status.return_value = None

        # Credential add complete response
        complete_resp = _make_mock_response(
            status_code=200,
            json_data={
                "id": "cred_new_789",
                "label": "YubiKey 2",
                "status": "ok",
            },
        )
        complete_resp.raise_for_status.return_value = None

        mock_http.request.side_effect = [start_resp, complete_resp]
        client._http = mock_http

        mock_credential = self._make_mock_credential()

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            with patch("venya_cli.fido2_client.list_devices", return_value=["fake_device"]):
                with patch("venya_cli.fido2_client.Fido2Client") as mock_fido2:
                    mock_instance = MagicMock()
                    mock_fido2.return_value = mock_instance
                    mock_instance.make_credential.return_value = mock_credential
                    args = MagicMock()
                    args.label = "YubiKey 2"
                    args.json = False

                    result = cmd_credential_add(client, args)
                    assert result == 0

        call_args = mock_http.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/v1/credentials/add/browser/complete"
        client.close()
        config_file.unlink()

    def test_add_credential_json_output(self):
        """Add credential with --json outputs raw JSON."""
        client, config_file = _make_client()
        mock_http = MagicMock()

        start_resp = _make_mock_response(
            status_code=200,
            json_data={
                "challenge_id": "cred_chal_456",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp": {"name": "Venya"},
                    "user": {"id": "dXNlcjEyMw==", "name": "jsmith", "displayName": "jsmith"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60000,
                },
            },
        )
        start_resp.raise_for_status.return_value = None

        complete_resp = _make_mock_response(
            status_code=200,
            json_data={
                "id": "cred_new_789",
                "label": "YubiKey 2",
                "status": "ok",
            },
        )
        complete_resp.raise_for_status.return_value = None

        mock_http.request.side_effect = [start_resp, complete_resp]
        client._http = mock_http

        mock_credential = self._make_mock_credential()

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            with patch("venya_cli.fido2_client.list_devices", return_value=["fake_device"]):
                with patch("venya_cli.fido2_client.Fido2Client") as mock_fido2:
                    mock_instance = MagicMock()
                    mock_fido2.return_value = mock_instance
                    mock_instance.make_credential.return_value = mock_credential

                    args = MagicMock()
                    args.label = "YubiKey 2"
                    args.json = True

                    import io
                    from contextlib import redirect_stdout

                    f = io.StringIO()
                    with redirect_stdout(f):
                        result = cmd_credential_add(client, args)

                    assert result == 0
                    output = f.getvalue()
                    # Extract JSON from output (elevation messages come before JSON)
                    json_start = output.find("{")
                    assert json_start >= 0
                    parsed = json.loads(output[json_start:])
                    assert parsed["id"] == "cred_new_789"
                    assert parsed["label"] == "YubiKey 2"
        client.close()
        config_file.unlink()

    def test_add_credential_no_fido2_device(self):
        """Add credential with no FIDO2 device returns error."""
        client, config_file = _make_client()
        MagicMock()

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            with patch("venya_cli.fido2_client.list_devices", return_value=[]):
                args = MagicMock()
                args.label = "YubiKey 2"
                args.json = False

                result = cmd_credential_add(client, args)
                assert result == 1
        client.close()
        config_file.unlink()

    def test_add_credential_last_key_guard(self):
        """Add credential 400 error (last-key guard) returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()

        start_resp = _make_mock_response(
            status_code=400,
            json_data={"detail": "Cannot remove last credential"},
        )
        start_resp.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=start_resp
        )
        mock_http.request.return_value = start_resp
        client._http = mock_http

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            args = MagicMock()
            args.label = "YubiKey 2"
            args.json = False

            result = cmd_credential_add(client, args)
            assert result == 1
        client.close()
        config_file.unlink()


# ---------------------------------------------------------------------------
# cmd_credential_remove tests
# ---------------------------------------------------------------------------


class TestCredentialRemove:
    """Tests for venya credential remove command."""

    def test_remove_credential_success(self):
        """Remove credential succeeds."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=200,
            json_data={"deleted": True},
        )
        mock_response.raise_for_status.return_value = None
        mock_http.request.return_value = mock_response
        client._http = mock_http

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            args = MagicMock()
            args.credential_id = "cred_001"
            args.json = False

            result = cmd_credential_remove(client, args)
            assert result == 0

            call_args = mock_http.request.call_args
            assert call_args[0][0] == "DELETE"
            assert call_args[0][1] == "/api/v1/credentials/cred_001"
        client.close()
        config_file.unlink()

    def test_remove_credential_404_not_found(self):
        """Remove non-existent credential returns 404."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=404,
            json_data={"detail": "Credential not found"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "not found", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            args = MagicMock()
            args.credential_id = "cred_nonexistent"
            args.json = False

            result = cmd_credential_remove(client, args)
            assert result == 1
        client.close()
        config_file.unlink()

    def test_remove_credential_400_last_key_guard(self):
        """Remove last credential returns 400."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_response = _make_mock_response(
            status_code=400,
            json_data={"detail": "Cannot remove last credential"},
        )
        mock_response.raise_for_status.side_effect = httpx2.HTTPStatusError(
            "bad request", request=MagicMock(), response=mock_response
        )
        mock_http.request.return_value = mock_response
        client._http = mock_http

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            args = MagicMock()
            args.credential_id = "cred_last"
            args.json = False

            result = cmd_credential_remove(client, args)
            assert result == 1
        client.close()
        config_file.unlink()

    def test_remove_credential_no_elevation(self):
        """Remove credential with elevation failure returns 1."""
        client, config_file = _make_client()
        MagicMock()

        with patch("venya_cli.commands._elevate", side_effect=APIClientError("Elevation failed")):
            args = MagicMock()
            args.credential_id = "cred_001"
            args.json = False

            result = cmd_credential_remove(client, args)
            assert result == 1
        client.close()
        config_file.unlink()

    def test_remove_credential_network_error(self):
        """Remove credential with network error returns 1."""
        client, config_file = _make_client()
        mock_http = MagicMock()
        mock_http.request.side_effect = httpx2.ConnectError("Connection refused")
        client._http = mock_http

        with patch("venya_cli.commands._elevate", return_value="elev_token_xyz"):
            args = MagicMock()
            args.credential_id = "cred_001"
            args.json = False

            result = cmd_credential_remove(client, args)
            assert result == 1
        client.close()
        config_file.unlink()


class TestElevateBearerToken:
    """Regression for _elevate (found PHYSICALLY on win11, 2026-09-19): the
    /auth/elevate/* routes require the session bearer token
    (Depends(get_current_user)). Pre-fix _elevate called Fido2Auth._post, which
    sends no Authorization header, so every elevation on every platform died
    401 'Missing authentication token'. Both calls must go through APIClient."""

    def test_elevate_sends_authorization_on_both_calls(self):
        from venya_cli.commands import _elevate
        from venya_cli.fido2_client import Fido2Auth

        client, config_file = _make_client()
        client.config.access_token = "test-token-abc"
        client.config.server_url = "https://venya-core-1"
        mock_http = MagicMock()
        challenge_resp = _make_mock_response(
            status_code=200,
            json_data={
                "challenge_id": "chal_1",
                "options": {
                    "challenge": "dGVzdC1jaGFsbGVuZ2U=",
                    "rp_id": "venya-core-1",
                    "timeout": 60000,
                },
            },
        )
        assert_resp = _make_mock_response(status_code=200, json_data={"elevation_token": "elev_tok"})
        mock_http.request.side_effect = [challenge_resp, assert_resp]
        client._http = mock_http

        with patch.object(Fido2Auth, "_get_assertion", return_value=MagicMock()):
            with patch.object(Fido2Auth, "_format_assertion_response", return_value={"id": "x"}):
                token = _elevate(client)

        assert token == "elev_tok"
        assert mock_http.request.call_count == 2
        paths = [c.args[1] for c in mock_http.request.call_args_list]
        assert paths == ["/api/v1/auth/elevate/challenge", "/api/v1/auth/elevate/assert"]
        for call in mock_http.request.call_args_list:
            headers = call.kwargs.get("headers") or {}
            assert (
                headers.get("Authorization") == "Bearer test-token-abc"
            ), f"elevate call to {call.args[1]} missing bearer token"
        client.close()
        config_file.unlink()
