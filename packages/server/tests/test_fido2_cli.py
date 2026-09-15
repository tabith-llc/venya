# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for the FIDO2 CLI enrollment tool."""

from server.fido2.cli_enroll import (
    encode_assertion_response,
    encode_attestation_response,
)


class TestEncodeAttestationResponse:
    """Tests for encode_attestation_response conversion."""

    def test_encodes_credential_id(self):
        response = {"credentialId": b"test-cred-id", "authData": b"auth-data"}
        result = encode_attestation_response(response)
        assert result["id"] == result["rawId"]
        assert result["type"] == "public-key"
        assert result["clientExtensionResults"] == {}

    def test_encodes_auth_data(self):
        auth_data = b"\x04" + b"\x00" * 30 + b"\x00\x00\x00\x01" + b"\x00" * 20
        response = {"credentialId": b"cred", "authData": auth_data, "attStmt": {"sig": "abc"}}
        result = encode_attestation_response(response)
        assert "attestationObject" in result["response"]
        assert result["response"]["publicKey"]  # auth_data is base64url encoded

    def test_attestation_object_is_base64url(self):
        response = {"credentialId": b"cred", "authData": b"auth", "attStmt": {}}
        result = encode_attestation_response(response)
        ao = result["response"]["attestationObject"]
        assert "=" not in ao  # base64url has no padding
        assert "+" not in ao
        assert "/" not in ao

    def test_empty_auth_data(self):
        response = {"credentialId": b"cred", "authData": None, "attStmt": {}}
        result = encode_attestation_response(response)
        # Should not raise, auth_data should be empty string
        assert result["response"]["publicKey"] == ""


class TestEncodeAssertionResponse:
    """Tests for encode_assertion_response conversion."""

    def test_encodes_credential_id(self):
        response = {
            "credentialId": b"test-cred-id",
            "authData": b"auth-data",
            "signature": b"sig-data",
        }
        result = encode_assertion_response(response)
        assert result["id"] == result["rawId"]
        assert result["type"] == "public-key"

    def test_encodes_auth_data(self):
        response = {
            "credentialId": b"cred",
            "authData": b"auth-data",
            "signature": b"sig",
        }
        result = encode_assertion_response(response)
        assert "authenticatorData" in result["response"]
        assert result["response"]["authenticatorData"]  # base64url encoded

    def test_encodes_signature(self):
        response = {
            "credentialId": b"cred",
            "authData": b"auth",
            "signature": b"sig-data",
        }
        result = encode_assertion_response(response)
        assert "signature" in result["response"]
        assert result["response"]["signature"]

    def test_user_handle_optional(self):
        response = {
            "credentialId": b"cred",
            "authData": b"auth",
            "signature": b"sig",
        }
        result = encode_assertion_response(response)
        # userHandle should be empty string when not present
        assert result["response"]["userHandle"] == ""

    def test_user_handle_encoded(self):
        response = {
            "credentialId": b"cred",
            "authData": b"auth",
            "signature": b"sig",
            "userHandle": b"user-handle",
        }
        result = encode_assertion_response(response)
        assert result["response"]["userHandle"]  # base64url encoded


class TestWebSafeEncode:
    """Tests for websafe_encode output format."""

    def test_no_padding(self):
        from server.fido2.cli_enroll import websafe_encode

        encoded = websafe_encode(b"hello world")
        assert "=" not in encoded

    def test_no_plus_or_slash(self):
        from server.fido2.cli_enroll import websafe_encode

        encoded = websafe_encode(b"\xff\xff\xff")
        assert "+" not in encoded
        assert "/" not in encoded

    def test_roundtrip(self):
        from fido2.webauthn import websafe_decode, websafe_encode

        data = b"test data 12345"
        assert websafe_decode(websafe_encode(data)) == data
