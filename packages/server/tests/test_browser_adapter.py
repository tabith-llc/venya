"""Tests for the browser adapter module."""

import base64

from server.fido2.browser_adapter import (
    base64_to_base64url,
    base64url_decode,
    base64url_encode,
    base64url_to_base64,
    browser_assertion_to_fido2,
    browser_registration_to_fido2,
    challenge_to_browser_options,
    challenge_to_browser_registration_options,
)


class TestBase64RoundTrip:
    """Tests for base64url_encode / base64url_decode round-trip."""

    def test_roundtrip_empty(self):
        assert base64url_decode(base64url_encode(b"")) == b""

    def test_roundtrip_ascii(self):
        data = b"hello world"
        assert base64url_decode(base64url_encode(data)) == data

    def test_roundtrip_binary(self):
        data = bytes(range(256))
        assert base64url_decode(base64url_encode(data)) == data

    def test_roundtrip_32_bytes(self):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" * 2
        assert base64url_decode(base64url_encode(data)) == data

    def test_output_has_no_padding(self):
        encoded = base64url_encode(b"hello")
        assert "=" not in encoded

    def test_output_has_no_plus_or_slash(self):
        # 0xff 0xff 0xff → base64url should not have + or /
        encoded = base64url_encode(b"\xff\xff\xff")
        assert "+" not in encoded
        assert "/" not in encoded


class TestBase64Conversion:
    """Tests for base64 ↔ base64url conversion."""

    def test_base64_to_base64url_removes_padding(self):
        # "hello" → standard base64 = "aGVsbG8=" → base64url = "aGVsbG8"
        assert base64_to_base64url("aGVsbG8=") == "aGVsbG8"

    def test_base64_to_base64url_no_padding_needed(self):
        # "Hello" → standard base64 = "SGVsbG8=" → base64url = "SGVsbG8"
        # Actually "SGVsbG8=" has padding, let's use a case without
        # "f" → "Zg==" → "Zg"
        assert base64_to_base64url("Zg==") == "Zg"

    def test_base64url_to_base64_adds_padding(self):
        assert base64url_to_base64("aGVsbG8") == "aGVsbG8="

    def test_base64url_to_base64_no_padding_input(self):
        assert base64url_to_base64("SGVsbG8") == "SGVsbG8="

    def test_roundtrip_base64_to_base64url_to_base64(self):
        original = "aGVsbG8="
        b64url = base64_to_base64url(original)
        back = base64url_to_base64(b64url)
        assert back == original


class TestChallengeToBrowserOptions:
    """Tests for challenge_to_browser_options conversion."""

    def test_converts_challenge(self):
        options = {"challenge": base64.b64encode(b"test-challenge").decode()}
        result = challenge_to_browser_options("chal-1", options)
        # Should be base64url without padding
        assert "challenge" in result
        assert "=" not in result["challenge"]

    def test_converts_rp_id(self):
        options = {"rpId": "example.com", "rpName": "Example"}
        result = challenge_to_browser_options("chal-1", options)
        assert result["rp"] == {"id": "example.com", "name": "Example"}

    def test_converts_rp_dict(self):
        options = {"rp": {"id": "example.com", "name": "Example"}}
        result = challenge_to_browser_options("chal-1", options)
        assert result["rp"] == {"id": "example.com", "name": "Example"}

    def test_converts_user(self):
        user_b64 = base64.b64encode(b"user123").decode()
        options = {
            "user": {
                "id": user_b64,
                "name": "alice",
                "displayName": "Alice",
            }
        }
        result = challenge_to_browser_options("chal-1", options)
        assert result["user"]["name"] == "alice"
        assert result["user"]["displayName"] == "Alice"
        assert "=" not in result["user"]["id"]
        assert base64url_decode(result["user"]["id"]) == b"user123"

    def test_converts_pubKeyCredParams(self):
        options = {
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ]
        }
        result = challenge_to_browser_options("chal-1", options)
        assert result["pubKeyCredParams"] == options["pubKeyCredParams"]

    def test_converts_timeout(self):
        options = {"timeout": 60000}
        result = challenge_to_browser_options("chal-1", options)
        assert result["timeout"] == 60000

    def test_converts_exclude_credentials(self):
        cred_id_b64 = base64.b64encode(b"some-cred-id").decode()
        options = {
            "excludeCredentials": [
                {"type": "public-key", "id": cred_id_b64},
            ]
        }
        result = challenge_to_browser_options("chal-1", options)
        assert len(result["excludeCredentials"]) == 1
        assert "=" not in result["excludeCredentials"][0]["id"]
        assert result["excludeCredentials"][0]["type"] == "public-key"

    def test_converts_allow_credentials(self):
        cred_id_b64 = base64.b64encode(b"cred-abc").decode()
        options = {
            "allowCredentials": [
                {"type": "public-key", "id": cred_id_b64},
            ]
        }
        result = challenge_to_browser_options("chal-1", options)
        assert len(result["allowCredentials"]) == 1
        assert "=" not in result["allowCredentials"][0]["id"]

    def test_converts_user_verification(self):
        options = {"userVerification": "required"}
        result = challenge_to_browser_options("chal-1", options)
        assert result["userVerification"] == "required"

    def test_converts_attestation(self):
        options = {"attestation": "none"}
        result = challenge_to_browser_options("chal-1", options)
        assert result["attestation"] == "none"


class TestChallengeToBrowserRegistrationOptions:
    """Tests for challenge_to_browser_registration_options (alias)."""

    def test_is_alias_for_challenge_to_browser_options(self):
        options = {
            "challenge": base64.b64encode(b"reg-chal").decode(),
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": base64.b64encode(b"user1").decode(),
                "name": "alice",
                "displayName": "Alice",
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -257}],
            "attestation": "none",
        }
        result = challenge_to_browser_registration_options("chal-1", options)
        expected = challenge_to_browser_options("chal-1", options)
        assert result == expected


class TestBrowserAssertionToFido2:
    """Tests for browser_assertion_to_fido2 conversion."""

    def test_converts_id(self):
        assertion = {"id": "dGVzdA"}  # base64url for "test"
        result = browser_assertion_to_fido2(assertion)
        # Should convert to standard base64
        assert result["id"] == "dGVzdA=="

    def test_converts_raw_id(self):
        assertion = {"rawId": "dGVzdA"}
        result = browser_assertion_to_fido2(assertion)
        assert result["rawId"] == "dGVzdA=="

    def test_copies_response(self):
        assertion = {"response": {"clientDataJSON": "abc"}}
        result = browser_assertion_to_fido2(assertion)
        assert result["response"] == {"clientDataJSON": "abc"}

    def test_copies_transports(self):
        assertion = {"transports": ["internal", "usb"]}
        result = browser_assertion_to_fido2(assertion)
        assert result["transports"] == ["internal", "usb"]

    def test_copies_authenticator_data(self):
        assertion = {"authenticatorData": "some-data"}
        result = browser_assertion_to_fido2(assertion)
        assert result["authenticatorData"] == "some-data"

    def test_copies_signature(self):
        assertion = {"signature": "sig-data"}
        result = browser_assertion_to_fido2(assertion)
        assert result["signature"] == "sig-data"

    def test_copies_user_handle(self):
        assertion = {"userHandle": "handle-data"}
        result = browser_assertion_to_fido2(assertion)
        assert result["userHandle"] == "handle-data"

    def test_minimal_assertion(self):
        assertion = {"id": "dGVzdA"}
        result = browser_assertion_to_fido2(assertion)
        assert result == {"id": "dGVzdA=="}


class TestBrowserRegistrationToFido2:
    """Tests for browser_registration_to_fido2 conversion."""

    def test_converts_id(self):
        registration = {"id": "dGVzdA"}
        result = browser_registration_to_fido2(registration)
        assert result["id"] == "dGVzdA=="

    def test_converts_raw_id(self):
        registration = {"rawId": "dGVzdA"}
        result = browser_registration_to_fido2(registration)
        assert result["rawId"] == "dGVzdA=="

    def test_copies_response(self):
        registration = {"response": {"attestationObject": "abc"}}
        result = browser_registration_to_fido2(registration)
        assert result["response"] == {"attestationObject": "abc"}

    def test_copies_transports(self):
        registration = {"transports": ["nfc"]}
        result = browser_registration_to_fido2(registration)
        assert result["transports"] == ["nfc"]

    def test_copies_authenticator_attestation_response(self):
        registration = {"authenticatorAttestationResponse": {"attestationObject": "abc"}}
        result = browser_registration_to_fido2(registration)
        assert result["authenticatorAttestationResponse"] == {"attestationObject": "abc"}

    def test_copies_client_extension_results(self):
        registration = {"clientExtensionResults": {}}
        result = browser_registration_to_fido2(registration)
        assert result["clientExtensionResults"] == {}

    def test_minimal_registration(self):
        registration = {"id": "dGVzdA"}
        result = browser_registration_to_fido2(registration)
        assert result == {"id": "dGVzdA=="}


class FullRoundTrip:
    """Integration tests: full round-trip conversions."""

    def test_challenge_roundtrip(self):
        """Server → browser → server challenge conversion."""
        raw_challenge = b"a" * 32
        server_challenge = base64.b64encode(raw_challenge).decode()
        browser_challenge = base64_to_base64url(server_challenge)
        back = base64url_to_base64(browser_challenge)
        assert back == server_challenge

    def test_credential_id_roundtrip(self):
        """Server → browser → server credential ID conversion."""
        raw_id = b"credential-id-12345"
        server_id = base64.b64encode(raw_id).decode()
        browser_id = base64_to_base64url(server_id)
        back = base64url_to_base64(browser_id)
        assert back == server_id

    def test_assertion_roundtrip(self):
        """Browser assertion → fido2 → serialization → browser assertion."""
        browser_assertion = {
            "id": base64.urlsafe_b64encode(b"cred-123").decode().rstrip("="),
            "rawId": base64.urlsafe_b64encode(b"cred-123").decode().rstrip("="),
            "response": {"clientDataJSON": "test"},
            "transports": ["internal"],
        }
        fido2 = browser_assertion_to_fido2(browser_assertion)
        # fido2.id should be standard base64
        assert "=" in fido2["id"]
        # Decode back to verify
        assert base64.b64decode(fido2["id"]) == b"cred-123"

    def test_registration_roundtrip(self):
        """Browser registration → fido2 conversion."""
        browser_reg = {
            "id": base64.urlsafe_b64encode(b"new-cred").decode().rstrip("="),
            "response": {"attestationObject": "obj"},
            "transports": ["usb", "nfc"],
        }
        fido2 = browser_registration_to_fido2(browser_reg)
        assert base64.b64decode(fido2["id"]) == b"new-cred"
        assert fido2["transports"] == ["usb", "nfc"]
