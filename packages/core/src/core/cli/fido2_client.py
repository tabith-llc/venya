"""Headless FIDO2/WebAuthn client for CLI authentication.

Uses python-fido2 to perform WebAuthn authentication without a browser.
The CLI acts as a headless authenticator that communicates with a FIDO2
security key via USB HID transport.

Flow:
    1. Get challenge options from server (POST /auth/login/start)
    2. Perform WebAuthn assertion with security key
    3. Send assertion to server (POST /auth/login/complete)
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx2
from fido2.client import WebAuthnClient
from fido2.hid import list_devices
from fido2.webauthn import (
    AuthenticatorData,
    CollectedClientData,
    CredentialRequestOptions,
    CredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
)

logger = logging.getLogger("core.cli.fido2")


def _b64url_decode(data: str) -> bytes:
    """Decode a base64url-encoded string with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Fido2ClientError(Exception):
    """FIDO2 client error."""


class Fido2NotFoundError(Fido2ClientError):
    """No FIDO2 device found."""


class Fido2TimeoutError(Fido2ClientError):
    """FIDO2 operation timed out."""


class Fido2UserInteractionRequiredError(Fido2ClientError):
    """User interaction (key touch) required."""


class Fido2Auth:
    """Headless FIDO2/WebAuthn client for CLI authentication.

    Usage:
        auth = Fido2Auth(server_url="http://localhost:8000")
        result = auth.authenticate(user_id="admin")
        # result = {"user_id": "...", "session_token": "..."}
    """

    def __init__(self, server_url: str = "http://localhost:8000") -> None:
        self.server_url = server_url.rstrip("/")

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Simple GET request."""
        url = self.server_url + path
        try:
            with httpx2.Client() as client:
                resp = client.get(url, params=params, timeout=30.0)
                resp.raise_for_status()
                return resp.json() if resp.content else {}
        except httpx2.HTTPStatusError as e:
            error_msg = str(e)
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except (json.JSONDecodeError, Exception):  # noqa: F841
                pass
            raise Fido2ClientError(error_msg)
        except httpx2.ConnectError as e:
            raise Fido2ClientError(f"Connection failed: {e}")

    def _post(self, path: str, json_data: dict[str, Any]) -> dict[str, Any]:
        """Simple POST request."""
        url = self.server_url + path
        try:
            with httpx2.Client() as client:
                resp = client.post(
                    url,
                    json=json_data,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    timeout=30.0,
                )
                resp.raise_for_status()
                return resp.json() if resp.content else {}
        except httpx2.HTTPStatusError as e:
            error_msg = str(e)
            try:
                error_data = e.response.json()
                error_msg = error_data.get("detail", str(e))
            except (json.JSONDecodeError, Exception):  # noqa: F841
                pass
            raise Fido2ClientError(error_msg)
        except httpx2.ConnectError as e:
            raise Fido2ClientError(f"Connection failed: {e}")

    def authenticate(self, user_id: str | None = None, timeout: float = 60.0) -> dict[str, Any]:
        """Perform WebAuthn authentication.

        Args:
            user_id: Optional user ID to target. If not provided,
                     the user can authenticate with any enrolled key.
            timeout: Maximum seconds to wait for user interaction.

        Returns:
            Dict with user_id and session_token.

        Raises:
            Fido2ClientError: On authentication failure.
            Fido2NotFoundError: If no FIDO2 device is found.
            Fido2TimeoutError: If user doesn't touch key in time.
        """
        # Step 1: Get challenge from server
        logger.info("Requesting authentication challenge from server")
        start_result = self._post("/api/v1/auth/login/start", {
            "user_id": user_id,
        })
        challenge_id = start_result["challenge_id"]
        options = start_result["options"]

        # Step 2: Convert server options to fido2 types
        request_options = self._build_request_options(options)

        # Step 3: Perform WebAuthn assertion
        logger.info("Waiting for security key touch...")
        try:
            assertion = self._get_assertion(request_options, timeout=timeout)
        except OSError as e:
            # OSError covers device not found, USB errors, etc.
            # TimeoutError is a subclass of OSError on some platforms
            err_str = str(e).lower()
            if "fido" in err_str or "device" in err_str or "usb" in err_str or "no such" in err_str:
                raise Fido2NotFoundError(f"No FIDO2 device found: {e}") from e
            if "time" in err_str or "timeout" in err_str:
                raise Fido2TimeoutError(f"Authentication timed out: {e}") from e
            raise Fido2ClientError(f"FIDO2 error: {e}") from e
        except ValueError as e:
            err_msg = str(e).lower()
            if "user" in err_msg or "presence" in err_msg or "touch" in err_msg:
                raise Fido2UserInteractionRequiredError(
                    "Please touch your security key"
                ) from e
            raise Fido2ClientError(f"FIDO2 error: {e}") from e

        # Step 4: Convert assertion to server format and complete
        logger.info("Sending assertion to server")
        response = self._format_assertion_response(assertion)
        result = self._post("/api/v1/auth/login/complete", {
            "challenge_id": challenge_id,
            "response": response,
        })

        return {
            "user_id": result["user_id"],
            "session_token": result["session_token"],
            "credential_id": result["credential_id"],
        }

    def register(self, user_id: str, timeout: float = 60.0) -> dict[str, Any]:
        """Perform WebAuthn registration (enrollment).

        Used during core init to enroll the first admin's security key.

        Args:
            user_id: User ID to register.
            timeout: Maximum seconds to wait for user interaction.

        Returns:
            Dict with the server-expected attestation response format.

        Raises:
            Fido2ClientError: On registration failure.
            Fido2NotFoundError: If no FIDO2 device is found.
            Fido2TimeoutError: If user doesn't touch key in time.
        """
        # Step 1: Get challenge from server
        logger.info("Requesting registration challenge from server for user %s", user_id)
        start_result = self._post("/api/v1/init", {
            "user_id": user_id,
        })
        challenge_id = start_result["challenge_id"]
        options = start_result["options"]

        # Step 2: Convert server options to fido2 types
        request_options = self._build_registration_options(options)

        # Step 3: Perform WebAuthn creation
        logger.info("Waiting for security key touch to register...")
        try:
            credential = self._get_credential(request_options, timeout=timeout)
        except OSError as e:
            err_str = str(e).lower()
            if "fido" in err_str or "device" in err_str or "usb" in err_str or "no such" in err_str:
                raise Fido2NotFoundError(f"No FIDO2 device found: {e}") from e
            if "time" in err_str or "timeout" in err_str:
                raise Fido2TimeoutError(f"Registration timed out: {e}") from e
            raise Fido2ClientError(f"FIDO2 error: {e}") from e
        except ValueError as e:
            err_msg = str(e).lower()
            if "user" in err_msg or "presence" in err_msg or "touch" in err_msg:
                raise Fido2UserInteractionRequiredError(
                    "Please touch your security key"
                ) from e
            raise Fido2ClientError(f"FIDO2 error: {e}") from e

        # Step 4: Convert credential to server format and complete
        logger.info("Sending attestation to server")
        response = self._format_credential_response(credential)
        result = self._post("/api/v1/init/complete", {
            "user_id": user_id,
            "challenge_id": challenge_id,
            "response": response,
        })

        return result

    def _build_registration_options(
        self, options: dict[str, Any]
    ) -> CredentialCreationOptions:
        """Convert server challenge options to fido2 CredentialCreationOptions.

        Args:
            options: WebAuthn registration options from server.

        Returns:
            CredentialCreationOptions for python-fido2.
        """
        challenge = _b64url_decode(options["challenge"])

        pub_key_cred_params = []
        for param in options.get("pubKeyCredParams", []):
            pub_key_cred_params.append({
                "type": param.get("type", "public-key"),
                "alg": param.get("alg"),
            })

        exclude_credentials = []
        for cred in options.get("excludeCredentials", []):
            if "id" in cred:
                cred_id = _b64url_decode(cred["id"])
                exclude_credentials.append(PublicKeyCredentialDescriptor(
                    type=cred.get("type", "public-key"),
                    id=cred_id,
                    transports=cred.get("transports"),
                ))

        user_id = _b64url_decode(options["user"]["id"])

        public_key = {
            "rp": options.get("rp", {}),
            "user": {
                "id": user_id,
                "name": options["user"].get("name", ""),
                "display_name": options["user"].get("displayName", ""),
            },
            "challenge": challenge,
            "pubKeyCredParams": pub_key_cred_params,
            "timeout": options.get("timeout", 60000),
            "excludeCredentials": exclude_credentials or None,
            "attestation": options.get("attestation", "none"),
        }

        return CredentialCreationOptions(public_key=public_key)

    def _get_credential(
        self,
        request_options: CredentialCreationOptions,
        timeout: float = 60.0,
    ) -> Any:
        """Perform WebAuthn credential creation using python-fido2.

        Args:
            request_options: Credential creation options.
            timeout: Timeout in seconds.

        Returns:
            Credential selection from python-fido2.
        """
        devices = list_devices()
        if not devices:
            raise Fido2NotFoundError("No FIDO2 devices found")

        client = WebAuthnClient()
        return client.make_credential(request_options.public_key)

    def _format_credential_response(
        self,
        credential: Any,
    ) -> dict[str, Any]:
        """Convert python-fido2 credential to server-expected format.

        Args:
            credential: CredentialSelection from python-fido2.

        Returns:
            Dict in the format the server expects for init/complete.
        """
        auth_response = credential.auth_response

        # credential ID
        cred_id = auth_response.credential_id

        # authenticator data (raw bytes)
        auth_data = auth_response.auth_data

        # client data
        client_data = auth_response.client_data

        # attestation object (raw bytes)
        attestation_object = auth_response.attestation_object

        return {
            "id": _b64url_encode(cred_id),
            "rawId": _b64url_encode(cred_id),
            "response": {
                "clientDataJSON": _b64url_encode(
                    _serialize_client_data(client_data)
                ),
                "authenticatorData": _b64url_encode(_serialize_auth_data(auth_data)),
                "attestationObject": _b64url_encode(attestation_object),
                "transports": auth_response.transports or [],
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }

    def _build_request_options(
        self, options: dict[str, Any]
    ) -> CredentialRequestOptions:
        """Convert server challenge options to fido2 CredentialRequestOptions.

        Args:
            options: WebAuthn challenge options from server.

        Returns:
            CredentialRequestOptions for python-fido2.
        """
        challenge = _b64url_decode(options["challenge"])

        allow_credentials = []
        for cred in options.get("allow_credentials", []):
            cred_id = _b64url_decode(cred["id"])
            allow_credentials.append(PublicKeyCredentialDescriptor(
                type=cred.get("type", "public-key"),
                id=cred_id,
                transports=cred.get("transports"),
            ))

        uv_map = {
            "discouraged": UserVerificationRequirement.DISCOURAGED,
            "preferred": UserVerificationRequirement.PREFERRED,
            "required": UserVerificationRequirement.REQUIRED,
        }
        user_verification = uv_map.get(
            options.get("user_verification", "preferred"),
            UserVerificationRequirement.PREFERRED,
        )

        public_key = PublicKeyCredentialRequestOptions(
            challenge=challenge,
            timeout=options.get("timeout"),
            rp_id=options.get("rp_id"),
            allow_credentials=allow_credentials or None,
            user_verification=user_verification,
        )

        return CredentialRequestOptions(public_key=public_key)

    def _get_assertion(
        self,
        request_options: CredentialRequestOptions,
        timeout: float = 60.0,
    ) -> Any:
        """Perform WebAuthn assertion using python-fido2.

        Args:
            request_options: Credential request options.
            timeout: Timeout in seconds.

        Returns:
            Assertion selection from python-fido2.
        """
        devices = list_devices()
        if not devices:
            raise Fido2NotFoundError("No FIDO2 devices found")

        public_key = request_options.public_key
        rp_id = public_key.rp_id or "localhost"

        client = WebAuthnClient(rp_id)
        return client.get_assertion(request_options.public_key)

    def _format_assertion_response(
        self,
        assertion: Any,
    ) -> dict[str, Any]:
        """Convert python-fido2 assertion to server-expected format.

        Args:
            assertion: AssertionSelection from python-fido2.

        Returns:
            Dict in the format the server expects.
        """
        # Use the first assertion (single key)
        auth_response = assertion.assertions[0]

        # credential ID
        cred_id = auth_response.credential["id"]

        # authenticator data (raw bytes)
        auth_data = auth_response.auth_data

        # signature
        signature = auth_response.signature

        # client data
        client_data = assertion.client_data

        return {
            "id": _b64url_encode(cred_id),
            "rawId": _b64url_encode(cred_id),
            "response": {
                "clientDataJSON": _b64url_encode(
                    _serialize_client_data(client_data)
                ),
                "authenticatorData": _b64url_encode(_serialize_auth_data(auth_data)),
                "signature": _b64url_encode(signature),
                "userHandle": None,
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }


def _serialize_client_data(client_data: CollectedClientData) -> bytes:
    """Serialize CollectedClientData to JSON bytes.

    Args:
        client_data: The client data from the assertion.

    Returns:
        JSON-serialized client data bytes.
    """
    data = {
        "type": client_data.type,
        "challenge": _b64url_encode(client_data.challenge),
        "origin": client_data.origin,
        "crossOrigin": client_data.cross_origin,
    }
    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def _serialize_auth_data(auth_data: AuthenticatorData) -> bytes:
    """Serialize AuthenticatorData to raw bytes.

    Args:
        auth_data: The authenticator data from the assertion.

    Returns:
        Raw authenticator data bytes.
    """
    flags_byte = bytes([auth_data.flags.value if hasattr(auth_data.flags, 'value') else int(auth_data.flags)])
    counter_bytes = auth_data.counter.to_bytes(4, byteorder="big")
    return auth_data.rp_id_hash + flags_byte + counter_bytes
