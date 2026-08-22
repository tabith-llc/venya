"""Adapter between python-fido2 format and browser WebAuthn JSON format.

The browser WebAuthn API (via @simplewebauthn/browser) uses base64url encoding
without padding. The python-fido2 library uses standard base64 with padding.
This module handles conversion in both directions.
"""

import base64
from typing import Any


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding.

    Args:
        data: Raw bytes to encode.

    Returns:
        Base64url-encoded string without padding.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(s: str) -> bytes:
    """Decode a base64url-encoded string (with or without padding).

    Args:
        s: Base64url-encoded string.

    Returns:
        Decoded bytes.
    """
    padding = "=" * (4 - len(s) % 4) if len(s) % 4 else ""
    return base64.urlsafe_b64decode(s + padding)


def _base64url_bytes_to_b64(s: str) -> str:
    """Convert a base64url-encoded string to standard base64.

    Used when the browser sends base64url data that needs to be
    processed by python-fido2 (which expects standard base64).

    Args:
        s: Base64url-encoded string from the browser.

    Returns:
        Standard base64-encoded string.
    """
    return base64.urlsafe_b64decode(s).decode("latin-1")


def base64_to_base64url(s: str) -> str:
    """Convert standard base64 to base64url without padding.

    Used when converting Fido2Manager output for browser consumption.

    Args:
        s: Standard base64-encoded string.

    Returns:
        Base64url-encoded string without padding.
    """
    decoded = base64.b64decode(s)
    return base64url_encode(decoded)


def base64url_to_base64(s: str) -> str:
    """Convert base64url to standard base64 with padding.

    Used when browser sends base64url data that needs standard base64.

    Args:
        s: Base64url-encoded string from the browser.

    Returns:
        Standard base64-encoded string with padding.
    """
    decoded = base64url_decode(s)
    return base64.b64encode(decoded).decode("ascii")


def challenge_to_browser_options(challenge_id: str, options: dict[str, Any]) -> dict[str, Any]:
    """Convert Fido2Manager registration/login options to browser format.

    Converts base64-encoded fields to base64url without padding.

    Args:
        challenge_id: The challenge ID from Fido2Manager.
        options: The options dict from Fido2Manager (base64-encoded).

    Returns:
        Browser-compatible PublicKeyCredentialRequestOptions or
        PublicKeyCredentialCreationOptions dict.
    """
    browser_options: dict[str, Any] = {}

    # Convert challenge
    if "challenge" in options:
        browser_options["challenge"] = base64_to_base64url(options["challenge"])
    else:
        browser_options["challenge"] = options.get("challenge", "")

    # Convert rp
    if "rp" in options:
        browser_options["rp"] = options["rp"]
    elif "rpId" in options:
        browser_options["rp"] = {
            "id": options["rpId"],
            "name": options.get("rpName", "Venya"),
        }

    # Convert user (registration only)
    if "user" in options:
        user = options["user"]
        browser_options["user"] = {
            "id": base64_to_base64url(user["id"]),
            "name": user.get("name", ""),
            "displayName": user.get("displayName", ""),
        }

    # Convert pubKeyCredParams
    if "pubKeyCredParams" in options:
        browser_options["pubKeyCredParams"] = options["pubKeyCredParams"]

    # Convert timeout
    if "timeout" in options:
        browser_options["timeout"] = options["timeout"]

    # Convert excludeCredentials
    if "excludeCredentials" in options:
        browser_options["excludeCredentials"] = [
            {
                "type": c.get("type", "public-key"),
                "id": base64_to_base64url(c["id"]),
            }
            for c in options["excludeCredentials"]
        ]

    # Convert allowCredentials
    if "allowCredentials" in options:
        browser_options["allowCredentials"] = [
            {
                "type": c.get("type", "public-key"),
                "id": base64_to_base64url(c["id"]),
            }
            for c in options["allowCredentials"]
        ]

    # Convert userVerification
    if "userVerification" in options:
        browser_options["userVerification"] = options["userVerification"]

    # Convert attestation
    if "attestation" in options:
        browser_options["attestation"] = options["attestation"]

    return browser_options


def challenge_to_browser_registration_options(
    challenge_id: str,
    options: dict[str, Any],
) -> dict[str, Any]:
    """Convert Fido2Manager registration options to browser format.

    Alias for challenge_to_browser_options with explicit naming for
    registration flow clarity.

    Args:
        challenge_id: The challenge ID from Fido2Manager.
        options: The registration options dict from Fido2Manager.

    Returns:
        Browser-compatible PublicKeyCredentialCreationOptions dict.
    """
    return challenge_to_browser_options(challenge_id, options)


def browser_assertion_to_fido2(assertion: dict[str, Any]) -> dict[str, Any]:
    """Convert browser assertion response to fido2-compatible format.

    Converts base64url-encoded fields back to standard base64.

    Args:
        assertion: Browser assertion response from @simplewebauthn/browser.

    Returns:
        Dict compatible with Fido2Manager.finish_authentication().
    """
    fido2_response: dict[str, Any] = {}

    # Convert id (rawId) from base64url to base64
    if "id" in assertion:
        fido2_response["id"] = base64url_to_base64(assertion["id"])

    # Convert rawId from base64url to base64
    if "rawId" in assertion:
        fido2_response["rawId"] = base64url_to_base64(assertion["rawId"])

    # Copy response data
    if "response" in assertion:
        fido2_response["response"] = assertion["response"]

    # Copy transports
    if "transports" in assertion:
        fido2_response["transports"] = assertion["transports"]

    # Copy authenticator_data if present
    if "authenticatorData" in assertion:
        fido2_response["authenticatorData"] = assertion["authenticatorData"]

    # Copy signature if present
    if "signature" in assertion:
        fido2_response["signature"] = assertion["signature"]

    # Copy userHandle if present
    if "userHandle" in assertion:
        fido2_response["userHandle"] = assertion["userHandle"]

    return fido2_response


def browser_registration_to_fido2(registration: dict[str, Any]) -> dict[str, Any]:
    """Convert browser registration response to fido2-compatible format.

    Converts base64url-encoded fields back to standard base64.

    Args:
        registration: Browser registration response from @simplewebauthn/browser.

    Returns:
        Dict compatible with Fido2Manager.finish_registration().
    """
    fido2_response: dict[str, Any] = {}

    # Convert id (rawId) from base64url to base64
    if "id" in registration:
        fido2_response["id"] = base64url_to_base64(registration["id"])

    # Convert rawId from base64url to base64
    if "rawId" in registration:
        fido2_response["rawId"] = base64url_to_base64(registration["rawId"])

    # Copy response data
    if "response" in registration:
        fido2_response["response"] = registration["response"]

    # Copy transports
    if "transports" in registration:
        fido2_response["transports"] = registration["transports"]

    # Copy authenticatorAttestationResponse if present
    if "authenticatorAttestationResponse" in registration:
        fido2_response["authenticatorAttestationResponse"] = registration["authenticatorAttestationResponse"]

    # Copy clientExtensionResults if present
    if "clientExtensionResults" in registration:
        fido2_response["clientExtensionResults"] = registration["clientExtensionResults"]

    return fido2_response
