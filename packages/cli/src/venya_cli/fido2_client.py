# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Headless FIDO2/WebAuthn client for CLI authentication.

Uses python-fido2 to perform WebAuthn authentication without a browser.
The CLI acts as a headless authenticator that communicates with a FIDO2
security key via USB HID transport.

Flow:
    1. Get challenge options from server (POST /auth/login/start)
    2. Perform WebAuthn assertion with security key
    3. Send assertion to server (POST /auth/login/complete)
"""

import base64
import getpass
import json
import logging
import os
import sys
from typing import Any

import httpx2
from fido2.client import (
    AssertionSelection,
    ClientError,
    ClientPin,
    DefaultClientDataCollector,
    Fido2Client,
    UserInteraction,
    verify_rp_id,
)
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import list_devices
from fido2.webauthn import (
    AuthenticatorData,
    CollectedClientData,
    CredentialCreationOptions,
    CredentialRequestOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
)

from .webauthn import b64_decode_id as _b64_decode_id

logger = logging.getLogger("venya_cli.fido2")

# Enable detailed FIDO2 debug output with VENYA_FIDO2_DEBUG=1
FIDO2_DEBUG = os.environ.get("VENYA_FIDO2_DEBUG") == "1"


class CliInteraction(UserInteraction):
    """CLI user interaction: prompts for PIN via stdin (getpass).

    The library calls request_pin() when the authenticator requires a PIN.
    On wrong PIN the authenticator returns PIN_INVALID / PIN_AUTH_INVALID;
    the caller (Fido2Auth) catches CtapError and retries request_pin().
    """

    def request_pin(self, permissions: ClientPin.PERMISSION, rp_id: str | None) -> str | None:
        """Prompt for PIN via getpass (no echo, stderr only).

        Returns None if stdin is not a TTY (headless / piped).
        """
        if not sys.stdin.isatty():
            logger.warning("No TTY available — cannot prompt for PIN.")
            return None
        pin = getpass.getpass("\nEnter security key PIN: ")
        return pin

    def prompt_up(self) -> None:
        """Called when the authenticator awaits a user-presence touch.
        The key is flashing — this is the cue to touch it.
        """
        print(">>> Key is flashing — touch it to continue <<<", file=sys.stderr)

    def request_uv(self, permissions: ClientPin.PERMISSION, rp_id: str | None) -> bool:
        """Allow UV — the library will fall back to PIN if built-in UV
        is not available on the authenticator. We handle MISSING_PARAMETER
        errors in the retry loop below."""
        return True


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


def _make_webauthn_client(collector: DefaultClientDataCollector) -> Any:
    """Return the platform-appropriate WebAuthn client.

    Windows 10 1903+ restricts raw CTAP/HID access to elevated processes, so the
    raw Fido2Client path silently fails for standard (non-admin) users with a
    misleading "No FIDO2 devices found" — enumeration itself is admin-only. The
    Windows platform WebAuthn API (WindowsClient) is the supported unelevated
    path: the OS owns device enumeration, the PIN dialog, and user-presence
    prompts. Ticket: windows-fido2-requires-elevation.

    There is deliberately NO fallback to the raw path when the platform API is
    unavailable (Windows < 10 1903, missing webauthn.dll): a fallback would
    reproduce the silent admin-only failure this factory exists to eliminate.
    Callers get an explicit Fido2ClientError instead.

    On Linux/macOS the raw CTAP path is unchanged: enumerate HID devices, fail
    with Fido2NotFoundError when empty, wrap the first device in Fido2Client.
    """
    if sys.platform == "win32":
        # Lazy import: fido2.client.windows imports ctypes.WinDLL at module
        # load and is unimportable on Linux/macOS.
        from fido2.client.windows import WindowsClient

        if not WindowsClient.is_available():
            raise Fido2ClientError(
                "Windows WebAuthn platform API is unavailable "
                "(webauthn.dll missing or WEBAUTHN_API_VERSION == 0). "
                "Windows 10 version 1903 or later is required for venya CLI "
                "FIDO2 support."
            )
        return WindowsClient(collector)
    devices = list(list_devices())
    if not devices:
        raise Fido2NotFoundError("No FIDO2 devices found")
    return Fido2Client(devices[0], collector, user_interaction=CliInteraction())


# Windows platform WebAuthn (webauthn.dll) HRESULT -> operator-facing message.
# Kept evidence-driven on purpose: only codes PHYSICALLY OBSERVED on the win11
# acceptance runs get a pinned message; unmapped codes fall through to the OS's
# own text with a clear prefix — accurate, never invented.
_WINDOWS_HRESULT_MESSAGES = {
    0x8009000F: (  # NTE_EXISTS — observed 2026-09-19, `credential add` with an already-registered key
        "This security key is already registered for the account. "
        "Use a different key, or remove the existing credential first."
    ),
}


def _translate_windows_error(exc: Exception) -> Fido2ClientError:
    """Convert a WindowsClient ClientError into an accurate, readable message.

    WindowsClient wraps OS failures as ClientError.ERR.OTHER_ERROR(OSError);
    the HRESULT rides in OSError.winerror (signed). Acceptance requirement:
    device-absent must read as device-absent — never a privilege error, never
    a raw tuple like "(<ERR.OTHER_ERROR: 1>, OSError(22, ...))".
    """
    cause = getattr(exc, "cause", None)
    winerror = getattr(cause, "winerror", None)
    if winerror is not None:
        hresult = winerror & 0xFFFFFFFF
        message = _WINDOWS_HRESULT_MESSAGES.get(hresult)
        if message:
            return Fido2ClientError(message)
        detail = getattr(cause, "strerror", None) or cause
        return Fido2ClientError(f"Windows WebAuthn error: {detail} (HRESULT {hresult:#010x})")
    return Fido2ClientError(f"Windows WebAuthn error: {exc}")


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
            except (json.JSONDecodeError, Exception):  # noqa: S110
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
            # Carry the server's JSON `detail` so callers can pattern-match
            # actionable messages (cmd_init 409 handling; wording contract:
            # server routes/init.py "already initialized" / "pending
            # enrollment"). f71d4c5 removed this parsing on a wrong
            # hypothesis: "Incorrect padding" originated in _b64std_encode,
            # and json.loads cannot raise it. Guarded — any parse failure
            # falls back to the httpx status text.
            error_msg = str(e)
            try:
                error_data = e.response.json()
                detail = error_data.get("detail") if isinstance(error_data, dict) else None
                if isinstance(detail, str):
                    error_msg = detail
                elif detail is not None:
                    error_msg = f"{error_msg} (detail: {detail})"
            except Exception:  # noqa: S110  # nosec B110 — deliberate: parse failure keeps raw status text
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
        start_result = self._post(
            "/api/v1/auth/login/start",
            {
                "user_id": user_id,
            },
        )
        challenge_id = start_result["challenge_id"]
        options = start_result["options"]

        # Step 2: Convert server options to fido2 types
        request_options = self._build_request_options(options)

        # Step 3: Perform WebAuthn assertion (retry on wrong PIN)
        logger.info("Waiting for security key touch...")
        max_pin_retries = 3
        for attempt in range(max_pin_retries):
            try:
                assertion = self._get_assertion(request_options, timeout=timeout)
                break
            except (ClientError, CtapError) as e:
                # fido2 may surface a CTAP error wrapped in ClientError (original in
                # e.cause); unwrap so the PIN retry below still applies.
                if isinstance(e, ClientError) and isinstance(e.cause, CtapError):
                    e = e.cause
                if isinstance(e, ClientError):
                    if e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
                        raise Fido2ClientError(
                            "Security key has no PIN set and cannot verify the user "
                            "another way. Set a PIN on the key (e.g. yubikey-manager), "
                            "then try again."
                        ) from e
                    raise
                if e.code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_INVALID):
                    if attempt < max_pin_retries - 1:
                        logger.warning("Incorrect PIN. %d attempt(s) remaining.", max_pin_retries - 1 - attempt)
                        continue
                    raise Fido2ClientError(f"PIN incorrect after {max_pin_retries} attempts") from e
                if e.code == CtapError.ERR.PIN_BLOCKED:
                    raise Fido2ClientError("Security key PIN is blocked. Requires power-cycle or factory reset.") from e
                # `raise e`, not bare `raise`: e may be the REBOUND unwrapped CtapError;
                # a bare raise re-raises the original ClientError wrapper instead.
                raise e  # noqa: TRY201 — rebinding makes bare raise semantically wrong

        # Step 4: Convert assertion to server format and complete
        logger.info("Sending assertion to server")
        response = self._format_assertion_response(assertion)
        if FIDO2_DEBUG:
            print(f"DEBUG: assertion response id being sent={response.get('id')}", file=sys.stderr)
            try:
                raw_id = base64.b64decode(response.get("id", ""))
                print(f"DEBUG: assertion id raw bytes (hex)={raw_id.hex()}", file=sys.stderr)
            except Exception as ex:
                print(f"DEBUG: assertion id decode error={ex}", file=sys.stderr)
        result = self._post(
            "/api/v1/auth/login/complete",
            {
                "challenge_id": challenge_id,
                "response": response,
            },
        )

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
        start_result = self._post(
            "/api/v1/init",
            {
                "user_id": user_id,
            },
        )
        challenge_id = start_result["challenge_id"]
        options = start_result["options"]

        # Step 2: Convert server options to fido2 types
        request_options = self._build_registration_options(options)

        # Step 3: Perform WebAuthn creation (retry on wrong PIN)
        logger.info("Waiting for security key touch to register...")
        max_pin_retries = 3
        for attempt in range(max_pin_retries):
            try:
                credential = self._get_credential(request_options, timeout=timeout)
                break
            except CtapError as e:
                if e.code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_INVALID):
                    if attempt < max_pin_retries - 1:
                        logger.warning("Incorrect PIN. %d attempt(s) remaining.", max_pin_retries - 1 - attempt)
                        continue
                    raise Fido2ClientError(f"PIN incorrect after {max_pin_retries} attempts") from e
                if e.code == CtapError.ERR.PIN_BLOCKED:
                    raise Fido2ClientError("Security key PIN is blocked. Requires power-cycle or factory reset.") from e
                if e.code == CtapError.ERR.OPERATION_DENIED:
                    # Offer browser-assisted fallback for CLI-first alpha
                    raise Fido2ClientError(
                        "Security key denied the operation (0x27) during registration. "
                        "Please complete enrollment via the browser instead:\n"
                        "  1. Open https://venya-core-1/enroll\n"
                        "  2. Paste an enrollment token (mint via admin)\n"
                        "  3. Touch your key in the browser\n"
                        "Your credential will be usable from the CLI immediately after."
                    ) from e
                raise

        # Step 4: Convert credential to server format and complete
        logger.info("Sending attestation to server")
        response = self._format_credential_response(credential)
        result = self._post(
            "/api/v1/init/complete",
            {
                "user_id": user_id,
                "challenge_id": challenge_id,
                "response": response,
            },
        )

        return result

    def _build_registration_options(self, options: dict[str, Any]) -> CredentialCreationOptions:
        """Convert server challenge options to fido2 CredentialCreationOptions.

        Args:
            options: WebAuthn registration options from server.

        Returns:
            CredentialCreationOptions for python-fido2.
        """
        norm = self.normalize_webauthn_options(options)
        challenge = _b64_decode_id(norm["challenge"])

        pub_key_cred_params = []
        for param in norm.get("pubKeyCredParams", []):
            pub_key_cred_params.append(
                {
                    "type": param.get("type", "public-key"),
                    "alg": param.get("alg"),
                }
            )

        exclude_credentials = []
        for cred in norm.get("exclude_credentials", []):
            if "id" in cred:
                exclude_credentials.append(
                    PublicKeyCredentialDescriptor(
                        type=cred.get("type", "public-key"),
                        id=cred["id"],  # already decoded bytes by normalizer
                        transports=cred.get("transports"),
                    )
                )

        user = norm.get("user", {})
        user_id = _b64_decode_id(user["id"])

        public_key = {
            "rp": norm.get("rp", {}),
            "user": {
                "id": user_id,
                "name": user.get("name", ""),
                "display_name": user.get("displayName", ""),
            },
            "challenge": challenge,
            "pubKeyCredParams": pub_key_cred_params,
            "timeout": norm.get("timeout", 60000),
            "excludeCredentials": exclude_credentials or None,
            "attestation": norm.get("attestation", "none"),
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
        origin = self.server_url
        if FIDO2_DEBUG:
            rp_id = request_options.public_key.get("rp", {}).get("id", "unknown")
            pub_params = request_options.public_key.get("pubKeyCredParams", [])
            print(f"DEBUG: make_credential rp_id={rp_id} pubKeyCredParams={pub_params}", file=sys.stderr)

        collector = DefaultClientDataCollector(origin, verify_rp_id)
        # Factory: WindowsClient (platform API, no enumeration) on win32;
        # raw Fido2Client over the first HID device elsewhere. Raises
        # Fido2NotFoundError (non-win32, no device) or Fido2ClientError
        # (win32, platform API unavailable).
        client = _make_webauthn_client(collector)
        try:
            return client.make_credential(request_options.public_key)
        except (ClientError, CtapError) as e:
            if sys.platform == "win32":
                # The OS owns the PIN/UV dialog on the platform path, and the
                # raw-Ctap2 clientPin fallbacks below require admin-only
                # device access — unreachable for standard users by design.
                raise _translate_windows_error(e) from e
            print(
                f"DEBUG: make_credential high-level exception: {type(e).__name__} code={getattr(e, 'code', None)}",
                file=sys.stderr,
            )
            device = next(iter(list_devices()), None)
            if device is None:
                raise
            interaction = CliInteraction()
            # Unwrap ClientError to check the underlying CtapError
            cause = getattr(e, "cause", None)
            if isinstance(cause, CtapError) and cause.code == CtapError.ERR.OPERATION_DENIED:
                ctap2 = Ctap2(device)
                if ctap2.info.options.get("clientPin"):
                    return self._get_credential_pin_only(ctap2, request_options, interaction)
            if isinstance(e, ClientError) and e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
                ctap2 = Ctap2(device)
                if ctap2.info.options.get("clientPin"):
                    return self._get_credential_pin_only(ctap2, request_options, interaction)
            if isinstance(e, CtapError) and e.code == CtapError.ERR.OPERATION_DENIED:
                ctap2 = Ctap2(device)
                if ctap2.info.options.get("clientPin"):
                    return self._get_credential_pin_only(ctap2, request_options, interaction)
            raise

    @staticmethod
    def _format_credential_response(
        credential: Any,
    ) -> dict[str, Any]:
        """Convert python-fido2 credential to server-expected format.

        Handles both the legacy CredentialSelection shape and the modern
        RegistrationResponse / AttestationResponse shape returned by
        Fido2Client.make_credential in python-fido2 2.x.
        """
        if FIDO2_DEBUG:
            print(f"DEBUG: _format_credential_response received: {type(credential).__name__}", file=sys.stderr)
            print(f"DEBUG: dir(credential)={dir(credential)}", file=sys.stderr)

        # Modern RegistrationResponse (Fido2Client v2.x)
        if hasattr(credential, "response"):
            cred_id = credential.id or credential.raw_id
            # RegistrationResponse.id / raw_id may be base64url str; convert to bytes
            if isinstance(cred_id, str):
                cred_id = _b64_decode_id(cred_id)
            auth_response = credential.response
            if FIDO2_DEBUG:
                print(
                    f"DEBUG: auth_response type={type(auth_response).__name__} dir={dir(auth_response)}",
                    file=sys.stderr,
                )
            # AuthenticatorAttestationResponse (v2.x) only has attestation_object + client_data
            attestation_object = getattr(auth_response, "attestation_object", None)
            client_data = getattr(auth_response, "client_data", None)
            # We do not have auth_data from this shape; synthesize a minimal one if needed later
            auth_data = b""  # placeholder – server only needs attestationObject + clientDataJSON for init
            transports = getattr(auth_response, "transports", None) or []
        # Legacy CredentialSelection
        elif hasattr(credential, "auth_response"):
            auth_response = credential.auth_response
            cred_id = auth_response.credential_id
            auth_data = auth_response.auth_data
            client_data = auth_response.client_data
            attestation_object = auth_response.attestation_object
            transports = getattr(auth_response, "transports", None) or []
        else:
            # Fallback – treat credential itself as the response
            _cred_id = getattr(credential, "id", None) or getattr(credential, "credential_id", None)
            cred_id: bytes = _cred_id if isinstance(_cred_id, (bytes, bytearray)) else b""  # type: ignore[misc,no-redef]
            _auth_data = getattr(credential, "auth_data", None)
            auth_data: bytes = _auth_data if isinstance(_auth_data, (bytes, bytearray)) else b""  # type: ignore[misc,no-redef]
            _client_data = getattr(credential, "client_data", None)
            client_data: bytes = _client_data if isinstance(_client_data, (bytes, bytearray)) else b""  # type: ignore[misc,no-redef]
            _attestation_object = getattr(credential, "attestation_object", None)
            attestation_object: bytes = (  # type: ignore[misc,no-redef]
                _attestation_object if isinstance(_attestation_object, (bytes, bytearray)) else b""
            )
            transports = getattr(credential, "transports", None) or []

        resp = {
            "id": _b64url_encode(cred_id),
            "rawId": _b64url_encode(cred_id),
            "response": {
                "clientDataJSON": _b64url_encode(_serialize_client_data(client_data)),
                "attestationObject": _b64url_encode(attestation_object),  # type: ignore[arg-type]
                "transports": transports,
            },
            "type": "public-key",
        }
        if auth_data:
            resp["response"]["authenticatorData"] = _b64url_encode(_serialize_auth_data(auth_data))  # type: ignore[index]
        return resp

    def normalize_webauthn_options(self, options: dict[str, Any]) -> dict[str, Any]:
        """Convert Venya server WebAuthn JSON (camelCase, per WebAuthn spec)
        to python-fido2 constructor shape (snake_case keys where required).

        This is the single source of truth for the wire format the server emits
        (see fido2/manager.py). Explicit, forward-compatible, no heuristics.
        """
        norm: dict[str, Any] = {}

        # Top-level scalar / simple fields
        for camel, snake in [
            ("challenge", "challenge"),
            ("rpId", "rp_id"),
            ("timeout", "timeout"),
            ("userVerification", "user_verification"),
            ("attestation", "attestation"),
        ]:
            if camel in options:
                norm[snake] = options[camel]
            elif snake in options:
                norm[snake] = options[snake]

        # rp object (registration)
        if "rp" in options:
            norm["rp"] = options["rp"]
            # The browser-adapter wire shape (server/fido2/browser_adapter.py
            # challenge_to_browser_options, emitted by e.g.
            # /auth/elevate/challenge) folds rpId into rp.id and drops the
            # scalar. Assertion options still need rp_id — without it the
            # Windows platform API gets a NULL pwszRpId and fails
            # NTE_INVALID_PARAMETER (0x80090027), found physically on win11.
            if "rp_id" not in norm and isinstance(options["rp"], dict) and options["rp"].get("id"):
                norm["rp_id"] = options["rp"]["id"]

        # user object (registration)
        if "user" in options:
            norm["user"] = options["user"]

        # pubKeyCredParams (registration)
        if "pubKeyCredParams" in options:
            norm["pubKeyCredParams"] = options["pubKeyCredParams"]

        # Credential descriptor lists (decode ids to bytes immediately)
        for camel, snake in [
            ("allowCredentials", "allow_credentials"),
            ("excludeCredentials", "exclude_credentials"),
        ]:
            raw_list = options.get(camel) or options.get(snake)
            if raw_list:
                decoded = []
                for cred in raw_list:
                    if "id" in cred:
                        cred = dict(cred)  # copy so we don't mutate caller's dict
                        cred["id"] = _b64_decode_id(cred["id"])
                    decoded.append(cred)
                norm[snake] = decoded

        return norm

    def _build_request_options(self, options: dict[str, Any]) -> CredentialRequestOptions:
        """Convert server challenge options to fido2 CredentialRequestOptions.

        Args:
            options: WebAuthn challenge options from server.

        Returns:
            CredentialRequestOptions for python-fido2.
        """
        norm = self.normalize_webauthn_options(options)
        challenge = _b64_decode_id(norm["challenge"])

        allow_credentials = []
        for cred in norm.get("allow_credentials", []) or []:
            allow_credentials.append(
                PublicKeyCredentialDescriptor(
                    type=cred.get("type", "public-key"),
                    id=cred["id"],  # already decoded bytes by normalizer
                    transports=cred.get("transports"),
                )
            )

        public_key = PublicKeyCredentialRequestOptions(
            challenge=challenge,
            timeout=norm.get("timeout"),
            rp_id=norm.get("rp_id"),
            allow_credentials=allow_credentials or None,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        return CredentialRequestOptions(public_key=public_key)

    def _get_assertion(
        self,
        request_options: CredentialRequestOptions,
        timeout: float = 60.0,
    ) -> AssertionSelection:
        """Perform WebAuthn assertion using python-fido2.

        Dispatches on authenticator capability: keys with built-in UV use the
        high-level Fido2Client path; clientPin-only keys use a direct Ctap2
        getAssertion call with the pin token and no uv option.

        Args:
            request_options: Credential request options.
            timeout: Timeout in seconds.

        Returns:
            AssertionSelection from python-fido2.
        """
        public_key = request_options.public_key
        rp_id = public_key.rp_id or "localhost"
        origin = f"https://{rp_id}" if not self.server_url.startswith("http") else self.server_url
        collector = DefaultClientDataCollector(origin, verify_rp_id)

        if sys.platform == "win32":
            # Platform API path: no enumeration (admin-only on Windows), no
            # info-based dispatch — the OS negotiates UV/PIN via its own UI.
            try:
                return _make_webauthn_client(collector).get_assertion(public_key)
            except ClientError as e:
                raise _translate_windows_error(e) from e

        devices = list(list_devices())
        if not devices:
            raise Fido2NotFoundError("No FIDO2 devices found")

        ctap2 = Ctap2(devices[0])
        info = ctap2.info
        interaction = CliInteraction()

        # WHY THIS PATH EXISTS — deviation from library-norm documented deliberately.
        #
        # Normally a client uses Fido2Client.do_get_assertion and lets the library
        # negotiate user verification. fido2 2.2.1 _should_use_uv() treats
        # clientPin in get_info options as UV capability, returning True for
        # required verification. That routes the PIN through the UV-negotiation
        # path (_get_token → get_pin_token), which then issues a
        # _filter_creds discovery getAssertion (options={"up": false}, dummy
        # client_data_hash) before the real assertion. Authenticators with
        # clientPin but no built-in UV (uv absent from get_info options, e.g.
        # TrustKey T120) reject the discovery call — observed as
        # CTAP2_ERR_MISSING_PARAMETER (0x14), where the spec-required code is
        # CTAP2_ERR_INVALID_OPTION. Because the firmware's error code is itself
        # off-spec, we cannot retry on error codes; we must not send the
        # discovery call at all.
        #
        # Per FIDO Alliance guidance: for a clientPin-only key, user verification
        # is satisfied by the pinUvAuthParam (the PIN is the user verification);
        # the "uv" option is only for built-in UV methods. Sending no "uv" option
        # with the pin token is therefore spec-canonical, not a workaround.
        #
        # If upstream python-fido2 gates the uv option on info.options["uv"], this
        # branch should be removed and Fido2Client.do_get_assertion restored for
        # all keys. See tickets/fido2-upstream-uv-option-pin-only-keys.md.

        if info.options.get("uv"):
            # built-in UV: existing high-level path
            client = Fido2Client(devices[0], collector, user_interaction=interaction)
            return client.get_assertion(public_key)

        if info.options.get("clientPin"):
            return self._get_assertion_pin_only(ctap2, public_key, interaction)

        raise Fido2ClientError("Security key advertises neither built-in UV nor clientPin; cannot assert.")

    def _get_assertion_pin_only(
        self,
        ctap2: Ctap2,
        public_key: PublicKeyCredentialRequestOptions,
        interaction: CliInteraction,
    ) -> AssertionSelection:
        """Direct Ctap2.get_assertion for clientPin-only keys.

        Bypasses Fido2Client.do_get_assertion entirely. Uses the existing
        CliInteraction.request_pin() machinery to obtain the PIN, then drives
        Ctap2.get_assertion directly with the pin token and no uv option.

        Args:
            ctap2: The Ctap2 instance (already initialized, info cached).
            public_key: The PublicKeyCredentialRequestOptions.
            interaction: CliInteraction for PIN prompt.

        Returns:
            AssertionSelection wrapping the raw response.
        """
        # Negotiate PIN/UV protocol
        for proto in ClientPin.PROTOCOLS:
            if proto.VERSION in ctap2.info.pin_uv_protocols:
                pin_protocol = proto()
                break
        else:
            raise Fido2ClientError("No compatible PIN/UV protocol supported by the security key.")

        rp_id = public_key.rp_id or "localhost"
        pin = interaction.request_pin(ClientPin.PERMISSION.GET_ASSERTION, rp_id)
        if not pin:
            raise Fido2ClientError("No PIN entered; a clientPin-only key requires the key PIN to assert.")

        client_pin = ClientPin(ctap2, pin_protocol)
        if FIDO2_DEBUG:
            print("DEBUG: obtaining PIN token...", file=sys.stderr)
        try:
            token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.GET_ASSERTION, rp_id)
        except CtapError as e:
            if FIDO2_DEBUG:
                print(f"DEBUG: PIN token FAILED: {e}", file=sys.stderr)
            raise Fido2ClientError(f"PIN token failed: {e}") from e
        if FIDO2_DEBUG:
            print("DEBUG: PIN token OK, building client data...", file=sys.stderr)

        # Construct client data for the hash used in pinUvAuthParam
        origin = f"https://{rp_id}"
        if FIDO2_DEBUG:
            print(f"DEBUG: client_data origin={origin}", file=sys.stderr)
        client_data, _ = DefaultClientDataCollector(origin, verify_rp_id).collect_client_data(public_key)

        pin_uv_param = pin_protocol.authenticate(token, client_data.hash)
        pin_uv_protocol = pin_protocol.VERSION

        allow_list = [{"type": c.type, "id": c.id} for c in (public_key.allow_credentials or [])] or None

        if FIDO2_DEBUG:
            if allow_list:
                cred_ids = [c["id"].hex() for c in allow_list]
                print(f"DEBUG: allow_list ids (hex): {cred_ids}", file=sys.stderr)
            print(
                f"DEBUG: calling get_assertion (allow_list={len(allow_list) if allow_list else 0} creds, rp_id={rp_id})",
                file=sys.stderr,
            )
        try:
            response = ctap2.get_assertion(
                rp_id,
                client_data.hash,
                allow_list,
                pin_uv_param=pin_uv_param,
                pin_uv_protocol=pin_uv_protocol,
                on_keepalive=lambda status: interaction.prompt_up(),
            )
        except CtapError as e:
            if FIDO2_DEBUG:
                print(f"DEBUG: get_assertion FAILED: {e}", file=sys.stderr)
            if e.code == CtapError.ERR.OPERATION_DENIED:
                raise Fido2ClientError(
                    "Security key denied the operation (0x27). "
                    "This usually means the credential was registered under a "
                    "different RP ID than the one being asserted for "
                    f"(current rp_id={rp_id}). "
                    "Re-enroll the key or verify the stored RP ID for this user."
                ) from e
            raise Fido2ClientError(f"get_assertion failed: {e}") from e
        if FIDO2_DEBUG:
            print("DEBUG: assertion OK", file=sys.stderr)
        return AssertionSelection(client_data, [response])

    def _get_credential_pin_only(
        self,
        ctap2: Ctap2,
        request_options: CredentialCreationOptions,
        interaction: CliInteraction,
    ) -> Any:
        """Direct Ctap2.make_credential for clientPin-only keys.

        Bypasses Fido2Client.make_credential entirely. Uses the existing
        CliInteraction.request_pin() machinery to obtain the PIN, then drives
        Ctap2.make_credential directly with the pin token and no uv option.

        This is the production fix for 0x27 OPERATION_DENIED during registration
        on clientPin-only keys (TrustKey T120, YubiKey, etc.).
        """
        # Negotiate PIN/UV protocol
        for proto in ClientPin.PROTOCOLS:
            if proto.VERSION in ctap2.info.pin_uv_protocols:
                pin_protocol = proto()
                break
        else:
            raise Fido2ClientError("No compatible PIN/UV protocol supported by the security key.")

        public_key = request_options.public_key
        rp = public_key.get("rp", {})
        rp_id = rp.get("id", "localhost")
        user = public_key.get("user", {})
        # Ensure user id is a proper opaque 32-byte value (CTAP2 requirement).
        # The server currently sends the username string; we override it here
        # for the direct Ctap2 path to satisfy strict authenticators.
        if len(user.get("id", b"")) < 16:
            import os

            user = dict(user)
            user["id"] = os.urandom(32)

        pin = interaction.request_pin(ClientPin.PERMISSION.MAKE_CREDENTIAL, rp_id)
        if not pin:
            raise Fido2ClientError("No PIN entered; a clientPin-only key requires the key PIN to register.")

        client_pin = ClientPin(ctap2, pin_protocol)
        if FIDO2_DEBUG:
            print("DEBUG: obtaining PIN token (MAKE_CREDENTIAL)...", file=sys.stderr)
        try:
            token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp_id)
        except CtapError as e:
            if FIDO2_DEBUG:
                print(f"DEBUG: PIN token FAILED: {e}", file=sys.stderr)
            raise Fido2ClientError(f"PIN token failed: {e}") from e
        if FIDO2_DEBUG:
            print("DEBUG: PIN token OK, building client data...", file=sys.stderr)

        # Construct client data for the hash used in pinUvAuthParam
        origin = f"https://{rp_id}"
        if FIDO2_DEBUG:
            print(f"DEBUG: client_data origin={origin}", file=sys.stderr)

        client_data, _ = DefaultClientDataCollector(origin, verify_rp_id).collect_client_data(
            request_options.public_key
        )

        pin_uv_param = pin_protocol.authenticate(token, client_data.hash)
        pin_uv_protocol = pin_protocol.VERSION

        if FIDO2_DEBUG:
            print(f"DEBUG: calling make_credential (rp_id={rp_id})", file=sys.stderr)
            print(f"DEBUG: rp={rp}", file=sys.stderr)
            print(f"DEBUG: user={user}", file=sys.stderr)
            print(f"DEBUG: client_data_hash (len={len(client_data.hash)})", file=sys.stderr)
            print(f"DEBUG: pubKeyCredParams={public_key.get('pubKeyCredParams', [])}", file=sys.stderr)
            print(f"DEBUG: exclude_list={public_key.get('excludeCredentials')}", file=sys.stderr)
            print("DEBUG: options sent to ctap2={'rk': True}", file=sys.stderr)
        try:
            # Some keys require "rk": True for the first credential after reset
            response = ctap2.make_credential(
                client_data.hash,
                rp,
                user,
                public_key.get("pubKeyCredParams", []),
                exclude_list=public_key.get("excludeCredentials"),
                options={"rk": True},
                pin_uv_param=pin_uv_param,
                pin_uv_protocol=pin_uv_protocol,
                on_keepalive=lambda status: interaction.prompt_up(),
            )
        except CtapError as e:
            if FIDO2_DEBUG:
                print(f"DEBUG: make_credential FAILED: {e}", file=sys.stderr)
            raise Fido2ClientError(f"make_credential failed: {e}") from e

        if FIDO2_DEBUG:
            print("DEBUG: make_credential OK", file=sys.stderr)
        # Wrap the raw AttestationResponse so it looks like the high-level
        # CredentialSelection.auth_response that _format_credential_response expects.
        auth_response = type(
            "obj",
            (object,),
            {
                "credential_id": response.credential_id,
                "auth_data": response.auth_data,
                "client_data": client_data,
                "attestation_object": response.attestation_object,
            },
        )()

        return type(
            "obj",
            (object,),
            {
                "auth_response": auth_response,
                "transports": None,
            },
        )()

    def _format_assertion_response(
        self,
        assertion: AssertionSelection,
    ) -> dict[str, Any]:
        """Convert python-fido2 assertion to server-expected format.

        Uses the real AssertionSelection API (.get_assertions(),
        .get_response()) rather than non-existent .assertions/.client_data
        attributes. This fixes a latent bug where the formatter used
        attributes that do not exist on the real AssertionSelection class.

        Args:
            assertion: AssertionSelection from python-fido2.

        Returns:
            Dict in the format the server expects.
        """
        auth_response = assertion.get_assertions()[0]

        cred_id = auth_response.credential["id"]
        if FIDO2_DEBUG:
            print(f"DEBUG: assertion cred_id from key (hex)={cred_id.hex()}", file=sys.stderr)
        auth_data = auth_response.auth_data
        signature = auth_response.signature
        client_data = assertion.get_response(0).response.client_data

        # Standard base64 WITH padding — server decodes response["id"] via
        # base64.b64decode, which requires padded input for lengths != 0 mod 3
        # (e.g. 64-byte credential IDs → 86 chars + '='). Stripping padding
        # caused "Incorrect padding" → 401 on every 64-byte credential.
        def _b64std_encode(data: bytes) -> str:
            if FIDO2_DEBUG:
                print(f"DEBUG: _b64std_encode input (hex)={data.hex()}", file=sys.stderr)
            return base64.b64encode(data).decode("ascii")

        if FIDO2_DEBUG:
            print(f"DEBUG: cred_id bytes passed to _b64std_encode (hex)={cred_id.hex()}", file=sys.stderr)

        encoded_id = _b64std_encode(cred_id)
        if FIDO2_DEBUG:
            print(f"DEBUG: _b64std_encode output={encoded_id}", file=sys.stderr)

        return {
            "id": encoded_id,
            "rawId": encoded_id,
            "response": {
                "clientDataJSON": _b64url_encode(_serialize_client_data(client_data)),
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
    flags_byte = bytes([auth_data.flags.value if hasattr(auth_data.flags, "value") else int(auth_data.flags)])
    counter_bytes = auth_data.counter.to_bytes(4, byteorder="big")
    return auth_data.rp_id_hash + flags_byte + counter_bytes
