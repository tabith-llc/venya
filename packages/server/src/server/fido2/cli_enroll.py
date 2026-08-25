"""CLI tool for FIDO2 enrollment and authentication.

Communicates with physical FIDO2 authenticators via HID and converts
CBOR attestation/assertion responses to browser-style WebAuthn JSON
format compatible with the server's Fido2Manager.

Usage:
    # Enrollment (step 2 of /api/v1/init flow):
    venya-fido2 enroll --rp-id venya-core-1 --user-id alice

    # Login (step 2 of /api/v1/auth/login flow):
    venya-fido2 login --rp-id venya-core-1

    # Pipe to curl:
    venya-fido2 enroll --rp-id venya-core-1 --user-id alice | \
        curl -sk -X POST https://venya-core-1/api/v1/init/complete \
             -H "Content-Type: application/json" \
             -d @-
"""

import argparse
import json
import sys
from typing import Any

from fido2.ctap2 import Ctap2
from fido2.hid import list_devices as hid_list_devices
from fido2.webauthn import websafe_encode


def list_fido2_devices() -> list[Ctap2]:
    """List available FIDO2 authenticators."""
    devices = []
    for descriptor in hid_list_devices():
        try:
            conn = Ctap2.open(descriptor)
            devices.append(conn)
        except Exception:
            pass
    return devices


def select_device(devices: list[Ctap2]) -> Ctap2:
    """Interactively select a FIDO2 device."""
    if len(devices) == 1:
        return devices[0]

    print("Available FIDO2 authenticators:", file=sys.stderr)
    for i, dev in enumerate(devices):
        info = dev.get_info()
        print(f"  [{i}] {info.vendor} {info.product} - {info.device_version}", file=sys.stderr)
    print(file=sys.stderr)

    while True:
        try:
            choice = input(f"Select device [0-{len(devices) - 1}]: ")
            idx = int(choice)
            if 0 <= idx < len(devices):
                return devices[idx]
        except (ValueError, EOFError):
            pass
        print("Invalid selection.", file=sys.stderr)


def encode_attestation_response(response: Any) -> dict[str, Any]:
    """Convert a CTAP2 AttestationResponse to browser WebAuthn JSON format.

    Args:
        response: AttestationResponse from Ctap2.make_credential().

    Returns:
        Dict compatible with browser WebAuthn API format.
    """
    auth_data = response.get("authData")
    att_stmt = response.get("attStmt", {})

    # Build the authenticatorAttestationResponse structure
    aar = {
        "publicKeyAlgorithm": response.get("publicKeyAlgorithm"),
        "publicKey": websafe_encode(auth_data) if auth_data else "",
        "attestationObject": "",
    }

    # The attestationObject is the full CBOR-encoded AttestationObject
    # We need to reconstruct it from the CTAP2 response
    if auth_data:
        # The full attestationObject is authData + attStmt CBOR
        # For the browser format, we need the complete attestationObject
        # which is authData || attestationStatement
        # Since the CTAP2 response splits these, we need to re-encode
        from fido2 import cbor

        ao_data = cbor.encode({"fmt": "packed", "authData": auth_data, "attStmt": att_stmt})
        aar["attestationObject"] = websafe_encode(ao_data)

    return {
        "id": websafe_encode(response.get("credentialId", b"")),
        "rawId": websafe_encode(response.get("credentialId", b"")),
        "response": aar,
        "type": "public-key",
        "clientExtensionResults": {},
    }


def encode_assertion_response(response: Any) -> dict[str, Any]:
    """Convert a CTAP2 AssertionResponse to browser WebAuthn JSON format.

    Args:
        response: AssertionResponse from Ctap2.get_assertion().

    Returns:
        Dict compatible with browser WebAuthn API format.
    """
    auth_data = response.get("authData", b"")
    signature = response.get("signature", b"")
    credential_id = response.get("credentialId", b"")

    return {
        "id": websafe_encode(credential_id),
        "rawId": websafe_encode(credential_id),
        "response": {
            "authenticatorData": websafe_encode(auth_data),
            "signature": websafe_encode(signature),
            "userHandle": websafe_encode(response.get("userHandle", b"")) if response.get("userHandle") else "",
        },
        "type": "public-key",
        "clientExtensionResults": {},
    }


def cmd_enroll(args: argparse.Namespace) -> None:
    """Handle the enroll subcommand."""
    devices = list_fido2_devices()
    if not devices:
        print("ERROR: No FIDO2 authenticators found.", file=sys.stderr)
        sys.exit(1)

    print("Waiting for FIDO2 authenticator touch...", file=sys.stderr)
    device = select_device(devices)

    rp_id = args.rp_id
    user_id = args.user_id
    user_id_bytes = user_id.encode("utf-8")

    # Generate a 32-byte challenge
    challenge = bytes(range(32))

    # Build the makeCredential parameters
    key_params = [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}]

    try:
        response = device.make_credential(
            client_data_hash=challenge,
            rp={"id": rp_id, "name": rp_id},
            user={
                "id": user_id_bytes,
                "name": user_id,
                "displayName": user_id,
            },
            key_params=key_params,
            timeout=60000,
        )
    except Exception as e:
        print(f"ERROR: FIDO2 attestation failed: {e}", file=sys.stderr)
        sys.exit(1)

    result = encode_attestation_response(response)
    print(json.dumps(result))


def cmd_login(args: argparse.Namespace) -> None:
    """Handle the login subcommand."""
    devices = list_fido2_devices()
    if not devices:
        print("ERROR: No FIDO2 authenticators found.", file=sys.stderr)
        sys.exit(1)

    print("Waiting for FIDO2 authenticator touch...", file=sys.stderr)
    device = select_device(devices)

    rp_id = args.rp_id

    # Generate a 32-byte challenge
    challenge = bytes(range(32))

    try:
        response = device.get_assertion(
            rp_id=rp_id,
            client_data_hash=challenge,
            timeout=60000,
        )
    except Exception as e:
        print(f"ERROR: FIDO2 assertion failed: {e}", file=sys.stderr)
        sys.exit(1)

    result = encode_assertion_response(response)
    print(json.dumps(result))


def main() -> None:
    parser = argparse.ArgumentParser(description="FIDO2 CLI enrollment and authentication tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # enroll subcommand
    enroll_parser = subparsers.add_parser("enroll", help="FIDO2 enrollment (attestation)")
    enroll_parser.add_argument("--rp-id", required=True, help="Relying party ID")
    enroll_parser.add_argument("--user-id", required=True, help="User ID")

    # login subcommand
    login_parser = subparsers.add_parser("login", help="FIDO2 authentication (assertion)")
    login_parser.add_argument("--rp-id", required=True, help="Relying party ID")

    args = parser.parse_args()

    if args.command == "enroll":
        cmd_enroll(args)
    elif args.command == "login":
        cmd_login(args)


if __name__ == "__main__":
    main()
