# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Command implementations for the CLI."""

import getpass
import hashlib
import json
import os
import ssl
import sys
from datetime import UTC
from pathlib import Path
from typing import Any

import httpx2
from cryptography import x509

from .api_client import (
    DEFAULT_CONFIG_FILE,
    APIClient,
    APIClientAuthenticationError,
    APIClientError,
)


def run_command(args: Any) -> int:
    """Run a CLI command.

    Args:
        args: Parsed argparse namespace.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    server_url = getattr(args, "server_url", None)
    client = APIClient(server_url=server_url)

    # Authenticate if no token is available (init, recovery, config, and exec are public)
    command = args.command
    if command not in ("init", "enroll", "login", "recovery", "config", "exec") and not client.config.access_token:
        user_id = getattr(args, "user_id", None)
        try:
            print("Authenticating with security key...")
            client.authenticate(user_id=user_id)
            print("Authentication successful.")
        except APIClientAuthenticationError as e:
            print(f"Authentication failed: {e}", file=sys.stderr)
            client.close()
            return 1
        except APIClientError as e:
            print(f"Authentication failed: {e}", file=sys.stderr)
            client.close()
            return 1

    try:
        if command == "init":
            return cmd_init(client, args)
        elif command == "store":
            return cmd_store(client, args)
        elif command == "get":
            return cmd_get(client, args)
        elif command == "list":
            return cmd_list(client, args)
        elif command == "delete":
            return cmd_delete(client, args)
        elif command == "update-metadata":
            return cmd_update_metadata(client, args)
        elif command == "audit":
            return cmd_audit(client, args)
        elif command == "admin":
            return cmd_admin(client, args)
        elif command == "role":
            return cmd_role(client, args)
        elif command == "credential":
            return cmd_credential(client, args)
        elif command == "enroll":
            return cmd_enroll(client, args)
        elif command == "login":
            return cmd_login(client, args)
        elif command == "recovery":
            return cmd_recovery(client, args)
        elif command == "run":
            return cmd_run(client, args)
        elif command == "exec":
            return cmd_exec_group(client, args)
        elif command == "config":
            return cmd_config(client, args)
        else:
            print(f"Unknown command: {command}", file=sys.stderr)
            return 1
    finally:
        client.close()


def cmd_init(client: APIClient, args: Any) -> int:
    """Bootstrap the core with mandatory FIDO2 enrollment.

    Flow:
    1. Call POST /api/v1/init → get FIDO2 challenge
    2. Perform WebAuthn registration with security key
    3. Call POST /api/v1/init/complete → get recovery code
    4. Print recovery code

    Migrations are not run here: the core installer migrates the database
    at install time, and a live server implies a migrated schema.

    If --installation-reset is set, resets core to pre-initialization state first.
    """
    from .fido2_client import (
        Fido2Auth,
        Fido2ClientError,
        Fido2NotFoundError,
        Fido2TimeoutError,
        Fido2UserInteractionRequiredError,
    )

    # Run installation reset if requested
    if getattr(args, "installation_reset", False):
        try:
            print("Resetting core to pre-initialization state...")
            reset_result = client.post("/api/v1/init/reset")
            print(f"Reset complete: {reset_result.get('message', 'ok')}")
        except APIClientError as e:
            print(f"Reset failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Reset failed: {e}", file=sys.stderr)
            return 1

    if getattr(args, "skip_migrations", False):
        print(
            "warning: --skip-migrations is a no-op and will be removed; "
            "migrations run on the server at install time.",
            file=sys.stderr,
        )

    try:
        fido2 = Fido2Auth(client.config.server_url)

        print(f"Starting core initialization for user '{args.user_id}'...")
        print("Please insert your security key when prompted.\n")

        result = fido2.register(user_id=args.user_id, timeout=60.0)

        print(f"Initialization complete. User '{args.user_id}' enrolled as admin.")

        # Print recovery code (printed once, never stored)
        recovery_code = result.get("recovery_code")
        if recovery_code:
            print("\n" + "=" * 50)
            print("RECOVERY CODE — Print and store securely!")
            print("This code is printed only once and never stored.")
            print("=" * 50)
            # Recovery code is always shown in full — it is only printed once
            # and is the sole disaster-recovery mechanism if all admin keys are lost.
            print(f"  {recovery_code}")
            print("=" * 50)
        return 0
    except Fido2NotFoundError as e:
        print(f"FIDO2 registration failed: {e}", file=sys.stderr)
        return 1
    except Fido2TimeoutError as e:
        print(f"FIDO2 registration timed out: {e}", file=sys.stderr)
        return 1
    except Fido2UserInteractionRequiredError as e:
        print(f"FIDO2 registration failed: {e}", file=sys.stderr)
        return 1
    except Fido2ClientError as e:
        error_text = str(e)
        if "already initialized" in error_text.lower():
            print(f"FIDO2 registration failed: {error_text}", file=sys.stderr)
            return 1
        elif "pending enrollment" in error_text.lower():
            print(f"FIDO2 registration failed: {error_text}", file=sys.stderr)
            print(
                "A pending enrollment already exists. Use --installation-reset to clear it:",
                file=sys.stderr,
            )
            print(f"  venya init {args.user_id} --installation-reset", file=sys.stderr)
            return 1
        print(f"FIDO2 registration failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Initialization failed: {e}", file=sys.stderr)
        return 1


def cmd_store(client: APIClient, args: Any) -> int:
    """Store a secret.

    Value input, in precedence order: explicit positional argument; stdin
    (positional ``-``, or omitted value with piped stdin); hidden TTY prompt
    (omitted value with interactive stdin). The stdin/prompt paths keep the
    value out of argv — /proc/*/cmdline and shell history are not secret
    stores (ticket cli-store-stdin-help-false; same stdin-carriage discipline
    the installers use for passwords). Trailing newline stripped from piped
    input (``echo`` convention).
    """
    value = args.value
    if value is None or value == "-":
        if value == "-" or not sys.stdin.isatty():
            value = sys.stdin.read().rstrip("\r\n")
        else:
            value = getpass.getpass("Secret value (input hidden): ")
        if not value:
            print(
                "Error: secret value required (provide as argument, pipe via stdin, or pass '-' to read stdin)",
                file=sys.stderr,
            )
            return 1

    # Resolve key_version_id: explicit --key-version wins, otherwise the
    # server's active key version (POST /secrets requires the field).
    key_version_id = getattr(args, "key_version", None)
    if not key_version_id:
        try:
            kv = client.get("/api/v1/key-versions/active")
            key_version_id = kv["key_version_id"]
        except APIClientError as e:
            print(
                f"Failed to resolve active key version: {e}. " "Pass --key-version explicitly (e.g. --key-version v1).",
                file=sys.stderr,
            )
            return 1

    try:
        payload = {
            "key": args.key,
            "value": value,
            "roles": args.roles,
            "key_version_id": key_version_id,
        }

        # Parse metadata key=value pairs
        metadata = getattr(args, "metadata", None)
        if metadata:
            meta_dict = {}
            for item in metadata:
                k, _, v = item.partition("=")
                meta_dict[k] = v
            payload["metadata"] = meta_dict

        resp = client.post(
            "/api/v1/secrets",
            json=payload,
        )
        if isinstance(resp, dict) and resp.get("replaced"):
            print(f"Secret '{args.key}' replaced existing (id {resp.get('id')}).")
        else:
            print(f"Secret '{args.key}' stored successfully.")
        return 0
    except APIClientError as e:
        print(f"Failed to store secret: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to store secret: {e}", file=sys.stderr)
        return 1


def cmd_get(client: APIClient, args: Any) -> int:
    """Retrieve a secret."""
    try:
        result = client.get(
            f"/api/v1/secrets/{args.key}",
            params={"unmask": args.unmask},
        )
        if args.unmask:
            print(result.get("value", ""))
        else:
            print("\u2022" * 8)  # ••••••••
        return 0
    except APIClientError as e:
        print(f"Failed to retrieve secret: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to retrieve secret: {e}", file=sys.stderr)
        return 1


def cmd_list(client: APIClient, args: Any) -> int:
    """List secrets."""
    try:
        params = {}
        if getattr(args, "prefix", None):
            params["prefix"] = args.prefix
        if getattr(args, "executor", None):
            params["executor"] = args.executor
        if getattr(args, "purpose", None):
            params["purpose"] = args.purpose
        if getattr(args, "username", None):
            params["username"] = args.username

        result = client.get("/api/v1/secrets", params=params)
        secrets = result.get("secrets", [])

        if not secrets:
            print("No secrets found.")
            return 0

        for secret in secrets:
            line = f"  {secret['key']}"
            meta = secret.get("metadata")
            if meta:
                parts = []
                if meta.get("executor"):
                    parts.append(f"executor={meta['executor']}")
                if meta.get("purpose"):
                    parts.append(f"purpose={meta['purpose']}")
                if meta.get("username"):
                    parts.append(f"username={meta['username']}")
                if parts:
                    line += f"  [{', '.join(parts)}]"
            print(line)
        return 0
    except APIClientError as e:
        print(f"Failed to list secrets: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to list secrets: {e}", file=sys.stderr)
        return 1


def cmd_delete(client: APIClient, args: Any) -> int:
    """Delete a secret."""
    try:
        client.delete(f"/api/v1/secrets/{args.key}")
        print(f"Secret '{args.key}' deleted.")
        return 0
    except APIClientError as e:
        print(f"Failed to delete secret: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to delete secret: {e}", file=sys.stderr)
        return 1


def cmd_update_metadata(client: APIClient, args: Any) -> int:
    """Update metadata for a secret."""
    try:
        meta_dict = {}
        for item in args.metadata:
            k, _, v = item.partition("=")
            meta_dict[k] = v

        client.patch(f"/api/v1/secrets/{args.key}/metadata", json={"metadata": meta_dict})
        print(f"Metadata updated for secret '{args.key}'.")
        return 0
    except APIClientError as e:
        print(f"Failed to update metadata: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to update metadata: {e}", file=sys.stderr)
        return 1


def cmd_audit(client: APIClient, args: Any) -> int:
    """Query audit log."""
    try:
        params = {}
        if args.user:
            params["user"] = args.user
        if args.key:
            params["key"] = args.key
        if args.start_date:
            params["start_date"] = args.start_date
        if args.end_date:
            params["end_date"] = args.end_date
        if args.days:
            params["days"] = args.days
        if args.hours:
            params["hours"] = args.hours
        params["limit"] = args.limit
        params["offset"] = args.offset

        result = client.get("/api/v1/audit", params=params)
        events = result.get("events", [])

        if not events:
            print("No audit events found.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        for event in events:
            print(f"  [{event['timestamp']}] {event['event_type']} " f"(user: {event.get('user_id', 'N/A')})")
        return 0
    except APIClientError as e:
        print(f"Failed to query audit log: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to query audit log: {e}", file=sys.stderr)
        return 1


def cmd_admin(client: APIClient, args: Any) -> int:
    """Admin operations."""
    admin_command = getattr(args, "admin_command", None)
    if admin_command is None:
        print("Error: admin subcommand required", file=sys.stderr)
        return 1

    if admin_command == "enroll":
        return cmd_admin_enroll(client, args)
    elif admin_command == "remove":
        return cmd_admin_remove(client, args)
    elif admin_command == "configure-user":
        return cmd_admin_configure(client, args)
    elif admin_command == "list":
        return cmd_admin_list(client, args)
    elif admin_command == "create-user":
        return cmd_admin_create_user(client, args)
    elif admin_command == "set-command-policy":
        return cmd_admin_set_policy(client, args)
    elif admin_command == "get-command-policy":
        return cmd_admin_get_policy(client, args)
    elif admin_command == "add-allowed-command":
        return cmd_admin_add_command(client, args)
    elif admin_command == "key-version":
        return cmd_admin_key_version(client, args)
    elif admin_command == "rotate-key":
        return cmd_admin_rotate_key(client, args)
    elif admin_command == "revoke-executor":
        return cmd_admin_revoke_executor(client, args)
    elif admin_command == "executor-enroll":
        return cmd_admin_executor_enroll(client, args)
    elif admin_command == "list-tokens":
        return cmd_admin_list_tokens(client, args)
    elif admin_command == "issue-token":
        return cmd_admin_issue_token(client, args)
    elif admin_command == "revoke-token":
        return cmd_admin_revoke_token(client, args)
    elif admin_command == "re-enroll":
        return cmd_admin_re_enroll(client, args)
    elif admin_command == "export-ca-cert":
        return cmd_admin_export_ca_cert(args)
    elif admin_command == "export-ca-key":
        return cmd_admin_export_ca_key(args)
    elif admin_command == "split-ca-key":
        return cmd_admin_split_ca_key(args)
    elif admin_command == "restore-ca-key":
        return cmd_admin_restore_ca_key(args)
    elif admin_command == "init-admin-ca":
        return cmd_admin_init_admin_ca(args)
    elif admin_command == "generate-admin-cert":
        return cmd_admin_generate_admin_cert(args)
    elif admin_command == "revoke-admin-cert":
        return cmd_admin_revoke_admin_cert(client, args)
    else:
        print(f"Unknown admin command: {admin_command}", file=sys.stderr)
        return 1


def cmd_admin_enroll(client: APIClient, args: Any) -> int:
    """Enroll a new user."""
    try:
        result = client.post(
            "/api/v1/admin/enroll",
            json={"user_id": args.user_id, "auth_mode": args.mode},
        )
        print(f"User '{args.user_id}' enrolled successfully.")
        if "enrollment_token" in result:
            print(f"Enrollment token: {result['enrollment_token']}")
        return 0
    except APIClientError as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_remove(client: APIClient, args: Any) -> int:
    """Remove a user."""
    try:
        client.delete(f"/api/v1/admin/users/{args.user_id}")
        print(f"User '{args.user_id}' removed.")
        return 0
    except APIClientError as e:
        print(f"Remove failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Remove failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_configure(client: APIClient, args: Any) -> int:
    """Configure user settings."""
    try:
        config = {}
        if args.mode:
            config["auth_mode"] = args.mode
        if args.timeout:
            config["session_timeout"] = args.timeout

        client.put(
            f"/api/v1/admin/users/{args.user_id}",
            json=config,
        )
        print(f"User '{args.user_id}' configured.")
        return 0
    except APIClientError as e:
        print(f"Configure failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Configure failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_list(client: APIClient, args: Any) -> int:
    """List all users."""
    try:
        result = client.get("/api/v1/admin/users")
        users = result.get("users", [])

        if not users:
            print("No users found.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        # Calculate column widths
        headers = ["USER_ID", "DISPLAY_NAME", "STATUS", "AUTH_MODE", "ENROLLED_AT", "SESSION_TIMEOUT"]
        rows = []
        for u in users:
            rows.append(
                [
                    u.get("user_id", ""),
                    u.get("display_name") or "-",
                    u.get("status", ""),
                    u.get("auth_mode", ""),
                    u.get("enrolled_at") or "-",
                    str(u.get("session_timeout", "")),
                ]
            )

        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))

        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print(fmt.format(*["-" * w for w in widths]))
        for row in rows:
            print(fmt.format(*row))
        return 0
    except Exception as e:
        print(f"List failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_create_user(client: APIClient, args: Any) -> int:
    """Create a new user and issue an enrollment token."""
    try:
        payload = {"username": args.username}
        if getattr(args, "display_name", None):
            payload["display_name"] = args.display_name
        if getattr(args, "roles", None):
            payload["roles"] = [r.strip() for r in args.roles.split(",")]

        result = client.post("/api/v1/admin/users", json=payload)

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        print("User created successfully.")
        print(f"  User ID:       {result.get('user_id', '')}")
        print(f"  Status:        {result.get('status', '')}")
        token = result.get("enrollment_token", "")
        expires = result.get("expires_in_seconds", 900)
        if token:
            print(f"  Enrollment Token: {token}")
            print("    WARNING: Token is printed once and never stored.")
            print(f"    Expires in: {expires} seconds")
        return 0
    except APIClientError as e:
        print(f"Create user failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Create user failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_set_policy(client: APIClient, args: Any) -> int:
    """Set command policy."""
    try:
        policy = {"preset": args.preset}
        if args.custom:
            policy["custom"] = args.custom

        client.post("/api/v1/admin/command-policy", json=policy)
        print(f"Command policy set to '{args.preset}'.")
        return 0
    except APIClientError as e:
        print(f"Set policy failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Set policy failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_get_policy(client: APIClient, args: Any) -> int:
    """Get command policy."""
    try:
        result = client.get("/api/v1/admin/command-policy")
        print(json.dumps(result, indent=2))
        return 0
    except APIClientError as e:
        print(f"Get policy failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Get policy failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_add_command(client: APIClient, args: Any) -> int:
    """Add allowed command."""
    try:
        client.post(
            "/api/v1/admin/command-policy/allowed",
            json={"command_path": args.command_path},
        )
        print(f"Command '{args.command_path}' added to allowlist.")
        return 0
    except APIClientError as e:
        print(f"Add command failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Add command failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_key_version(client: APIClient, args: Any) -> int:
    """Key version management."""
    kv_command = getattr(args, "kv_command", None)
    if kv_command is None:
        print("Error: key-version subcommand required", file=sys.stderr)
        return 1

    if kv_command == "list":
        result = client.get("/api/v1/admin/key-versions")
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result, indent=2))
    elif kv_command == "deactivate":
        version_id = getattr(args, "version_id", None)
        if not version_id:
            print("Error: version_id required", file=sys.stderr)
            return 1
        client.post(f"/api/v1/admin/key-versions/{version_id}/deactivate")
        print(f"Key version {version_id} deactivated.")
    elif kv_command == "revoke":
        version_id = getattr(args, "version_id", None)
        if not version_id:
            print("Error: version_id required", file=sys.stderr)
            return 1
        client.post(f"/api/v1/admin/key-versions/{version_id}/revoke")
        print(f"Key version {version_id} revoked.")
    elif kv_command == "rotate-status":
        result = client.get("/api/v1/admin/key-rotation/status")
        print(json.dumps(result, indent=2))
    elif kv_command == "rollback":
        job_id = getattr(args, "job_id", None)
        if not job_id:
            print("Error: job_id required", file=sys.stderr)
            return 1
        client.post(f"/api/v1/admin/key-rotation/{job_id}/rollback")
        print(f"Rotation job {job_id} rolled back.")
    else:
        print(f"Unknown key-version command: {kv_command}", file=sys.stderr)
        return 1

    return 0


def cmd_admin_rotate_key(client: APIClient, args: Any) -> int:
    """Rotate key."""
    try:
        payload = {}
        if args.new_key:
            payload["new_key_path"] = args.new_key

        result = client.post("/api/v1/admin/key-rotation", json=payload)
        print(f"Key rotation started: {result.get('job_id', 'N/A')}")
        return 0
    except APIClientError as e:
        print(f"Key rotation failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Key rotation failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_revoke_executor(client: APIClient, args: Any) -> int:
    """Revoke executor certificate (admin command entry point).

    Delegates to executor_cert_revoke() with the admin client.
    """

    # Build a minimal args-like object with executor_id
    class _RevokeArgs:
        executor_id = args.executor_id
        cert_path = "/etc/venya/executor/executor.crt"

    return executor_cert_revoke(_RevokeArgs(), client=client)


def cmd_admin_executor_enroll(client: APIClient, args: Any) -> int:
    """Generate an enrollment token for executor bootstrap registration."""
    try:
        result = client.post(f"/api/v1/admin/executors/{args.executor_id}/enroll")
        token = result.get("enrollment_token", "")
        expires_in = result.get("expires_in_seconds", 900)
        output_dir = getattr(args, "output_dir", None)

        if output_dir:
            import hashlib as hashlib_mod

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            token_path = output_path / "token"
            token_path.write_text(token)

            core_ca_path = output_path / "core-server-ca.crt"
            venya_ca_path = Path("/var/lib/venya/ca/ca.crt")
            if venya_ca_path.exists():
                core_ca_path.write_bytes(venya_ca_path.read_bytes())
                core_ca_written = True
            else:
                core_ca_written = False

            admin_ca_path = output_path / "admin-ca.crt"
            admin_ca_dir = Path("/var/lib/venya/ca/admin-ca")
            if (admin_ca_dir / "admin-ca.crt").exists():
                admin_ca_path.write_bytes((admin_ca_dir / "admin-ca.crt").read_bytes())
                admin_ca_written = True
            else:
                admin_ca_written = False

            bundle_data = token.encode()
            if core_ca_written:
                bundle_data += core_ca_path.read_bytes()
            if admin_ca_written:
                bundle_data += admin_ca_path.read_bytes()
            bundle_hash = hashlib_mod.sha256(bundle_data).hexdigest()

            print(f"Generated enrollment bundle for {args.executor_id}:")
            print(f"  {token_path}")
            if core_ca_written:
                print(f"  {core_ca_path}")
            else:
                print(f"  {core_ca_path} (NOT FOUND — install core first)")
            if admin_ca_written:
                print(f"  {admin_ca_path}")
            else:
                print(f"  {admin_ca_path} (NOT FOUND)")
            print()
            print("Bundle fingerprint (verify before copying to executor):")
            print(f"  SHA256: {bundle_hash}")
            print()
            print("To install on executor VM:")
            print(f"  scp -r {output_dir} bot@venya-exec-1:/tmp/")
            print()
            print("  curl -fsSL http://.../install-venya-executor.sh | \\")
            print("    sudo VENYA_SERVER_URL=https://venya-core-1 \\")
            print(f"         VENYA_EXECUTOR_ID={args.executor_id} \\")
            print(f"         VENYA_EXECUTOR_ENROLLMENT_TOKEN=$(cat {token_path}) \\")
            print(f"         VENYA_CORE_CA_CERT={core_ca_path} \\")
            print("         bash -s")
            print()
            print(f"Note: This bundle is valid for {expires_in // 60} minutes.")
        else:
            print(f"Enrollment token for executor '{args.executor_id}':")
            print(f"  Token: {token}")
            print(f"  Expires in: {expires_in} seconds ({expires_in // 60} minutes)")
            print("Deliver this token to the executor operator out-of-band.")

        return 0
    except APIClientError as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_list_tokens(client: APIClient, args: Any) -> int:
    """List all enrollment tokens for a user."""
    try:
        result = client.get(f"/api/v1/admin/users/{args.user_id}/enrollment-tokens")
        tokens = result.get("tokens", [])

        if not tokens:
            print("No tokens found.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        headers = ["ID", "STATE", "CREATED_AT", "EXPIRES_AT", "USED_AT"]
        rows = []
        for t in tokens:
            rows.append(
                [
                    t.get("id", ""),
                    t.get("state", ""),
                    t.get("created_at") or "-",
                    t.get("expires_at") or "-",
                    t.get("used_at") or "-",
                ]
            )

        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))

        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print(fmt.format(*["-" * w for w in widths]))
        for row in rows:
            print(fmt.format(*row))
        return 0
    except APIClientError as e:
        print(f"List tokens failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"List tokens failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_issue_token(client: APIClient, args: Any) -> int:
    """Revoke old tokens and issue a new enrollment token for a user."""
    try:
        result = client.post(f"/api/v1/admin/users/{args.user_id}/enrollment-tokens")

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        print(f"Token issued successfully for user '{args.user_id}'.")
        token = result.get("enrollment_token", "")
        if token:
            print(f"  Enrollment Token: {token}")
            print("    WARNING: Token is printed once and never stored.")
        print(f"  Previous tokens revoked: {result.get('previous_tokens_revoked', 0)}")
        print(f"  Expires in: {result.get('expires_in_seconds', 900)} seconds")
        return 0
    except APIClientError as e:
        print(f"Issue token failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Issue token failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_revoke_token(client: APIClient, args: Any) -> int:
    """Revoke a single enrollment token."""
    try:
        client.delete(f"/api/v1/admin/enrollment-tokens/{args.token_id}")
        print(f"Token '{args.token_id}' revoked.")
        return 0
    except APIClientError as e:
        print(f"Revoke token failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Revoke token failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_re_enroll(client: APIClient, args: Any) -> int:
    """Deactivate credentials, revoke tokens, and issue a new enrollment token."""
    try:
        result = client.post(f"/api/v1/admin/users/{args.user_id}/re-enroll")

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        print(f"Re-enrollment initiated for user '{args.user_id}'.")
        print(f"  User ID:       {result.get('user_id', '')}")
        print(f"  Status:        {result.get('status', '')}")
        token = result.get("enrollment_token", "")
        if token:
            print(f"  Enrollment Token: {token}")
            print("    WARNING: Token is printed once and never stored.")
        print(f"  Credentials deactivated: {result.get('credentials_deactivated', False)}")
        print(f"  Tokens revoked: {result.get('tokens_revoked', 0)}")
        print(f"  Expires in: {result.get('expires_in_seconds', 900)} seconds")
        return 0
    except APIClientError as e:
        print(f"Re-enroll failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Re-enroll failed: {e}", file=sys.stderr)
        return 1


def cmd_role(client: APIClient, args: Any) -> int:
    """Role management."""
    role_command = getattr(args, "role_command", None)
    if role_command is None:
        print("Error: role subcommand required", file=sys.stderr)
        return 1

    if role_command == "create":
        return cmd_role_create(client, args)
    elif role_command == "list":
        return cmd_role_list(client, args)
    elif role_command == "get":
        return cmd_role_get(client, args)
    elif role_command == "delete":
        return cmd_role_delete(client, args)
    elif role_command == "members":
        return cmd_role_members(client, args)
    elif role_command == "add-member":
        return cmd_role_add_member(client, args)
    elif role_command == "remove-member":
        return cmd_role_remove_member(client, args)
    else:
        print(f"Unknown role command: {role_command}", file=sys.stderr)
        return 1


def cmd_role_create(client: APIClient, args: Any) -> int:
    """Create a role."""
    try:
        client.post(
            "/api/v1/roles",
            json={
                "name": args.name,
                "permissions": args.permissions,
                "description": args.description,
            },
        )
        print(f"Role '{args.name}' created.")
        return 0
    except APIClientError as e:
        print(f"Failed to create role: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to create role: {e}", file=sys.stderr)
        return 1


def cmd_role_list(client: APIClient, args: Any) -> int:
    """List roles."""
    try:
        result = client.get("/api/v1/roles")
        roles = result.get("roles", [])

        if not roles:
            print("No roles found.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        for role in roles:
            print(f"  {role['id']}: {role['name']} " f"({role['permissions']})")
        return 0
    except APIClientError as e:
        print(f"Failed to list roles: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to list roles: {e}", file=sys.stderr)
        return 1


def cmd_role_get(client: APIClient, args: Any) -> int:
    """Get role details."""
    try:
        result = client.get(f"/api/v1/roles/{args.role_id}")
        print(json.dumps(result, indent=2))
        return 0
    except APIClientError as e:
        print(f"Failed to get role: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to get role: {e}", file=sys.stderr)
        return 1


def cmd_role_delete(client: APIClient, args: Any) -> int:
    """Delete a role."""
    try:
        client.delete(f"/api/v1/roles/{args.role_id}")
        print(f"Role '{args.role_id}' deleted.")
        return 0
    except APIClientError as e:
        print(f"Failed to delete role: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to delete role: {e}", file=sys.stderr)
        return 1


def cmd_role_members(client: APIClient, args: Any) -> int:
    """List role members."""
    try:
        result = client.get(f"/api/v1/roles/{args.role_id}/members")
        members = result.get("members", [])

        if not members:
            print("No members found.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        for member in members:
            print(f"  {member['user_id']}")
        return 0
    except APIClientError as e:
        print(f"Failed to list members: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to list members: {e}", file=sys.stderr)
        return 1


def cmd_role_add_member(client: APIClient, args: Any) -> int:
    """Add user to role."""
    try:
        client.post(
            f"/api/v1/roles/{args.role_id}/members",
            json={"user_id": args.user_id},
        )
        print(f"User '{args.user_id}' added to role '{args.role_id}'.")
        return 0
    except APIClientError as e:
        print(f"Failed to add member: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to add member: {e}", file=sys.stderr)
        return 1


def cmd_role_remove_member(client: APIClient, args: Any) -> int:
    """Remove user from role."""
    try:
        client.delete(f"/api/v1/roles/{args.role_id}/members/{args.user_id}")
        print(f"User '{args.user_id}' removed from role '{args.role_id}'.")
        return 0
    except APIClientError as e:
        print(f"Failed to remove member: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to remove member: {e}", file=sys.stderr)
        return 1


def cmd_recovery(client: APIClient, args: Any) -> int:
    """Break-glass recovery."""
    try:
        client.post(
            "/api/v1/recovery",
            json={
                "code": args.code,
                "new_user_id": args.new_user_id,
                "force": getattr(args, "force", False),
                "confirm": getattr(args, "confirm", False),
            },
        )
        print("Recovery completed successfully.")
        return 0
    except APIClientError as e:
        print(f"Recovery failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Recovery failed: {e}", file=sys.stderr)
        return 1


def cmd_run(client: APIClient, args: Any) -> int:
    """Execute a command via the executor with secret injection and output filtering.

    Flow:
        1. Authenticate (if not already)
        2. Resolve secrets for the command
        3. Create executor session
        4. Execute command via executor daemon API
        5. Display filtered output
    """
    command_args = getattr(args, "command_args", None)
    # argparse REMAINDER captures a leading `--` separator literally (verified
    # on CPython 3.14): strip exactly one so `venya run -- cmd...` sends
    # `cmd...`. A second `--` is the user's intended command token. The
    # captured separator broke validator ssh-shape recognition (false
    # 'Dangerous pattern' rejects) and sandbox execution (`sh -c "-- ..."` →
    # 127) — ticket command-validator-sudo-inconsistency. Any future
    # REMAINDER-based command needs the same strip (invariant lives here, not
    # in argparse).
    if command_args and command_args[0] == "--":
        command_args = command_args[1:]
    command = " ".join(command_args) if command_args else ""
    if not command:
        print("Error: command required", file=sys.stderr)
        return 1

    executor_id = getattr(args, "executor_id", None) or "default"

    # Step 1: Collect secret keys (server resolves and wraps them)
    secret_keys = getattr(args, "secrets", None) or []
    if not secret_keys:
        print("No secrets specified. Command will run without injected credentials.")

    # Step 2: Create executor session (keys only; server-side wrapping)
    try:
        session_result = client.post(
            "/api/v1/executors/sessions",
            json={
                "executor_id": executor_id,
                "secret_keys": secret_keys,
            },
        )
        session_id = session_result["session_id"]
        print(f"Session created: {session_id}")
    except APIClientError as e:
        print(f"Failed to create session: {e}", file=sys.stderr)
        return 1

    # Step 3: Execute command via executor
    try:
        print(f"Executing: {command}")
        exec_result = client.post(
            f"/api/v1/executors/{executor_id}/execute",
            json={
                "session_id": session_id,
                "command": command,
            },
        )
        exit_code = exec_result.get("exit_code", 0)
        stdout = exec_result.get("stdout", "")
        stderr = exec_result.get("stderr", "")

        # Display filtered output
        if stdout:
            print(stdout, end="" if stdout.endswith("\n") else "\n")
        if stderr:
            print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)

        masked_count = exec_result.get("masked_count", 0)
        if masked_count > 0:
            print(f"\n({masked_count} secret(s) masked in output)", file=sys.stderr)

        print(f"\nCommand exited with code: {exit_code}")
        return exit_code
    except APIClientError as e:
        print(f"Execution failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Execution failed: {e}", file=sys.stderr)
        return 1


def cmd_config(client: APIClient, args: Any) -> int:
    """Manage CLI configuration."""
    config_command = getattr(args, "config_command", None)
    if config_command is None:
        print("Error: config subcommand required (show, set-server, clear-token)", file=sys.stderr)
        return 1

    if config_command == "show":
        return cmd_config_show(client)
    elif config_command == "set-server":
        return cmd_config_set_server(client, args)
    elif config_command == "clear-token":
        return cmd_config_clear_token(client)
    else:
        print(f"Unknown config command: {config_command}", file=sys.stderr)
        return 1


def cmd_config_show(client: APIClient) -> int:
    """Show current configuration."""
    config = client.config
    print("Venya CLI Configuration:")
    print(f"  Server URL: {config.server_url}")
    if config.access_token:
        print("  Access Token: [set] (expires soon — run 'venya run' to refresh)")
    else:
        print("  Access Token: [not set]")
    print(f"  Config File: {config.config_file}")
    return 0


def cmd_config_set_server(client: APIClient, args: Any) -> int:
    """Set the server URL."""
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    client.config.server_url = url
    print(f"Server URL set to: {url}")
    return 0


def cmd_config_clear_token(client: APIClient) -> int:
    """Clear stored access token."""
    client.config.access_token = None
    print("Access token cleared. Re-authentication required.")
    return 0


def cmd_credential(client: APIClient, args: Any) -> int:
    """Credential management operations."""
    cred_command = getattr(args, "credential_command", None)
    if cred_command is None:
        print("Error: credential subcommand required (list, add, remove)", file=sys.stderr)
        return 1

    if cred_command == "list":
        return cmd_credential_list(client, args)
    elif cred_command == "add":
        return cmd_credential_add(client, args)
    elif cred_command == "remove":
        return cmd_credential_remove(client, args)
    else:
        print(f"Unknown credential command: {cred_command}", file=sys.stderr)
        return 1


def cmd_credential_list(client: APIClient, args: Any) -> int:
    """List own credentials."""
    try:
        result = client.get("/api/v1/credentials")
        credentials = result.get("credentials", [])

        if not credentials:
            print("No credentials found.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        headers = ["ID", "LABEL", "CREATED_AT", "LAST_USED_AT"]
        rows = []
        for c in credentials:
            rows.append(
                [
                    # Server returns the DB id as int; table cells must be str
                    # before the len() width pass below (TypeError otherwise —
                    # found physically on Windows, broken on every platform).
                    str(c.get("id", "")),
                    str(c.get("label") or "-"),
                    str(c.get("created_at") or "-"),
                    str(c.get("last_used_at") or "-"),
                ]
            )

        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))

        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print(fmt.format(*["-" * w for w in widths]))
        for row in rows:
            print(fmt.format(*row))
        return 0
    except APIClientError as e:
        print(f"Failed to list credentials: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to list credentials: {e}", file=sys.stderr)
        return 1


def _elevate(client: APIClient) -> str:
    """Perform elevation via WebAuthn re-authentication.

    Returns:
        Elevation token string.

    Raises:
        APIClientError: If elevation fails.
    """
    try:
        # Step 1: Get elevation challenge. MUST go through the APIClient: the
        # route requires the session bearer token (Depends(get_current_user)),
        # and Fido2Auth._post sends no Authorization header — pre-fix every
        # elevation died 401 "Missing authentication token" on every platform
        # (found physically on win11 during the elevation acceptance run;
        # unit tests had only ever exercised a mocked _post).
        challenge_result = client.post("/api/v1/auth/elevate/challenge", json={})
        challenge_id = challenge_result["challenge_id"]
        options = challenge_result["options"]
    except APIClientError as e:
        raise APIClientError(f"Elevation challenge failed: {e}") from e

    # Step 2: Build request options
    from fido2.webauthn import (
        CredentialRequestOptions,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions,
        UserVerificationRequirement,
    )

    from .fido2_client import Fido2Auth
    from .webauthn import b64_decode_id

    # Use the production normalizer (single source of truth for server JSON shape)
    fido2 = Fido2Auth(client.config.server_url)
    norm = fido2.normalize_webauthn_options(options)
    challenge = b64_decode_id(norm["challenge"])

    allow_credentials = []
    for cred in norm.get("allow_credentials", []) or []:
        allow_credentials.append(
            PublicKeyCredentialDescriptor(
                type=cred.get("type", "public-key"),
                id=cred["id"],  # already decoded by normalizer
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

    request_options = CredentialRequestOptions(public_key=public_key)

    # Step 3: Perform WebAuthn assertion (retry on wrong PIN).
    # UV/PIN dispatch is in Fido2Auth._get_assertion (see full comment there):
    # clientPin-only keys are asserted via Ctap2.get_assertion directly.
    from fido2.client import ClientError, CtapError

    try:
        max_pin_retries = 3
        for attempt in range(max_pin_retries):
            try:
                assertion = fido2._get_assertion(request_options, timeout=60.0)
                break
            except (ClientError, CtapError) as e:
                # fido2 may surface a CTAP error wrapped in ClientError (original in
                # e.cause); unwrap so the PIN retry below still applies.
                if isinstance(e, ClientError) and isinstance(e.cause, CtapError):
                    e = e.cause
                if isinstance(e, ClientError):
                    if e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
                        raise APIClientError(
                            "Security key has no PIN set and cannot verify the user "
                            "another way. Set a PIN on the key (e.g. yubikey-manager), "
                            "then try again."
                        ) from e
                    raise
                if e.code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PIN_AUTH_INVALID):
                    if attempt < max_pin_retries - 1:
                        continue
                    raise APIClientError(f"PIN incorrect after {max_pin_retries} attempts") from e
                if e.code == CtapError.ERR.PIN_BLOCKED:
                    raise APIClientError("Security key PIN is blocked.") from e
                raise
    except OSError as e:
        err_str = str(e).lower()
        if "fido" in err_str or "device" in err_str or "usb" in err_str or "no such" in err_str:
            raise APIClientError(f"No FIDO2 device found: {e}") from e
        if "time" in err_str or "timeout" in err_str:
            raise APIClientError(f"Elevation timed out: {e}") from e
        raise APIClientError(f"FIDO2 error: {e}") from e
    except ValueError as e:
        err_msg = str(e).lower()
        if "user" in err_msg or "presence" in err_msg or "touch" in err_msg:
            raise APIClientError("Please touch your security key") from e
        raise APIClientError(f"FIDO2 error: {e}") from e

    # Step 4: Format assertion (deduped — also fixes latent bug where the
    # inline formatter used non-existent AssertionSelection.assertions/.client_data).
    response = fido2._format_assertion_response(assertion)

    # Step 5: Submit assertion to get elevation token (APIClient — bearer
    # token required, same reason as step 1)
    try:
        assert_result = client.post(
            "/api/v1/auth/elevate/assert",
            json={
                "challenge_id": challenge_id,
                "response": response,
            },
        )
    except APIClientError as e:
        raise APIClientError(f"Elevation assertion failed: {e}") from e

    return assert_result["elevation_token"]


def cmd_credential_add(client: APIClient, args: Any) -> int:
    """Add a new credential (requires elevation via WebAuthn re-auth)."""
    try:
        label = args.label

        # Step 1: Elevate
        print("Re-authenticating with security key for elevation...")
        elevation_token = _elevate(client)
        print("Elevation successful.")

        # Step 2: Start credential registration
        start_result = client.post(
            "/api/v1/credentials/add/browser/start",
            json={"label": label},
            extra_headers={"X-Elevation-Token": elevation_token},
        )
        challenge_id = start_result["challenge_id"]
        options = start_result["options"]

        print("Please touch your security key to register the credential...")

        # Steps 3+4: Perform WebAuthn registration and format the response —
        # routed through the shared Fido2Auth machinery exactly like cmd_enroll:
        # platform factory on Windows (WindowsClient), raw CTAP path elsewhere,
        # server-URL origin for the client-data collector, real-shape formatter.
        # The duplicated inline ceremony that lived here produced three
        # independent platform-agnostic bugs (.auth_response AttributeError;
        # no bearer token on the elevation calls; hardcoded https://localhost
        # origin -> rp_id verification -> BAD_REQUEST, found physically on
        # win11) — deleted, not patched (option-B ruling 2026-09-19).
        from .fido2_client import Fido2Auth, Fido2ClientError

        fido2 = Fido2Auth(client.config.server_url)
        try:
            request_options = fido2._build_registration_options(options)
            credential = fido2._get_credential(request_options, timeout=60.0)
        except Fido2ClientError as e:
            raise APIClientError(f"FIDO2 error: {e}") from e
        cred_response = fido2._format_credential_response(credential)

        # Step 5: Complete registration
        result = client.post(
            "/api/v1/credentials/add/browser/complete",
            json={
                "challenge_id": challenge_id,
                "response": cred_response,
                "label": label,
            },
            extra_headers={"X-Elevation-Token": elevation_token},
        )

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        print("Credential added successfully.")
        print(f"  Credential ID: {result.get('id', '')}")
        print(f"  Label: {result.get('label', label)}")
        print("  Status: ok")
        return 0
    except APIClientError as e:
        print(f"Failed to add credential: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to add credential: {e}", file=sys.stderr)
        return 1


def cmd_credential_remove(client: APIClient, args: Any) -> int:
    """Remove a credential (requires elevation via WebAuthn re-auth)."""
    try:
        credential_id = args.credential_id

        # Step 1: Elevate
        print("Re-authenticating with security key for elevation...")
        elevation_token = _elevate(client)
        print("Elevation successful.")

        # Step 2: Remove credential
        client.delete(
            f"/api/v1/credentials/{credential_id}",
            extra_headers={"X-Elevation-Token": elevation_token},
        )
        print(f"Credential '{credential_id}' removed.")
        return 0
    except APIClientError as e:
        print(f"Failed to remove credential: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to remove credential: {e}", file=sys.stderr)
        return 1


def cmd_enroll(client: APIClient, args: Any) -> int:
    """Single-command enrollment: start → FIDO2 attestation → complete → store token."""
    from .fido2_client import (
        Fido2Auth,
        Fido2ClientError,
        Fido2NotFoundError,
        Fido2TimeoutError,
        Fido2UserInteractionRequiredError,
    )

    token = args.token
    label = getattr(args, "label", None)
    try:
        fido2 = Fido2Auth(client.config.server_url)
        print("Starting enrollment...")
        print("Please insert/touch your security key when prompted.\n")
        start = client.post("/api/v1/enroll/browser/start", json={"enrollment_token": token})
        request_options = fido2._build_registration_options(start["options"])
        credential = fido2._get_credential(request_options, timeout=60.0)
        response = fido2._format_credential_response(credential)
        payload = {
            "enrollment_token": token,
            "challenge_id": start["challenge_id"],
            "response": response,
            "label": label or "CLI",
        }
        result = client.post("/api/v1/enroll/browser/complete", json=payload)
        session_token = result.get("session_token", "")
        if not session_token:
            print("Enrollment completed but server returned no session token.", file=sys.stderr)
            return 1
        client.config.access_token = session_token
        print(f"Enrollment complete. Authenticated as {result.get('user_id', '')}.")
        return 0
    except (Fido2NotFoundError, Fido2TimeoutError, Fido2UserInteractionRequiredError, Fido2ClientError) as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1
    except APIClientError as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1


def cmd_login(client: APIClient, args: Any) -> int:
    """Authenticate with a security key and store the session token."""
    try:
        result = client.authenticate(user_id=args.user_id)
        print(f"Authenticated as {result['user_id']}.")
        return 0
    except APIClientAuthenticationError as e:
        print(f"Login failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Login failed: {e}", file=sys.stderr)
        return 1


# --- Executor Lifecycle Commands ---


def cmd_exec_group(client: APIClient, args: Any) -> int:
    """Dispatch executor lifecycle subcommands."""
    exec_command = getattr(args, "exec_command", None)
    if exec_command is None:
        print("Error: exec subcommand required (register, cert, heartbeat, audit, status)", file=sys.stderr)
        return 1

    if exec_command == "register":
        return executor_register(client, args)
    elif exec_command == "cert":
        return executor_cert(client, args)
    elif exec_command == "heartbeat":
        return executor_heartbeat(args)
    elif exec_command == "audit":
        return executor_audit(client, args)
    elif exec_command == "status":
        return executor_status(args)
    else:
        print(f"Unknown exec command: {exec_command}", file=sys.stderr)
        return 1


def executor_register(client: APIClient, args: Any) -> int:
    """Register this machine as an executor with the core.

    Flow:
        1. Generate ECDSA P-256 keypair locally
        2. Create CSR with CN=executor_id
        3. Submit CSR via client.register_executor() (with TLS fallback)
        4. Save signed cert + key to output-dir
        5. Verify auth with GET /api/v1/executors/certs/revocation-list
        6. Print success/failure
    """
    import os
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    executor_id = getattr(args, "executor_id", "venya-exec")
    output_dir = getattr(args, "output_dir", "/etc/venya")
    core_url = getattr(args, "core_url", None)
    enrollment_token = getattr(args, "enrollment_token", None)
    ca_bundle = getattr(args, "ca_bundle", None)
    if ca_bundle is not None and not isinstance(ca_bundle, str):
        ca_bundle = None

    # Fall back to executor config ca_bundle if not passed via CLI
    if ca_bundle is None:
        executor_config_path = Path("/etc/venya/executor.toml")
        if executor_config_path.exists():
            try:
                import tomllib

                with open(executor_config_path, "rb") as f:
                    config_data = tomllib.load(f)
                ca_bundle = config_data.get("ca_bundle")
            except Exception:  # nosec B110  # noqa: S110 — ignore optional config parse errors
                pass

    # Validate executor_id format before any operations
    try:
        from .executor_id import validate_executor_id

        executor_id = validate_executor_id(executor_id)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Determine server URL
    if core_url:
        server_url = core_url.rstrip("/")
    elif client.config.server_url and client.config.server_url != "http://localhost:8000":
        server_url = client.config.server_url.rstrip("/")
    else:
        print(
            f"Error: core URL required. Set it in config ({DEFAULT_CONFIG_FILE}) or pass --core-url",
            file=sys.stderr,
        )
        return 1

    # Step 1: Generate ECDSA P-256 keypair
    try:
        print("Generating ECDSA P-256 keypair...")
        private_key = ec.generate_private_key(ec.SECP256R1())
    except Exception as e:
        print(f"Key generation failed: {e}", file=sys.stderr)
        return 1

    # Step 2: Create CSR
    try:
        print(f"Creating CSR with CN={executor_id}...")
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
            ]
        )
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    except Exception as e:
        print(f"CSR creation failed: {e}", file=sys.stderr)
        return 1

    # Step 3: Submit CSR via register_executor() with TLS fallback
    try:
        print(f"Submitting CSR to {server_url}/api/v1/executors/register...")
        result = client.register_executor(
            executor_id=executor_id,
            csr_pem=csr_pem,
            enrollment_token=enrollment_token,
            ca_bundle=ca_bundle,
            server_url=server_url,
        )
        cert_pem = result.get("cert_pem", "")
        ca_cert_pem = result.get("ca_cert_pem", "")
        serial_number = result.get("serial_number", "")
        not_after = result.get("not_after", "")

        if not cert_pem:
            print("Registration failed: no certificate returned", file=sys.stderr)
            return 1
    except APIClientError as e:
        print(f"Registration failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Registration failed: {e}", file=sys.stderr)
        return 1

    # Step 4: Save cert + key to output-dir
    try:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save private key
        key_path = output_path / "executor.key"
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(key_pem)
        os.chmod(str(key_path), 0o600)

        # Save signed certificate
        cert_path = output_path / "executor.crt"
        cert_path.write_bytes(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)

        # Save CA certificate
        ca_cert_path = output_path / "ca.crt"
        if ca_cert_pem:
            ca_cert_path.write_bytes(ca_cert_pem.encode() if isinstance(ca_cert_pem, str) else ca_cert_pem)

        print(f"Certificate saved to {cert_path}")
        print(f"Private key saved to {key_path} (permissions: 600)")
        if ca_cert_pem:
            print(f"CA certificate saved to {ca_cert_path}")
    except OSError as e:
        print(f"Failed to save certificate: {e}", file=sys.stderr)
        return 1

    # Step 5: Verify auth with revocation list
    try:
        print("Verifying authentication...")
        client.get("/api/v1/executors/certs/revocation-list")
        print("Authentication verified.")
    except APIClientError as e:
        print(f"Warning: authentication verification failed: {e}", file=sys.stderr)
        print("Certificate was saved, but auth verification failed.", file=sys.stderr)

    # Step 6: Print success
    print(f"\nExecutor '{executor_id}' registered successfully.")
    print(f"  Serial: {serial_number}")
    print(f"  Expires: {not_after}")
    print(f"  Cert: {cert_path}")
    print("\nTo use mTLS authentication, set VENYA_MTLS_CERT and VENYA_MTLS_KEY:")
    print(f"  export VENYA_MTLS_CERT={cert_path}")
    print(f"  export VENYA_MTLS_KEY={key_path}")
    return 0


def executor_cert(client: APIClient, args: Any) -> int:
    """Certificate management subcommands."""
    cert_command = getattr(args, "cert_command", None)
    if cert_command is None:
        print("Error: cert subcommand required (status, renew, revoke)", file=sys.stderr)
        return 1

    if cert_command == "status":
        return executor_cert_status(args)
    elif cert_command == "renew":
        return executor_cert_renew(args)
    elif cert_command == "revoke":
        return executor_cert_revoke(args)
    else:
        print(f"Unknown cert command: {cert_command}", file=sys.stderr)
        return 1


def _parse_executor_cert(cert_path: str) -> dict[str, Any] | None:
    """Parse executor certificate and return metadata.

    Returns None if cert doesn't exist or can't be parsed.
    """
    from datetime import datetime

    from cryptography import x509
    from cryptography.x509 import load_pem_x509_certificate

    path = Path(cert_path)
    if not path.exists():
        return None

    try:
        cert_data = path.read_bytes()
        cert = load_pem_x509_certificate(cert_data)
        not_after = cert.not_valid_after_utc
        now = datetime.now(UTC)
        days_remaining = (not_after - now).days

        cn = "unknown"
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                cn = attr.value
                break

        return {
            "executor_id": cn,
            "serial": format(cert.serial_number, "X"),
            "subject": cert.subject.rfc4514_string(),
            "not_after": not_after,
            "days_remaining": days_remaining,
        }
    except Exception:
        return None


def _get_server_url(args: Any) -> str:
    """Resolve server URL from args, config, or executor.toml.

    Fallback chain:
    1. --core-url arg
    2. config.json via Config() (default: ~/.config/venya on Linux,
       ~/Library/Application Support/venya on macOS)
    3. /etc/venya/executor.toml via tomllib
    4. "unknown" as last resort
    """
    if getattr(args, "core_url", None):
        return args.core_url

    try:
        from .api_client import Config as CLIConfig

        config = CLIConfig()
        url = config.server_url
        if url and url != "http://localhost:8000":
            return url
    except Exception:  # nosec B110  # noqa: S110
        pass

    executor_config_path = getattr(args, "config_path", "/etc/venya/executor.toml")
    try:
        import tomllib

        with open(executor_config_path, "rb") as f:
            data = tomllib.load(f)
        return data.get("server_url", "unknown")
    except FileNotFoundError:
        return "unknown"
    except Exception:
        return "unknown"


def executor_cert_status(args: Any) -> int:
    """Show certificate expiry status.

    Reads the certificate file and prints days until expiry.
    """
    cert_path = getattr(args, "cert_path", "/etc/venya/executor/executor.crt")
    info = _parse_executor_cert(cert_path)

    if info is None:
        print(f"Error: certificate not found at {cert_path}", file=sys.stderr)
        print("Run 'venya exec register' to create a certificate.", file=sys.stderr)
        return 1

    print(f"Certificate: {cert_path}")
    print(f"  Subject: {info['executor_id']}")
    print(f"  Expires: {info['not_after'].isoformat()}")
    print(f"  Days remaining: {info['days_remaining']}")

    if info["days_remaining"] < 0:
        print("  STATUS: EXPIRED", file=sys.stderr)
        return 1
    elif info["days_remaining"] < 7:
        print("  WARNING: Certificate expires in less than 7 days!", file=sys.stderr)
        return 0
    else:
        print("  STATUS: OK")
        return 0


def executor_cert_renew(args: Any) -> int:
    """Renew executor certificate.

    Generates a new ECDSA P-256 keypair + CSR, submits via mTLS to
    /api/v1/executors/register, and saves the new cert/key atomically.
    """
    cert_path = getattr(args, "cert_path", "/etc/venya/executor/executor.crt")
    key_path = getattr(args, "key_path", None)
    if key_path is None:
        key_path = str(Path(cert_path).with_suffix(".key"))  # type: ignore[assignment]

    info = _parse_executor_cert(cert_path)
    if info is None:
        print(f"Error: certificate not found at {cert_path}", file=sys.stderr)
        print("Run 'venya exec register' to create a certificate.", file=sys.stderr)
        return 1

    if not Path(key_path).exists():
        print(f"Error: private key not found at {key_path}", file=sys.stderr)
        return 1

    executor_id = info["executor_id"]

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # Generate new ECDSA P-256 keypair + CSR
    try:
        print("Generating new ECDSA P-256 keypair...")
        new_private_key = ec.generate_private_key(ec.SECP256R1())
    except Exception as e:
        print(f"Key generation failed: {e}", file=sys.stderr)
        return 1

    try:
        print(f"Creating CSR with CN={executor_id}...")
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.COMMON_NAME, executor_id),
            ]
        )
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(new_private_key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    except Exception as e:
        print(f"CSR creation failed: {e}", file=sys.stderr)
        return 1

    # Build mTLS client with current cert
    server_url = _get_server_url(args)
    if server_url == "unknown":
        print("Error: server URL not configured. Use --core-url or set config.", file=sys.stderr)
        return 1

    try:
        tls_verify_env = os.environ.get("VENYA_TLS_VERIFY", "")
        if tls_verify_env.lower() == "false":
            tls_verify = False
            print("WARNING: VENYA_TLS_VERIFY=false — TLS verification disabled (dev only)", file=sys.stderr)
        else:
            tls_verify = True

        print("Submitting renewal request via mTLS...")
        ca_cert_path = str(Path(cert_path).parent / "ca.crt")
        if tls_verify:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.load_cert_chain(cert_path, key_path)
            if Path(ca_cert_path).exists():
                ssl_ctx.load_verify_locations(ca_cert_path)
        else:
            ssl_ctx = False  # type: ignore[assignment]
        with httpx2.Client(
            verify=ssl_ctx,
            timeout=30.0,
        ) as http_client:
            url = f"{server_url}/api/v1/executors/register"
            response = http_client.post(
                url,
                json={
                    "executor_id": executor_id,
                    "csr_pem": csr_pem,
                },
            )
            response.raise_for_status()
            result = response.json() if response.content else {}
    except httpx2.HTTPStatusError as e:
        error_msg = "Unknown error"
        try:
            error_data = e.response.json()
            error_msg = error_data.get("detail", str(e))
        except Exception:
            error_msg = str(e)
        if e.response.status_code in (401, 403):
            print(f"mTLS authentication failed: {error_msg}", file=sys.stderr)
        else:
            print(f"Renewal failed: {error_msg}", file=sys.stderr)
        return 1
    except httpx2.ConnectError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        return 1
    except httpx2.TimeoutException as e:
        print(f"Request timed out: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Renewal failed: {e}", file=sys.stderr)
        return 1

    cert_pem = result.get("cert_pem", "")
    ca_cert_pem = result.get("ca_cert_pem", "")
    serial_number = result.get("serial_number", "")
    not_after = result.get("not_after", "")

    if not cert_pem:
        print("Renewal failed: no certificate returned", file=sys.stderr)
        return 1

    # Atomic write: write to temp files, then rename
    try:
        output_dir = str(Path(cert_path).parent)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        cert_tmp = Path(cert_path).with_suffix(".pem.tmp")
        key_tmp = Path(key_path).with_suffix(".key.tmp")

        cert_tmp.write_bytes(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)

        key_pem = new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_tmp.write_bytes(key_pem)
        key_tmp.chmod(0o600)

        if ca_cert_pem:
            ca_cert_path = Path(cert_path).with_name("ca.crt")  # type: ignore[assignment]
            ca_tmp = ca_cert_path.with_suffix(".pem.tmp")  # type: ignore[attr-defined]
            ca_tmp.write_bytes(ca_cert_pem.encode() if isinstance(ca_cert_pem, str) else ca_cert_pem)
            ca_tmp.rename(ca_cert_path)

        key_tmp.rename(key_path)
        cert_tmp.rename(cert_path)
    except OSError as e:
        # Clean up temp files on failure
        for tmp in (cert_tmp, key_tmp):
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        print(f"Failed to save certificate: {e}", file=sys.stderr)
        return 1

    # Verify auth with revocation list
    try:
        print("Verifying authentication...")
        if tls_verify:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.load_cert_chain(cert_path, key_path)
            if Path(ca_cert_path).exists():
                ssl_ctx.load_verify_locations(ca_cert_path)
        else:
            ssl_ctx = False  # type: ignore[assignment]
        with httpx2.Client(
            verify=ssl_ctx,
            timeout=30.0,
        ) as http_client:
            url = f"{server_url}/api/v1/executors/certs/revocation-list"
            response = http_client.get(url)
            response.raise_for_status()
        print("Authentication verified.")
    except Exception:
        print("Certificate was renewed, but auth verification failed.", file=sys.stderr)

    print("\nCertificate renewed successfully.")
    print(f"  Executor ID:    {executor_id}")
    print(f"  Serial:         {serial_number}")
    print(f"  Expires:        {not_after}")
    print(f"  Cert:           {cert_path}")
    print(f"  Key:            {key_path}")
    return 0


def executor_cert_revoke(args: Any, client: APIClient | None = None) -> int:
    """Revoke an executor certificate.

    Dual-mode operation:
    - With --executor-id: revoke a remote executor by ID (admin action)
    - Without --executor-id: read CN from local cert file and revoke that executor

    Requires admin bearer token in config.json (Authorization: Bearer <token>).

    Args:
        args: Parsed CLI arguments.
        client: Optional APIClient. If None, creates one from config.

    Returns:
        0 on success, 1 on error.
    """
    executor_id = getattr(args, "executor_id", None)
    cert_path = getattr(args, "cert_path", "/etc/venya/executor/executor.crt")

    # Resolve executor_id: explicit arg > local cert CN
    if executor_id is None:
        info = _parse_executor_cert(cert_path)
        if info is None:
            print(f"Error: certificate not found at {cert_path}", file=sys.stderr)
            print("Specify --executor-id or ensure the cert file exists.", file=sys.stderr)
            return 1
        executor_id = info["executor_id"]

    # Create client if not provided (for exec cert revoke entry point)
    if client is None:
        client = APIClient()

    try:
        result = client.post(f"/api/v1/admin/executors/{executor_id}/revoke")
        revoked = result.get("revoked", False) if result else False
        print("Certificate revoked.")
        print(f"  Executor ID:  {executor_id}")
        print(f"  Revoked:      {'Yes' if revoked else 'No'}")
        return 0
    except APIClientAuthenticationError as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        print("This command requires admin credentials (bearer token in config.json).", file=sys.stderr)
        return 1
    except APIClientError as e:
        print(f"Revoke failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Revoke failed: {e}", file=sys.stderr)
        return 1


def executor_heartbeat(args: Any) -> int:
    """Send heartbeat to core.

    Reads the executor certificate to extract the executor_id (CN),
    computes the cert fingerprint, and POSTs to /api/v1/heartbeat
    using an mTLS client. Prints the server's response.
    """
    cert_path = getattr(args, "cert_path", "/etc/venya/executor/executor.crt")
    key_path = getattr(args, "key_path", None)
    if key_path is None:
        key_path = str(Path(cert_path).with_suffix(".key"))  # type: ignore[assignment]

    info = _parse_executor_cert(cert_path)
    if info is None:
        print(f"Error: certificate not found at {cert_path}", file=sys.stderr)
        print("Run 'venya exec register' to create a certificate.", file=sys.stderr)
        return 1

    if not Path(key_path).exists():
        print(f"Error: private key not found at {key_path}", file=sys.stderr)
        return 1

    server_url = _get_server_url(args)
    if server_url == "unknown":
        print("Error: server URL not configured. Use --core-url or set config.", file=sys.stderr)
        return 1

    # Compute SHA-256 fingerprint of the certificate
    try:
        cert_pem = Path(cert_path).read_bytes()
        x509.load_pem_x509_certificate(cert_pem)
        fingerprint = hashlib.sha256(cert_pem).hexdigest()
    except Exception as e:
        print(f"Failed to compute certificate fingerprint: {e}", file=sys.stderr)
        return 1

    executor_id = info["executor_id"]
    url = f"{server_url}/api/v1/heartbeat"

    # Build mTLS client
    try:
        ca_cert_path = str(Path(cert_path).parent / "ca.crt")
        use_tls = server_url.startswith("https://")
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.load_cert_chain(cert_path, key_path)
            if Path(ca_cert_path).exists():
                ssl_ctx.load_verify_locations(ca_cert_path)
        else:
            ssl_ctx = False  # type: ignore[assignment]
        with httpx2.Client(
            verify=ssl_ctx,
            timeout=10.0,
        ) as http_client:
            response = http_client.post(
                url,
                json={"executor_id": executor_id, "cert_fingerprint": fingerprint},
            )
            response.raise_for_status()
            data = response.json() if response.content else {}
    except httpx2.HTTPStatusError as e:
        print(f"Heartbeat failed: {e}", file=sys.stderr)
        return 1
    except httpx2.ConnectError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        return 1
    except httpx2.TimeoutException as e:
        print(f"Request timed out: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Heartbeat failed: {e}", file=sys.stderr)
        return 1

    revoked = data.get("revoked", False)
    new_cert_required = data.get("new_cert_required", False)

    print("Heartbeat Response")
    print(f"  Executor ID:     {executor_id}")
    print(f"  Revoked:         {'YES' if revoked else 'No'}")
    print(f"  Cert Rotation:   {'Required' if new_cert_required else 'Not Required'}")
    print(f"  Fingerprint:     {fingerprint}")

    if revoked:
        print("WARNING: This executor's certificate has been revoked.", file=sys.stderr)
        return 1

    return 0


def executor_audit(client: APIClient, args: Any) -> int:
    """View executor audit log.

    Dual-mode operation:
    - With explicit executor_id: audit a specific executor
    - Without executor_id: read CN from local cert file (same as exec cert revoke)

    Requires admin or auditor permission (bearer token in config.json).
    """
    executor_id = getattr(args, "executor_id", None)
    cert_path = getattr(args, "cert_path", "/etc/venya/executor/executor.crt")

    # Resolve executor_id: explicit arg > local cert CN
    if executor_id is None:
        info = _parse_executor_cert(cert_path)
        if info is None:
            print(f"Error: certificate not found at {cert_path}", file=sys.stderr)
            print("Specify an executor ID or ensure the cert file exists.", file=sys.stderr)
            return 1
        executor_id = info["executor_id"]

    try:
        params = {
            "limit": getattr(args, "limit", 100),
            "offset": getattr(args, "offset", 0),
        }
        if getattr(args, "hours", None):
            params["hours"] = args.hours
        if getattr(args, "days", None):
            params["days"] = args.days

        result = client.get("/api/v1/audit", params={**params, "executor_id": executor_id})
        events = result.get("events", [])

        if not events:
            print(f"No audit events found for {executor_id}.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        print(f"Audit Events for {executor_id}")
        print(f"  {'ID':<5} | {'EVENT_TYPE':<25} | {'EXECUTOR_ID':<18} | {'USER':<10} | TIMESTAMP")
        print(f"  {'-'*5}-+-{'-'*25}-+-{'-'*18}-+-{'-'*10}-+-{'-'*23}")
        for event in events:
            fields = event.get("fields") or {}
            evt_executor_id = fields.get("executor_id", "-")
            user_id = event.get("user_id") or "-"
            print(
                f"  {event['id']:<5} | {event['event_type']:<25} | {evt_executor_id:<18} | "
                f"{user_id:<10} | {event['timestamp']}"
            )
        return 0
    except APIClientAuthenticationError as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        print("This command requires admin or auditor credentials.", file=sys.stderr)
        return 1
    except APIClientError as e:
        print(f"Audit query failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Audit query failed: {e}", file=sys.stderr)
        return 1


def executor_status(args: Any) -> int:
    """Show executor registration status.

    Reads local cert file and config to display registration status,
    certificate details, and health. No network calls.
    """
    cert_path = getattr(args, "cert_path", "/etc/venya/executor/executor.crt")
    server_url = _get_server_url(args)
    info = _parse_executor_cert(cert_path)

    if info is None:
        print("Executor Status")
        print(f"  Server URL:     {server_url}")
        print("  Registered:     No")
        print(f"  Certificate:    {cert_path}")
        print("  Status:         NOT REGISTERED")
        print("Run 'venya exec register' to register this executor.", file=sys.stderr)
        return 1

    not_after = info["not_after"]
    days_remaining = info["days_remaining"]

    if days_remaining < 0:
        status = "EXPIRED"
        exit_code = 1
    elif days_remaining < 7:
        status = "WARNING"
        exit_code = 0
    else:
        status = "OK"
        exit_code = 0

    print("Executor Status")
    print(f"  Executor ID:    {info['executor_id']}")
    print(f"  Server URL:     {server_url}")
    print("  Registered:     Yes")
    print(f"  Certificate:    {cert_path}")
    print(f"  Serial:         {info['serial']}")
    print(f"  Subject:        {info['executor_id']}")
    print(f"  Expires:        {not_after.isoformat()}")
    print(f"  Days Remaining: {days_remaining}")
    print(f"  Status:         {status}")

    if status == "WARNING":
        print("WARNING: Certificate expires in less than 7 days!", file=sys.stderr)
    elif status == "EXPIRED":
        print("  STATUS: EXPIRED", file=sys.stderr)

    return exit_code


# --- CA Key Management Commands (local, run on server) ---


def _resolve_ca_dir(args: Any) -> str:
    """Resolve the CA directory path."""
    return getattr(args, "ca_dir", None) or "/etc/venya/ca"


def cmd_admin_export_ca_cert(args: Any) -> int:
    """Export the CA certificate to a file or stdout.

    This command reads the CA certificate from the server's CA directory
    and writes it to the specified output file or stdout. The certificate
    is then distributed out-of-band to executor machines.
    """
    import sys
    from pathlib import Path

    ca_dir = _resolve_ca_dir(args)
    ca_cert_path = Path(ca_dir) / "ca.crt"

    if not ca_cert_path.exists():
        print(f"Error: CA certificate not found at {ca_cert_path}", file=sys.stderr)
        print("Run 'venya init' on the server to generate the CA.", file=sys.stderr)
        return 1

    cert_data = ca_cert_path.read_bytes()

    output = getattr(args, "output", None)
    if output:
        Path(output).write_bytes(cert_data)
        print(f"CA certificate exported to {output}")
    else:
        sys.stdout.buffer.write(cert_data)
        sys.stdout.buffer.write(b"\n")
        print("(CA certificate written to stdout — transfer securely)", file=sys.stderr)

    return 0


def cmd_admin_export_ca_key(args: Any) -> int:
    """Export the CA private key, encrypted with a passphrase.

    Reads the CA private key from disk, encrypts it using AES-256-CBC
    with a user-provided passphrase, and writes the encrypted blob to
    the specified output file.

    The plaintext key is never written to disk or stdout.
    """
    from pathlib import Path

    from cryptography.hazmat.primitives import ciphers, hashes
    from cryptography.hazmat.primitives.ciphers import algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    ca_dir = _resolve_ca_dir(args)
    ca_key_path = Path(ca_dir) / "ca.key"
    output_path = Path(args.output)

    if not ca_key_path.exists():
        print(f"Error: CA key not found at {ca_dir}", file=sys.stderr)
        print("Run 'venya init' on the server to generate the CA.", file=sys.stderr)
        return 1

    # Read the plaintext key
    plaintext_key = ca_key_path.read_bytes()

    # Prompt for passphrase (twice for confirmation)
    passphrase1 = None
    while passphrase1 is None:
        passphrase1 = input("Enter passphrase for encrypted key: ")
        passphrase2 = input("Confirm passphrase: ")
        if passphrase1 != passphrase2:
            print("Passphrases do not match. Try again.")
            passphrase1 = None

    if not passphrase1:
        print("Error: passphrase cannot be empty", file=sys.stderr)
        return 1

    # Derive encryption key from passphrase using PBKDF2
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(passphrase1.encode())

    # Encrypt with AES-256-CBC
    iv = os.urandom(16)
    cipher = ciphers.Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )
    encryptor = cipher.encryptor()

    # PKCS7 padding
    block_size = 16
    padding_len = block_size - (len(plaintext_key) % block_size)
    padded = plaintext_key + bytes([padding_len] * padding_len)

    encrypted = encryptor.update(padded) + encryptor.finalize()

    # Write: salt (16) + iv (16) + encrypted data
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(salt + iv + encrypted)
    output_path.chmod(0o600)

    print(f"CA key encrypted and exported to {output_path}")
    print("Store this file securely. It requires the passphrase to decrypt.")
    return 0


def cmd_admin_split_ca_key(args: Any) -> int:
    """Split the CA private key using Shamir's Secret Sharing.

    Creates N shares of the CA key where any K shares can reconstruct
    the key. Shares are written as individual files in the output directory.

    This is the recommended backup method for the CA key.
    """
    from pathlib import Path

    from .shamir import split

    ca_dir = _resolve_ca_dir(args)
    ca_key_path = Path(ca_dir) / "ca.key"
    output_dir = Path(args.output_dir)

    if not ca_key_path.exists():
        print(f"Error: CA key not found at {ca_dir}", file=sys.stderr)
        print("Run 'venya init' on the server to generate the CA.", file=sys.stderr)
        return 1

    plaintext_key = ca_key_path.read_bytes()
    threshold = args.threshold
    num_shares = args.shares

    if threshold > num_shares:
        print("Error: threshold cannot exceed number of shares", file=sys.stderr)
        return 1

    shares = split(plaintext_key, threshold=threshold, shares=num_shares)
    output_dir.mkdir(parents=True, exist_ok=True)

    for i, share in enumerate(shares):
        share_id = share[0]
        share_file = output_dir / f"share-{share_id:02d}"
        share_file.write_bytes(share[1:])  # Store data only (ID is embedded)
        share_file.chmod(0o600)
        print(f"  Share {share_id}/{num_shares} written to {share_file}")

    print(f"\n{num_shares} shares created. Any {threshold} are needed to reconstruct.")
    print("Distribute shares to different locations/administrators.")
    print("Keep this directory secure and delete after distribution.")
    return 0


def cmd_admin_restore_ca_key(args: Any) -> int:
    """Restore the CA private key from shares or an encrypted backup.

    Two modes:
    - shares: Reconstruct using Shamir's Secret Sharing from N share files
    - backup: Decrypt from a passphrase-encrypted backup file
    """
    from pathlib import Path

    from .shamir import combine

    ca_dir = _resolve_ca_dir(args)
    ca_key_path = Path(ca_dir) / "ca.key"
    mode = args.mode

    if mode == "shares":
        share_files = getattr(args, "shares", None)
        if not share_files or len(share_files) < 2:
            print("Error: at least 2 share files required for SSS restore", file=sys.stderr)
            return 1

        # Read shares (prepend ID byte back)
        shares = []
        for share_path_str in share_files:
            share_path = Path(share_path_str)
            if not share_path.exists():
                print(f"Error: share file not found: {share_path}", file=sys.stderr)
                return 1
            data = share_path.read_bytes()
            # We don't know the ID from the file, so we need to embed it
            # The share file is just the data bytes; ID must be provided
            # For simplicity, we expect the filename to encode the ID
            # e.g., share-01, share-02, etc.
            try:
                share_id = int(share_path.stem.split("-")[-1])
            except (ValueError, IndexError):
                print(
                    f"Error: cannot determine share ID from filename '{share_path.stem}'. "
                    f"Use filenames like 'share-01', 'share-02', etc.",
                    file=sys.stderr,
                )
                return 1
            shares.append(bytes([share_id]) + data)

        try:
            reconstructed = combine(shares)
        except ValueError as e:
            print(f"Error reconstructing shares: {e}", file=sys.stderr)
            return 1

    elif mode == "backup":
        backup_file = getattr(args, "backup_file", None)
        if not backup_file:
            print("Error: --backup-file required for backup restore mode", file=sys.stderr)
            return 1

        backup_path = Path(backup_file)
        if not backup_path.exists():
            print(f"Error: backup file not found: {backup_path}", file=sys.stderr)
            return 1

        from cryptography.hazmat.primitives import ciphers, hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        encrypted_data = backup_path.read_bytes()
        if len(encrypted_data) < 32:
            print("Error: backup file too small", file=sys.stderr)
            return 1

        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        passphrase = input("Enter passphrase to decrypt backup: ")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = kdf.derive(passphrase.encode())

        cipher = ciphers.Cipher(
            ciphers.algorithms.AES(key),
            ciphers.modes.CBC(iv),
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_len = padded[-1]
        if padding_len < 1 or padding_len > 16:
            print("Error: invalid passphrase or corrupted backup", file=sys.stderr)
            return 1
        reconstructed = padded[:-padding_len]

    else:
        print(f"Unknown restore mode: {mode}", file=sys.stderr)
        return 1

    # Write the restored key
    ca_key_path.parent.mkdir(parents=True, exist_ok=True)
    ca_key_path.write_bytes(reconstructed)
    ca_key_path.chmod(0o600)

    print(f"CA key restored to {ca_key_path}")
    print("WARNING: All existing executor certificates signed by this CA are now valid again.")
    print("Consider rotating executor certificates after restore.")
    return 0


# --- Admin CA Management Commands ---


def cmd_admin_init_admin_ca(args: Any) -> int:
    """Initialize the admin CA (create key/cert pair locally).

    Creates a new ECDSA P-256 keypair and self-signed admin CA certificate.
    If VENYA_ADMIN_CA_KEY_PASSPHRASE is set, the key is encrypted on disk.
    """
    import os
    from datetime import datetime, timedelta
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        PrivateFormat,
    )
    from cryptography.x509.oid import NameOID

    output_dir = Path(args.output_dir)

    if output_dir.exists() and (output_dir / "admin-ca.key").exists():
        print(f"Error: admin CA already exists at {output_dir}", file=sys.stderr)
        return 1

    try:
        # Generate ECDSA P-256 keypair
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Load passphrase for encryption
        passphrase = os.environ.get("VENYA_ADMIN_CA_KEY_PASSPHRASE")
        passphrase_bytes = passphrase.encode("utf-8") if passphrase else None

        if passphrase_bytes:
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(passphrase_bytes),
            )
        else:
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

        # Create directory
        output_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(str(output_dir), 0o700)

        # Write key
        key_path = output_dir / "admin-ca.key"
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)

        # Create self-signed CA certificate
        now = datetime.now(UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin Certificate Authority"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Venya Admin CA"),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        cert = builder.sign(private_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        cert_path = output_dir / "admin-ca.crt"
        cert_path.write_bytes(cert_pem)
        cert_path.chmod(0o644)

        print(f"Admin CA initialized at {output_dir}")
        print(f"  Key:  {key_path} (permissions: 600)")
        print(f"  Cert: {cert_path} (permissions: 644)")
        return 0
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to initialize admin CA: {e}", file=sys.stderr)
        return 1


def cmd_admin_generate_admin_cert(args: Any) -> int:
    """Sign an admin client certificate using the admin CA.

    Generates a new ECDSA P-256 keypair, signs it with the admin CA,
    and writes the cert and key to the output directory.
    """
    import os
    from datetime import datetime, timedelta
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import PrivateFormat
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    identity = args.identity
    output_dir = Path(args.output_dir)

    # Resolve admin CA directory
    ca_dir_str = getattr(args, "ca_dir", None) or os.environ.get("VENYA_ADMIN_CA_DIR", "/var/lib/venya/ca/admin-ca")
    ca_dir = Path(ca_dir_str)

    ca_key_path = ca_dir / "admin-ca.key"
    ca_cert_path = ca_dir / "admin-ca.crt"

    if not ca_key_path.exists():
        print(f"Error: admin CA key not found at {ca_key_path}", file=sys.stderr)
        print("Run 'venya admin init-admin-ca' first.", file=sys.stderr)
        return 1

    if not ca_cert_path.exists():
        print(f"Error: admin CA cert not found at {ca_cert_path}", file=sys.stderr)
        print("Run 'venya admin init-admin-ca' first.", file=sys.stderr)
        return 1

    try:
        # Load admin CA key
        passphrase = os.environ.get("VENYA_ADMIN_CA_KEY_PASSPHRASE")
        key_data = ca_key_path.read_bytes()
        is_encrypted = b"ENCRYPTED" in key_data

        if is_encrypted and not passphrase:
            print(
                "Error: CA key is encrypted but VENYA_ADMIN_CA_KEY_PASSPHRASE is not set",
                file=sys.stderr,
            )
            return 1

        ca_key = serialization.load_pem_private_key(key_data, password=passphrase.encode() if passphrase else None)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

        # Generate new keypair for admin cert
        admin_key = ec.generate_private_key(ec.SECP256R1())

        # Build certificate
        now = datetime.now(UTC)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
                x509.NameAttribute(NameOID.COMMON_NAME, identity),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(admin_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(identity)]),
                critical=False,
            )
        ).sign(ca_key, hashes.SHA256())

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write key (unencrypted — operator manages security)
        key_pem = admin_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path = output_dir / "admin.key"
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)

        # Write cert
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path = output_dir / "admin.crt"
        cert_path.write_bytes(cert_pem)
        cert_path.chmod(0o644)

        # Print details
        serial_hex = format(cert.serial_number, "016x")
        not_after = cert.not_valid_after_utc

        print(f"Admin certificate signed for '{identity}'")
        print(f"  Serial:   {serial_hex}")
        print(f"  Expires:  {not_after.isoformat()}")
        print(f"  Key:      {key_path} (permissions: 600)")
        print(f"  Cert:     {cert_path} (permissions: 644)")
        return 0
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Failed to sign admin certificate: {e}", file=sys.stderr)
        return 1


def cmd_admin_revoke_admin_cert(client: APIClient, args: Any) -> int:
    """Revoke an admin certificate by serial number via the API.

    Requires bearer token authentication and admin role.
    """
    import os
    import sys

    serial = args.serial
    reason = getattr(args, "reason", "unspecified")
    server_url = getattr(args, "server_url", None)

    # Resolve server URL
    if not server_url:
        server_url = os.environ.get("VENYA_SERVER_URL", "")
        if not server_url:
            server_url = client.config.server_url

    if not server_url:
        print("Error: server URL required. Pass --server-url or set VENYA_SERVER_URL", file=sys.stderr)
        return 1

    # Validate serial format (must be valid hex, up to 16 chars)
    try:
        int(serial, 16)
        if len(serial) > 16:
            raise ValueError("Serial too long")
    except ValueError as e:
        print(f"Error: invalid serial format — must be hex string (up to 16 chars): {e}", file=sys.stderr)
        return 1

    url = server_url.rstrip("/")
    try:
        client.post(
            f"{url}/api/v1/admin/certs/revoke",
            json={"serial": serial, "reason": reason},
        )
        print(f"Certificate {serial} revoked (reason: {reason})")
        return 0
    except APIClientAuthenticationError as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return 1
    except APIClientError as e:
        print(f"Revocation failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Revocation failed: {e}", file=sys.stderr)
        return 1
