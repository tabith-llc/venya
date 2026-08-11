"""Command implementations for the CLI."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .api_client import APIClient, APIClientAuthenticationError, APIClientError


def _run_migrations(_db_path: str | None = None, _db_key: str | None = None) -> None:
    """Run Alembic migrations programmatically.

    This is called by `venya init` to ensure the database schema is up to date
    before bootstrapping. Users never need to run `alembic` directly.

    Args:
        _db_path: [deprecated] Path to the database file. PostgreSQL is used exclusively.
        _db_key: [deprecated] Database encryption key. PostgreSQL is used exclusively.

    Raises:
        RuntimeError: If VENYA_DB_URL is not set or migrations fail.
    """
    from alembic.config import Config
    from alembic import command

    venya_db_url = os.environ.get("VENYA_DB_URL", "")
    if not venya_db_url:
        raise RuntimeError(
            "VENYA_DB_URL not set. Set it before running 'venya init'.\n"
            "Example:\n"
            "  VENYA_DB_URL=postgresql://user:pass@host/db venya init"
        )

    # Find alembic.ini relative to the vault package root
    # __file__ = .../src/venya/cli/commands.py
    # parent x4 = .../packages/vault/
    _pkg_root = Path(__file__).resolve().parent.parent.parent.parent
    _alembic_ini = _pkg_root / "alembic.ini"
    if not _alembic_ini.exists():
        raise RuntimeError(f"alembic.ini not found at {_alembic_ini}")

    alembic_cfg = Config(str(_alembic_ini))

    # Resolve script_location relative to the alembic.ini directory
    # (Alembic doesn't do this automatically when run programmatically)
    ini_dir = _alembic_ini.parent
    current_script = alembic_cfg.get_main_option("script_location")
    if current_script and not Path(current_script).is_absolute():
        alembic_cfg.set_main_option(
            "script_location", str(ini_dir / current_script)
        )
    print(f"Running database migrations...")
    command.upgrade(alembic_cfg, "head")
    print("Database migrations complete.")


def run_command(args: Any) -> int:
    """Run a CLI command.

    Args:
        args: Parsed argparse namespace.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    server_url = getattr(args, "server_url", None)
    client = APIClient(server_url=server_url)

    # Authenticate if no token is available (init and recovery are public)
    command = args.command
    if command not in ("init", "recovery", "config") and not client.config.access_token:
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
        elif command == "audit":
            return cmd_audit(client, args)
        elif command == "admin":
            return cmd_admin(client, args)
        elif command == "role":
            return cmd_role(client, args)
        elif command == "recovery":
            return cmd_recovery(client, args)
        elif command == "exec":
            return cmd_exec(client, args)
        elif command == "config":
            return cmd_config(client, args)
        else:
            print(f"Unknown command: {command}", file=sys.stderr)
            return 1
    finally:
        client.close()


def cmd_init(client: APIClient, args: Any) -> int:
    """Bootstrap the vault with mandatory FIDO2 enrollment.

    Two-step flow:
    1. Run migrations
    2. Call POST /api/v1/init → get FIDO2 challenge
    3. Perform WebAuthn registration with security key
    4. Call POST /api/v1/init/complete → get recovery code
    5. Print recovery code

    If --installation-reset is set, resets vault to pre-initialization state first.
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
            print("Resetting vault to pre-initialization state...")
            reset_result = client.post("/api/v1/init/reset")
            print(f"Reset complete: {reset_result.get('message', 'ok')}")
        except APIClientError as e:
            print(f"Reset failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Reset failed: {e}", file=sys.stderr)
            return 1

    # Run migrations unless skipped
    if not getattr(args, "skip_migrations", False):
        try:
            _run_migrations(getattr(args, "db_path", None), getattr(args, "db_key", None))
        except RuntimeError as e:
            print(f"Migration failed: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Migration failed: {e}", file=sys.stderr)
            return 1

    try:
        fido2 = Fido2Auth(client.config.server_url)

        print(f"Starting vault initialization for user '{args.user_id}'...")
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
        print(f"FIDO2 registration failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Initialization failed: {e}", file=sys.stderr)
        return 1


def cmd_store(client: APIClient, args: Any) -> int:
    """Store a secret."""
    value = args.value
    if value is None:
        print("Error: secret value required (provide as argument or stdin)", file=sys.stderr)
        return 1

    try:
        client.post(
            "/api/v1/secrets",
            json={
                "key": args.key,
                "value": value,
                "roles": args.roles,
                "force": getattr(args, "force", False),
            },
        )
        print(f"Secret '{args.key}' stored successfully.")
        return 0
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
    except Exception as e:
        print(f"Failed to retrieve secret: {e}", file=sys.stderr)
        return 1


def cmd_list(client: APIClient, args: Any) -> int:
    """List secrets."""
    try:
        params = {}
        if getattr(args, "prefix", None):
            params["prefix"] = args.prefix

        result = client.get("/api/v1/secrets", params=params)
        secrets = result.get("secrets", [])

        if not secrets:
            print("No secrets found.")
            return 0

        for secret in secrets:
            print(f"  {secret['key']}")
        return 0
    except Exception as e:
        print(f"Failed to list secrets: {e}", file=sys.stderr)
        return 1


def cmd_delete(client: APIClient, args: Any) -> int:
    """Delete a secret."""
    try:
        client.delete(f"/api/v1/secrets/{args.key}")
        print(f"Secret '{args.key}' deleted.")
        return 0
    except Exception as e:
        print(f"Failed to delete secret: {e}", file=sys.stderr)
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

        for event in events:
            print(
                f"  [{event['timestamp']}] {event['event_type']} "
                f"(user: {event.get('user_id', 'N/A')})"
            )
        return 0
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
    elif admin_command == "export-ca-cert":
        return cmd_admin_export_ca_cert(args)
    elif admin_command == "export-ca-key":
        return cmd_admin_export_ca_key(args)
    elif admin_command == "split-ca-key":
        return cmd_admin_split_ca_key(args)
    elif admin_command == "restore-ca-key":
        return cmd_admin_restore_ca_key(args)
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
    except Exception as e:
        print(f"Enrollment failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_remove(client: APIClient, args: Any) -> int:
    """Remove a user."""
    try:
        client.delete(f"/api/v1/admin/users/{args.user_id}")
        print(f"User '{args.user_id}' removed.")
        return 0
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

        for user in users:
            print(
                f"  {user['user_id']} (mode: {user['auth_mode']}, "
                f"enrolled: {user.get('enrolled_at', 'N/A')})"
            )
        return 0
    except Exception as e:
        print(f"List failed: {e}", file=sys.stderr)
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
    except Exception as e:
        print(f"Set policy failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_get_policy(client: APIClient, args: Any) -> int:
    """Get command policy."""
    try:
        result = client.get("/api/v1/admin/command-policy")
        print(json.dumps(result, indent=2))
        return 0
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
    except Exception as e:
        print(f"Key rotation failed: {e}", file=sys.stderr)
        return 1


def cmd_admin_revoke_executor(client: APIClient, args: Any) -> int:
    """Revoke executor certificate."""
    try:
        client.post(f"/api/v1/admin/executors/{args.executor_id}/revoke")
        print(f"Executor '{args.executor_id}' certificate revoked.")
        return 0
    except Exception as e:
        print(f"Revoke failed: {e}", file=sys.stderr)
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

        for role in roles:
            print(
                f"  {role['id']}: {role['name']} "
                f"({role['permissions']})"
            )
        return 0
    except Exception as e:
        print(f"Failed to list roles: {e}", file=sys.stderr)
        return 1


def cmd_role_get(client: APIClient, args: Any) -> int:
    """Get role details."""
    try:
        result = client.get(f"/api/v1/roles/{args.role_id}")
        print(json.dumps(result, indent=2))
        return 0
    except Exception as e:
        print(f"Failed to get role: {e}", file=sys.stderr)
        return 1


def cmd_role_delete(client: APIClient, args: Any) -> int:
    """Delete a role."""
    try:
        client.delete(f"/api/v1/roles/{args.role_id}")
        print(f"Role '{args.role_id}' deleted.")
        return 0
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

        for member in members:
            print(f"  {member['user_id']}")
        return 0
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
    except Exception as e:
        print(f"Failed to add member: {e}", file=sys.stderr)
        return 1


def cmd_role_remove_member(client: APIClient, args: Any) -> int:
    """Remove user from role."""
    try:
        client.delete(
            f"/api/v1/roles/{args.role_id}/members/{args.user_id}"
        )
        print(f"User '{args.user_id}' removed from role '{args.role_id}'.")
        return 0
    except Exception as e:
        print(f"Failed to remove member: {e}", file=sys.stderr)
        return 1


def cmd_recovery(client: APIClient, args: Any) -> int:
    """Break-glass recovery."""
    try:
        result = client.post(
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
    except Exception as e:
        print(f"Recovery failed: {e}", file=sys.stderr)
        return 1


def cmd_exec(client: APIClient, args: Any) -> int:
    """Execute a command via the executor with secret injection and output filtering.

    Flow:
        1. Authenticate (if not already)
        2. Resolve secrets for the command
        3. Create executor session
        4. Execute command via executor daemon API
        5. Display filtered output
    """
    command = " ".join(args.command) if args.command else ""
    if not command:
        print("Error: command required", file=sys.stderr)
        return 1

    executor_id = getattr(args, "executor_id", None) or "default"

    # Step 1: Get secrets for this command
    secret_keys = getattr(args, "secrets", None)
    secret_bundles = []

    if secret_keys:
        print(f"Fetching {len(secret_keys)} secret(s) for executor...")
        for key in secret_keys:
            try:
                result = client.get(f"/api/v1/secrets/{key}/executor")
                secret_bundles.append({
                    "secret_id": result["secret_id"],
                    "value": result["wrapped_value"],
                })
                print(f"  Secret '{key}' ready.")
            except APIClientError as e:
                print(f"  Warning: could not fetch secret '{key}': {e}", file=sys.stderr)
    else:
        print("No secrets specified. Command will run without injected credentials.")

    # Step 2: Create executor session
    try:
        session_result = client.post(
            "/api/v1/executors/sessions",
            json={
                "executor_id": executor_id,
                "secrets": secret_bundles,
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
                "secrets": secret_bundles,
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
        print(f"  Access Token: [set] (expires soon — run 'venya exec' to refresh)")
    else:
        print("  Access Token: [not set]")
    print(f"  Config File: {config.config_file}")
    return 0


def cmd_config_set_server(client: APIClient, args: Any) -> int:
    """Set the server URL."""
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    client.config.server_url = url
    print(f"Server URL set to: {url}")
    return 0


def cmd_config_clear_token(client: APIClient) -> int:
    """Clear stored access token."""
    client.config.access_token = None
    print("Access token cleared. Re-authentication required.")
    return 0


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

    import cryptography.hazmat.primitives.ciphers as ciphers
    import cryptography.hazmat.primitives.hashes as hashes
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

    from vault.shamir import combine, split

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

    from vault.shamir import combine

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

        import cryptography.hazmat.primitives.ciphers as ciphers
        import cryptography.hazmat.primitives.hashes as hashes
        from cryptography.hazmat.primitives.ciphers import algorithms, modes
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
