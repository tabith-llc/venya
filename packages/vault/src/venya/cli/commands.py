"""Command implementations for the CLI."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .api_client import APIClient


def _run_migrations(db_path: str | None, db_key: str | None) -> None:
    """Run Alembic migrations programmatically.

    This is called by `venya init` to ensure the database schema is up to date
    before bootstrapping. Users never need to run `alembic` directly.

    Args:
        db_path: Path to the database file. Falls back to VENYA_DB_PATH env var
                 or ./venya.db.
        db_key: Database encryption key. Falls back to VENYA_DB_KEY env var.

    Raises:
        RuntimeError: If VENYA_DB_KEY is not set or migrations fail.
    """
    from alembic.config import Config
    from alembic import command

    resolved_db_path = db_path or os.environ.get("VENYA_DB_PATH", "./venya.db")
    resolved_db_key = db_key or os.environ.get("VENYA_DB_KEY", "")

    if not resolved_db_key:
        raise RuntimeError(
            "Database key not found. Set --db-key or VENYA_DB_KEY environment "
            "variable. Example:\n"
            "  venya init admin --db-key mysecret\n"
            "  VENYA_DB_KEY=mysecret venya init admin"
        )

    # Set env vars that alembic env.py reads
    os.environ["VENYA_DB_PATH"] = str(resolved_db_path)
    os.environ["VENYA_DB_KEY"] = resolved_db_key

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
    client = APIClient()

    command = args.command

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
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        return 1


def cmd_init(client: APIClient, args: Any) -> int:
    """Bootstrap the vault."""
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
        result = client.post("/api/v1/init", json={"user_id": args.user_id})
        print(f"Initialization complete. User '{args.user_id}' enrolled as admin.")

        # Print recovery code (printed once, never stored)
        if "recovery_code" in result:
            print("\n" + "=" * 50)
            print("RECOVERY CODE — Print and store securely!")
            print("This code is printed only once and never stored.")
            print("=" * 50)
            print(f"  {result['recovery_code']}")
            print("=" * 50)
        return 0
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
