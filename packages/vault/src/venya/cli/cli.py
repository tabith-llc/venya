"""CLI argument parser."""

from __future__ import annotations

import argparse
import sys
from typing import Any


def create_parser() -> argparse.ArgumentParser:
    """Create the main CLI argument parser.

    Commands:
        venya init <user_id>                    # Bootstrap
        venya store <key> [value]               # Store a secret
        venya get <key>                         # Retrieve a secret
        venya list [prefix]                     # List secrets
        venya delete <key>                      # Delete a secret
        venya audit [filters]                   # Query audit log
        venya admin <subcommand>                # Admin operations
        venya role <subcommand>                 # Role management
    """
    parser = argparse.ArgumentParser(
        prog="venya",
        description="Venya — A secrets broker system for LLMs",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_parser = subparsers.add_parser("init", help="Bootstrap the vault")
    init_parser.add_argument("user_id", help="User ID for first admin")
    init_parser.add_argument(
        "--db-path",
        help="Path to the vault database (default: $VENYA_DB_PATH or ./venya.db)",
    )
    init_parser.add_argument(
        "--db-key",
        help="Database encryption key (default: $VENYA_DB_KEY)",
    )
    init_parser.add_argument(
        "--skip-migrations",
        action="store_true",
        help="Skip running database migrations",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-initialization",
    )
    init_parser.add_argument(
        "--confirm-reset",
        action="store_true",
        help="Confirm data wipe during reset",
    )

    # store
    store_parser = subparsers.add_parser("store", help="Store a secret")
    store_parser.add_argument("key", help="Secret key")
    store_parser.add_argument("value", nargs="?", help="Secret value (or read from stdin)")
    store_parser.add_argument(
        "--roles",
        nargs="+",
        required=True,
        help="Role(s) to scope the secret to",
    )
    store_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite even if roles differ",
    )

    # get
    get_parser = subparsers.add_parser("get", help="Retrieve a secret")
    get_parser.add_argument("key", help="Secret key")
    get_parser.add_argument(
        "--unmask",
        action="store_true",
        help="Return plaintext (requires re-authentication)",
    )

    # list
    list_parser = subparsers.add_parser("list", help="List secrets")
    list_parser.add_argument("prefix", nargs="?", help="Optional key prefix filter")

    # delete
    delete_parser = subparsers.add_parser("delete", help="Delete a secret")
    delete_parser.add_argument("key", help="Secret key to delete")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Query audit log")
    audit_parser.add_argument("--user", help="Filter by user ID")
    audit_parser.add_argument("--key", help="Filter by secret key")
    audit_parser.add_argument("--start-date", help="Start date (ISO format)")
    audit_parser.add_argument("--end-date", help="End date (ISO format)")
    audit_parser.add_argument("--days", type=int, help="Query last N days")
    audit_parser.add_argument("--hours", type=int, help="Query last N hours")
    audit_parser.add_argument("--limit", type=int, default=100, help="Max results (default 100)")
    audit_parser.add_argument("--offset", type=int, default=0, help="Result offset")

    # admin
    admin_parser = subparsers.add_parser("admin", help="Admin operations")
    admin_sub = admin_parser.add_subparsers(dest="admin_command")

    # admin enroll
    enroll_parser = admin_sub.add_parser("enroll", help="Enroll a new user")
    enroll_parser.add_argument("user_id", help="User ID to enroll")
    enroll_parser.add_argument(
        "--mode",
        choices=["security-key", "platform"],
        default="security-key",
        help="Auth mode (default: security-key)",
    )

    # admin remove
    remove_parser = admin_sub.add_parser("remove", help="Remove a user")
    remove_parser.add_argument("user_id", help="User ID to remove")

    # admin configure-user
    configure_parser = admin_sub.add_parser(
        "configure-user", help="Configure user settings"
    )
    configure_parser.add_argument("user_id", help="User ID to configure")
    configure_parser.add_argument(
        "--mode", choices=["security-key", "platform"], help="Auth mode"
    )
    configure_parser.add_argument(
        "--timeout", type=int, help="Session timeout in seconds"
    )

    # admin list
    admin_sub.add_parser("list", help="List all registered users")

    # admin set-command-policy
    set_policy_parser = admin_sub.add_parser(
        "set-command-policy", help="Set executor command policy"
    )
    set_policy_parser.add_argument(
        "preset",
        choices=["strict", "balanced", "permissive"],
        help="Policy preset",
    )
    set_policy_parser.add_argument(
        "--custom", help="Path to custom policy file"
    )

    # admin get-command-policy
    admin_sub.add_parser(
        "get-command-policy", help="Get current executor command policy"
    )

    # admin add-allowed-command
    add_cmd_parser = admin_sub.add_parser(
        "add-allowed-command", help="Add a command to the strict allowlist"
    )
    add_cmd_parser.add_argument("command_path", help="Full path to allowed command")

    # admin key-version
    kv_parser = admin_sub.add_parser(
        "key-version", help="Key version management"
    )
    kv_sub = kv_parser.add_subparsers(dest="kv_command")

    kv_sub.add_parser("list", help="List all key versions")
    deactivate_parser = kv_sub.add_parser("deactivate", help="Deactivate a key version")
    deactivate_parser.add_argument("version_id", help="Version ID")
    kv_sub.add_parser("revoke", help="Revoke a key version")
    kv_sub.add_parser("rotate-status", help="Show rotation job progress")
    rollback_parser = kv_sub.add_parser("rollback", help="Roll back a failed rotation job")
    rollback_parser.add_argument("job_id", help="Rotation job ID")

    # admin rotate-key
    rotate_parser = admin_sub.add_parser(
        "rotate-key", help="Rotate the key encryption key"
    )
    rotate_parser.add_argument(
        "--new-key", help="Path to new KEK file"
    )

    # admin revoke-executor
    revoke_parser = admin_sub.add_parser(
        "revoke-executor", help="Revoke an executor certificate"
    )
    revoke_parser.add_argument("executor_id", help="Executor ID to revoke")

    # role
    role_parser = subparsers.add_parser("role", help="Role management")
    role_sub = role_parser.add_subparsers(dest="role_command")

    # role create
    role_create = role_sub.add_parser("create", help="Create a role")
    role_create.add_argument("name", help="Role name")
    role_create.add_argument(
        "--permissions",
        choices=["read", "read-write"],
        default="read",
        help="Permission tier",
    )
    role_create.add_argument("--description", help="Role description")

    # role list
    role_sub.add_parser("list", help="List all roles")

    # role get
    role_get = role_sub.add_parser("get", help="Get role details")
    role_get.add_argument("role_id", help="Role ID or name")

    # role delete
    role_delete = role_sub.add_parser("delete", help="Delete a role")
    role_delete.add_argument("role_id", help="Role ID or name")

    # role members
    role_members = role_sub.add_parser("members", help="List role members")
    role_members.add_argument("role_id", help="Role ID or name")

    # role add-member
    role_add = role_sub.add_parser("add-member", help="Add user to role")
    role_add.add_argument("role_id", help="Role ID or name")
    role_add.add_argument("user_id", help="User ID to add")

    # role remove-member
    role_remove = role_sub.add_parser("remove-member", help="Remove user from role")
    role_remove.add_argument("role_id", help="Role ID or name")
    role_remove.add_argument("user_id", help="User ID to remove")

    # recovery
    recovery_parser = subparsers.add_parser(
        "recovery", help="Break-glass recovery"
    )
    recovery_parser.add_argument("code", help="Recovery code")
    recovery_parser.add_argument("new_user_id", help="New user ID")
    recovery_parser.add_argument(
        "--force", action="store_true", help="Force operation"
    )
    recovery_parser.add_argument(
        "--confirm", action="store_true", help="Confirm recovery action"
    )

    return parser


def main() -> int:
    """Entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Import command implementations
    from .commands import run_command

    try:
        return run_command(args)
    except Exception as e:
        if args.verbose:
            raise
        print(f"Error: {e}", file=sys.stderr)
        return 1
