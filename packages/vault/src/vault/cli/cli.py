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
        venya run <command>                     # Execute a command via executor
        venya exec <subcommand>                 # Executor lifecycle operations
        venya config <subcommand>               # Manage CLI configuration
        venya credential <subcommand>           # Manage credentials
        venya enroll <subcommand>               # Headless enrollment
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
        help="[deprecated] PostgreSQL is used exclusively. Set VENYA_DB_URL instead.",
    )
    init_parser.add_argument(
        "--db-key",
        help="[deprecated] PostgreSQL is used exclusively. Set VENYA_DB_URL instead.",
    )
    init_parser.add_argument(
        "--skip-migrations",
        action="store_true",
        help="Skip running database migrations",
    )
    init_parser.add_argument(
        "--installation-reset",
        action="store_true",
        help="Reset vault to pre-initialization state before starting (only allowed when no users are enrolled)",
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
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

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
    admin_list_parser = admin_sub.add_parser("list", help="List all registered users")
    admin_list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin create-user
    create_user_parser = admin_sub.add_parser(
        "create-user", help="Create a new user and issue an enrollment token"
    )
    create_user_parser.add_argument("username", help="User ID (e.g. 'jsmith')")
    create_user_parser.add_argument(
        "--display-name",
        help="Human-readable display name",
    )
    create_user_parser.add_argument(
        "--roles",
        help="Comma-separated list of role names to assign",
    )
    create_user_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

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
    get_policy_parser = admin_sub.add_parser(
        "get-command-policy", help="Get current executor command policy"
    )
    get_policy_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
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

    list_parser = kv_sub.add_parser("list", help="List all key versions")
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
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
    revoke_executor_parser = admin_sub.add_parser(
        "revoke-executor", help="Revoke an executor certificate"
    )
    revoke_executor_parser.add_argument("executor_id", help="Executor ID to revoke")

    # admin executor-enroll
    enroll_executor_parser = admin_sub.add_parser(
        "executor-enroll", help="Generate an enrollment token for an executor"
    )
    enroll_executor_parser.add_argument("executor_id", metavar="EXECUTOR_ID",
                                       help="Executor ID to enroll")

    # admin list-tokens
    list_tokens_parser = admin_sub.add_parser(
        "list-tokens", help="List all enrollment tokens for a user"
    )
    list_tokens_parser.add_argument("user_id", help="User ID")
    list_tokens_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin issue-token
    issue_token_parser = admin_sub.add_parser(
        "issue-token", help="Revoke old tokens and issue a new enrollment token"
    )
    issue_token_parser.add_argument("user_id", help="User ID")
    issue_token_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin revoke-token
    revoke_token_parser = admin_sub.add_parser(
        "revoke-token", help="Revoke a single enrollment token"
    )
    revoke_token_parser.add_argument("token_id", help="Token ID to revoke")

    # admin re-enroll
    re_enroll_parser = admin_sub.add_parser(
        "re-enroll", help="Deactivate credentials and issue a new enrollment token"
    )
    re_enroll_parser.add_argument("user_id", help="User ID to re-enroll")
    re_enroll_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin export-ca-cert
    export_cert_parser = admin_sub.add_parser(
        "export-ca-cert", help="Export the CA certificate (for distribution to executors)"
    )
    export_cert_parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )
    export_cert_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /etc/venya/ca)",
    )

    # admin export-ca-key
    export_key_parser = admin_sub.add_parser(
        "export-ca-key", help="Export the CA private key (encrypted with passphrase)"
    )
    export_key_parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output file path for encrypted key",
    )
    export_key_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /etc/venya/ca)",
    )

    # admin split-ca-key
    split_key_parser = admin_sub.add_parser(
        "split-ca-key", help="Split CA key using Shamir's Secret Sharing"
    )
    split_key_parser.add_argument(
        "--threshold", "-t",
        type=int,
        required=True,
        help="Minimum shares needed to reconstruct (K)",
    )
    split_key_parser.add_argument(
        "--shares", "-s",
        type=int,
        required=True,
        help="Total number of shares to create (N)",
    )
    split_key_parser.add_argument(
        "--output-dir", "-d",
        required=True,
        help="Directory to write share files",
    )
    split_key_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /etc/venya/ca)",
    )

    # admin restore-ca-key
    restore_key_parser = admin_sub.add_parser(
        "restore-ca-key", help="Restore CA key from shares or encrypted backup"
    )
    restore_key_parser.add_argument(
        "--mode",
        choices=["shares", "backup"],
        required=True,
        help="Restore mode: from shares (SSS) or from encrypted backup file",
    )
    restore_key_parser.add_argument(
        "--shares", nargs="+",
        help="Share files for SSS restore (e.g., share-1 share-2 share-3)",
    )
    restore_key_parser.add_argument(
        "--backup-file",
        help="Encrypted backup file for backup restore mode",
    )
    restore_key_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /etc/venya/ca)",
    )

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
    role_list_parser = role_sub.add_parser("list", help="List all roles")
    role_list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # role get
    role_get = role_sub.add_parser("get", help="Get role details")
    role_get.add_argument("role_id", help="Role ID or name")
    role_get.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # role delete
    role_delete = role_sub.add_parser("delete", help="Delete a role")
    role_delete.add_argument("role_id", help="Role ID or name")

    # role members
    role_members = role_sub.add_parser("members", help="List role members")
    role_members.add_argument("role_id", help="Role ID or name")
    role_members.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

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

    # run (formerly exec)
    run_parser = subparsers.add_parser(
        "run", help="Execute a command via executor (Stage 1 + Stage 2 filtering)"
    )
    run_parser.add_argument(
        "command_args", help="Command to execute", nargs=argparse.REMAINDER
    )
    run_parser.add_argument(
        "--secret",
        action="append",
        dest="secrets",
        help="Secret key to inject (can be specified multiple times)",
    )
    run_parser.add_argument(
        "--executor-id",
        help="Executor ID to target (default: from config or 'default')",
    )
    run_parser.add_argument(
        "--server-url",
        help="Server URL override (default: from config)",
    )

    # exec — executor lifecycle management
    exec_parser = subparsers.add_parser(
        "exec", help="Executor lifecycle operations"
    )
    exec_subparsers = exec_parser.add_subparsers(dest="exec_command")

    # exec register
    register_parser = exec_subparsers.add_parser(
        "register", help="Register this machine as an executor with the vault"
    )
    register_parser.add_argument(
        "--executor-id",
        default="venya-exec",
        help="Executor ID (default: venya-exec)",
    )
    register_parser.add_argument(
        "--vault-url",
        help="Vault server URL (default: from config)",
    )
    register_parser.add_argument(
        "--output-dir",
        default="/etc/venya",
        help="Directory to save cert and key (default: /etc/venya)",
    )
    register_parser.add_argument(
        "--enrollment-token",
        dest="enrollment_token",
        default=None,
        help="Enrollment token for bootstrap registration (from admin executor-enroll)",
    )

    # exec cert — certificate management
    cert_parser = exec_subparsers.add_parser(
        "cert", help="Certificate management"
    )
    cert_subparsers = cert_parser.add_subparsers(dest="cert_command")

    # exec cert status
    cert_status_parser = cert_subparsers.add_parser(
        "status", help="Show certificate expiry status"
    )
    cert_status_parser.add_argument(
        "--cert-path",
        default="/etc/venya/executor.pem",
        help="Path to executor certificate (default: /etc/venya/executor.pem)",
    )

    # exec cert renew
    cert_subparsers.add_parser(
        "renew", help="Renew executor certificate (not yet implemented)"
    )

    # exec cert revoke
    cert_subparsers.add_parser(
        "revoke", help="Revoke executor certificate (not yet implemented)"
    )

    # exec heartbeat
    heartbeat_parser = exec_subparsers.add_parser(
        "heartbeat", help="Send heartbeat to vault (not yet implemented)"
    )
    heartbeat_parser.add_argument(
        "--vault-url",
        help="Vault server URL (default: from config)",
    )

    # exec audit
    exec_subparsers.add_parser(
        "audit", help="View executor audit log (not yet implemented)"
    )

    # exec status
    exec_subparsers.add_parser(
        "status", help="Show executor registration status (not yet implemented)"
    )

    # config
    config_parser = subparsers.add_parser(
        "config", help="Manage CLI configuration"
    )
    config_sub = config_parser.add_subparsers(dest="config_command")

    # config show
    config_sub.add_parser("show", help="Show current configuration")

    # config set-server
    set_server_parser = config_sub.add_parser(
        "set-server", help="Set the server URL"
    )
    set_server_parser.add_argument("url", help="Server URL")

    # config clear-token
    config_sub.add_parser(
        "clear-token", help="Clear stored access token (forces re-auth)"
    )

    # credential
    credential_parser = subparsers.add_parser(
        "credential", help="Manage credentials (security keys)"
    )
    credential_sub = credential_parser.add_subparsers(dest="credential_command")

    # credential list
    cred_list = credential_sub.add_parser("list", help="List own credentials")
    cred_list.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # credential add
    cred_add = credential_sub.add_parser("add", help="Add a new credential (requires security key)")
    cred_add.add_argument("label", help="Label for the new credential")
    cred_add.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # credential remove
    cred_remove = credential_sub.add_parser("remove", help="Remove a credential (requires security key)")
    cred_remove.add_argument("credential_id", help="Credential ID to remove")

    # enroll
    enroll_parser = subparsers.add_parser(
        "enroll", help="Headless enrollment using an enrollment token"
    )
    enroll_sub = enroll_parser.add_subparsers(dest="enroll_command")

    # enroll start
    enroll_start = enroll_sub.add_parser(
        "start", help="Start enrollment: get WebAuthn challenge from token"
    )
    enroll_start.add_argument("token", help="Enrollment token")
    enroll_start.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # enroll complete
    enroll_complete = enroll_sub.add_parser(
        "complete", help="Complete enrollment: submit WebAuthn attestation"
    )
    enroll_complete.add_argument("token", help="Enrollment token")
    enroll_complete.add_argument("challenge_id", help="Challenge ID from enroll start")
    enroll_complete.add_argument("response", help="WebAuthn attestation response (JSON)")
    enroll_complete.add_argument(
        "--label",
        help="Label for the new credential",
    )
    enroll_complete.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
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
