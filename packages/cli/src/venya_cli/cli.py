# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""CLI argument parser."""

import argparse
import sys
from datetime import UTC


def _cli_version() -> str:
    """Single-sourced version (feature/version-surfaces condition 1): dist
    metadata (pyproject) is the only truth — never a string literal."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        return _pkg_version("venya-cli")
    except PackageNotFoundError:
        return "unknown"


def create_parser() -> argparse.ArgumentParser:
    """Create the main CLI argument parser.

    Commands:
        venya setup <corename>                  # Save server URL + install core CA cert
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
         venya enroll <token>                    # Enroll with enrollment token + security key
         venya login <user_id>                   # Authenticate with security key
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
    parser.add_argument(
        "--version",
        action="version",
        version=f"{_cli_version()}",
        help="Print the CLI version and exit",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init
    init_parser = subparsers.add_parser("init", help="Bootstrap the core")
    init_parser.add_argument("user_id", help="User ID for first admin")
    init_parser.add_argument(
        "--skip-migrations",
        action="store_true",
        help=argparse.SUPPRESS,  # deprecated no-op; migrations run server-side at install
    )
    init_parser.add_argument(
        "--installation-reset",
        action="store_true",
        help="Reset core to pre-initialization state before starting (only allowed when no users are enrolled)",
    )

    # store
    store_parser = subparsers.add_parser("store", help="Store a secret")
    store_parser.add_argument("key", help="Secret key")
    store_parser.add_argument(
        "value",
        nargs="?",
        help="Secret value; '-' or omitted reads stdin (interactive TTY: hidden prompt)",
    )
    store_parser.add_argument(
        "--roles",
        nargs="+",
        required=True,
        help="Role(s) to scope the secret to",
    )
    store_parser.add_argument(
        "--key-version",
        default=None,
        help="Key version ID to encrypt with (default: server's active key version)",
    )
    store_parser.add_argument(
        "--metadata",
        "-m",
        action="append",
        default=None,
        help="Metadata key=value pair (can be specified multiple times)",
    )
    store_parser.add_argument(
        "--shape",
        default=None,
        help="How this secret is consumed (ssh-password, ssh-key, http-netrc, http-header-file, mysql-defaults, ipmi-passfile, askpass, env:NAME, or a custom name)",
    )
    store_parser.add_argument(
        "--usage",
        default=None,
        help="Command template for humans/agents; reference the secret only via {secret_path} (e.g. 'sshpass -f {secret_path} ssh user@host cmd')",
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
    list_parser.add_argument(
        "--user-id",
        default=None,
        help="User ID for authentication (required if no token stored)",
    )
    list_parser.add_argument(
        "--executor",
        default=None,
        help="Filter by executor metadata field",
    )
    list_parser.add_argument(
        "--purpose",
        default=None,
        help="Filter by purpose metadata field",
    )
    list_parser.add_argument(
        "--username",
        default=None,
        help="Filter by username metadata field",
    )

    # delete
    delete_parser = subparsers.add_parser("delete", help="Delete a secret")
    delete_parser.add_argument("key", help="Secret key to delete")

    # update-metadata
    update_meta_parser = subparsers.add_parser("update-metadata", help="Update metadata for a secret")
    update_meta_parser.add_argument("key", help="Secret key to update")
    update_meta_parser.add_argument(
        "--metadata",
        "-m",
        action="append",
        default=None,
        help="Metadata key=value pair (can be specified multiple times)",
    )
    update_meta_parser.add_argument(
        "--shape",
        default=None,
        help="How this secret is consumed (ssh-password, ssh-key, http-netrc, http-header-file, mysql-defaults, ipmi-passfile, askpass, env:NAME, or a custom name)",
    )
    update_meta_parser.add_argument(
        "--usage",
        default=None,
        help="Command template for humans/agents; reference the secret only via {secret_path} (e.g. 'sshpass -f {secret_path} ssh user@host cmd')",
    )

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

    # admin remove
    remove_parser = admin_sub.add_parser("remove", help="Remove a user")
    remove_parser.add_argument("user_id", help="User ID to remove")

    # admin configure-user
    configure_parser = admin_sub.add_parser("configure-user", help="Configure user settings")
    configure_parser.add_argument("user_id", help="User ID to configure")
    configure_parser.add_argument("--timeout", type=int, help="Session timeout in seconds")

    # admin list
    admin_list_parser = admin_sub.add_parser("list", help="List all registered users")
    admin_list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin create-user
    create_user_parser = admin_sub.add_parser("create-user", help="Create a new user and issue an enrollment token")
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
    set_policy_parser = admin_sub.add_parser("set-command-policy", help="Set executor command policy")
    set_policy_parser.add_argument(
        "preset",
        choices=["strict", "balanced", "permissive"],
        help="Policy preset",
    )
    set_policy_parser.add_argument("--custom", help="Path to custom policy file")

    # admin get-command-policy
    get_policy_parser = admin_sub.add_parser("get-command-policy", help="Get current executor command policy")
    get_policy_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin add-allowed-command
    add_cmd_parser = admin_sub.add_parser("add-allowed-command", help="Add a command to the strict allowlist")
    add_cmd_parser.add_argument("command_path", help="Full path to allowed command")

    # admin key-version
    kv_parser = admin_sub.add_parser("key-version", help="Key version management")
    kv_sub = kv_parser.add_subparsers(dest="kv_command")

    list_parser = kv_sub.add_parser("list", help="List all key versions")
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    deactivate_parser = kv_sub.add_parser("deactivate", help="Deactivate a key version")
    deactivate_parser.add_argument("version_id", help="Version ID")
    revoke_kv_parser = kv_sub.add_parser("revoke", help="Revoke a key version")
    revoke_kv_parser.add_argument("version_id", help="Version ID")
    kv_sub.add_parser("rotate-status", help="Show rotation job progress")
    rollback_parser = kv_sub.add_parser("rollback", help="Roll back a failed rotation job")
    rollback_parser.add_argument("job_id", help="Rotation job ID")

    # admin rotate-key
    rotate_parser = admin_sub.add_parser("rotate-key", help="Rotate the key encryption key")
    rotate_parser.add_argument("--new-key", help="Path to new KEK file")

    # admin revoke-executor
    revoke_executor_parser = admin_sub.add_parser("revoke-executor", help="Revoke an executor certificate")
    revoke_executor_parser.add_argument("executor_id", help="Executor ID to revoke")
    revoke_executor_parser.add_argument(
        "--serial",
        default=None,
        help=(
            "Revoke ONLY this certificate serial (hex, up to 16 chars) without revoking "
            "the executor identity — for orphaned/predecessor credentials. Omit for the "
            "identity form (terminal: re-enrollment then requires a NEW executor_id)."
        ),
    )

    # admin executor-enroll
    enroll_executor_parser = admin_sub.add_parser(
        "executor-enroll", help="Generate an enrollment token for an executor"
    )
    enroll_executor_parser.add_argument("executor_id", metavar="EXECUTOR_ID", help="Executor ID to enroll")
    enroll_executor_parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=None,
        help="Directory to write token and CA certs (creates token, core-server-ca.crt, admin-ca.crt)",
    )

    # admin list-tokens
    list_tokens_parser = admin_sub.add_parser("list-tokens", help="List all enrollment tokens for a user")
    list_tokens_parser.add_argument("user_id", help="User ID")
    list_tokens_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin issue-token
    issue_token_parser = admin_sub.add_parser("issue-token", help="Revoke old tokens and issue a new enrollment token")
    issue_token_parser.add_argument("user_id", help="User ID")
    issue_token_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # admin revoke-token
    revoke_token_parser = admin_sub.add_parser("revoke-token", help="Revoke a single enrollment token")
    revoke_token_parser.add_argument("token_id", help="Token ID to revoke")

    # admin re-enroll
    re_enroll_parser = admin_sub.add_parser("re-enroll", help="Deactivate credentials and issue a new enrollment token")
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
        "--output",
        "-o",
        help="Output file path (default: stdout)",
    )
    export_cert_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /var/lib/venya/ca)",
    )

    # admin export-ca-key
    export_key_parser = admin_sub.add_parser(
        "export-ca-key", help="Export the CA private key (encrypted with passphrase)"
    )
    export_key_parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Output file path for encrypted key",
    )
    export_key_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /var/lib/venya/ca)",
    )

    # admin split-ca-key
    split_key_parser = admin_sub.add_parser("split-ca-key", help="Split CA key using Shamir's Secret Sharing")
    split_key_parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        required=True,
        help="Minimum shares needed to reconstruct (K)",
    )
    split_key_parser.add_argument(
        "--shares",
        "-s",
        type=int,
        required=True,
        help="Total number of shares to create (N)",
    )
    split_key_parser.add_argument(
        "--output-dir",
        "-d",
        required=True,
        help="Directory to write share files",
    )
    split_key_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /var/lib/venya/ca)",
    )

    # admin restore-ca-key
    restore_key_parser = admin_sub.add_parser("restore-ca-key", help="Restore CA key from shares or encrypted backup")
    restore_key_parser.add_argument(
        "--mode",
        choices=["shares", "backup"],
        required=True,
        help="Restore mode: from shares (SSS) or from encrypted backup file",
    )
    restore_key_parser.add_argument(
        "--shares",
        nargs="+",
        help="Share files for SSS restore (e.g., share-1 share-2 share-3)",
    )
    restore_key_parser.add_argument(
        "--backup-file",
        help="Encrypted backup file for backup restore mode",
    )
    restore_key_parser.add_argument(
        "--ca-dir",
        help="CA directory path (default: /var/lib/venya/ca)",
    )

    # admin init-admin-ca
    init_admin_ca_parser = admin_sub.add_parser("init-admin-ca", help="Initialize the admin CA (create key/cert pair)")
    init_admin_ca_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to create admin CA key/cert in",
    )

    # admin generate-admin-cert
    gen_admin_cert_parser = admin_sub.add_parser("generate-admin-cert", help="Sign an admin client certificate")
    gen_admin_cert_parser.add_argument(
        "identity",
        help="Admin identity (used as CN and SAN DNS name)",
    )
    gen_admin_cert_parser.add_argument(
        "--ca-dir",
        default=None,
        help="Admin CA directory path (default: $VENYA_ADMIN_CA_DIR or /var/lib/venya/ca/admin-ca)",
    )
    gen_admin_cert_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write admin cert/key to",
    )

    # admin revoke-admin-cert
    revoke_admin_cert_parser = admin_sub.add_parser(
        "revoke-admin-cert", help="Revoke an admin certificate by serial number"
    )
    revoke_admin_cert_parser.add_argument(
        "--serial",
        required=True,
        help="Hex serial number of certificate to revoke",
    )
    revoke_admin_cert_parser.add_argument(
        "--reason",
        default="unspecified",
        help="Revocation reason (default: unspecified)",
    )
    revoke_admin_cert_parser.add_argument(
        "--server-url",
        default=None,
        help="Core server URL (default: from config or VENYA_SERVER_URL)",
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
    recovery_parser = subparsers.add_parser("recovery", help="Break-glass recovery")
    recovery_parser.add_argument("code", help="Recovery code")
    recovery_parser.add_argument("new_user_id", help="New user ID")
    recovery_parser.add_argument("--force", action="store_true", help="Force operation")
    recovery_parser.add_argument("--confirm", action="store_true", help="Confirm recovery action")

    # run (formerly exec)
    run_parser = subparsers.add_parser("run", help="Execute a command via executor (Stage 1 + Stage 2 filtering)")
    run_parser.add_argument(
        "command_args",
        help="Command to execute (a leading -- separator is consumed, not sent to the executor)",
        nargs=argparse.REMAINDER,
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
    exec_parser = subparsers.add_parser("exec", help="Executor lifecycle operations")
    exec_subparsers = exec_parser.add_subparsers(dest="exec_command")

    # exec register
    register_parser = exec_subparsers.add_parser("register", help="Register this machine as an executor with the core")
    register_parser.add_argument(
        "--executor-id",
        default=None,
        help="Executor ID (default: executor_id from /etc/venya/executor.toml)",
    )
    register_parser.add_argument(
        "--core-url",
        "--server-url",
        dest="core_url",
        help="Core server URL (default: from config or VENYA_SERVER_URL)",
    )
    register_parser.add_argument(
        "--output-dir",
        default="/etc/venya/executor",
        help="Directory to save cert and key (default: /etc/venya/executor)",
    )
    register_parser.add_argument(
        "--enrollment-token",
        dest="enrollment_token",
        default=None,
        help="Enrollment token for bootstrap registration (from admin executor-enroll; "
        "falls back to VENYA_EXECUTOR_ENROLLMENT_TOKEN env)",
    )
    register_parser.add_argument(
        "--ca-bundle",
        dest="ca_bundle",
        default=None,
        help="Path to CA bundle for verifying core server TLS",
    )

    # exec cert — certificate management
    cert_parser = exec_subparsers.add_parser("cert", help="Certificate management")
    cert_subparsers = cert_parser.add_subparsers(dest="cert_command")

    # exec cert status
    cert_status_parser = cert_subparsers.add_parser("status", help="Show certificate expiry status")
    cert_status_parser.add_argument(
        "--cert-path",
        default="/etc/venya/executor/executor.crt",
        help="Path to executor certificate (default: /etc/venya/executor/executor.crt)",
    )

    # exec cert renew
    cert_renew_parser = cert_subparsers.add_parser("renew", help="Renew executor certificate")
    cert_renew_parser.add_argument(
        "--cert-path",
        default="/etc/venya/executor/executor.crt",
        help="Path to executor certificate (default: /etc/venya/executor/executor.crt)",
    )
    cert_renew_parser.add_argument(
        "--key-path",
        dest="key_path",
        default=None,
        help="Path to executor private key (default: derive from --cert-path)",
    )

    # exec cert revoke
    revoke_parser = cert_subparsers.add_parser("revoke", help="Revoke an executor certificate (admin action)")
    revoke_parser.add_argument(
        "--executor-id",
        dest="executor_id",
        default=None,
        help="Executor ID to revoke (default: read from local cert file)",
    )
    revoke_parser.add_argument(
        "--cert-path",
        dest="cert_path",
        default="/etc/venya/executor/executor.crt",
        help="Path to executor certificate file (used for ID fallback, default: /etc/venya/executor/executor.crt)",
    )

    # exec heartbeat
    heartbeat_parser = exec_subparsers.add_parser("heartbeat", help="Send heartbeat to core")
    heartbeat_parser.add_argument(
        "--core-url",
        "--server-url",
        dest="core_url",
        help="Core server URL (default: from config or VENYA_SERVER_URL)",
    )
    heartbeat_parser.add_argument(
        "--cert-path",
        default="/etc/venya/executor/executor.crt",
        help="Path to executor certificate (default: /etc/venya/executor/executor.crt)",
    )
    heartbeat_parser.add_argument(
        "--key-path",
        dest="key_path",
        default=None,
        help="Path to executor private key (default: derive from --cert-path)",
    )

    # exec audit
    audit_parser = exec_subparsers.add_parser("audit", help="View executor audit log")
    audit_parser.add_argument(
        "executor_id",
        nargs="?",
        default=None,
        help="Executor ID to audit (default: read from local cert file)",
    )
    audit_parser.add_argument(
        "--cert-path",
        dest="cert_path",
        default="/etc/venya/executor/executor.crt",
        help="Path to executor certificate file (used for ID fallback, default: /etc/venya/executor/executor.crt)",
    )
    audit_parser.add_argument(
        "--hours",
        type=int,
        default=None,
        help="Query last N hours",
    )
    audit_parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Query last N days",
    )
    audit_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Max results (default: 100)",
    )
    audit_parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Result offset (default: 0)",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # exec status
    exec_subparsers.add_parser("status", help="Show executor registration status")

    # exec list
    exec_list_parser = exec_subparsers.add_parser(
        "list", help="List registered executors with heartbeat-reported versions (admin)"
    )
    exec_list_parser.add_argument("--json", action="store_true", help="Output raw JSON")

    # config
    config_parser = subparsers.add_parser("config", help="Manage CLI configuration")
    config_sub = config_parser.add_subparsers(dest="config_command")

    # config show
    config_sub.add_parser("show", help="Show current configuration")

    # config set-server
    set_server_parser = config_sub.add_parser("set-server", help="Set the server URL")
    set_server_parser.add_argument("url", help="Server URL")

    # config clear-token
    config_sub.add_parser("clear-token", help="Clear stored access token (forces re-auth)")

    # credential
    credential_parser = subparsers.add_parser("credential", help="Manage credentials (security keys)")
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
    enroll_parser = subparsers.add_parser("enroll", help="Enroll with a security key using an enrollment token")
    enroll_parser.add_argument("token", help="Enrollment token")
    enroll_parser.add_argument("--label", help="Label for the new credential")
    enroll_parser.add_argument("--json", action="store_true")

    # login
    login_parser = subparsers.add_parser("login", help="Authenticate with a security key")
    login_parser.add_argument("user_id", help="User ID to authenticate as")
    login_parser.add_argument("--json", action="store_true")

    # setup
    setup_parser = subparsers.add_parser("setup", help="Save the server URL and install the core's CA certificate")
    setup_parser.add_argument("corename", help="Core server hostname or full URL (e.g. venya-core-1)")
    setup_parser.add_argument(
        "--ca-sha256",
        default=None,
        help="Pin the expected CA SHA-256 fingerprint (hex; colons, spaces, and case are ignored)",
    )

    return parser


def _install_stderr_tee():
    """Append a copy of everything written to stderr into <config_dir>/venya.log.

    Every command failure path ends in a print to stderr (and verbose mode
    raises tracebacks there too), so tee-ing stderr captures them all without
    touching any call site. Returns the log path, or None if logging could not
    be set up — a broken log must never break the CLI.

    PIN prompts (getpass) go to stderr but typed PINs never pass through it
    (TTY echo-off), so no secret material lands in the file.
    """
    try:
        from datetime import datetime

        from .api_client import default_config_dir

        log_dir = default_config_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "venya.log"
        # ponytail: single-generation rotation at 1 MiB; a real retention
        # policy only if logs ever become operationally important.
        try:
            if log_path.stat().st_size > 1_048_576:
                log_path.replace(log_path.with_suffix(".log.1"))
        except FileNotFoundError:
            pass
        logf = open(log_path, "a", encoding="utf-8")  # noqa: SIM115 — lives for the process lifetime
        logf.write(f"\n=== {datetime.now(UTC).isoformat()} argv={sys.argv[1:]} ===\n")
        logf.flush()
        original = sys.stderr

        class _Tee:
            def write(self, s: str) -> int:
                original.write(s)
                try:
                    logf.write(s)
                    logf.flush()
                except Exception:  # noqa: S110  # nosec B110 — logging must never break the command
                    pass
                return len(s)

            def flush(self) -> None:
                original.flush()
                try:
                    logf.flush()
                except Exception:  # noqa: S110  # nosec B110
                    pass

            def __getattr__(self, name: str):
                return getattr(original, name)

        sys.stderr = _Tee()
        return log_path
    except Exception:  # nosec B110 — unwritable config dir must not break the CLI
        return None


def main() -> int:
    """Entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    log_path = _install_stderr_tee()

    # Import command implementations
    from .commands import run_command

    try:
        rc = run_command(args)
    except Exception as e:
        if args.verbose:
            raise
        print(f"Error: {e}", file=sys.stderr)
        rc = 1
    if rc != 0 and log_path is not None:
        print(f"(error details logged to {log_path})", file=sys.stderr)
    return rc
