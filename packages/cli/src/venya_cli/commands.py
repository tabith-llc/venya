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
import shlex
import ssl
import sys
import tempfile
from datetime import UTC
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx2
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .api_client import (
    DEFAULT_CONFIG_FILE,
    APIClient,
    APIClientAuthenticationError,
    APIClientError,
    _build_ssl_context,
    cli_version,
    execution_timeout,
    version_tuple,
)
from .at_rest_key import (
    acquire_server_passphrase,
    atomic_write_key,
    ensure_secret_dir,
    resolve_ca_key_path,
    restore_at_rest_bytes,
    server_passphrase_env_for,
    unwrap_at_rest,
)

# --- Version-mismatch advisory (ticket cli-version-mismatch-upgrade-nudge) ---
# Ruled design (#324 D1-D4): nudge only, never a gate; one /health fetch per
# CLI process; offline -> silent skip; the unauthenticated health fence serves
# the core version and NEVER grows (executor versions ride the authenticated
# executor lists only). Wording names the OUT-OF-DATE side and never advises
# downgrading a server.

_SERVER_VERSION_UNCHECKED = object()
_server_version_cache: Any = _SERVER_VERSION_UNCHECKED


def get_server_version(client: APIClient) -> str | None:
    """Core's dist version from the fenced /health ``version`` field, fetched
    ONCE per process (module cache). None = unknown (offline, old server
    without the field, unparseable) — every caller stays silent on None."""
    global _server_version_cache
    if _server_version_cache is _SERVER_VERSION_UNCHECKED:
        try:
            body = client.get("/api/v1/health", timeout=5.0)
            raw = body.get("version") if isinstance(body, dict) else None
            _server_version_cache = raw if isinstance(raw, str) and version_tuple(raw) else None
        except Exception:
            # D1 offline rule: a failed advisory fetch must never add a second
            # error to the run — the real command surfaces its own honest error.
            _server_version_cache = None
    return _server_version_cache  # type: ignore[return-value]


def version_advisory(client: APIClient) -> None:
    """Compare the CLI dist version to the core version once per process and
    print a one-line advisory naming the out-of-date side. Equal (PEP 440
    normalized, so 0.1.0alpha16 == 0.1.0a16) or unknown -> silence."""
    server_ver = get_server_version(client)
    cli_ver = cli_version()
    if server_ver is None:
        return
    server_vt, cli_vt = version_tuple(server_ver), version_tuple(cli_ver)
    if server_vt is None or cli_vt is None or server_vt == cli_vt:
        return
    if cli_vt < server_vt:
        print(
            f"Note: CLI version {cli_ver} is older than the core server {server_ver} — "
            "update the CLI (re-run the CLI installer).",
            file=sys.stderr,
        )
    else:
        print(
            f"Note: CLI version {cli_ver} is newer than the core server {server_ver} — "
            "the core is the out-of-date side; update the core (re-run the core installer).",
            file=sys.stderr,
        )


def _run_argv_strict_utf8_error(command_args: Any) -> int | None:
    """Return the first argv index that is not strict-UTF-8 encodable, else None.

    Ticket argv-surrogate-executes-then-crashes-audit-write #334 (posture B):
    a lone surrogate (e.g. ``\\ud800``) rides JSON and fsencode round-trips as
    a Python str, EXECUTES, and then dies on the server's completion audit
    write — side effects kept, record lost. The CLI refuses locally BEFORE any
    network: the probe is the default-strict ``encode("utf-8")``. The offending
    element's value is never echoed (argv may carry user-sensitive text) — only
    its index. Byte-faithful handling is ticketed for post-beta (#335).
    """
    for i, elem in enumerate(command_args or []):
        try:
            elem.encode("utf-8")
        except UnicodeEncodeError:
            return i
    return None


def run_command(args: Any) -> int:
    """Run a CLI command.

    Args:
        args: Parsed argparse namespace.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    # Layer-1 strict-UTF-8 gate for the run path (#334, posture B): probe
    # every captured argv element BEFORE the client exists — no session, no
    # relay, no HTTP of any kind happens with a non-encodable element.
    if getattr(args, "command", None) == "run":
        bad_index = _run_argv_strict_utf8_error(getattr(args, "command_args", None))
        if bad_index is not None:
            print(
                f"Error: argument {bad_index} is not valid UTF-8 text — a lone surrogate "
                "cannot be executed faithfully or audited losslessly. "
                "Command refused locally; nothing was sent.",
                file=sys.stderr,
            )
            return 1

    # Server URL precedence (matches the --server-url help text and the
    # revoke-admin-cert handler): explicit flag > VENYA_SERVER_URL env >
    # config.json (APIClient fallback). Empty env falls through (ticket
    # cli-server-url-env-ignored: headless guidance drove the CLI by env only,
    # which silently hit the localhost:8000 default -> Errno 111).
    # #387: the exec-family alias is dest=core_url (--core-url / --server-url)
    # — it never reached this chokepoint, so `exec register` posted the CSR to
    # the flag URL while the client's post-register verify call silently hit
    # the config/env default (Errno 111 on config-less hosts).
    server_url = (
        getattr(args, "server_url", None)
        or getattr(args, "core_url", None)
        or os.environ.get("VENYA_SERVER_URL")
        or None
    )
    client = APIClient(server_url=server_url)

    # Authenticate if no token is available (init, setup, enroll, login,
    # recovery, config, exec are public — setup is pre-bootstrap: it exists to
    # make the first authenticated call possible). Headless admin exemption:
    # `venya admin ...` with VENYA_ADMIN_CERT/KEY configured presents the mTLS
    # client cert instead, and the server's require_admin cert-only shortcut is
    # the authority (a bad cert surfaces as its 401/403). Scoped to command ==
    # "admin" ONLY -- role-gated commands (list/store/audit/...) still require
    # FIDO2/token, matching the server, which 401s cert-only callers on
    # require_role routes.
    command = args.command
    admin_mtls_exempt = command == "admin" and getattr(client, "has_admin_mtls", False)
    if admin_mtls_exempt and not client.config.access_token:
        print("Using admin mTLS certificate (VENYA_ADMIN_CERT) for authentication.")
    elif (
        command not in ("init", "setup", "enroll", "login", "recovery", "config", "exec")
        and not client.config.access_token
    ):
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

    # Version-mismatch advisory: one fenced /health fetch per process, silent
    # offline, warn-only (#324 D1/D2 — no request the server would serve is blocked).
    version_advisory(client)

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
        elif command == "setup":
            return cmd_setup(client, args)
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


def _win_ceremony_hint(kind: str) -> str | None:
    """Windows platform-dialog guidance (ticket cli-windows-ceremony-guidance-ux).

    On Windows the OS-drawn dialogs own PIN/touch — and when no key is attached
    they wait for INSERTION. Terminal text written for the raw-CTAP path
    ("touch your key") contradicts what the operator sees, and dual-key flows
    (credential add: registered key for elevation, then the NEW key for
    registration) need step-scoped guidance. Returns the win32 hint for the
    ceremony kind ("assertion" | "registration" | "credential-add"), or None on
    other platforms so POSIX output stays byte-identical (truth-table tested).
    """
    if sys.platform != "win32":
        return None
    if kind == "assertion":
        return (
            "Windows: a security dialog will open — use your REGISTERED key "
            "(PIN and touch happen in the dialog, not this terminal). If it asks "
            "you to insert a key, plug in the registered one."
        )
    if kind == "registration":
        return (
            "Windows: a security dialog will open — INSERT the key you are "
            "enrolling when asked (PIN and touch happen in the dialog)."
        )
    return (
        "Windows: TWO dialogs will open, in order — FIRST verify with your "
        "REGISTERED key (elevation), THEN insert the NEW key you are enrolling "
        "when the registration dialog opens (about 60 s total)."
    )


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
        fido2 = Fido2Auth(client.config.server_url, ca_path=client.config.ca_path)

        print(f"Starting core initialization for user '{args.user_id}'...")
        print("Please insert your security key when prompted.\n")
        _hint = _win_ceremony_hint("registration")
        if _hint:
            print(_hint)

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
    the installers use for passwords). Piped stdin is stored BYTE-EXACT —
    no trailing-newline stripping (ticket cli-store-stdin-rstrip-pem-corruption:
    the former rstrip corrupted PEM keys, which OpenSSH >= 10 refuses to load
    unterminated). ``echo pass |`` therefore stores a trailing newline —
    harmless for line-based consumers (sshpass -f, sudo -S) and output masking
    (trimmed-hash filter variant); use ``printf %s pass |`` for byte-exact
    single-line values.
    """
    value = args.value
    if value is None or value == "-":
        if value == "-" or not sys.stdin.isatty():
            value = sys.stdin.read()
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
            # --roles accepts space- (nargs='+') AND comma-separated tokens;
            # split each like cmd_admin_create_user does, else 'a,b' reaches
            # the server as ONE role name (ticket cli-role-name-and-comma-defects).
            "roles": [r.strip() for item in args.roles for r in item.split(",")],
            "key_version_id": key_version_id,
        }

        # Parse metadata key=value pairs + --shape/--usage sugar
        meta_dict: dict[str, str] = {}
        for item in getattr(args, "metadata", None) or []:
            k, _, v = item.partition("=")
            meta_dict[k] = v
        for flag, key in (("--shape", "shape"), ("--usage", "usage")):
            val = getattr(args, key, None)
            if val is not None:
                if key in meta_dict and meta_dict[key] != val:
                    print(
                        f"Conflicting {key}: given both via '-m {key}=...' and {flag}. Use one form.",
                        file=sys.stderr,
                    )
                    return 1
                meta_dict[key] = val
        if meta_dict:
            payload["metadata"] = meta_dict

        resp = client.post(
            "/api/v1/secrets",
            json=payload,
        )
        if isinstance(resp, dict):
            for w in resp.get("metadata_warnings") or []:
                print(f"warning: {w}", file=sys.stderr)
            if resp.get("replaced"):
                print(f"Secret '{args.key}' replaced existing (id {resp.get('id')}).")
            else:
                shape_suffix = f" (shape: {meta_dict['shape']})" if "shape" in meta_dict else ""
                print(f"Secret '{args.key}' stored successfully{shape_suffix}.")
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
        params: dict[str, Any] = {"unmask": args.unmask}
        get_kwargs: dict[str, Any] = {"params": params}
        if args.unmask:
            # Unmask is elevation-gated server-side (ticket
            # sec-secret-caller-param-plaintext-bypass): re-authenticate with
            # the security key first, same ceremony as credential add.
            # The token rides the X-Elevation-Token HEADER — the server
            # deleted the query-param transport (sec-auth-elevation-authz-
            # hardening #13) and a query token leaks into access logs
            # (ticket cli-elevation-token-query-param-transport).
            print("Re-authenticating with security key for elevation...")
            get_kwargs["extra_headers"] = {"X-Elevation-Token": _elevate(client)}
        result = client.get(
            f"/api/v1/secrets/{quote(args.key, safe='')}",
            **get_kwargs,
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

        # --json: byte-exact passthrough of the API envelope (keys+metadata,
        # never values). BEFORE the empty check on purpose: an empty store
        # must still emit parseable JSON ({"secrets": []}). cmd_audit uses
        # the same ordering ({"events": []} on an empty vault, ticket
        # audit-json-empty-case-unparseable).
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        if not secrets:
            print("No secrets found.")
            return 0

        for secret in secrets:
            line = f"  {secret['key']}"
            meta = secret.get("metadata")
            if meta:
                parts = []
                if meta.get("shape"):
                    parts.append(f"shape={meta['shape']}")
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
        client.delete(f"/api/v1/secrets/{quote(args.key, safe='')}")
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
        meta_dict: dict[str, str] = {}
        for item in getattr(args, "metadata", None) or []:
            k, _, v = item.partition("=")
            meta_dict[k] = v
        for flag, key in (("--shape", "shape"), ("--usage", "usage")):
            val = getattr(args, key, None)
            if val is not None:
                if key in meta_dict and meta_dict[key] != val:
                    print(
                        f"Conflicting {key}: given both via '-m {key}=...' and {flag}. Use one form.",
                        file=sys.stderr,
                    )
                    return 1
                meta_dict[key] = val
        if not meta_dict:
            print(
                "Nothing to update: pass -m key=value, --shape, or --usage.",
                file=sys.stderr,
            )
            return 1

        resp = client.patch(f"/api/v1/secrets/{quote(args.key, safe='')}/metadata", json={"metadata": meta_dict})
        if isinstance(resp, dict):
            for w in resp.get("metadata_warnings") or []:
                print(f"warning: {w}", file=sys.stderr)
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

        # --json: byte-exact passthrough of the API envelope. BEFORE the
        # empty check: an empty vault must still emit parseable JSON
        # ({"events": []}) — same ordering as cmd_list (ticket
        # audit-json-empty-case-unparseable).
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        if not events:
            print("No audit events found.")
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
    elif admin_command == "remove-executor":
        return cmd_admin_remove_executor(client, args)
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
    elif admin_command == "reissue-recovery-code":
        return cmd_admin_reissue_recovery_code(client, args)
    else:
        print(f"Unknown admin command: {admin_command}", file=sys.stderr)
        return 1


def cmd_admin_enroll(client: APIClient, args: Any) -> int:
    """Enroll a new user."""
    try:
        result = client.post(
            "/api/v1/admin/enroll",
            json={"user_id": args.user_id},
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
        client.delete(f"/api/v1/admin/users/{quote(args.user_id, safe='')}")
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
        if args.timeout:
            config["session_timeout"] = args.timeout

        client.put(
            f"/api/v1/admin/users/{quote(args.user_id, safe='')}",
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
        # Real AdminSetCommandPolicyRequest fields only (#289: the old
        # "custom" key was silently dropped server-side). Comma/space tokens
        # flatten with the #293 idiom; each list REPLACES its stored one.
        if args.custom_allowed:
            policy["custom_allowed_commands"] = [c.strip() for item in args.custom_allowed for c in item.split(",")]
        if args.custom_dangerous:
            policy["custom_dangerous_patterns"] = [p.strip() for item in args.custom_dangerous for p in item.split(",")]

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
    """Rotate key.

    Single-KEK bookkeeping rotation — takes no parameters (#355: the former
    --new-key flag posted new_key_path, which the server model never read;
    the flag is retired with the model now validating extra="forbid").
    """
    try:
        result = client.post("/api/v1/admin/key-rotation", json={})
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
        serial = getattr(args, "serial", None)

    return executor_cert_revoke(_RevokeArgs(), client=client)


def cmd_admin_remove_executor(client: APIClient, args: Any) -> int:
    """Remove an executor row (admin action, ticket #391 arm (b)).

    Removal implies revocation: the server revokes the current certificate
    serial, deletes the cert and executor rows, and refuses (409) while
    execution-session history is retained. 404/409 details surface on
    stderr with a nonzero exit (user-remove precedent).
    """
    try:
        client.delete(f"/api/v1/admin/executors/{quote(args.executor_id, safe='')}")
        print(f"Executor '{args.executor_id}' removed (current certificate revoked).")
        return 0
    except APIClientError as e:
        print(f"Remove failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Remove failed: {e}", file=sys.stderr)
        return 1


# CA source paths for the executor-enroll --output-dir bundle. Module-level
# constants = test seam (monkeypatchable); the bundle copies these into the
# output dir for offline/air-gapped executor installs.
_BUNDLE_CORE_CA = Path("/var/lib/venya/ca/ca.crt")
_BUNDLE_ADMIN_CA = Path("/var/lib/venya/ca/admin-ca/admin-ca.crt")


def cmd_admin_executor_enroll(client: APIClient, args: Any) -> int:
    """Generate an enrollment token for executor bootstrap registration."""
    try:
        output_dir = getattr(args, "output_dir", None)
        if output_dir:
            # Stale-token defense BEFORE the mint (ticket
            # cli-executor-enroll-token-ux): a failed POST must never leave a
            # previous run's dead token on disk for `test -s` to trust.
            # Removal AFTER the POST would resurrect the bug on a crash
            # between the two.
            (Path(output_dir) / "token").unlink(missing_ok=True)

        result = client.post(f"/api/v1/admin/executors/{args.executor_id}/enroll")
        token = result.get("enrollment_token", "")
        expires_in = result.get("expires_in_seconds", 900)

        if output_dir:
            import hashlib as hashlib_mod

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            ensure_secret_dir(output_path)

            token_path = output_path / "token"
            token_tmp: str | None = None
            try:
                with tempfile.NamedTemporaryFile(dir=output_path, prefix=".venya-token-", delete=False) as fd:
                    token_tmp = fd.name
                    fd.write(token.encode())
                    fd.flush()
                    os.fchmod(fd.fileno(), 0o600)
                os.replace(token_tmp, token_path)
            except BaseException:
                if token_tmp is not None:
                    try:
                        os.unlink(token_tmp)
                    except OSError:
                        pass
                raise

            core_ca_path = output_path / "core-server-ca.crt"
            if _BUNDLE_CORE_CA.exists():
                core_ca_path.write_bytes(_BUNDLE_CORE_CA.read_bytes())
                core_ca_written = True
            else:
                core_ca_written = False

            admin_ca_path = output_path / "admin-ca.crt"
            if _BUNDLE_ADMIN_CA.exists():
                admin_ca_path.write_bytes(_BUNDLE_ADMIN_CA.read_bytes())
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
            if not core_ca_written:
                print()
                print("WARNING: core CA missing — bundle INCOMPLETE for offline/air-gapped install.")
                print("         Online installs fetch the CA from the server; offline installs need it pre-copied.")
            print()
            print("Bundle fingerprint (verify before copying to executor):")
            print(f"  SHA256: {bundle_hash}")
            print()
            print("To install on executor VM:")
            print(f"  scp -r {output_dir} bot@{args.executor_id}:/tmp/")
            print()
            print("  curl -fsSL http://.../install-venya-executor.sh | \\")
            print(f"    sudo VENYA_SERVER_URL={client.config.server_url} \\")
            print(f"         VENYA_EXECUTOR_ID={args.executor_id} \\")
            print(f"         VENYA_EXECUTOR_ENROLLMENT_TOKEN=$(cat {token_path}) \\")
            if core_ca_written:
                print(f"         VENYA_VENYA_CA_FILE={core_ca_path} \\")
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
        result = client.get(f"/api/v1/admin/users/{quote(args.user_id, safe='')}/enrollment-tokens")
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
        result = client.post(f"/api/v1/admin/users/{quote(args.user_id, safe='')}/enrollment-tokens")

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
        result = client.post(f"/api/v1/admin/users/{quote(args.user_id, safe='')}/re-enroll")

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
        print(f"  Credentials deactivated: {result.get('credentials_deactivated', 0)}")
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


def _resolve_role_id(client: APIClient, role_ref: str) -> str:
    """Resolve a role reference: an int ID passes through, a name is looked
    up in GET /api/v1/roles and matched case-folded (ticket
    cli-role-name-and-comma-defects — the help advertises "Role ID or name"
    but the /roles/{role_id} path param is int-validated, so raw names died
    at 422). Case folding mirrors the server convention: RoleManager stores
    names lowercased and matches func.lower(Role.name) == name.lower()
    (core/iam/role_manager.py). Raises APIClientError naming the failed
    lookup — never a raw 422 dump.
    """
    try:
        int(role_ref)
        return role_ref
    except ValueError:
        pass
    target = role_ref.casefold()
    result = client.get("/api/v1/roles")
    for role in result.get("roles", []):
        if str(role.get("name", "")).casefold() == target:
            return str(role["id"])
    raise APIClientError(f"role '{role_ref}' not found — no name match in the role list (check `venya role list`)")


def cmd_role_get(client: APIClient, args: Any) -> int:
    """Get role details."""
    try:
        role_id = _resolve_role_id(client, args.role_id)
        result = client.get(f"/api/v1/roles/{role_id}")
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
        role_id = _resolve_role_id(client, args.role_id)
        client.delete(f"/api/v1/roles/{role_id}")
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
        role_id = _resolve_role_id(client, args.role_id)
        result = client.get(f"/api/v1/roles/{role_id}/members")
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
        role_id = _resolve_role_id(client, args.role_id)
        client.post(
            f"/api/v1/roles/{role_id}/members",
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
        role_id = _resolve_role_id(client, args.role_id)
        client.delete(f"/api/v1/roles/{quote(role_id, safe='')}/members/{quote(args.user_id, safe='')}")
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
                # #367: only the declared RecoveryRequest fields cross. The
                # former --force/--confirm local no-ops retired with #377.
                "code": args.code,
                "new_user_id": args.new_user_id,
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
    # The REMAINDER argv list posts AS a list (ticket execution-command-wire-
    # unstructured-string #322, ruling Q1=A1): argument boundaries ride the wire
    # as structured data. The #319 interim per-arg shlex.quote join is deleted —
    # quoting artifacts no longer enter the wire, audit, or the echo below.
    if not command_args:
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
        print(f"Executing: {shlex.join(command_args)}")
        exec_result = client.post(
            f"/api/v1/executors/{executor_id}/execute",
            json={
                "session_id": session_id,
                "command": command_args,
            },
            # Last-fuse read timeout (relay 300s < nginx 330s < 340s default):
            # a cold-sandbox run (~65s template pull) must not be abandoned
            # client-side while the server completes it — ticket
            # cli-execution-timeout-cold-start-default.
            timeout=execution_timeout(),
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


def _require_https_server_url(server_url: str, *, site: str, ticket: str, detail: str = "") -> bool:
    """One shared https:// scheme guard for every place the CLI dials a core URL.

    Plaintext http is REJECTED — never downgraded, never warned-and-continued. That
    is the owner ruling on ``sec-sweep-low-informational`` #17 (2026-09-21), which
    the executor heartbeat has carried since; the renew / register / setup /
    config-write sites are being brought onto the same rule rather than inventing
    one (#497 #506 #508 #509).

    The sanctioned ``VENYA_TLS_VERIFY=false`` knob is NOT consulted here: it means
    "distrust this certificate over https", never "no TLS", so it cannot re-open
    plaintext. The check runs on the RESOLVED URL, so no source of that URL
    (flag, env, config.json, executor.toml) escapes it.

    Returns True when the URL is usable. On failure prints the refusal (the exact
    wording class the heartbeat site pinned) and returns False, so the caller only
    has to ``return 1``.
    """
    if server_url.startswith("https://"):
        return True
    suffix = f" — {detail}" if detail else ""
    print(
        f"Error: server URL must be https:// — got '{server_url}'. Plaintext http is "
        f"not supported for {site}{suffix} (ticket {ticket}).",
        file=sys.stderr,
    )
    return False


def cmd_setup(client: APIClient, args: Any) -> int:
    """Save the server URL and install the core's CA certificate.

    Workstation bootstrap in one command: normalize <corename> to an https
    URL, save it, fetch /.well-known/venya-ca.crt, validate it as X.509 PEM,
    and write it beside config.json as ca.crt (0600, atomic). APIClient and
    Fido2Auth then verify core TLS against it automatically — no
    SSL_CERT_FILE incantation needed for any later command.

    An explicit http:// URL is REFUSED before anything is written (#497): the
    fetched bytes become the trust anchor every later call verifies against, so
    a plaintext answer from an on-path adversary would be installed as the CA.
    A bare hostname still normalizes to https://.

    The fetch is a scoped, unverified GET (trust-on-first-use): the cert it
    returns becomes the verification anchor, and its subject + SHA-256
    fingerprint are printed so the operator can confirm them out-of-band.
    No subsequent call reuses that unverified client.
    """
    core = args.corename
    if not core.startswith(("http://", "https://")):
        core = "https://" + core
    # #497, now on the shared guard: the fetched bytes become this workstation's
    # trust anchor, so a plaintext answer from an on-path adversary would be
    # installed as the CA. Bare hostnames still normalize to https:// above.
    if not _require_https_server_url(
        core,
        site="venya setup",
        ticket="cli-setup-ca-fetch-plaintext-http",
        detail="the fetched certificate is installed as this workstation's trust anchor",
    ):
        return 1
    client.config.server_url = core

    url = f"{core}/.well-known/venya-ca.crt"
    try:
        resp = httpx2.get(url, verify=False, timeout=5.0)  # nosec B403 -- scoped TOFU bootstrap; see docstring
    except httpx2.HTTPError as e:
        print(f"setup incomplete: cannot fetch CA certificate from {url}: {e}", file=sys.stderr)
        print(f"Server URL saved: {core} — re-run 'venya setup {args.corename}' to retry", file=sys.stderr)
        return 1
    if resp.status_code == 404:
        print(f"setup incomplete: {url} not found — is {core} a venya core?", file=sys.stderr)
        return 1
    if resp.status_code != 200:
        print(f"setup incomplete: GET {url} returned HTTP {resp.status_code}", file=sys.stderr)
        return 1

    try:
        cert = x509.load_pem_x509_certificate(resp.content)
    except ValueError:
        print(f"setup incomplete: response from {url} is not a PEM X.509 certificate", file=sys.stderr)
        return 1

    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    if args.ca_sha256 is not None:
        # Normalize colons/spaces/case; anything else is a mismatch (fail loud).
        pin = "".join(args.ca_sha256.split()).replace(":", "").lower()
        if pin != fingerprint:
            print(
                f"setup incomplete: CA fingerprint mismatch — pin {pin}, fetched {fingerprint}; nothing written",
                file=sys.stderr,
            )
            return 1

    ca_path = client.config.ca_path
    try:
        # Pinned secret-dir idiom (#376 D-3): mode=0o700 at create +
        # ensure_secret_dir for pre-existing dirs — matching every sibling
        # CLI secret-dir site.
        ca_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_secret_dir(ca_path.parent)
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=ca_path.parent, prefix=".venya-ca-", delete=False) as fd:
                tmp_path = fd.name
                fd.write(resp.content)
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
            os.replace(tmp_path, ca_path)
        except BaseException:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise
    except OSError as e:
        print(f"setup incomplete: cannot write {ca_path}: {e}", file=sys.stderr)
        return 1

    print(f"Server URL saved: {core}")
    print(f"CA certificate subject: {cert.subject}")
    print(f"CA certificate SHA-256: {fingerprint}")
    print(f"CA certificate saved to: {ca_path}")
    print(
        "Next: run 'venya init <user-id>' to bootstrap the core (or 'venya login <user-id>' if it is already initialized)."
    )
    return 0


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
    ca_path = config.ca_path
    if ca_path.exists():
        try:
            cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
            print(f"  CA: {ca_path} [SHA-256 {cert.fingerprint(hashes.SHA256()).hex()[:16]}]")
        except (ValueError, OSError):
            print(f"  CA: {ca_path} [unreadable]")
    else:
        print("  CA: [not set]")
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
    fido2 = Fido2Auth(client.config.server_url, ca_path=client.config.ca_path)
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
                            "another way. Venya creates a key's PIN during registration — "
                            "run venya credential add for this key (first enrollment: "
                            "venya enroll <token>) and enter the PIN when prompted, "
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
        _hint = _win_ceremony_hint("credential-add")
        if _hint:
            print(_hint)
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

        fido2 = Fido2Auth(client.config.server_url, ca_path=client.config.ca_path)
        try:
            request_options = fido2._build_registration_options(options)
            credential = fido2._get_credential(request_options, timeout=60.0)
        except Fido2ClientError as e:
            raise APIClientError(f"FIDO2 error: {e}") from e
        cred_response = fido2._format_credential_response(credential)

        # Step 5: Complete registration — with a FRESH elevation token:
        # tokens are single-use (server burns on verify; #6 ruling option (a),
        # sec-auth-elevation-authz-hardening) and the start call consumed the
        # first one. A cancel/timeout inside _elevate raises APIClientError →
        # clean exit via the handler below, no stuck flow; the server-side
        # burn is idempotent (replay of a burned token = clean 401).
        print("Re-authenticating with security key for elevation...")
        elevation_token = _elevate(client)
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
        # Server-truth label (CredentialAddCompleteResponse.credential_label);
        # the local variable is only the documented fallback for a response
        # that omits the field (#482 AC2).
        print(f"  Label: {result.get('credential_label', label)}")
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
        _hint = _win_ceremony_hint("assertion")
        if _hint:
            print(_hint)
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
        fido2 = Fido2Auth(client.config.server_url, ca_path=client.config.ca_path)
        print("Starting enrollment...")
        print("Please insert/touch your security key when prompted.\n")
        _hint = _win_ceremony_hint("registration")
        if _hint:
            print(_hint)
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
        _hint = _win_ceremony_hint("assertion")
        if _hint:
            print(_hint)
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
        print("Error: exec subcommand required (register, cert, heartbeat, audit, status, list)", file=sys.stderr)
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
    elif exec_command == "list":
        return executor_list(client, args)
    else:
        print(f"Unknown exec command: {exec_command}", file=sys.stderr)
        return 1


def executor_list(client: APIClient, args: Any) -> int:
    """List registered executors with their heartbeat-reported build versions.

    Version is the executor dist version the daemon reports on every
    heartbeat (single-sourced from package metadata). NULL renders as
    'unknown (pre-B daemon)' — the explicit "has not reported yet" signal,
    never a blank cell (feature/version-surfaces condition 3). Observability
    only: no version gating anywhere in this path (scope guard). Table mode
    adds a warn-only per-executor line (stderr) when a reported version
    disagrees with the core's (#324) — display only, never a gate.
    """
    try:
        result = client.get("/api/v1/admin/executors")
        executors = result.get("executors", [])

        if not executors:
            print("No executors found.")
            return 0

        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        headers = ["EXECUTOR_ID", "SERIAL", "NOT_AFTER", "VERSION"]
        rows = []
        for e in executors:
            rows.append(
                [
                    e.get("executor_id", ""),
                    (e.get("serial_number") or "")[:16],
                    e.get("not_after") or "-",
                    e.get("version") or "unknown (pre-B daemon)",
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

        # Version-mismatch warning (#324 D3): executor versions already ride
        # this authenticated list (zero server change); compare each against
        # the core's fenced /health version. Warn-only — no behavior gate, and
        # a version we cannot parse (NULL daemon) gets no verdict, never a
        # wrong-side nudge.
        core_ver = get_server_version(client)
        core_vt = version_tuple(core_ver) if core_ver else None
        if core_vt is not None:
            for e in executors:
                exec_ver = e.get("version")
                exec_vt = version_tuple(exec_ver) if exec_ver else None
                if exec_vt is not None and exec_vt != core_vt:
                    print(
                        f"Warning: executor '{e.get('executor_id')}' reports version {exec_ver}, "
                        f"core is {core_ver} — upgrade the out-of-date side (installer re-run); "
                        "mismatched versions are unsupported.",
                        file=sys.stderr,
                    )
        return 0
    except Exception as e:
        print(f"List failed: {e}", file=sys.stderr)
        return 1


# Test seam + single source of truth for the executor host-config path
# (installer writes it; register/URL fallbacks read it).
EXECUTOR_TOML_PATH = "/etc/venya/executor.toml"
EXECUTOR_SERVICE_USER = "venya"


def _executor_service_ids(output_path: Path) -> tuple[int, int] | None:
    """Ownership target for root-context executor-credential self-hardening (#373).

    A root-context ``venya exec register``/``cert renew`` used to leave the
    credential dir (0700) and the key inside it (0600) root-owned; the
    venya-executor service (User=venya) cannot read either and crash-loops
    Errno 13 until the installer's "Executor credentials hardened" block
    (chown -R venya:venya) is applied manually. Root-context writes now
    self-harden at the creation site, following the #317 atomic-create
    precedent (at_rest_key.atomic_write_key chowns the temp before
    os.replace): when this returns (uid, gid), the caller chowns the output
    dir right after the mkdir and each staged temp before it is published.

    Returns None — writes stay as they are, zero behavior change — when:
    - the process is not root (chown would EPERM; daemon hosts provision and
      re-register via sudo, and the installer block owns ownership there);
    - no ``venya`` account exists (workstation/CI hosts have no daemon —
      warn LOUD with the exact chown remedy instead of failing a registration
      that already succeeded);
    - the platform is not POSIX (no POSIX accounts, no ``User=`` service,
      no root — the self-harden path is a no-op; writes stay as they are).
    """
    if os.name != "posix":
        # No POSIX accounts, no systemd `User=` service, no root to be: the
        # self-harden path is a no-op on Windows. Returning None is the
        # documented "writes stay as they are, zero behavior change" branch.
        return None
    if os.geteuid() != 0:
        return None
    import grp
    import pwd

    try:
        return (pwd.getpwnam(EXECUTOR_SERVICE_USER).pw_uid, grp.getgrnam(EXECUTOR_SERVICE_USER).gr_gid)
    except KeyError:
        print(
            f"WARNING: user '{EXECUTOR_SERVICE_USER}' not found — {output_path} stays root-owned. "
            f"If the venya-executor service runs on this machine, hand it over before starting: "
            f"sudo chown -R {EXECUTOR_SERVICE_USER}:{EXECUTOR_SERVICE_USER} {output_path}",
            file=sys.stderr,
        )
        return None


def _chown_secret_temp(fileno: int, service_ids: tuple[int, int] | None) -> None:
    """Chown a staged secret temp to the service account BEFORE it is published
    (#373, closing the create-then-chown window in the #317 shape). Best-effort
    like at_rest_key.atomic_write_key: a failure costs only the service user's
    read of that file — warned loudly, the installer hardening block stays the
    remedy."""
    if service_ids is None:
        return
    try:
        os.fchown(fileno, *service_ids)
    except OSError as e:
        print(f"WARNING: cannot hand a staged temp file to {EXECUTOR_SERVICE_USER}: {e}", file=sys.stderr)


def _resolve_register_verify_cafile(client: APIClient, ca_bundle: str | None) -> str:
    """Trust source for the post-register verify call (#395, lead ruling).

    Build order: config-dir CA (what the plain ``client`` already trusts) if
    present, ELSE the explicit ``--ca-bundle`` (already resolved from the
    flag / executor.toml by the caller), ELSE fail loud. There is deliberately
    no system-store or no-verify fallback: an unverifiable verification is an
    error, never a silent pass (production mandate: propagate trust, never
    weaken validation).
    """
    config_ca = client.config.ca_path
    if config_ca.exists():
        return str(config_ca)
    if ca_bundle:
        return str(ca_bundle)
    raise APIClientError(
        "Cannot verify the registration: no TLS trust material found — no config-dir CA "
        f"({config_ca}) and no --ca-bundle. Re-run with --ca-bundle <venya-ca.crt> "
        "(the register response also saved the CA beside the certificate)."
    )


def _verify_register_auth(client: APIClient, server_url: str, ca_bundle: str | None) -> None:
    """Verify executor auth against the resolved core URL (#387) with the
    register-path TLS trust (#395) — the plain ``client`` trust store is
    config-dir-only, so on a config-less host the verify call could never
    succeed while the CSR POST (which honors --ca-bundle) had just worked."""
    cafile = _resolve_register_verify_cafile(client, ca_bundle)
    headers = {"Accept": "application/json"}
    if client.config.access_token:
        headers["Authorization"] = f"Bearer {client.config.access_token}"
    try:
        with httpx2.Client(verify=_build_ssl_context(cafile=cafile, certfile=None, keyfile=None), timeout=30.0) as http:
            response = http.get(f"{server_url}/api/v1/executors/certs/revocation-list", headers=headers)
            response.raise_for_status()
    except httpx2.HTTPStatusError as e:
        raise APIClientError(f"Server returned {e.response.status_code}") from e
    except httpx2.ConnectError as e:
        raise APIClientError(f"Connection failed: {e}") from e


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

    executor_id = getattr(args, "executor_id", None)
    output_dir = getattr(args, "output_dir", "/etc/venya")
    core_url = getattr(args, "core_url", None)
    # flag > env VENYA_EXECUTOR_ENROLLMENT_TOKEN; empty string counts as unset,
    # matching the installer's ${VAR:-} semantics (ticket
    # cli-exec-register-token-env-unsupported — the env contract every
    # generated instruction names was silently ignored here).
    enrollment_token = (
        getattr(args, "enrollment_token", None) or os.environ.get("VENYA_EXECUTOR_ENROLLMENT_TOKEN") or None
    )
    ca_bundle = getattr(args, "ca_bundle", None)
    if ca_bundle is not None and not isinstance(ca_bundle, str):
        ca_bundle = None

    # Single executor.toml read serving BOTH fallbacks (ticket
    # cli-exec-register-ignores-config-executor-id): resolution is
    # flag → toml → FAIL-LOUD. The former hardcoded 'venya-exec' default
    # silently minted a wrong-identity cert (CSR CN) on hosts whose toml
    # carried the real id; a made-up id on a toml-less machine is the
    # phantom-registration trap, so missing id is a hard error, and a
    # malformed toml fails loudly instead of parse-silently falling through.
    toml_data: dict[str, Any] | None = None
    if executor_id is None or ca_bundle is None:
        executor_config_path = Path(EXECUTOR_TOML_PATH)
        if executor_config_path.exists():
            try:
                import tomllib

                with open(executor_config_path, "rb") as f:
                    toml_data = tomllib.load(f)
            except Exception as e:
                print(f"Error: failed to parse {EXECUTOR_TOML_PATH}: {e}", file=sys.stderr)
                return 1

    if executor_id is None and toml_data is not None:
        executor_id = toml_data.get("executor_id")
    if executor_id is None:
        print(
            f"Error: executor_id required: pass --executor-id or set executor_id in {EXECUTOR_TOML_PATH}",
            file=sys.stderr,
        )
        return 1
    if ca_bundle is None and toml_data is not None:
        ca_bundle = toml_data.get("ca_bundle")

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
            f"Error: server URL required. Pass --server-url (alias: --core-url), set it in config "
            f"({DEFAULT_CONFIG_FILE}), or set VENYA_SERVER_URL",
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
        output_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_secret_dir(output_path)
        # #373: a root-context register hands the dirs to the service account
        # at the creation site (None for non-root or account-less hosts).
        service_ids = _executor_service_ids(output_path)
        if service_ids is not None:
            try:
                os.chown(output_path, *service_ids)
            except OSError as e:
                print(f"WARNING: cannot hand {output_path} to {EXECUTOR_SERVICE_USER}: {e}", file=sys.stderr)
                service_ids = None

        # Save private key
        key_path = output_path / "executor.key"
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_tmp: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=output_path, prefix=".venya-key-", delete=False) as fd:
                key_tmp = fd.name
                fd.write(key_pem)
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
                _chown_secret_temp(fd.fileno(), service_ids)
            os.replace(key_tmp, key_path)
        except BaseException:
            if key_tmp is not None:
                try:
                    os.unlink(key_tmp)
                except OSError:
                    pass
            raise

        # Save signed certificate — atomic create pinned 0644 (#376: certs are
        # public material; pre-fix the mode was umask-inherited — 0600 under a
        # restrictive umask, diverging from the installer/daemon posture).
        cert_path = output_path / "executor.crt"
        cert_tmp: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=output_path, prefix=".venya-cert-", delete=False) as fd:
                cert_tmp = fd.name
                fd.write(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
                fd.flush()
                os.fchmod(fd.fileno(), 0o644)
                _chown_secret_temp(fd.fileno(), service_ids)
            os.replace(cert_tmp, cert_path)
        except BaseException:
            if cert_tmp is not None:
                try:
                    os.unlink(cert_tmp)
                except OSError:
                    pass
            raise

        # Save CA certificate — same pinned 0644 public-material posture (#376).
        ca_cert_path = output_path / "ca.crt"
        if ca_cert_pem:
            ca_tmp: str | None = None
            try:
                with tempfile.NamedTemporaryFile(dir=output_path, prefix=".venya-ca-", delete=False) as fd:
                    ca_tmp = fd.name
                    fd.write(ca_cert_pem.encode() if isinstance(ca_cert_pem, str) else ca_cert_pem)
                    fd.flush()
                    os.fchmod(fd.fileno(), 0o644)
                    _chown_secret_temp(fd.fileno(), service_ids)
                os.replace(ca_tmp, ca_cert_path)
            except BaseException:
                if ca_tmp is not None:
                    try:
                        os.unlink(ca_tmp)
                    except OSError:
                        pass
                raise

        # All three staged temps (key, cert, ca) are handed to the service
        # account BEFORE os.replace — no post-publish chown window (#373).

        print(f"Certificate saved to {cert_path}")
        print(f"Private key saved to {key_path} (permissions: 600)")
        if ca_cert_pem:
            print(f"CA certificate saved to {ca_cert_path}")
    except OSError as e:
        print(f"Failed to save certificate: {e}", file=sys.stderr)
        return 1

    # Step 5: Verify auth with revocation list (#395: the verify client carries
    # the register-path trust — config-dir CA, else --ca-bundle, else loud).
    try:
        print("Verifying authentication...")
        _verify_register_auth(client, server_url, ca_bundle)
        print("Authentication verified.")
    except APIClientError as e:
        print(f"Error: authentication verification failed: {e}", file=sys.stderr)
        # Ruling (ii): fail loud — rc!=0, cert/key/CA kept on disk, wording
        # unambiguous for scripts. An unverified registration is not a success.
        print(
            f"Executor '{executor_id}' registered, auth NOT verified — certificate kept at {cert_path}.",
            file=sys.stderr,
        )
        return 1

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
    """Resolve server URL from args, env, config, or executor.toml.

    Fallback chain (aligned with the run_command chokepoint precedence —
    flag > env > config, ticket cli-core-url-server-url-naming-split /
    cli-server-url-env-ignored fix 3f3ed1b):
    1. --core-url / --server-url arg (dest=core_url)
    2. VENYA_SERVER_URL env (empty = unset)
    3. config.json via Config() (default: ~/.config/venya on Linux,
       ~/Library/Application Support/venya on macOS)
    4. /etc/venya/executor.toml via tomllib
    5. "unknown" as last resort
    """
    if getattr(args, "core_url", None):
        return args.core_url

    env_url = os.environ.get("VENYA_SERVER_URL")
    if env_url:
        return env_url

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
        print(
            "Error: server URL not configured. Pass --server-url (alias: --core-url) or set VENYA_SERVER_URL.",
            file=sys.stderr,
        )
        return 1

    # #506: this POST carries the executor's existing client certificate AND a
    # fresh CSR, so a plaintext scheme would put both on the wire. Refused before
    # any transport object exists (shared guard; the TLS-verify knob below is
    # never a way back into http).
    if not _require_https_server_url(
        server_url,
        site="the executor certificate renewal",
        ticket="executor-renew-no-scheme-check",
        detail="this request carries your client certificate and a new CSR",
    ):
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

    # Atomic write: random-name temp files + os.replace (#352 — the predictable
    # '<cert>.pem.tmp' name let a symlink planted in a co-writable dir hijack
    # the rename target; same pattern as the key path below, #317 second
    # application).
    cert_tmp_name: str | None = None
    ca_tmp_name: str | None = None
    key_tmp_name: str | None = None
    try:
        output_dir = str(Path(cert_path).parent)
        Path(output_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_secret_dir(Path(output_dir))
        # #373: same root-context self-hardening as executor_register — a
        # root renew that leaves the key root-owned crash-loops the daemon.
        service_ids = _executor_service_ids(Path(output_dir))
        if service_ids is not None:
            try:
                os.chown(output_dir, *service_ids)
            except OSError as e:
                print(f"WARNING: cannot hand {output_dir} to {EXECUTOR_SERVICE_USER}: {e}", file=sys.stderr)
                service_ids = None

        # #388: crt/ca are public material — pinned 0644 at this writer too,
        # matching the #376 register posture (keys stay 0600).
        with tempfile.NamedTemporaryFile(dir=output_dir, prefix=".venya-cert-", suffix=".pem", delete=False) as fd:
            cert_tmp_name = fd.name
            fd.write(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
            fd.flush()
            os.fchmod(fd.fileno(), 0o644)
            _chown_secret_temp(fd.fileno(), service_ids)

        key_pem = new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with tempfile.NamedTemporaryFile(dir=Path(key_path).parent, prefix=".venya-key-", delete=False) as fd:
            key_tmp_name = fd.name
            fd.write(key_pem)
            fd.flush()
            os.fchmod(fd.fileno(), 0o600)
            _chown_secret_temp(fd.fileno(), service_ids)
        os.replace(key_tmp_name, key_path)
        key_tmp_name = None

        if ca_cert_pem:
            ca_dir = str(Path(cert_path).parent)
            ca_cert_path = Path(ca_dir) / "ca.crt"  # type: ignore[assignment]
            with tempfile.NamedTemporaryFile(dir=ca_dir, prefix=".venya-ca-", suffix=".pem", delete=False) as fd:
                ca_tmp_name = fd.name
                fd.write(ca_cert_pem.encode() if isinstance(ca_cert_pem, str) else ca_cert_pem)
                fd.flush()
                os.fchmod(fd.fileno(), 0o644)
                _chown_secret_temp(fd.fileno(), service_ids)
            os.replace(ca_tmp_name, str(ca_cert_path))
            ca_tmp_name = None

        os.replace(cert_tmp_name, cert_path)
        cert_tmp_name = None
    except OSError as e:
        # Clean up any staged temp on failure
        for leftover in (cert_tmp_name, ca_tmp_name, key_tmp_name):
            if leftover is not None:
                try:
                    os.unlink(leftover)
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
    serial = getattr(args, "serial", None)
    if serial is not None:
        # Serial form (ticket executor-revocation-by-identity, ruling 1):
        # kill ONE credential (e.g. an orphaned predecessor serial) WITHOUT
        # revoking the executor identity. Incident-response tool.
        try:
            int(serial, 16)
            if not 1 <= len(serial) <= 16:
                raise ValueError("bad length")
        except (ValueError, TypeError):
            print(f"Error: --serial must be hex, 1-16 chars (got {serial!r})", file=sys.stderr)
            return 1

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
        result = client.post(
            f"/api/v1/admin/executors/{executor_id}/revoke",
            json={"serial": serial.casefold()} if serial else None,
        )
        revoked = result.get("revoked", False) if result else False
        if serial:
            print("Certificate serial revoked (identity NOT revoked).")
            print(f"  Executor ID:  {executor_id}")
            print(f"  Serial:       {serial.casefold()}")
        else:
            print("Certificate revoked.")
            print(f"  Executor ID:  {executor_id}")
        if not serial and revoked:
            print("  Identity:     REVOKED (terminal — re-enrollment requires a NEW executor_id)")
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
        print(
            "Error: server URL not configured. Pass --server-url (alias: --core-url) or set VENYA_SERVER_URL.",
            file=sys.stderr,
        )
        return 1

    # Compute SHA-256 fingerprint of the certificate over its DER encoding --
    # matching the server (ca.py compute_fingerprint) and executor (daemon.py)
    # convention. Hashing the PEM bytes produced a value that could never match
    # the admin-listing fingerprint for the same cert.
    try:
        from cryptography.hazmat.primitives import serialization

        cert_pem = Path(cert_path).read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        der = cert.public_bytes(serialization.Encoding.DER)
        fingerprint = hashlib.sha256(der).hexdigest()
    except Exception as e:
        print(f"Failed to compute certificate fingerprint: {e}", file=sys.stderr)
        return 1

    executor_id = info["executor_id"]
    url = f"{server_url}/api/v1/heartbeat"

    # Plaintext http:// is REJECTED (ticket sec-sweep-low-informational #17,
    # user ruling 2026-09-21): this POST carries executor-identifying state,
    # and silently disabling TLS for an http:// URL was the CLI's only
    # non-knob TLS-off path. The sanctioned VENYA_TLS_VERIFY=false knob covers
    # a DISTRUSTED CERT over https — it never means "no TLS".
    if not server_url.startswith("https://"):
        print(
            f"Error: server URL must be https:// — got '{server_url}'. Plaintext http is "
            "not supported for the executor heartbeat (ticket sec-sweep-low-informational #17).",
            file=sys.stderr,
        )
        return 1

    # Build mTLS client
    try:
        ca_cert_path = str(Path(cert_path).parent / "ca.crt")
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_cert_chain(cert_path, key_path)
        if Path(ca_cert_path).exists():
            ssl_ctx.load_verify_locations(ca_cert_path)
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

        # --json: byte-exact passthrough of the API envelope. BEFORE the
        # empty check: an empty log must still emit parseable JSON
        # ({"events": []}) — same ordering as cmd_list / cmd_audit (ticket
        # exec-audit-json-empty-case-unparseable).
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2))
            return 0

        if not events:
            print(f"No audit events found for {executor_id}.")
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
    """Resolve the CA directory path.

    Default MUST match the server's ca_dir default (/var/lib/venya/ca,
    server config.py) and the --ca-dir help text in cli.py — the old
    /etc/venya/ca value existed nowhere in a deployment (ticket
    cli-ca-dir-default-mismatch).
    """
    return getattr(args, "ca_dir", None) or "/var/lib/venya/ca"


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


# --- CA-key backup envelope (ticket fido2-device-layer-sweep-findings
# finding 5, canonical-format ruling 2026-09-21) --------------------------
# Canonical: b"VENYACA1" + PBKDF2 salt(16) + GCM nonce(12) + AES-256-GCM
# ciphertext+tag; KDF = PBKDF2HMAC(SHA256, 32, salt, 600_000). Byte-identical
# to the server ca.py envelope — the CLI has no `core` dependency, so the
# implementations are ALIGNED COPIES pinned by the cross-compat contract
# tests in tests/test_cli_ca_key_format.py (both directions).
# Restore is a DUAL-FORMAT reader: canonical GCM primary + legacy alpha.11
# CBC (salt16 + iv16 + PKCS7 ct) read-only (precedent: the bootstrap-token
# dual-location reader) — no exported key material may be stranded.
_CA_BLOB_MAGIC = b"VENYACA1"
_CA_KDF_ITERATIONS = 600_000


def _derive_ca_backup_key(salt: bytes, passphrase: str) -> bytes:
    """PBKDF2-SHA256 key derivation for CA-key backup envelopes."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_CA_KDF_ITERATIONS)
    return kdf.derive(passphrase.encode())


def _decrypt_ca_backup(data: bytes, passphrase: str) -> bytes:
    """Decrypt a CA-key backup blob (canonical GCM primary, legacy CBC read-only).

    Raises ValueError with an operator-actionable message on any format,
    passphrase, or tamper failure — never returns suspect material. The
    legacy CBC path runs FULL PKCS7 validation (the pre-fix check inspected
    only the last padding byte's RANGE). Padding alone is NOT authenticated,
    though: a wrong passphrase can pass strict PKCS7 by coincidence (~1/256),
    so the reconstructed bytes are additionally content-validated as a parseable
    PEM private key by `_validate_ca_key_pem` at all three custody entry
    sites (#297: export read, split pre-shard, restore reconstruct).
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import ciphers
    from cryptography.hazmat.primitives.ciphers import algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if data.startswith(_CA_BLOB_MAGIC):
        body = data[len(_CA_BLOB_MAGIC) :]
        if len(body) < 16 + 12 + 16:  # salt + nonce + GCM tag minimum
            raise ValueError("backup file too small (canonical GCM envelope)")
        salt, nonce, ciphertext = body[:16], body[16:28], body[28:]
        try:
            return AESGCM(_derive_ca_backup_key(salt, passphrase)).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise ValueError("invalid passphrase or corrupted backup (GCM authentication failed)") from None

    # Legacy alpha.11 CBC envelope: salt(16) + iv(16) + PKCS7-padded ciphertext.
    if len(data) < 16 + 16 + 16:
        raise ValueError("backup file too small")
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    try:
        decryptor = ciphers.Cipher(algorithms.AES(_derive_ca_backup_key(salt, passphrase)), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    except ValueError:
        raise ValueError("invalid passphrase or corrupted backup (CBC)") from None
    pad = padded[-1] if padded else 0
    if pad < 1 or pad > 16 or pad > len(padded) or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid passphrase or corrupted backup (PKCS7 validation failed)")
    return padded[:-pad]


def _validate_ca_key_pem(data: bytes) -> bytes:
    """Fail closed unless `data` parses as a PLAINTEXT PEM private key.

    Compensating control for the unauthenticated legacy CBC reader: a wrong
    passphrase that coincidentally passes PKCS7 (~1/256) would otherwise be
    written to disk as ca.key behind a success banner. Applied at ALL THREE
    custody entry-path sites (#297 ruling Q3): export source read, split
    pre-shard, restore reconstruct — one function, no per-site variants.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        load_pem_private_key(data, password=None)
    except Exception as exc:
        raise ValueError("restored data is not a valid PEM private key") from exc
    return data


def cmd_admin_export_ca_key(args: Any) -> int:
    """Export the CA private key, encrypted with a passphrase.

    Reads the CA private key from disk, encrypts it using the canonical
    VENYACA1 envelope (AES-256-GCM, authenticated — finding-5 ruling), and
    writes the blob to the specified output file.

    The plaintext key is never written to disk or stdout.
    """
    from pathlib import Path

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    ca_dir = _resolve_ca_dir(args)
    ca_key_path = resolve_ca_key_path(ca_dir)
    output_path = Path(args.output)

    if not ca_key_path.exists():
        print(f"Error: CA key not found at {ca_dir}", file=sys.stderr)
        print("Run 'venya init' on the server to generate the CA.", file=sys.stderr)
        return 1

    # Unwrap the at-rest envelope (#297): the file is PKCS#8-encrypted PEM on
    # every install since 4218ec1/3667c6e — the old raw read exported
    # ciphertext-of-ciphertext. Legacy plaintext files pass through; anything
    # that is neither fails LOUD with zero output written.
    raw_at_rest = ca_key_path.read_bytes()
    server_env_var = server_passphrase_env_for(ca_key_path)
    try:
        try:
            plaintext_key = unwrap_at_rest(raw_at_rest)
        except ValueError:
            plaintext_key = unwrap_at_rest(raw_at_rest, acquire_server_passphrase(server_env_var))
        plaintext_key = _validate_ca_key_pem(plaintext_key)  # entry-path validator, site 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Prompt for passphrase (twice for confirmation)
    passphrase1 = None
    while passphrase1 is None:
        passphrase1 = getpass.getpass("Enter passphrase for encrypted key: ")
        passphrase2 = getpass.getpass("Confirm passphrase: ")
        if passphrase1 != passphrase2:
            print("Passphrases do not match. Try again.")
            passphrase1 = None

    if not passphrase1:
        print("Error: passphrase cannot be empty", file=sys.stderr)
        return 1

    # Derive encryption key from passphrase using PBKDF2
    salt = os.urandom(16)
    key = _derive_ca_backup_key(salt, passphrase1)

    # Encrypt with AES-256-GCM — canonical VENYACA1 envelope (finding-5
    # ruling): authenticated encryption, so tampering and wrong passphrases
    # fail LOUDLY at restore. The old CBC envelope validated only the last
    # padding byte and could restore silently-corrupted key material.
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, plaintext_key, None)

    # Write: MAGIC(8) + salt(16) + nonce(12) + ciphertext+tag
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    ensure_secret_dir(output_path.parent)
    blob_tmp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_path.parent, prefix=".venya-cabackup-", delete=False) as fd:
            blob_tmp = fd.name
            fd.write(_CA_BLOB_MAGIC + salt + nonce + encrypted)
            fd.flush()
            os.fchmod(fd.fileno(), 0o600)
        os.replace(blob_tmp, output_path)
    except BaseException:
        if blob_tmp is not None:
            try:
                os.unlink(blob_tmp)
            except OSError:
                pass
        raise

    print(f"CA key encrypted (AES-256-GCM) and exported to {output_path}")
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
    ca_key_path = resolve_ca_key_path(ca_dir)
    output_dir = Path(args.output_dir)

    if not ca_key_path.exists():
        print(f"Error: CA key not found at {ca_dir}", file=sys.stderr)
        print("Run 'venya init' on the server to generate the CA.", file=sys.stderr)
        return 1

    # Unwrap the at-rest envelope BEFORE sharding (#297, Q2): pre-fix this
    # silently split the at-rest ciphertext into plausible-looking shares.
    # A wrong server passphrase or garbage file dies LOUDLY here — zero
    # shards written. Shares then carry the plaintext PEM (the #39 validator
    # semantics applied pre-shard, entry-path site 2 of 3).
    raw_at_rest = ca_key_path.read_bytes()
    server_env_var = server_passphrase_env_for(ca_key_path)
    try:
        try:
            plaintext_key = unwrap_at_rest(raw_at_rest)
        except ValueError:
            plaintext_key = unwrap_at_rest(raw_at_rest, acquire_server_passphrase(server_env_var))
        plaintext_key = _validate_ca_key_pem(plaintext_key)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    threshold = args.threshold
    num_shares = args.shares

    if threshold > num_shares:
        print("Error: threshold cannot exceed number of shares", file=sys.stderr)
        return 1

    shares = split(plaintext_key, threshold=threshold, shares=num_shares)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ensure_secret_dir(output_dir)

    for i, share in enumerate(shares):
        share_id = share[0]
        share_file = output_dir / f"share-{share_id:02d}"
        share_tmp: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=output_dir, prefix=".venya-share-", delete=False) as fd:
                share_tmp = fd.name
                fd.write(share[1:])  # Store data only (ID is embedded)
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
            os.replace(share_tmp, share_file)
        except BaseException:
            if share_tmp is not None:
                try:
                    os.unlink(share_tmp)
                except OSError:
                    pass
            raise
        print(f"  Share {share_id}/{num_shares} written to {share_file}")

    print(f"\n{num_shares} shares created. Any {threshold} are needed to reconstruct.")
    print("Distribute shares to different locations/administrators.")
    print("Keep this directory secure and delete after distribution.")
    return 0


def cmd_admin_restore_ca_key(args: Any) -> int:
    """Restore the CA private key from shares or an encrypted backup.

    Two modes:
    - shares: Reconstruct using Shamir's Secret Sharing from N share files
    - backup: Decrypt from a passphrase-encrypted backup file — DUAL-FORMAT
      reader: canonical VENYACA1 GCM primary + legacy alpha.11 CBC read-only
      with FULL PKCS7 validation (finding-5 ruling; no exported key material
      is stranded)
    """
    from pathlib import Path

    from .shamir import combine

    ca_dir = _resolve_ca_dir(args)
    ca_key_path = resolve_ca_key_path(ca_dir)
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

        if shares and not shares[0][1:].startswith(b"V2"):
            print(
                "warning: pre-V2 share files — threshold and integrity cannot be verified; "
                "after restore, validate ca.key against ca.crt before trusting it",
                file=sys.stderr,
            )

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

        encrypted_data = backup_path.read_bytes()
        passphrase = getpass.getpass("Enter passphrase to decrypt backup: ")
        try:
            reconstructed = _decrypt_ca_backup(encrypted_data, passphrase)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    else:
        print(f"Unknown restore mode: {mode}", file=sys.stderr)
        return 1

    try:
        reconstructed = _validate_ca_key_pem(reconstructed)  # entry-path validator, site 3
        # Re-encrypt into the at-rest envelope before writing (#297): target-
        # format preserving, probe-verified against the current encrypted
        # file (wrong server passphrase -> LOUD, ZERO writes, byte-identity),
        # plaintext never persisted where the envelope is expected.
        at_rest_bytes = restore_at_rest_bytes(ca_key_path, reconstructed)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    atomic_write_key(ca_key_path, at_rest_bytes)

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
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_secret_dir(output_dir)

        # Write key
        key_path = output_dir / "admin-ca.key"
        key_tmp: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=output_dir, prefix=".venya-cakey-", delete=False) as fd:
                key_tmp = fd.name
                fd.write(key_pem)
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
            os.replace(key_tmp, key_path)
        except BaseException:
            if key_tmp is not None:
                try:
                    os.unlink(key_tmp)
                except OSError:
                    pass
            raise

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


# #353 ruling R2 (owner batch-yes 2026-10-02): forgery-charset gate on the
# admin identity before CA signing. CN/SAN interpolate the identity verbatim;
# structural characters — comma, double quote, backslash, equals, and control
# characters incl. CR/LF — would forge X.509 RDN/SAN structure in a cert this
# CA signs. REJECT, don't escape (ruled posture). Everything else is allowed:
# plain hostnames AND the shipped email-form identities (the server identity
# extractor prefers SAN RFC822) are untouched.
_IDENTITY_FORGERY_CHARS = frozenset(',"\\=') | {chr(c) for c in range(0x20)} | {chr(0x7F)}


def _identity_forgery_error(identity: str) -> str | None:
    """Return an actionable error string if the identity carries RDN/SAN
    structural forgery characters (or is empty); None when allowed."""
    if not identity:
        return "Invalid identity: must be a non-empty string"
    bad = sorted({c for c in identity if c in _IDENTITY_FORGERY_CHARS})
    if bad:
        shown = ", ".join(repr(c) for c in bad)
        return (
            f"Invalid identity {identity!r}: contains structural character(s) {shown}. "
            "Comma, double quote, backslash, equals, and control characters can forge "
            "X.509 RDN/SAN structure. Use a plain hostname or an email-style identity."
        )
    return None


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
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    identity = args.identity
    problem = _identity_forgery_error(identity)
    if problem is not None:
        print(f"Error: {problem}", file=sys.stderr)
        return 1
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
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        ensure_secret_dir(output_dir)

        # Write key (unencrypted — operator manages security)
        key_pem = admin_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path = output_dir / "admin.key"
        key_tmp: str | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=output_dir, prefix=".venya-key-", delete=False) as fd:
                key_tmp = fd.name
                fd.write(key_pem)
                fd.flush()
                os.fchmod(fd.fileno(), 0o600)
            os.replace(key_tmp, key_path)
        except BaseException:
            if key_tmp is not None:
                try:
                    os.unlink(key_tmp)
                except OSError:
                    pass
            raise

        # Write cert
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path = output_dir / "admin.crt"
        cert_path.write_bytes(cert_pem)
        cert_path.chmod(0o644)

        # Print details. The serial renders in the ONE canonical form (lowercase
        # hex, zero-padded to 16) that server/core utils `canonical_serial` defines
        # — the value an operator pastes into `revoke-admin-cert`. This package is
        # barred from importing core (tests/test_capability_isolation.py keeps
        # venya-cli standalone), so the format literal is repeated HERE on purpose;
        # keep it byte-identical to core.utils.cert_serial.canonical_serial.
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


def cmd_admin_reissue_recovery_code(client: APIClient, args: Any) -> int:
    """Reissue the caller's own break-glass recovery code (admin role).

    Requires: a logged-in session whose user holds the admin role, the
    admin mTLS cert material, and a fresh WebAuthn elevation assertion —
    strictly more proof than holding the old code (ticket #296 ruling).
    The server returns the new code exactly once; the old one dies at the
    same instant (single live code).
    """
    try:
        elevation_token = _elevate(client)
        result = client.post(
            "/api/v1/admin/recovery-code/reissue",
            json={},
            extra_headers={"X-Elevation-Token": elevation_token},
        )
    except APIClientError as e:
        print(f"Recovery-code reissue failed: {e}", file=sys.stderr)
        return 1

    print("Recovery code re-issued. The previous code is now DEAD.")
    print("This code is shown ONCE — store it securely with your off-site backup set:")
    print(f"  {result['recovery_code']}")
    return 0
