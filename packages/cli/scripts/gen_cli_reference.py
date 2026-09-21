# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Generate docs/cli-reference.md from the live argparse tree.

Single source of truth = `create_parser()`. The document is GENERATED — do
not hand-edit it. Regenerate after any CLI change:

    uv run -p 3.14 --directory packages/cli python scripts/gen_cli_reference.py

Interlock (tests/test_cli_reference_doc.py):
  1. regenerate-in-memory == committed file  -> doc drift is RED;
  2. every EXAMPLES argv parses through create_parser() -> examples can
     never rot into invalid syntax;
  3. every leaf command path has >= 1 example, every EXAMPLES key is a real
     path -> a new subcommand without documentation is RED.

EXAMPLES below is the ONLY hand-written surface. Values are placeholders;
examples are invocations only (no fabricated output text — output samples
are unverifiable claims that rot).
"""

import argparse
import shlex
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC_PATH = REPO_ROOT / "docs" / "cli-reference.md"

# ---------------------------------------------------------------------------
# Hand-written examples, keyed by command path (argv WITHOUT the 'venya'
# prefix). Every entry is parse-validated by the test suite.
# ---------------------------------------------------------------------------

EXAMPLES: dict[tuple[str, ...], list[tuple[list[str], str]]] = {
    ("init",): [
        (["init", "jsmith"], "bootstrap the core; jsmith becomes the first admin"),
        (
            ["init", "jsmith", "--installation-reset"],
            "re-init after wiping users but not roles (avoids uq_roles_name violation)",
        ),
    ],
    ("store",): [
        (["store", "db/password", "--roles", "app"], "value omitted -> read from stdin (hidden prompt on a TTY)"),
        (["store", "db/password", "sekrit", "--roles", "app", "readers"], "value inline, scoped to two roles"),
        (["store", "db/password", "-", "--roles", "app", "-m", "purpose=ci"], "'-' also reads stdin; -m adds metadata"),
    ],
    ("get",): [
        (["get", "db/password"], "masked value (secrets are masked by default)"),
        (["get", "db/password", "--unmask"], "plaintext — requires re-authentication with a security key"),
    ],
    ("list",): [
        (["list"], "all secrets visible to you"),
        (["list", "db/"], "keys under the db/ prefix"),
        (["list", "--purpose", "ci"], "filter by a metadata field"),
    ],
    ("delete",): [
        (["delete", "db/password"], "delete a secret (fails if still referenced by an execution session)"),
    ],
    ("update-metadata",): [
        (
            ["update-metadata", "db/password", "-m", "purpose=ci", "-m", "owner=team-a"],
            "replace metadata key=value pairs",
        ),
    ],
    ("audit",): [
        (["audit", "--days", "7"], "last 7 days of audit events"),
        (["audit", "--key", "db/password", "--json"], "events for one secret, machine-readable"),
        (["audit", "--user", "jsmith", "--limit", "50"], "filter by user, cap results"),
    ],
    ("recovery",): [
        (
            ["recovery", "RECOVERY-CODE", "newadmin"],
            "break-glass: restore admin access with the one-shot recovery code",
        ),
        (["recovery", "RECOVERY-CODE", "newadmin", "--confirm"], "skip the interactive confirmation prompt"),
    ],
    ("run",): [
        (["run", "--", "/usr/bin/true"], "smoke-test an executor round trip"),
        (
            ["run", "--secret", "db/password", "--", "/usr/bin/ssh", "tier1@t1", "systemctl", "status", "apache2"],
            "inject a secret into a sandboxed remote command; the agent never sees the value",
        ),
        (["run", "--executor-id", "venya-exec-1", "--", "/bin/echo", "hello"], "target a specific executor"),
    ],
    ("enroll",): [
        (["enroll", "TOKEN"], "enroll with an enrollment token; binds your security key"),
        (["enroll", "TOKEN", "--label", "yubikey-office"], "label the new credential"),
    ],
    ("login",): [
        (["login", "jsmith"], "authenticate with your security key; stores a session token"),
        (["login", "jsmith", "--json"], "machine-readable result"),
    ],
    ("admin", "enroll"): [
        (["admin", "enroll", "jsmith"], "issue an enrollment token for a new user (security-key mode)"),
        (
            ["admin", "enroll", "jsmith", "--mode", "platform"],
            "enroll for a platform authenticator (e.g. Windows Hello)",
        ),
    ],
    ("admin", "remove"): [
        (["admin", "remove", "jsmith"], "remove a user"),
    ],
    ("admin", "configure-user"): [
        (["admin", "configure-user", "jsmith", "--timeout", "1800"], "session timeout in seconds"),
        (["admin", "configure-user", "jsmith", "--mode", "platform"], "switch the user's auth mode"),
    ],
    ("admin", "list"): [
        (["admin", "list"], "all registered users"),
        (["admin", "list", "--json"], "machine-readable"),
    ],
    ("admin", "create-user"): [
        (
            ["admin", "create-user", "jsmith", "--display-name", "Jane Smith", "--roles", "app,devs"],
            "create a user, assign roles, and issue an enrollment token",
        ),
        (["admin", "create-user", "jsmith", "--json"], "machine-readable (token included)"),
    ],
    ("admin", "set-command-policy"): [
        (["admin", "set-command-policy", "strict"], "allowlist-only execution policy"),
        (["admin", "set-command-policy", "balanced"], "default middle tier"),
        (["admin", "set-command-policy", "permissive", "--custom", "policy.toml"], "custom policy file"),
    ],
    ("admin", "get-command-policy"): [
        (["admin", "get-command-policy"], "show the active executor command policy"),
    ],
    ("admin", "add-allowed-command"): [
        (["admin", "add-allowed-command", "/usr/sbin/apache2ctl"], "add a binary to the strict allowlist"),
    ],
    ("admin", "key-version", "list"): [
        (["admin", "key-version", "list", "--json"], "all key-encryption-key versions and their states"),
    ],
    ("admin", "key-version", "deactivate"): [
        (
            ["admin", "key-version", "deactivate", "3"],
            "deactivate a version (existing secrets stay decryptable until re-encrypted)",
        ),
    ],
    ("admin", "key-version", "revoke"): [
        (["admin", "key-version", "revoke", "3"], "revoke a key version by ID (compromise path; irreversible)"),
    ],
    ("admin", "key-version", "rotate-status"): [
        (["admin", "key-version", "rotate-status"], "progress of the running rotation job"),
    ],
    ("admin", "key-version", "rollback"): [
        (["admin", "key-version", "rollback", "JOB_ID"], "roll back a failed rotation job by ID"),
    ],
    ("admin", "rotate-key"): [
        (["admin", "rotate-key"], "rotate the key-encryption key (server generates the new KEK)"),
        (["admin", "rotate-key", "--new-key", "/secure/kek.bin"], "rotate to a specific KEK file"),
    ],
    ("admin", "revoke-executor"): [
        (
            ["admin", "revoke-executor", "venya-exec-1"],
            "revoke an executor certificate; the server then refuses to relay to it",
        ),
    ],
    ("admin", "executor-enroll"): [
        (["admin", "executor-enroll", "venya-exec-1"], "print a bootstrap enrollment token for an executor"),
        (
            ["admin", "executor-enroll", "venya-exec-1", "--output-dir", "/secure/enroll"],
            "write token + CA certs to a directory for transfer",
        ),
    ],
    ("admin", "list-tokens"): [
        (["admin", "list-tokens", "jsmith"], "all enrollment tokens for a user"),
    ],
    ("admin", "issue-token"): [
        (["admin", "issue-token", "jsmith"], "revoke old tokens and issue a fresh one"),
    ],
    ("admin", "revoke-token"): [
        (["admin", "revoke-token", "TOKEN_ID"], "revoke a single enrollment token"),
    ],
    ("admin", "re-enroll"): [
        (
            ["admin", "re-enroll", "jsmith"],
            "deactivate a user's credentials and issue a new enrollment token (lost-key path)",
        ),
    ],
    ("admin", "export-ca-cert"): [
        (["admin", "export-ca-cert"], "CA certificate to stdout (distribute to executors)"),
        (["admin", "export-ca-cert", "-o", "/secure/venya-ca.crt"], "write to a file"),
    ],
    ("admin", "export-ca-key"): [
        (
            ["admin", "export-ca-key", "-o", "/secure/admin-ca.key.enc"],
            "export the CA key, encrypted with the CA passphrase",
        ),
    ],
    ("admin", "split-ca-key"): [
        (
            ["admin", "split-ca-key", "-t", "2", "-s", "3", "-d", "/secure/shares"],
            "Shamir split: any 2 of 3 shares reconstruct the key",
        ),
    ],
    ("admin", "restore-ca-key"): [
        (
            ["admin", "restore-ca-key", "--mode", "shares", "--shares", "share-1", "share-2"],
            "reconstruct from SSS shares",
        ),
        (
            ["admin", "restore-ca-key", "--mode", "backup", "--backup-file", "/secure/admin-ca.key.enc"],
            "restore from the encrypted backup",
        ),
    ],
    ("admin", "init-admin-ca"): [
        (["admin", "init-admin-ca", "--output-dir", "/var/lib/venya/ca/admin-ca"], "create the admin CA key/cert pair"),
    ],
    ("admin", "generate-admin-cert"): [
        (
            ["admin", "generate-admin-cert", "admin1", "--output-dir", "/etc/venya/admin"],
            "sign an admin client certificate (identity = CN + SAN DNS name)",
        ),
    ],
    ("admin", "revoke-admin-cert"): [
        (["admin", "revoke-admin-cert", "--serial", "1A2B3C"], "revoke by hex serial; mTLS bundle then rejects it"),
    ],
    ("role", "create"): [
        (["role", "create", "app"], "read-only role (default tier)"),
        (
            ["role", "create", "app", "--permissions", "read-write", "--description", "App secrets"],
            "read-write tier with a description",
        ),
    ],
    ("role", "list"): [
        (["role", "list"], "all roles"),
    ],
    ("role", "get"): [
        (["role", "get", "app"], "role details by name or ID"),
    ],
    ("role", "delete"): [
        (["role", "delete", "app"], "delete a role"),
    ],
    ("role", "members"): [
        (["role", "members", "app"], "users and executors in the role"),
    ],
    ("role", "add-member"): [
        (["role", "add-member", "app", "jsmith"], "grant a user the role"),
    ],
    ("role", "remove-member"): [
        (["role", "remove-member", "app", "jsmith"], "revoke the role from a user"),
    ],
    ("exec", "register"): [
        (["exec", "register"], "register this machine as an executor (mTLS cert from config)"),
        (
            [
                "exec",
                "register",
                "--executor-id",
                "venya-exec-1",
                "--enrollment-token",
                "TOKEN",
                "--core-url",
                "https://venya-core-1",
            ],
            "bootstrap registration with an enrollment token from admin executor-enroll",
        ),
    ],
    ("exec", "cert", "status"): [
        (["exec", "cert", "status"], "expiry status of the local executor certificate"),
        (["exec", "cert", "status", "--cert-path", "/etc/venya/executor/executor.crt"], "explicit cert path"),
    ],
    ("exec", "cert", "renew"): [
        (["exec", "cert", "renew"], "renew the executor certificate before expiry"),
    ],
    ("exec", "cert", "revoke"): [
        (["exec", "cert", "revoke"], "revoke own cert (ID read from the local cert file)"),
        (["exec", "cert", "revoke", "--executor-id", "venya-exec-1"], "admin action against another executor"),
    ],
    ("exec", "heartbeat"): [
        (["exec", "heartbeat"], "one heartbeat to the core (the daemon sends these automatically)"),
    ],
    ("exec", "audit"): [
        (["exec", "audit"], "audit trail for this executor (ID from the local cert)"),
        (["exec", "audit", "venya-exec-1", "--days", "7", "--json"], "another executor, last 7 days, machine-readable"),
    ],
    ("exec", "status"): [
        (["exec", "status"], "registration status of this executor"),
    ],
    ("exec", "list"): [
        (
            ["exec", "list"],
            "registered executors with heartbeat-reported versions (NULL renders 'unknown (pre-B daemon)')",
        ),
        (["exec", "list", "--json"], "same listing as raw JSON"),
    ],
    ("config", "show"): [
        (["config", "show"], "current CLI config (server URL, stored token state)"),
    ],
    ("config", "set-server"): [
        (["config", "set-server", "https://venya-core-1"], "point the CLI at a core server"),
    ],
    ("config", "clear-token"): [
        (["config", "clear-token"], "drop the stored access token (forces re-auth on next call)"),
    ],
    ("credential", "list"): [
        (["credential", "list"], "your registered security-key credentials"),
    ],
    ("credential", "add"): [
        (["credential", "add", "yubikey-office"], "register an additional security key (touch required)"),
    ],
    ("credential", "remove"): [
        (["credential", "remove", "3"], "remove a credential by ID (touch required)"),
    ],
}

# ---------------------------------------------------------------------------
# Parser walk (same pattern as tests/test_cli_arg_surface.py)
# ---------------------------------------------------------------------------


def walk_parsers() -> list[tuple[tuple[str, ...], argparse.ArgumentParser]]:
    out: list[tuple[tuple[str, ...], argparse.ArgumentParser]] = []

    def _walk(parser: argparse.ArgumentParser, path: tuple[str, ...]) -> None:
        out.append((path, parser))
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    _walk(sub, path + (name,))

    sys.path.insert(0, str(REPO_ROOT / "packages" / "cli" / "src"))
    from venya_cli.cli import create_parser

    _walk(create_parser(), ())
    return out


PARSERS = walk_parsers()
PARSER_BY_PATH = dict(PARSERS)


def command_help(path: tuple[str, ...]) -> str:
    """One-line help as registered on the parent via add_parser(help=...)."""
    if not path:
        return PARSER_BY_PATH[()].description or ""
    parent = PARSER_BY_PATH[path[:-1]]
    for a in parent._actions:
        if isinstance(a, argparse._SubParsersAction):
            for pseudo in a._choices_actions:
                if pseudo.dest == path[-1]:
                    return pseudo.help or ""
    return ""


def arg_actions(parser: argparse.ArgumentParser) -> list[argparse.Action]:
    return [a for a in parser._actions if a.dest != "help" and not isinstance(a, argparse._SubParsersAction)]


def is_dispatcher(parser: argparse.ArgumentParser) -> bool:
    return any(isinstance(a, argparse._SubParsersAction) for a in parser._actions)


def subcommand_choices(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            return dict(a.choices)
    return {}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _synopsis(path: tuple[str, ...], parser: argparse.ArgumentParser) -> str:
    parts = ["venya", *path]
    has_optional = False
    for a in arg_actions(parser):
        if a.help == argparse.SUPPRESS:
            continue  # hidden args never appear in the synopsis
        if a.nargs == argparse.REMAINDER:
            parts.append("[-- <command> ...]")
            continue
        if not a.option_strings:
            name = a.metavar or a.dest.upper()
            if a.choices:
                name = "{" + "|".join(str(c) for c in a.choices) + "}"
            if a.nargs == "?":
                parts.append(f"[{name}]")
                has_optional = True
            elif a.nargs == "+":
                parts.append(f"{name} [{name} ...]")
            else:
                parts.append(f"<{name}>" if not a.choices else name)
        elif a.required:
            flag = a.option_strings[0]
            if isinstance(a, argparse._StoreTrueAction):
                parts.append(flag)
            else:
                val = "{" + "|".join(str(c) for c in a.choices) + "}" if a.choices else (a.metavar or a.dest.upper())
                parts.append(f"{flag} {val}")
        else:
            has_optional = True
    if has_optional:
        parts.append("[OPTIONS]")
    return " ".join(parts)


def _fmt_default(a: argparse.Action) -> str:
    if isinstance(a, argparse._StoreTrueAction):
        return "false (flag)"
    if a.default is None:
        return "—"
    return f"`{a.default!r}`" if not isinstance(a.default, str) else f"`{a.default}`"


def _fmt_type(a: argparse.Action) -> str:
    bits = []
    if isinstance(a, argparse._StoreTrueAction):
        bits.append("flag")
    elif a.type is int:
        bits.append("int")
    if a.choices:
        bits.append("one of: " + ", ".join(f"`{c}`" for c in a.choices))
    if a.nargs == "+":
        bits.append("repeatable/space-separated list")
    if isinstance(a, argparse._AppendAction):
        bits.append("repeatable (accumulates)")
    if a.nargs == argparse.REMAINDER:
        bits.append("remainder (see note)")
    return "; ".join(bits) or "string"


def _arg_table(parser: argparse.ArgumentParser) -> list[str]:
    visible = [a for a in arg_actions(parser) if a.help != argparse.SUPPRESS]
    if not visible:
        return []
    lines = [
        "| Argument | Required | Type / choices | Default | Description |",
        "|----------|----------|----------------|---------|-------------|",
    ]
    for a in visible:
        if a.option_strings:
            name = ", ".join(f"`{o}`" for o in a.option_strings)
            req = "**yes**" if a.required else "no"
        else:
            if a.nargs is None:
                shape = " (positional)"
            elif a.nargs == argparse.REMAINDER:
                shape = " (positional, remainder)"
            else:
                shape = f" (positional, nargs={a.nargs})"
            name = f"`{a.metavar or a.dest.upper()}`" + shape
            req = "no" if a.nargs in ("?", "*") or a.nargs == argparse.REMAINDER else "**yes**"
        help_text = (a.help or "").replace("|", "\\|") or "—"
        lines.append(f"| {name} | {req} | {_fmt_type(a)} | {_fmt_default(a)} | {help_text} |")
    return lines


def _hidden_args(parser: argparse.ArgumentParser) -> list[str]:
    hidden = [a for a in arg_actions(parser) if a.help == argparse.SUPPRESS]
    if not hidden:
        return []
    lines = ["", "*Hidden / deprecated (accepted but not shown in `--help`):*", ""]
    for a in hidden:
        lines.append(
            f"- `{', '.join(a.option_strings)}` — deprecated no-op, accepted for compatibility (prints a warning). Hidden via `argparse.SUPPRESS`."
        )
    return lines


_RUN_NOTE = """> **REMAINDER semantics (`run` only):** everything after the first command token belongs to
> the remote command — including tokens that look like venya flags (`venya run ssh -o ...` sends
> `-o` to ssh, not to venya). A leading `--` separator is accepted and stripped before sending
> (`venya run -- /usr/bin/true`). Venya's own options (`--secret`, `--executor-id`,
> `--server-url`) must come BEFORE the command."""


def _examples(path: tuple[str, ...]) -> list[str]:
    entries = EXAMPLES.get(path, [])
    if not entries:
        return []
    lines = ["", "**Examples**", "", "```bash"]
    for argv, comment in entries:
        line = "venya " + shlex.join(argv)
        lines.append(f"{line}  # {comment}" if comment else line)
    lines.append("```")
    return lines


def _render_parser(path: tuple[str, ...], parser: argparse.ArgumentParser, out: list[str]) -> None:
    if not path:
        return  # top level rendered by generate() preamble
    depth = len(path)
    out.append("")
    out.append(f"{'#' * (depth + 1)} `venya {' '.join(path)}`")
    out.append("")
    help_text = command_help(path)
    if help_text:
        out.append(help_text)
        out.append("")
    out.append("```")
    out.append(_synopsis(path, parser))
    out.append("```")
    out.append("")
    if is_dispatcher(parser):
        out.append("Subcommands:")
        out.append("")
        for name in subcommand_choices(parser):
            child = (*path, name)
            out.append(f"- [`venya {' '.join(child)}`](#venya-{'-'.join(child)}) — {command_help(child)}")
        out.append("")
    table = _arg_table(parser)
    if table:
        out.extend(table)
        out.append("")
    elif not is_dispatcher(parser):
        out.append("*Takes no arguments.*")
        out.append("")
    out.extend(_hidden_args(parser))
    if any(a.nargs == argparse.REMAINDER for a in arg_actions(parser)):
        out.append("")
        out.append(_RUN_NOTE)
    out.extend(_examples(path))


def generate() -> str:
    parsers = PARSERS
    out: list[str] = []
    out.append("# Venya CLI Reference")
    out.append("")
    out.append(
        "<!-- GENERATED FILE — DO NOT HAND-EDIT.\n"
        "     Source of truth: packages/cli/src/venya_cli/cli.py create_parser().\n"
        "     Regenerate: uv run -p 3.14 --directory packages/cli python scripts/gen_cli_reference.py\n"
        "     Enforced by packages/cli/tests/test_cli_reference_doc.py (drift = RED,\n"
        "     every example argv is parse-validated, every leaf command has >=1 example). -->"
    )
    out.append("")
    out.append(
        "Complete reference for the `venya` workstation CLI. Every command, argument, default, and\n"
        "constraint below is generated from the live argument parser — it cannot disagree with the\n"
        "shipped binary. Examples use placeholder values and are parse-validated by the test suite."
    )
    out.append("")
    out.append("**Global options** (before the command): `-v` / `--verbose` (tracebacks on error), `-h` / `--help`.")
    out.append("")
    out.append(
        "**Exit codes:** `0` success · `1` runtime/command error (details also tee'd to `venya.log` in the\n"
        "config dir) · `2` argparse usage error (bad/missing arguments). No command given prints help\n"
        "and exits `1`."
    )
    out.append("")
    out.append("**Config:** `venya config show|set-server|clear-token` manage the per-user config file")
    out.append(
        "(server URL, access token) under `~/.config/venya` (Linux), `~/Library/Application Support/venya` (macOS), `%APPDATA%\\venya` (Windows)."
    )
    out.append("")
    out.append("## Contents")
    out.append("")
    for path, parser in parsers:
        if not path:
            continue
        indent = "  " * (len(path) - 1)
        anchor = "#venya-" + "-".join(path)
        kind = ""
        if is_dispatcher(parser):
            kind = " *(group)*"
        out.append(f"{indent}- [`venya {' '.join(path)}`]({anchor}){kind}")
    out.append("")
    out.append("---")
    for path, parser in parsers:
        _render_parser(path, parser, out)
    text = "\n".join(out).rstrip("\n") + "\n"
    # collapse accidental triple blank lines
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text


def main() -> None:
    DOC_PATH.write_text(generate(), encoding="utf-8")
    print(f"wrote {DOC_PATH}")


if __name__ == "__main__":
    main()
