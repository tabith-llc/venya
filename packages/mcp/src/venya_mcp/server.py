# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""MCP server — tool definitions and stdio transport.

Runs as a subprocess of the LLM client (Claude Code, Cursor, etc.).
Communicates over stdin/stdout using the MCP protocol.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

from mcp.server import Server
from mcp.server.session import ServerSession
from mcp.server.stdio import stdio_server
from mcp.types import ProgressToken, TextContent, Tool

from .client import SessionExpiredError, VenyaAPIError, VenyaClient, _bootstrap_tls_verify
from .config import MCPConfig

logger = logging.getLogger("venya.mcp.server")

app = Server("venya")
_client: VenyaClient | None = None

# Emission cadence for run_command progress notifications (#710 option (a)). This is a TICK
# INTERVAL, not a fuse: it bounds nothing. No timeout in this stack moves here — the chain that
# does bound a run is named in client.py's own comment (relay < nginx proxy_read_timeout <
# _EXECUTE_TIMEOUT_SECONDS) and is unchanged, as is the MCP host's per-request deadline, which
# is the only fuse a progress notification can re-arm (leg 637 §1: the client-side one, not the
# server-to-core httpx one).
_PROGRESS_TICK_SECONDS = 5.0

# The whole payload is this constant plus a tick counter. Stage and liveness only: no command
# text, no argv, no output fragment, no secret key, no path, no executor id (#710 AC, owner
# ruling R-2632). A shape that is identical for every call cannot disclose anything about a call.
_PROGRESS_STAGE = "running"


def _progress_target() -> tuple[ServerSession, ProgressToken] | None:
    """Return ``(session, progress_token)`` if this request asked for progress, else ``None``.

    Progress is opt-in per request (`_meta.progressToken`), so a caller that did not ask is
    served exactly as before and nothing is emitted. Outside a request context — the handler
    called directly, as the unit suite does — ``request_context`` raises LookupError and there
    is nobody to notify.
    """
    try:
        ctx = app.request_context
    except LookupError:
        return None
    meta = ctx.meta
    token = meta.progressToken if meta is not None else None
    if token is None:
        return None
    return ctx.session, token


async def _await_with_ticks(awaitable, *, stage: str = _PROGRESS_STAGE):
    """Await ``awaitable``, ticking a liveness notification beside it until it completes.

    ``client.run_command`` awaits one HTTP request that does not return until the command is
    done, so there is no gap inside which to tick: the emitter has to be concurrent with the
    await (#710 leg 637 §4). The tick is advisory — a notification that cannot be delivered
    (a caller already gone) is dropped with a log line and never replaces the answer, which is
    still whatever the awaited call returned, unchanged.
    """
    target = _progress_target()
    if target is None:
        return await awaitable

    session, token = target
    task = asyncio.ensure_future(awaitable)
    ticks = 0
    try:
        while True:
            # `timeout=` here is asyncio.wait's own kwarg carrying the tick interval. It is not
            # a deadline on the command: the task is never cancelled by it, only by the caller.
            done, _ = await asyncio.wait({task}, timeout=_PROGRESS_TICK_SECONDS)
            if done:
                break
            ticks += 1
            try:
                await session.send_progress_notification(progress_token=token, progress=float(ticks), message=stage)
            except Exception:
                logger.debug("progress tick %d undelivered; serving the answer anyway", ticks)
    finally:
        # Reachable only when the caller itself was cancelled (a host that gave up mid-run):
        # the command task then goes the way its caller already went, exactly as it did when
        # the handler awaited it directly.
        if not task.done():
            task.cancel()
    return task.result()


def get_client() -> VenyaClient:
    if _client is None:
        raise RuntimeError("Venya client not initialized")
    return _client


def build_client(config: MCPConfig) -> VenyaClient:
    """VenyaClient with the startup TLS trust decision (VENYA_CA_CERT) applied."""
    return VenyaClient(config, verify=_bootstrap_tls_verify())


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Return the tools Venya exposes to LLM clients."""

    return [
        Tool(
            name="list_secrets",
            description=(
                "List secrets stored in Venya. Returns secret keys and metadata "
                "(id, executor, purpose, username, and — when stored — shape and "
                "usage) — NEVER secret values. Use this to discover which secrets "
                "are available for a given executor or purpose. Filter by executor "
                "to find secrets for a specific host. When a secret carries a "
                "'usage' entry, it is the command template for that secret with "
                "{secret_path} and {secret_id} ALREADY RESOLVED to the injected "
                "sandbox file (/run/secrets/venya/<id>) — follow it as written; "
                "fill any {host}/{user} placeholders from your task and the "
                "secret's metadata. Never inline a secret value."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "executor": {
                        "type": "string",
                        "description": "Filter by executor ID (e.g., 'web-server-3')",
                    },
                    "purpose": {
                        "type": "string",
                        "description": "Filter by purpose (e.g., 'ssh_login', 'api_key')",
                    },
                    "username": {
                        "type": "string",
                        "description": "Filter by associated username",
                    },
                },
                "additionalProperties": False,
            },
        ),
        Tool(
            name="list_executors",
            description=(
                "List all registered executors and their online status. "
                "Use this to discover which hosts are available as execution "
                "targets. An executor must be online to run commands on it."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        ),
        Tool(
            name="run_command",
            description=(
                "Execute a command on a remote executor with automatic secret "
                "injection. Secrets are injected into the executor's sandbox — "
                "the command can access them, but secret values are NEVER returned "
                "in the output. Output containing secret values is automatically "
                "redacted with [REDACTED:<id>] markers.\n\n"
                "Each injected secret is a FILE at /run/secrets/venya/<id> inside "
                "the sandbox — reference it by path, never inline a value. If the "
                "secret's metadata carries a 'usage' template, follow it.\n\n"
                "IMPORTANT: The command runs in a sandbox with restricted network "
                "egress. Attempts to exfiltrate secrets via network connections "
                "will be blocked.\n\n"
                "Example: SSH into web-server-3 as 'bot' using its stored password "
                "(secret id 7) and install apache2:\n"
                "  command: 'sshpass -f /run/secrets/venya/7 ssh bot@web-server-3 "
                "sudo apt install -y apache2'\n"
                "  secret_keys: ['bot_password_web_server_3']"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "executor_id": {
                        "type": "string",
                        "description": "Target executor ID (e.g., 'web-server-3')",
                    },
                    "command": {
                        "type": "string",
                        "description": (
                            "Command to execute on the remote host "
                            "(tokens run directly — no shell; shell "
                            "metacharacters are rejected)"
                        ),
                    },
                    "secret_keys": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 32,
                        "description": (
                            "Secret keys to inject into the sandbox. "
                            "Use list_secrets to discover available keys. "
                            "Only request the secrets the command actually needs."
                        ),
                    },
                },
                "required": ["executor_id", "command", "secret_keys"],
                "additionalProperties": False,
            },
        ),
        Tool(
            name="get_audit",
            description=(
                "Query the Venya audit log. Shows what commands have been executed, "
                "by whom, when, and what secrets were used. Use this to review "
                "recent activity or investigate a specific event. Callers with "
                "admin or an auditor-tier role see the full log; other "
                "read-write callers see only their own events; plain-read "
                "callers are denied (403)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "Look back this many hours (default: 1)",
                        "default": 1,
                        "minimum": 0,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max records to return (default: 50)",
                        "default": 50,
                    },
                    "event_type": {
                        "type": "string",
                        "description": "Filter by event type (e.g., 'command_executed')",
                    },
                    "executor_id": {
                        "type": "string",
                        "description": "Filter by executor ID",
                    },
                },
                "additionalProperties": False,
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool invocations from the LLM client.

    All responses are human-readable text (not JSON) — LLM clients
    render tool output as text.
    """

    client = get_client()

    try:
        if name == "list_secrets":
            secrets = await client.list_secrets(
                executor=arguments.get("executor"),
                purpose=arguments.get("purpose"),
                username=arguments.get("username"),
            )
            if not secrets:
                return [TextContent(type="text", text="No secrets found matching the criteria.")]
            lines = ["Available secrets (values not shown):"]
            for s in secrets:
                meta = s.get("metadata", {})
                secret_id = s.get("id")
                parts = [f"  - key: {s['key']}"]
                if secret_id is not None:
                    parts.append(f"id: {secret_id}")
                parts.append(f"executor: {meta.get('executor', 'N/A')}")
                parts.append(f"purpose: {meta.get('purpose', 'N/A')}")
                parts.append(f"username: {meta.get('username', 'N/A')}")
                # host renders only when stored (no N/A noise): it is the
                # target of the usage template's {host} placeholder, so the
                # agent can complete the command from the listing alone.
                host = meta.get("host")
                if isinstance(host, str) and host:
                    parts.append(f"host: {host}")
                shape = meta.get("shape")
                if isinstance(shape, str) and shape:
                    parts.append(f"shape: {shape}")
                usage = meta.get("usage")
                if isinstance(usage, str) and usage:
                    if secret_id is not None:
                        # Owner ruling a2 (ticket mcp-list-secrets-id-usage-not-rendered):
                        # resolve the id-derived placeholders HERE so agents receive a
                        # ready-to-run template instead of performing string surgery.
                        # {host}/{user} are task-context placeholders and stay as
                        # authored. Values can never appear: usage write-time
                        # validation rejects value interpolation (routes/secrets.py).
                        usage = usage.replace("{secret_path}", f"/run/secrets/venya/{secret_id}")
                        usage = usage.replace("{secret_id}", str(secret_id))
                    parts.append(f"usage: {usage}")
                lines.append("  ".join(parts))
            return [TextContent(type="text", text="\n".join(lines))]

        elif name == "list_executors":
            result = await client.list_executors()
            executors = result.get("executors", [])
            if not executors:
                return [TextContent(type="text", text="No executors registered.")]
            lines = ["Registered executors:"]
            for e in executors:
                status = "ONLINE" if e["online"] else "OFFLINE"
                lines.append(f"  - {e['id']} [{status}] " f"(last heartbeat: {e.get('last_heartbeat', 'never')})")
            return [TextContent(type="text", text="\n".join(lines))]

        elif name == "run_command":
            executor_id = arguments["executor_id"]
            result = await _await_with_ticks(
                client.run_command(
                    executor_id=executor_id,
                    command=arguments["command"],
                    secret_keys=arguments["secret_keys"],
                )
            )
            exit_code = result.get("exit_code", -1)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            masked_count = result.get("masked_count", 0)

            # The answer names the executor it ran on, echoed from the caller's own
            # argument — never inferred from the command text (#712 AC5). Without it a
            # sandbox answer and a production answer read identically (#712).
            lines = [f"Command exited with code {exit_code}. (executor={executor_id})"]
            if stdout:
                lines.append(f"\nstdout:\n{stdout}")
            if stderr:
                lines.append(f"\nstderr:\n{stderr}")
            if masked_count > 0:
                lines.append(f"\n({masked_count} secret(s) masked in output)")
            return [TextContent(type="text", text="\n".join(lines))]

        elif name == "get_audit":
            records = await client.get_audit(
                hours=arguments.get("hours", 1),
                limit=arguments.get("limit", 50),
                event_type=arguments.get("event_type"),
                executor_id=arguments.get("executor_id"),
            )
            if not records:
                return [TextContent(type="text", text="No audit records found.")]
            lines = ["Recent audit records:"]
            for r in records:
                fields = r.get("fields", {})
                lines.append(
                    f"  [{r.get('timestamp', 'N/A')}] "
                    f"{r.get('event_type', 'N/A')} "
                    f"user={r.get('user_id', 'N/A')} "
                    f"executor={fields.get('executor_id', 'N/A')}"
                )
            return [TextContent(type="text", text="\n".join(lines))]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except (SessionExpiredError, VenyaAPIError):
        # Propagate: the low-level Server converts handler exceptions into
        # isError=True results. Returning error text would look like success.
        raise
    except Exception as e:
        logger.exception("Unexpected error in tool %s", name)
        raise RuntimeError(f"Unexpected error in tool {name}: {e}") from e


async def main() -> None:
    global _client

    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,  # MCP uses stdio for protocol; logs go to stderr
    )

    config = MCPConfig()
    _client = build_client(config)

    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())
    finally:
        await _client.close()


def run() -> None:
    """Sync console-script entry point — async main() must be awaited.

    Startup-precondition failures (missing or malformed config, missing CA
    trust anchor) exit 1 with the actionable message on stderr instead of a
    raw traceback (tickets mcp-missing-config-traceback-ux,
    mcp-ca-missing-traceback-ux #41). The TLS refusal itself is unchanged —
    this only renders the message cleanly.
    """
    try:
        asyncio.run(main())
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Venya config is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run()
