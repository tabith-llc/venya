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
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .client import SessionExpiredError, VenyaAPIError, VenyaClient, _bootstrap_tls_verify
from .config import MCPConfig

logger = logging.getLogger("venya.mcp.server")

app = Server("venya")
_client: VenyaClient | None = None


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
                "(executor, purpose, username) — NEVER secret values. "
                "Use this to discover which secrets are available for a given "
                "executor or purpose. Filter by executor to find secrets for a "
                "specific host."
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
                "IMPORTANT: The command runs in a sandbox with restricted network "
                "egress. Attempts to exfiltrate secrets via network connections "
                "will be blocked.\n\n"
                "Example: To SSH into web-server-3 as user 'bot' and install apache2:\n"
                "  command: 'ssh bot@web-server-3 sudo apt install -y apache2'\n"
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
                        "description": "Shell command to execute on the remote host",
                    },
                    "secret_keys": {
                        "type": "array",
                        "items": {"type": "string"},
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
                "recent activity or investigate a specific event. Non-admin users "
                "see only their own events."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "Look back this many hours (default: 1)",
                        "default": 1,
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
                lines.append(
                    f"  - key: {s['key']}"
                    f"  executor: {meta.get('executor', 'N/A')}"
                    f"  purpose: {meta.get('purpose', 'N/A')}"
                    f"  username: {meta.get('username', 'N/A')}"
                )
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
            result = await client.run_command(
                executor_id=arguments["executor_id"],
                command=arguments["command"],
                secret_keys=arguments["secret_keys"],
            )
            exit_code = result.get("exit_code", -1)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            masked_count = result.get("masked_count", 0)

            lines = [f"Command exited with code {exit_code}."]
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

    Startup-precondition failures (missing or malformed config) exit 1 with the
    actionable message on stderr instead of a raw traceback
    (ticket mcp-missing-config-traceback-ux).
    """
    try:
        asyncio.run(main())
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Venya config is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run()
