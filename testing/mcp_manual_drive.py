# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interactive MCP driver — operate venya-mcp by hand and SEE the proof.

Companion to testing/test-plan.md Phase D. Spawns the real `venya-mcp` stdio
server as a subprocess (exactly like an LLM client would), speaks the MCP
protocol over stdio, and lets the operator call each tool interactively and
see the raw results — including the redaction proof from run_command.

Usage (from the workstation, plan D.4 Path 1):
    $ADMIN_WS/.venv/bin/python testing/mcp_manual_drive.py \
        --mcp-bin $ADMIN_WS/.venv/bin/venya-mcp \
        --config  $ADMIN_WS/mcp/config.json \
        --ca      /tmp/venya-ca.crt
"""

import argparse
import asyncio
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def show(result) -> None:
    for c in result.content:
        print(getattr(c, "text", str(c)))
    if result.isError:
        print("!! tool returned isError=True")


async def drive(mcp_bin: str, config: str, ca: str) -> None:
    env = dict(os.environ)
    env["VENYA_CONFIG"] = config
    env["VENYA_CA_CERT"] = ca
    params = StdioServerParameters(command=mcp_bin, args=[], env=env)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("\nvenya-mcp connected. Tools:", sorted(t.name for t in tools.tools))
            print(
                "\nMenu:\n"
                "  1 = list_secrets        (keys + metadata, never values)\n"
                "  2 = list_executors      (online status)\n"
                "  3 = run_command         (inject secrets; watch the redaction)\n"
                "  4 = get_audit           (your events only, if non-admin)\n"
                "  q = quit\n"
            )
            while True:
                try:
                    choice = input("mcp> ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
                if choice in ("q", "quit", "exit"):
                    return
                if choice == "1":
                    show(await session.call_tool("list_secrets", {}))
                elif choice == "2":
                    show(await session.call_tool("list_executors", {}))
                elif choice == "3":
                    executor_id = input("  executor_id: ").strip()
                    command = input("  command: ").strip()
                    keys = input("  secret_keys (comma-separated): ").strip()
                    secret_keys = [k.strip() for k in keys.split(",") if k.strip()]
                    show(
                        await session.call_tool(
                            "run_command",
                            {"executor_id": executor_id, "command": command, "secret_keys": secret_keys},
                        )
                    )
                elif choice == "4":
                    hours = input("  look-back hours [1]: ").strip() or "1"
                    show(await session.call_tool("get_audit", {"hours": int(hours)}))
                else:
                    print("  unknown choice")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mcp-bin", required=True, help="path to the venya-mcp executable")
    ap.add_argument("--config", required=True, help="MCP config json (server_url + access_token)")
    ap.add_argument("--ca", default="/tmp/venya-ca.crt", help="core CA cert path (VENYA_CA_CERT)")
    args = ap.parse_args()
    asyncio.run(drive(args.mcp_bin, args.config, args.ca))


if __name__ == "__main__":
    main()
