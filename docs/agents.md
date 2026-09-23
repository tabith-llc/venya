# Venya — Instructions for AI Agents

You are an LLM agent operating (or being asked to operate) infrastructure
through Venya. Read this once, fully, before your first tool call.

## What Venya is

Venya brokers privileged operations: credentials stay in its vault, commands
run in sandboxed executors, secrets are injected inside the sandbox, and
output is filtered before it reaches you. A human authorized your session
with a physical FIDO2 key. Every action you take is audited and attributed
to that human.

## Your four tools (MCP)

| Tool | Use it for |
|---|---|
| `list_secrets` | Discovery: secret keys + metadata (purpose, executor hints). Values are NEVER returned — to anyone, ever. |
| `list_executors` | Which executors exist and are online. |
| `run_command` | Execute a command on an executor with named secrets injected (`secret_keys`). |
| `get_audit` | Your authorizing user's execution history (non-admins see only their own events). |

## Hard rules

1. **Never attempt to read, echo, encode, or exfiltrate secret values.**
   They are unreachable by design: injection happens inside the sandbox
   (`/run/secrets/venya/<secret-id>`), output passes a redaction filter,
   and network egress is deny-by-default. Attempts are logged and
   attributed to your human.
2. `[REDACTED:<id>]` markers in output are the system working, not an
   error. Do not try to decode, work around, or re-request them.
3. **Commands must resolve into trusted directories** — use absolute binary
   paths (`/bin/cat`, `/usr/bin/ssh`, `/usr/bin/apt-get`). Bare names are
   PATH-resolved and accepted only if they land in a trusted dir; shell
   builtins are rejected (503) by design.
4. With the `venya` CLI, a leading `--` separator on `venya run` is consumed
   (not sent to the executor); venya's own flags (`--secret`,
   `--executor-id`) must come BEFORE the command — everything after the
   first command token belongs to the remote command.
5. Use **IP addresses** for hosts inside commands when instructed —
   sandbox DNS does not resolve site-local hostnames.
6. **First run after an executor install may time out** (~60 s agent-
   template pull) while still succeeding server-side. Before retrying:
   check the result of the first attempt (audit/target state). Warm runs
   are seconds-scale.
7. On `401`/expired session: **ask your human to re-authenticate**
   (`venya login`, physical key touch). Sessions idle out after 15 minutes
   and hard-cap at 4 hours. You cannot and must not renew authorization
   yourself.
8. Sandbox execution failures return 503 with the cause in the executor
   journal — surface the error to your human verbatim; do not loop retries.

## Installing and configuring (usually a human task)

- Full install flow: [installation.md](installation.md)
- Server configuration: required fields, env-var mapping, validation timing: [deployment-config.md](deployment-config.md)
- Every CLI command (incl. `venya setup` workstation configuration): [cli-reference.md](cli-reference.md)
- MCP client wiring (generic + opencode): [installation.md §6](installation.md#6-mcp-client-wiring-llm-operators)
- See the whole chain work end-to-end: [alpha-demo.md](alpha-demo.md)
- Architecture and guarantees: [architecture.md](architecture.md)

If you were asked to install Venya yourself: the server installers require
root on dedicated machines and the workstation installer requires the
operator's own account — hand the commands to your human rather than
improvising.

## Conduct

Behave as if every command is being read by your human's security team —
it is. Prefer narrow commands over broad ones, never disable security
features to make something work, and stop-and-report when observed
behavior contradicts expectations.
