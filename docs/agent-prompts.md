# Venya — Agent Prompts (paste-ready operating contract)

**This page is for the human wiring an AI agent to Venya.** Paste the block
below into the instruction file your agent framework reads at every session:

| Framework | Paste into |
|---|---|
| opencode | `AGENTS.md` |
| Claude Code | `CLAUDE.md` |
| Cursor | `.cursor/rules` (or `.cursorrules`) |
| Anything else | the agent's system prompt / instructions field |

The block is deliberately short and self-contained — instruction files are
prime real estate, and a bloated contract gets trimmed or ignored. The full
operating brief is [agents.md](agents.md), linked for the human; the agent
needs no web fetches to operate. An interlock test in `packages/mcp/tests/`
pins the block's load-bearing claims to the live MCP tool surface, so it
cannot silently rot when the tools change.

<!-- snippet-start -->
## Venya — operating contract

You operate infrastructure through Venya. Four MCP tools: `list_executors`,
`list_secrets`, `run_command`, `get_audit`.

1. **Secret values are unreachable by design.** Never attempt to read, echo,
   encode, or exfiltrate one — attempts are logged and attributed to the
   human who authorized you.
2. **`list_secrets` shows a `usage` line for most secrets: a ready-to-run
   command template** with the secret's sandbox path
   (`/run/secrets/venya/<id>`) already resolved. Copy it and fill any
   `{host}`/`{user}` placeholders from your task and the listed metadata.
   Never construct secret paths yourself; never inline a secret value.
3. **`[REDACTED:<id>]` in output is the system working**, not an error.
   Never decode, work around, or re-request it.
4. **Commands:** use absolute binary paths (`/usr/bin/ssh`, `/bin/cat`);
   shell builtins are rejected (503) by design. Hostnames resolve only if
   the operator allowlisted them as hostnames — otherwise use IP addresses.
5. **The first run after an executor install can take ~60 s** (sandbox
   template pull) while still succeeding server-side. Check the result
   before retrying; warm runs are seconds-scale.
6. **On 401 / expired session:** ask your human to re-authenticate
   (`venya login`, physical key touch). You cannot and must not renew
   authorization yourself.
7. **On 503:** surface the error to your human verbatim. Do not loop
   retries. When something is missing (a credential, a setup step), say
   WHAT is needed — never invent CLI commands for your human to run.
8. **Everything you run is permanently attributed to your human.** Behave
   as if their security team reads every command — they do.
<!-- snippet-end -->

---

*Honesty note: every claim in the block is source-matched to the shipped
tool surface (the pinning interlock lives in
`packages/mcp/tests/test_agent_prompts_doc.py`); the ~60 s cold-start figure
is the observed template-pull time on a fresh executor.*
