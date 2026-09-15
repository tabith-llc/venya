# Venya Alpha Demo — 5 Minutes

The shortest honest demo of the core claim: **a command uses a secret the
caller never sees, and the output proves the redaction works.** No LLM, no
target hosts required — one core, one executor, one workstation with a FIDO2
key.

## Prerequisites

- Core + executor installed and enrolled ([installation.md](installation.md))
- Workstation bundle installed; admin (or any enrolled user) logged in:
  ```bash
  SSL_CERT_FILE=~/.config/venya-ca.crt venya login <user-id>
  ```
- Executor shows active: `systemctl is-active venya-executor` on the
  executor host (or the `list_executors` MCP tool from an LLM client)

## 1. Seed a demo secret (~1 min)

Known alpha limitation: `venya store` currently omits a required field
(ticketed, fix deferred post-alpha). Seed via the API instead — the token
comes from your login:

```bash
TOKEN=$(python3 -c "import json; print(json.load(open('$HOME/.config/venya/config.json'))['access_token'])")
curl -s --cacert ~/.config/venya-ca.crt \
  --cert admin-cert/admin.crt --key admin-cert/admin.key \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"key":"demo-pass","value":"hunter2-demo-only","roles":["user"],"key_version_id":"v1"}' \
  https://<core-host>/api/v1/secrets
```

Note the response: id, key, roles — **the value is never echoed back**.

## 2. Discovery sees metadata only (~30 s)

```bash
venya list
```

Key names, roles, metadata. No values — this is exactly what an LLM client
sees via the `list_secrets` MCP tool.

## 3. Run a command that consumes the secret (~1 min)

The executor exposes each injected secret as a file inside the sandbox at
`/run/secrets/venya/<secret-id>` (tmpfs, zeroed after the run). Use the id
from step 1/2:

```bash
venya run --secret demo-pass --executor-id <executor-id> -- \
  /bin/cat /run/secrets/venya/<secret-id>
```

**Expected output: `[REDACTED:...]`** — the command genuinely read the
secret (exit code 0, correct byte count where applicable), and the Rust
filter replaced the value before it left the executor. The secret never
traversed your workstation, your shell history holds no value, and the audit
log records the secret id — never the plaintext.

## 4. Prove the audit trail (~30 s)

```bash
venya audit
```

Your execution appears: actor, command string, executor, secret ids,
timestamp. Non-admin users see only their own events (server-enforced).

## Extended demo: real work on a target host

The canonical end-to-end shape — install a package on a remote target
without the operator or the LLM ever touching the target's credentials:

1. Store the target SSH credential as a secret (step-1 shape).
2. From an MCP client (Claude Code, Cursor) with `venya-mcp` wired per
   [installation.md §6](installation.md#6-mcp-client-wiring-llm-operators),
   prompt: *"Install apache2 on <target-host> using the stored SSH
   credential."*
3. The agent lists executors + secrets (metadata), constructs the command,
   and calls `run_command`. The executor injects the credential inside the
   sandbox (e.g. `/usr/bin/sshpass -f /run/secrets/venya/<id>
   /usr/bin/ssh <user>@<target> …`) and the filter scrubs the output.
4. Watch the agent's context: it contains the package-manager log lines and
   `[REDACTED:...]` where the credential appeared — never the credential.

Sandbox notes for the extended demo: commands run in an sbx microVM with
deny-by-default egress (allowlist on the executor); trusted-path validation
requires absolute binary paths (`/bin/cat`, `/usr/bin/ssh`) — shell builtins
are rejected by design; the sandbox template must contain the tools you
invoke (`sshpass` etc.).

## What you just proved

| Claim | Where |
|---|---|
| Caller never sees the secret value | steps 1–3 (store echo, list, run output) |
| Secret is usable inside execution | step 3 exit status |
| Redaction is enforced, not best-effort | step 3 `[REDACTED:...]` |
| Every use is attributable | step 4 |
| LLM clients get the same guarantees | extended demo |

## Troubleshooting

- `422` on step 1: check the JSON body carries `key_version_id` (required).
- `503` on step 3: builtins/relative paths in the command — use absolute
  paths. Do NOT pass a `--` separator to `venya run`; it is captured
  literally into the command string (known quirk, ticketed) and can trip
  the command validator.
- **First run times out** ("read operation timed out") on a freshly
  installed executor: the first sandbox create pulls the agent template
  (~60 s+) and can exceed the client read timeout while the command
  completes server-side. Check the executor journal
  (`journalctl -u venya-executor`) and the target's state, then rerun —
  warm runs are seconds-scale.
- `503` with `Not authenticated to Docker` / `global network policy has not
  been initialized` in the executor journal: executor sandbox setup
  incomplete — see [installation.md](installation.md) troubleshooting.
- `401` anywhere: access tokens live 5 minutes; re-run `venya login`
  (touch the key). Sessions hard-cap at 4 hours and idle out after 15
  minutes — an MCP session dies the same way; re-login and retry.
- Relay `403` during extended demo: core/executor hostname disagreement —
  see the troubleshooting section of [installation.md](installation.md).
