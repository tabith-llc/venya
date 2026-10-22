# Secret shapes — how a secret is consumed

Status: this is the Phase-1 documentation deliverable of ticket #61
(`secret-shape-registry`). Shapes are a **metadata convention** — verified
against the tree at writing time (branch base `9e0e4ad`). Phase 2 (a
server-side shape registry) is NOT built and NOT ruled; where this document
mentions it, it is labeled as parked design, not capability.

Questions or feedback: use the contact published on the Venya website
(venya.ai).

## 1. The ruled framing

**"Shapes customize usage, not security."**

Customizable via shapes:

| Aspect | Customizable | Notes |
|---|---|---|
| Consumption syntax | YES | usage template: `sshpass -f {secret_path} ssh …` |
| Tool requirements | YES | declared binaries the sandbox template must carry |
| Usage guidance | YES | human/agent-readable instructions |
| Naming/taxonomy | YES | shape names (`api-key-header`, `postgres-url`, …) |

NOT customizable (Venya guarantees, all shapes):

| Control | Why |
|---|---|
| Injection primitives + path | FIXED: 0400 tmpfs file `/run/secrets/venya/<secret_id>` (`packages/executor/src/executor/strategies/sbx_strategy.py`: `CONTAINER_SECRET_DIR`, `SbxStrategy.prepare`, `extra_fds=[]`). The env primitive arrives ONLY via the env-injection mechanism (contract bump + argv ruling). A shape choosing its own injection target (workspace-writable paths etc.) is a security regression — REJECTED. |
| Output filtering (Stage 1 + Stage 2) | core disclosure guarantee; no opt-out, ever |
| Audit (who / which secret / which command) | attribution requirement; not disableable |
| Egress deny-by-default | executor-level (`/etc/venya/egress-allowlist.txt`), not shape-level |
| Command policy gates | metachar ban (`packages/executor/src/executor/executor.py:SHELL_METACHARS`), dangerous patterns, trusted paths |
| Values never logged | foundational; template rule enforces path-references-only |

A shape is ADVISORY text. It never executes anything by itself: the real
command is still bounded by the policy gates, and destinations are still
bounded by the egress allowlist.

## 2. Built-in shapes

The blessed taxonomy is `BUILTIN_SHAPES` in
`packages/server/src/server/routes/secrets.py` — plus the `env:` prefix
(`ENV_SHAPE_PREFIX`). Everything else is a CUSTOM shape (allowed; see §4).
`MECHANISM_PENDING_SHAPES` is currently EMPTY: every listed mechanism ships.

| Shape | Consumption | Example command (path canon only — `{secret_path}` = the injected file `/run/secrets/venya/<secret_id>`) |
|---|---|---|
| `ssh-password` | sshpass reads the password file. Available in **balanced** and **permissive** policy; refused under **strict**, and by the empty allowlist (`STRICT_DEFAULT_COMMANDS`), not by a named pattern. Not supported in the same command as a remote `sudo -S` — see [beta-known-limitations.md](beta-known-limitations.md) | `sshpass -f {secret_path} ssh -o StrictHostKeyChecking=accept-new bot@web-server-3 uptime` |
| `ssh-key` | key material presented to ssh from the file | `ssh -i {secret_path} -o StrictHostKeyChecking=accept-new bot@web-server-3 uptime` (see the operator note in architecture.md: ssh-carried commands must avoid space-bearing argument traps) |
| `http-netrc` | curl/netrc credential file | `curl -n --netrc-file {secret_path} https://api.example.com/data` |
| `http-header-file` | header lives INSIDE the file; curl reads the config | `curl -K {secret_path} https://api.example.com/data` — the file carries the `header = …` line |
| `mysql-defaults` | client option file | `mysql --defaults-file={secret_path} -e "status"` |
| `ipmi-passfile` | password from file | `ipmitool -H 192.0.2.10 -U admin -f {secret_path} chassis power status` |
| `askpass` | sudo/git/ssh passphrase prompts answered via the static helper | stored value = the passphrase; at execute time the relay wires `GIT_ASKPASS`/`SSH_ASKPASS` to the helper (`routes/executors.py` askpass branch, `venya_contract.relay.ASKPASS_HELPER_PATH`). The command itself needs no shape-specific syntax. |
| `sudo-stdin` | sudo's `-S` reads the password from stdin; the session-bound `<` redirect pair is the ruled delivery. Aimed at a **local** `sudo -S` it delivers. Carried through `sshpass`, the same pair feeds `sshpass`'s own stdin instead of `ssh`'s, so a remote `sudo -S` is answered by nothing and waits. Without `sshpass` (key authentication) the redirect does reach the remote `sudo -S`, and that is the ruled delivery for an unattended remote `sudo` | `sudo -S < {secret_path} systemctl restart httpd` (the `<` must be its own argument followed exactly by the bound secret path — `executor.py:_redirect_pair`; do NOT add `-p ''` to remote ssh commands, see architecture.md) |
| `env:NAME` | value is written into the sandbox env file as `NAME=<value>` before the run (`routes/executors.py` env-shape branch; `RelayEnvVar` contract) | store the key as `env:KUBECONFIG`; then plain `kubectl get pods` works — see the `$` constraint in §5 |

Every shape is mediated through the same per-session tmpfs staging file;
`venya list` / MCP `list_secrets` surface the stored `shape` so humans and
agents can discover it.

## 3. Custom shape recipe (works today)

Any `shape` name outside the built-in set is accepted as CUSTOM. The server
warns (loud, not fatal) and stores the metadata; consumption is by the value
of `usage`. Real CLI surface (`packages/cli/src/venya_cli/cli.py` store
parser — positional key, optional positional value; `-` or omitted reads
stdin byte-exact with a hidden prompt on a TTY; `--shape`/`--usage` are sugar
for `-m shape=…`/`-m usage=…`, `commands.py:cmd_store`):

```
venya store my_api_key - --roles ops \
  -m shape=custom-api-key \
  -m usage='curl -K {secret_path} https://api.example.com' \
  -m description='read-only token for the example API'
```

Then use it in a session like any other secret key (`cli.py` run parser —
repeatable `--secret`, `--executor-id`, command after `--`):

```
venya run --secret my_api_key --executor-id venya-exec-1 -- \
  curl -K /run/secrets/venya/<id> https://api.example.com
```

The server enforces at store time (`routes/secrets.py:_validate_shape_metadata`):

| Input | Result |
|---|---|
| non-builtin `shape` name | WARNING, stored (forward compatible) |
| `usage` interpolating the secret VALUE | 400 — rejected (see §6 rule; the response names the allowed placeholders) |
| `usage` with an unknown `{placeholder}` | WARNING, stored; canon is `{secret_path}` |
| `env:NAME` value containing a newline | 400 — the sandbox env-file format is line-based |

## 4. Template rules (gate-cited)

- **Path references only.** A template may reference `{secret_path}`
  (= `/run/secrets/venya/<secret_id>`), never the value. The placeholder set
  the server currently recognizes is `USAGE_PLACEHOLDERS`
  (`{secret_path}`, `{secret_id}`, `{host}`, `{user}`); anything else warns.
  A value inside command text persists UNMASKED in the audit log and `/proc`
  — the store rejects it (400) so a bypass is never blessed in an example.
- **No shell metacharacters.** Commands are validated element-by-element
  against `SHELL_METACHARS` (`executor.py:_validate_command_structure`).
  One ruled exception exists: the standalone `<` followed by a session-bound
  secret path (the `sudo-stdin` delivery pair). Everything else — pipes,
  semicolons, backticks, substitution syntax, braces — is refused before the
  sandbox starts.
- **Trusted paths.** What the gate computes is RESOLUTION into a trusted
  directory (`DEFAULT_TRUSTED_PATHS`: `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`),
  not shell-ness: an absolute path qualifies only inside one of those, and a bare
  name is PATH-resolved first, so a name that resolves outside them is refused as
  well. `echo`, `true`, `test`, `printf` and `pwd` are shell builtins that have
  real binaries in a trusted directory and therefore PASS, while `cd`, `export`,
  `source` and `eval` have no file to resolve and are refused — and so is any
  non-builtin that fails the same test. The validator keeps no builtin table, so
  builtins are not a refused class; a refusal from this gate reads
  `Command not in trusted paths: '<name>'`. See architecture.md §Sandbox and
  egress for the same statement (the metacharacter and dangerous-pattern gates
  above are separate gates with their own reasons).
- **Egress allowlist.** Destinations are fleet-controlled
  (`/etc/venya/egress-allowlist.txt`, deny-by-default). A shape whose example
  points at an unlisted host simply fails at connect time; a shape cannot
  widen egress.

## 5. Env shapes and the `$` constraint (hidden, load-bearing)

`$` is a blocked metacharacter, so a command can NEVER reference `$VAR`
explicitly. An `env:NAME` secret therefore helps ONLY tools that read their
environment IMPLICITLY: `aws` (credential env vars), `kubectl` +
`KUBECONFIG`, `psql` + `PGPASSFILE`-style discovery, and similar. Drafting an
env shape for a tool that only takes a CLI flag is a dead end; keep it a
file-based shape. (Recorded on the `secret-shape-env-injection` ticket.)

## 6. The operator rule (#14): never inline a secret in command text

Masking (Stage 1 Rust filter + Stage 2 server filter) covers **stdout/stderr
only**. The command string itself persists unmasked by design: audit events,
the executor spool, server journals, and the `execution_sessions` row all
carry it, and on the target it would show in `/proc/<pid>/cmdline`. So the
guarantee shapes provide (for shape-compliant usage) is: the secret reaches
the tool through the injected file or env, never through the command text.
This is a property of blessed shapes + the operator rule — the engine cannot
stop a human from typing a value into a command that involves no secret.
Details: architecture.md §Secret lifecycle.

## 7. Composite values: keep one secret = one fingerprintable value

Output masking fingerprints the STORED value. A composite blob (for example
host + user + password joined into one secret) is fingerprinted as a whole —
its individual components are NOT masked when they leak on their own. Prefer
one secret per fingerprintable value and compose at consumption time
(`{host}`/`{user}` placeholders, metadata, or separate secret keys).

## 8. Audit reality (no new events needed)

The executor spool accepts a FIXED event tuple
(`packages/executor/src/executor/audit.py:EVENT_TYPES`:
`credential_injected`, `command_executed`, `command_rejected`,
`token_revocation_failed`, and — added by #586, unrelated to shapes —
`relay_refused` for the relay listener's accept-gate refusals). Attribution is
already complete without any shape-specific event: `execution_session_created`
records the user and the secret KEYS; `command_executed` records
user/command/exit code/masked count; the spool's `credential_injected` records
the secret ids. The shape is derivable from secret metadata — a
`secret_used_via_shape` event was ruled REJECTED as redundant surface.

## 9. Who may author shapes (authorization split)

- **Method 1 (ships today):** shape/usage live in secret metadata; storing
  them requires a read-write role. This is safe because a usage template is
  advisory text — see §1.
- **Method 2 (Phase 2, NOT BUILT):** a server-side shape registry
  (fleet-shared definitions, `list_shapes` discovery) is ruled ADMIN-only and
  parked post-beta. Nothing in this document's §2-§8 depends on it; do not
  write code or docs that assume registry routes exist.

## 10. REJECTED patterns — never re-propose these (from the draft spec review, #61)

| Rejected item | Why (one line) |
|---|---|
| Options-form store flags (long key/value flag pair) | fabricated CLI surface — the real store command takes positional key + optional positional value, stdin for hidden input (`cli.py` store parser) |
| The draft's "GOOD" bearer example (a header argument built with dollar-open-paren substitution syntax) | contains blocked metacharacters; the structural gate rejects the whole string — the working bearer shape is `curl -K {secret_path}` with the header INSIDE the file (`secret-shape-http-api`) |
| Any double-brace value placeholder (embedding the secret VALUE in a template) | value in command/audit text is the disclosure path §6 exists to close; the store 400s it (`_validate_shape_metadata`) |
| "fd injection" language (the draft described the secret arriving as an open file handle) | injection is FILES — a 0400 tmpfs file; `extra_fds=[]` at `sbx_strategy.py:SbxStrategy.prepare`. The legacy spool field name `fd_count` is a misnomer for "secret files bundled"; three public artifacts already carry this correction — do not reintroduce it |
| Customizable injection paths/targets | security regression; the injection primitive is a guarantee (§1) |
| `secret_used_via_shape` audit event | redundant — `EVENT_TYPES` is fixed and attribution is already complete (§8) |
| Env-as-builtin taxonomy beyond the ruled `env:NAME` prefix; a two-step propose/approve CLI | ruled out of v1; registry routes are Phase 2 and need their own ruling |

## Cross-references

- `docs/architecture.md` §Secret lifecycle (zero-knowledge injection, the #14 operator rule, ssh/sudo traps), §Sandbox and egress
- `docs/alpha-demo.md` — end-to-end demo flow
- Ticket family (GitLab `tabith-llc-group/venya-dev`): `secret-shape-metadata`
  (validation + surfacing — shipped), `secret-shape-env-injection`,
  `secret-shape-askpass-helpers`, `secret-shape-sudo-remote` option (a),
  `secret-shape-http-api`, `secret-shape-registry` (#61, this doc = Phase 1)
