# Venya Architecture

Technical deep dive. For installation see [installation.md](installation.md);
for the threat-model pitch see the [README](../README.md).

## System topology

```
 Operator workstation                    Core server VM
┌─────────────────────────┐   HTTPS   ┌──────────────────────────────────┐
│ venya CLI  (venya-cli)  │──────────▶│ nginx :443                       │
│ venya-mcp  (MCP server) │  TLS +    │  ├─ admin paths: mTLS REQUIRED   │
│ FIDO2 security key      │  Bearer   │  └─ proxy → uvicorn 127.0.0.1    │
└─────────────────────────┘           │ FastAPI server (packages/server) │
        ▲ stdio (MCP)                 │  ├─ FIDO2/WebAuthn ceremonies    │
┌───────┴─────────────────┐           │  ├─ secret store (envelope enc) │
│ LLM client              │           │  ├─ RBAC + audit log             │
│ (Claude Code, Cursor…)  │           │  └─ CA services (root/admin CA)  │
└─────────────────────────┘           │ PostgreSQL (secrets, audit, IAM) │
                                      └────────────┬─────────────────────┘
                                                   │ mTLS (executor client cert)
                                                   │ + relay: core dials executor
                                      ┌────────────▼─────────────────────┐
                                      │ Executor host (packages/executor)│
                                      │  venya-executor daemon           │
                                      │  ├─ relay listener :8443 (mTLS,  │
                                      │  │   CERT_REQUIRED, CN allowlist)│
                                      │  ├─ heartbeat + revocation poll  │
                                      │  ├─ sbx microVM sandboxes        │
                                      │  ├─ secret injection (unwraps    │
                                      │  │   server-wrapped material)    │
                                      │  └─ Rust redaction filter        │
                                      │      (venya_filter .so)          │
                                      └────────────┬─────────────────────┘
                                                   │ SSH
                                              Target hosts
```

## Repository layout (uv workspace)

| Package | Distribution | Contents |
|---|---|---|
| `packages/core` | `core` | Shared library: IAM models, role manager, session manager, encryption engine (envelope encryption, KEK/DEK), DB models + Alembic migrations (`core/migrations.py`) |
| `packages/server` | `server` | FastAPI application: REST API, FIDO2 ceremonies, secrets routes, executor enrollment/revocation, audit, admin mTLS enforcement, static enrollment/login pages |
| `packages/executor` | `executor` | Daemon: mTLS registration + rotation + revocation polling, relay listener, sandbox execution (sbx), secret injection, output filtering via the Rust extension, egress allowlist enforcement |
| `packages/cli` | `venya-cli` | Workstation CLI (`venya`): init/enroll/login (FIDO2 via python-fido2, USB HID), admin operations (mTLS client cert), secrets, `run`, executor lifecycle. Deps: httpx2, fido2, cryptography — nothing server-side |
| `packages/mcp` | `venya-mcp` | MCP stdio server exposing exactly four tools: `list_secrets` (metadata only), `list_executors`, `run_command`, `get_audit` |
| Rust filter extension | (built at executor install) | `venya_filter.cpython-*.so` — scans command output for secret material in the executor host daemon, replacing matches with `[REDACTED:...]` markers before anything reaches the caller (see "Secret lifecycle" step 4 for the two-stage flow) |

The CLI is deliberately standalone (no `core` dependency) so a workstation
never installs server-side packages; a parity-tested duplication of the
executor-ID validator is the only shared logic (see
`packages/cli/tests/test_executor_id_parity.py`).

## Authentication and sessions

- **Users:** FIDO2/WebAuthn only — no passwords exist in the system for
  humans. Enrollment and every login are hardware-key ceremonies
  (user-presence touch + PIN).
- **Sessions:** 15-minute idle window (sliding), 4-hour hard cap;
  access tokens live 5 minutes and refresh transparently inside an active
  session. Expiry yields an actionable error for LLM clients ("ask the user
  to re-authenticate") — an agent can never renew a human's authorization.
- **Admin plane:** admin API paths additionally require a client certificate
  chained to the per-install Admin CA (nginx mTLS). There are two kinds of that
  certificate, and they are not interchangeable: the core's own **machine-plane**
  pair, minted on the core by the installer, valid 90 days, and never copied off
  that host; and a **person's** certificate, minted on their own workstation by a
  security-key ceremony, valid about an hour, and checked against their role on
  every use — so taking the role away stops the credential on the next request,
  rather than at expiry. The Admin CA key is
  encrypted at rest; its passphrase reaches the daemon only via a 0640
  root:venya EnvironmentFile.
- **Executors:** X.509 client certificates issued by the core at enrollment
  (single-use bootstrap token, ~30 min TTL, stored hashed). Rotation is
  supported; revocation propagates via the executor's revocation-list poll.
- **Recovery:** the first admin's one-time recovery code, plus CA-key backup
  (`venya admin export-ca-key` encrypted export, or Shamir-split via
  `venya admin split-ca-key`; restore via `venya admin restore-ca-key`), are
  the designed break-glass paths. (Shamir split/combine lives in
  `packages/cli`.)

## Trust and CA layout

| CA / cert | Location | Purpose |
|---|---|---|
| Venya root CA | core: `/var/lib/venya/ca/` | signs server TLS certs, relay client certs; distributed to clients via `/.well-known/venya-ca.crt` (workstations: `venya setup` installs it beside `config.json`) and installed into VM trust stores |
| Server TLS cert | core: `/etc/venya/tls/` | nginx termination for `<core-host>` |
| Relay client cert | core: `/etc/venya/relay/` | CN `<core-host>-relay`; presented when the core dials an executor's relay listener |
| Admin CA | core: `/var/lib/venya/ca/admin-ca/` (key encrypted) | admin mTLS client certs — the core's own machine-plane pair (90 days, stays on the core) and a person's workstation certificate (about an hour, security-key ceremony) |
| Executor client cert | executor: `/etc/venya/executor/` (0700/0600) | executor → core mTLS identity; SAN = executor-id; issued by the core CA (`/var/lib/venya/ca/`), copied to the executor as `/etc/venya/executor/ca.crt` |

Relay CN contract: executors accept relay connections only from client-cert
CNs listed in `relay_client_ids` (derived from the core hostname). Empty
allowlist = the relay listener refuses to bind (fail-closed); CN mismatch =
handshake rejection. Both directions verify; nothing falls back to
unauthenticated transport.

## Secret lifecycle (zero-knowledge injection)

1. **Store.** Secret value encrypted server-side under envelope encryption
   (random DEK per secret, wrapped by the KEK with AES-256-KW per RFC 5649;
   the value itself is ChaCha20-Poly1305), scoped to roles. Plaintext never
   persists; listing and admin surfaces return metadata only (key, roles,
   purpose, executor hints), and a value is returned only through the
   elevation-gated unmask (a human re-authenticating via WebAuthn with a
   single-use token) or mTLS-executor session injection at command time.
2. **Dispatch.** For a `run_command`/`venya run` execution, the server
   decrypts, wraps the value in cryptographic sentinel markers, and sends it
   over the mTLS relay channel to the targeted executor. The calling client
   (human or LLM) sees only the command result — the wrapped blob is routed
   server → executor, never through the caller.
 3. **Inject.** The executor daemon unwraps **host-side**, writes the
    plaintext to a per-session tmpfs staging file (0400, zeroed after the
    run), and exposes it inside the sbx sandbox at `/run/secrets/venya/<id>`.
    Execution sessions are ephemeral. File injection is the default
    consumption shape; a secret's `usage` metadata selects alternatives
    (`ssh-password`, `ssh-key`, `http-netrc`, `http-header-file`,
    `mysql-defaults`, `ipmi-passfile`, `askpass` for sudo/git, `sudo-stdin`,
    `env:NAME`, custom names) — every shape is mediated through the same per-session
    tmpfs staging, never through the caller's context. The shipped built-in set is
    `BUILTIN_SHAPES` in `packages/server/src/server/routes/secrets.py` — read it there
    rather than trusting this list, which is prose and can lag.
 4. **Filter.** Masking runs in two stages: the executor's Rust filter
    (Stage 1) replaces any occurrence of secret material with
    `[REDACTED:...]`, then the server-side **definitive** filter (Stage 2,
    `POST /api/v1/sessions/{id}/filter` over executor mTLS) re-screens the
    UNFILTERED bytes with the store's own knowledge and its answer is
    adopted. Stage 2 fails **closed**: an unknown or TTL-reaped session gets
    404, and the executor keeps the Stage-1-masked output — a filter failure
    never returns raw bytes.
5. **Audit.** Every step records actor, command string, executor id,
   secret ids (never values), and timestamps. Callers with admin or an
   auditor-tier role querying `get_audit` see the full log; all others
   see only their own events (enforced server-side).

**Operator rule (load-bearing).** Step 4's masking covers **stdout/stderr
only** — the command string itself persists UNMASKED by design (step 5:
audit events, the executor spool, server journals, and the
`execution_sessions` row all carry it). **Never inline a secret in command
text** (`sshpass -p <pw>`, `--password=…`, `echo <token> | …`): it lands in
those sinks, and on the target it is exposed via `/proc/<pid>/cmdline` and
shell history. The blessed shape is file injection —
`sshpass -f /run/secrets/venya/<id> ssh …` — which keeps the secret off
every command-line surface. When authoring usage templates for ssh-carried
commands, mind a second trap: ssh re-joins the remote command's arguments
with spaces **without re-quoting**, so an empty or space-bearing argument
vanishes or splits remotely — `sudo -S -p ''` arrives as `sudo -S -p` and
sudo swallows the next token as its prompt string (usage error, exit 1).
Omit `-p ''`; the remote sudo prompt text on stderr is harmless and carries
no secret. Carry `-o StrictHostKeyChecking=accept-new` in ssh-based
templates: every sandbox starts with no `known_hosts`, and without the
option the first connection to a host fails **silently** (`sshpass` exit 6,
empty stderr). accept-new still refuses CHANGED keys, so the trust-on-first-use
convenience costs no man-in-the-middle signal. Operator behavior is the primary control here;
post-beta hardening may additionally scrub the command string against known
secret values (ticket sec-secret-redaction-log-leaks #14).

**File-arg tool blessings (same rule, other tools).** A tool that natively
reads a credential from a file-path argument needs no code — the injected
`{secret_path}` file IS the mechanism:

- `mysql-defaults` — `mysql --defaults-extra-file={secret_path} …` with an
  INI body `[client]` / `password=…`. Inline `--password=X` is FORBIDDEN
  (command text persists unmasked in audit sinks, same as the `sshpass -p`
  case above). Physical verification is PARKED pending a MariaDB venue
  (ticket secret-shape-file-arg-tools #57; the 0400-acceptance and
  tmpfs-sweep pins land with that unpark).
- `ipmi-passfile` — `ipmitool … -f {secret_path}`. UNVERIFIED-PHYSICAL:
  no BMC exists in the test fleet; docs+taxonomy only (same recording
  discipline as the EROFS dormant-guard precedent).
- psql does NOT need a file-arg shape: `PGPASSFILE` points psql at the
  injected file via the env-shape family (`usage` metadata `env:PGPASSFILE`)
  — cross-reference secret-shape-env-injection, not a new blessing.

Pattern rule: any tool that natively reads a credential from a file-path
argument is a bless-only shape — a row in this list plus its verification
cells, NOT a code ticket. Tool availability inside the sandbox template is
a deployment property; document it per shape.

## Sandbox and egress

Commands run in sbx (Docker Sandboxes) microVMs. Networking is
deny-by-default against `/etc/venya/egress-allowlist.txt` (written empty by
design at install — fail-closed; seed it via `VENYA_EGRESS_ALLOW` or edit it
directly; the configured DNS resolver is always permitted); a compromised
command cannot phone home.
The executor service runs under a seccomp profile, `PrivateTmp`, and no
`CAP_IPC_LOCK` (mlock is confined to the core by design; the pair that pins it is
`packages/core/tests/test_capability_isolation.py` and
`packages/cli/tests/test_capability_isolation.py` — core and CLI, not core and
executor). The daemon user has KVM access for sandboxing;
sandbox SSH tooling requires commands to resolve into trusted directories
(`DEFAULT_TRUSTED_PATHS`: `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`) — absolute paths
qualify only inside those directories, and bare names are PATH-resolved first, so a name
that resolves outside them is refused too. What the gate computes is RESOLUTION into a
trusted directory, not shell-ness: `echo`, `true`, `test`, `printf` and `pwd` are shell
builtins that have real binaries in a trusted dir and therefore PASS, while `cd`,
`export`, `source`, `eval`, `set` and `read` have no file to resolve and are refused — and
so is any non-builtin that fails the same test, including one that resolves cleanly but
outside the trusted set. A refusal from THIS gate reads `Command not in trusted paths:
'<name>'` (other gates have their own reasons — the dangerous-pattern block and the empty
command check fire before it); the
validator keeps no builtin table to consult, so nothing in the product reasons about
builtins as a class. Unresolvable and non-trusted tokens are rejected — 503.

## Data stores

- **PostgreSQL** (core only): users, credentials (WebAuthn), sessions,
  secrets (ciphertext), roles, executors, enrollment tokens (hashed),
  execution sessions, audit events. All timestamps are timezone-aware UTC.
- **Filesystem state:** `/opt/venya/.env` is the runtime **settings** file on the
  core (pydantic settings; nested keys as `VENYA_<SECTION>__<KEY>`). It is not the only
  file the service reads: the CA key passphrases arrive through a separate root-only
  systemd `EnvironmentFile`, `/etc/venya/venya-core.env` (0640 `root:venya`), which
  pydantic never sees — it lands in `os.environ` — and the metrics port is set the same
  way, by a unit `Environment=` line; a name placed in `.env` instead is read by nobody.
  See `deployment-config.md`. Executors use `/etc/venya/executor.toml`. There is no TOML
  config on the core.

## Deployment shape

Single-core deployments are the alpha norm; the core is stateless apart from
PostgreSQL and its CA material, so HA is a replication problem (tracked for
beta). Executors scale horizontally — each is an independent daemon with its
own certificate. Targets are untouched: Venya installs nothing on them;
executors reach them over SSH with operator-provided credentials (which are
themselves secrets, injected per-command).
