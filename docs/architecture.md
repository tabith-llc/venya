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
┌───────┴─────────────────┐           │  ├─ secrets vault (envelope enc) │
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
| Rust filter extension | (built at executor install) | `venya_filter.cpython-*.so` — scans command output for secret material, replaces matches with `[REDACTED:...]` markers before anything leaves the sandbox host |

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
  chained to the per-install Admin CA (nginx mTLS). The Admin CA key is
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
| Admin CA | core: `/var/lib/venya/ca/admin-ca/` (key encrypted) | admin mTLS client certs |
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
   persists;
   the API never returns values — only metadata (key, roles, purpose,
   executor hints) for discovery by humans and LLMs.
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
    `mysql-defaults`, `ipmi-passfile`, `askpass` for sudo/git, `env:NAME`,
    custom names) — every shape is mediated through the same per-session
    tmpfs staging, never through the caller's context.
 4. **Filter.** Masking runs in two stages: the executor's Rust filter
    (Stage 1) replaces any occurrence of secret material with
    `[REDACTED:...]`, then the server-side **definitive** filter (Stage 2,
    `POST /api/v1/sessions/{id}/filter` over executor mTLS) re-screens the
    UNFILTERED bytes with the vault's own knowledge and its answer is
    adopted. Stage 2 fails **closed**: an unknown or TTL-reaped session gets
    404, and the executor keeps the Stage-1-masked output — a filter failure
    never returns raw bytes.
5. **Audit.** Every step records actor, command string, executor id,
   secret ids (never values), and timestamps. Non-admin users querying
   `get_audit` see only their own events (enforced server-side).

**Operator rule (load-bearing).** Step 4's masking covers **stdout/stderr
only** — the command string itself persists UNMASKED by design (step 5:
audit events, the executor spool, server journals, and the
`execution_sessions` row all carry it). **Never inline a secret in command
text** (`sshpass -p <pw>`, `--password=…`, `echo <token> | …`): it lands in
those sinks, and on the target it is exposed via `/proc/<pid>/cmdline` and
shell history. The blessed shape is file injection —
`sshpass -f /run/secrets/venya/<id> ssh …` — which keeps the secret off
every command-line surface. Operator behavior is the primary control here;
post-beta hardening may additionally scrub the command string against known
secret values (ticket sec-secret-redaction-log-leaks #14).

## Sandbox and egress

Commands run in sbx (Docker Sandboxes) microVMs. Networking is
deny-by-default against `/etc/venya/egress-allowlist.txt` (written empty by
design at install — fail-closed; seed it via `VENYA_EGRESS_ALLOW` or edit it
directly; the configured DNS resolver is always permitted); a compromised
command cannot phone home.
The executor service runs under a seccomp profile, `PrivateTmp`, and no
`CAP_IPC_LOCK` (mlock is confined to the core by design and enforced by
tests in both packages). The daemon user has KVM access for sandboxing;
sandbox SSH tooling requires commands to resolve into trusted directories
(absolute paths, or bare names resolved via PATH; shell builtins and
unresolvable tokens are rejected by design — 503).

## Data stores

- **PostgreSQL** (core only): users, credentials (WebAuthn), sessions,
  secrets (ciphertext), roles, executors, enrollment tokens (hashed),
  execution sessions, audit events. All timestamps are timezone-aware UTC.
- **Filesystem state:** `/opt/venya/.env` is the sole runtime config on the
  core (pydantic settings; nested keys as `VENYA_<SECTION>__<KEY>`);
  executors use `/etc/venya/executor.toml`. There is no TOML config on the
  core.

## Deployment shape

Single-core deployments are the alpha norm; the core is stateless apart from
PostgreSQL and its CA material, so HA is a replication problem (tracked for
beta). Executors scale horizontally — each is an independent daemon with its
own certificate. Targets are untouched: Venya installs nothing on them;
executors reach them over SSH with operator-provided credentials (which are
themselves vault secrets, injected per-command).
