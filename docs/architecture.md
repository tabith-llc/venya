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
| `packages/core` | `core` | Shared library: IAM models, role manager, session manager, encryption engine (envelope encryption, KEK/DEK), Shamir split/combine for CA-key backup, DB models + Alembic migrations (`core/migrations.py`) |
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
- **Recovery:** the first admin's one-time recovery code, plus Shamir-split
  CA-key backup (`venya admin ca-backup`), are the designed break-glass
  paths.

## Trust and CA layout

| CA / cert | Location | Purpose |
|---|---|---|
| Venya root CA | core: `/var/lib/venya/ca/` | signs server TLS certs, relay client certs; distributed to clients via `/.well-known/venya-ca.crt` and installed into VM trust stores |
| Server TLS cert | core: `/etc/venya/tls/` | nginx termination for `<core-host>` |
| Relay client cert | core: `/etc/venya/relay/` | CN `<core-host>-relay`; presented when the core dials an executor's relay listener |
| Admin CA | core: `/var/lib/venya/ca/admin-ca/` (key encrypted) | admin mTLS client certs |
| Executor client cert | executor: `/etc/venya/executor/` (0700/0600) | executor → core mTLS identity; SAN = executor-id |
| Executor CA | executor: `/var/lib/venya/executor-ca/` | executor-local issuance |

Relay CN contract: executors accept relay connections only from client-cert
CNs listed in `relay_client_ids` (derived from the core hostname). Empty
allowlist = the relay listener refuses to bind (fail-closed); CN mismatch =
handshake rejection. Both directions verify; nothing falls back to
unauthenticated transport.

## Secret lifecycle (zero-knowledge injection)

1. **Store.** Secret value encrypted server-side under envelope encryption
   (KEK-wrapped DEK, AES-256), scoped to roles. Plaintext never persists;
   the API never returns values — only metadata (key, roles, purpose,
   executor hints) for discovery by humans and LLMs.
2. **Dispatch.** For a `run_command`/`venya run` execution, the server
   decrypts, wraps the value in cryptographic sentinel markers, and sends it
   over the mTLS relay channel to the targeted executor. The calling client
   (human or LLM) sees only the command result — the wrapped blob is routed
   server → executor, never through the caller.
3. **Inject.** The executor unwraps **inside the sbx sandbox** and injects
   into the command environment. Execution sessions are ephemeral (tmpfs
   secrets mount).
4. **Filter.** stdout/stderr pass through the Rust filter, which replaces
   any occurrence of secret material with `[REDACTED:...]` before the output
   returns to the caller.
5. **Audit.** Every step records actor, command string, executor id,
   secret ids (never values), and timestamps. Non-admin users querying
   `get_audit` see only their own events (enforced server-side).

## Sandbox and egress

Commands run in sbx (Docker Sandboxes) microVMs. Networking is
deny-by-default against `/etc/venya/egress-allowlist.txt` (the installer
seeds the local subnet + DNS); a compromised command cannot phone home.
The executor service runs under a seccomp profile, `PrivateTmp`, and no
`CAP_IPC_LOCK` (mlock is confined to the core by design and enforced by
tests in both packages). The daemon user has KVM access for sandboxing;
sandbox SSH tooling requires absolute binary paths (builtins are rejected
by design — 503).

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
