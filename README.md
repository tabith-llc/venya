# Venya

> **AI agents:** start at **[docs/agents.md](docs/agents.md)** — how to install, configure, and operate
>
> **Wiring an agent?** paste the operating contract from **[docs/agent-prompts.md](docs/agent-prompts.md)** into its instruction file (AGENTS.md / CLAUDE.md / Cursor rules)

### AI agents manage infrastructure securely.

**First.** To our knowledge, the first platform where AI agents act with real credentials and never see one — zero-knowledge injection, FIDO2-elevated single-use disclosure, execution inside a fail-closed sandbox, and an audit trail that is append-only because the database makes it so, on infrastructure you host yourself. No other platform on the comparison we publish combines all five — [docs/security-landscape.md](docs/security-landscape.md). The LLM discovers what secrets exist, constructs the command, and the executor injects the credential into a sandboxed environment. Output is filtered. Every action is audited. A human authorized the session with a physical security key.

**To our knowledge, this combination ships nowhere else** — the side-by-side comparison is published in [docs/security-landscape.md](docs/security-landscape.md). Traditional secrets managers (HashiCorp Vault, CyberArk, cloud-native stores) store credentials — but they hand the plaintext to whatever process requests it. If you give an AI agent a Vault token, the agent can read every secret in plain text. Venya's zero-knowledge injection model means the agent never sees, handles, or can leak the credential value. It sees the result of the command — and nothing more. The same holds for the humans operating Venya: frontline operators authorize sessions, run commands, and read filtered output without ever seeing the credential values doing the work. Disclosure is a separate, deliberate act — FIDO2-elevated, single-use, audited — never part of normal operation. (Mechanized: values leave the server only through the elevation-gated unmask route or the mTLS executor-injection path; every disclosure is an audit event — see [docs/architecture.md](docs/architecture.md) "Secret lifecycle" and the Security Guarantees table below.)

### How it is controlled

Every mechanism named on this page is in the open: what a control enforces is written in
the doc that governs it, and you can hold the code to it.

- **Command policy, before execution.** The default blocklist — `scp`, `rsync`, `nc`,
  `ncat`, `sudo`, `su`, `dd`, `rm -rf`, `mkfs`, `fdisk`, `shred`, `mount`, `insmod`,
  `modprobe`, `chmod 4755`, `setuid` — ships on every executor, and an administrator can
  replace it wholesale —
  [docs/agents.md](docs/agents.md) "Hard rules" is the authority for what it covers, and
  it covers the **local (sandbox) half** of an `ssh`/`sshpass` command: tokens past the
  destination are remote-side and are not scanned by it. Name that scope when you depend
  on it.
- **Egress, deny-by-default, including names.** The sandbox reaches only what an
  allowlist authorizes, and its DNS is a policy-enforcing proxy: a hostname resolves if
  and only if that exact name is an entry. A target that is not allowlisted fails closed
  rather than quietly routing — [docs/architecture.md](docs/architecture.md) "Sandbox and
  egress", [docs/FIREWALL.md](docs/FIREWALL.md).
- **Command resolution.** Binaries must resolve into trusted directories, and whatever
  does not is refused before it starts. **No shell runs an agent's command — with one
  ruled exception:** a standalone `<` token naming a secret injected in the same call is
  the one form that does go through the guest shell, so the shell can open that file for
  the command it wraps; every other pipe, `&&`, or redirect is rejected
  ([docs/agents.md](docs/agents.md) "Hard rules", which carries the exception in full).
- **Secret handling.** Values are injected inside the sandbox and never enter the
  agent's context; output comes back redacted, and a filter failure returns nothing raw.
  Each kind of secret declares how it may be consumed, including the pairing a
  passphrase-protected key needs in the same call —
  [docs/secret-shapes.md](docs/secret-shapes.md).
- **Human authorization and revocation.** A session is authorized by a human touching a
  physical security key. Executor identity is mTLS-bound and revocable, and the
  revocation plane's lock behaviour is measured, not asserted —
  [docs/revocation-table-operations-runbook.md](docs/revocation-table-operations-runbook.md).
- **Audit.** Actor, command string, executor, secret ids (never values) and timestamps
  are recorded for every step; an admin or an auditor-tier caller querying `get_audit`
  sees the whole log and everyone else sees only their own events, enforced server-side.
  Reading a secret value is a separate, elevation-gated act that writes its own audit
  event — [docs/architecture.md](docs/architecture.md) "Secret lifecycle", and the tier
  itself in [docs/auditor-role.md](docs/auditor-role.md).
- **Change and recovery governance.** Deployed bytes trace to committed source
  ([docs/deploy-gate.md](docs/deploy-gate.md)), and backup is validated by a restore drill
  rather than by a file existing ([docs/BACKUPS.md](docs/BACKUPS.md)).
- **Every control above, one row at a time, with the command that re-derives it:**
  [docs/controls.md](docs/controls.md) states each mechanism as `file:symbol`, names the commit it
  was verified at, and gives the one command you run to check it yourself. A claim that cannot be
  re-derived that way is listed there as not verified, not quietly kept.

**No certification is claimed here.** Venya is software you host; it carries no
attestation and this page asserts none. What beta does **not** do is published, entry by
tracked entry, in [docs/beta-known-limitations.md](docs/beta-known-limitations.md) — read
that before treating any bullet above as a signed report.

---

[![Animated walkthrough: an agent runs a NAS failover incident — jreyes authorizes with a FIDO2 key and types one sentence; the agent lists executors and secrets, probes from network-01, fails over to storage-01, the credential travels Venya → executor → sandbox and the echoed password is redacted; every command audited](docs/diagrams/workflow.gif)](docs/example-workflow.md)

**Watch the full session: [the narrated example workflow →](docs/example-workflow.md)**

## Host Trust Model

Venya's components sit at deliberately different trust levels:

- **The core server is the trust anchor — give it its own protected host.**
  Firewalled, minimally exposed, reachable only by its executors (mTLS) and
  administrators. It holds the CA keys, the encrypted secret store, and the
  audit log.
- **Executor hosts are treated as compromised by design.** Agents run arbitrary
  commands on them, so Venya assumes an attacker may own the machine: secrets
  are injected only inside sandboxed microVMs, egress is deny-by-default,
  output is filtered, and executor identity is mTLS-bound and revocable. An
  executor breach must never become a core breach.

**Never install core and executor on the same machine.** Co-location merges the
trust anchor into the assume-compromised zone and voids the isolation above —
both services would run as the same OS user, letting a compromised executor
reach the core's key material. On a single physical machine, run the core and
each executor as separate virtual machines.

---

## Coming Soon

The following are planned for future releases:

- **Single sign-on (SSO).** Enterprise directory authentication (LDAP first)
  hybridized with WebAuthn hardware-key binding — passwords for identity,
  physical keys for privileged operations.
- **FIDO2 hardware attestation.** At enrollment, verify that security keys are
  genuine FIDO2-certified authenticators — checking attestation statements
  against FIDO Alliance metadata (make, model, and certification level), a
  depth beyond the enrollment-time attestation-CA allow/deny checks some
  products ship today — not merely holders of a registered credential.
- **PIV smart-card support.** FIPS 201 (PIV) certificate authentication for
  federal and regulated environments — a secondary login method alongside
  WebAuthn using dual-credential keys (FIDO2 + PIV, e.g. YubiKey 5-series),
  with configurable agency trust anchors and certificate revocation checking.
- **High-availability core.** Multi-node core deployment for availability
  without changing the trust-anchor model.
- **More secret shapes.** Beyond the shipped stack (env injection, askpass,
  sudo-stdin, sshpass): a custom shape registry so teams can define their own
  consumption patterns safely.
- **Offline-capable installation.** Self-contained install — vendored
  dependencies and locally seeded sandbox images; no internet access required
  from core or executor hosts at install or run time.
- **Fully air-gapped deployment.** Including guidance for local inference
  stacks — on the roadmap, behind the offline-capable tier.
- **TPM credential sealing.** Bind core service credentials to the host TPM so
  a stolen disk image alone cannot yield key material.
- **Audit export / SIEM integration.** Forward the append-only audit trail to
  external collectors (SIEM) for long-term retention and correlation.

---

## The Problem

Infrastructure teams are adopting AI agents (Claude Code, Cursor, autonomous coding assistants) to manage servers, deploy applications, and troubleshoot incidents. But these agents need credentials to do their work — SSH keys, API tokens, database passwords.

Today, teams solve this in one of three ways:

| Approach | What Happens | The Problem |
|----------|--------------|-------------|
| **Give the agent a Vault token** | Agent reads secrets in plaintext | Agent can exfiltrate every secret it can read. Full credential exposure. |
| **Embed credentials in prompts** | User pastes passwords into the chat | Credentials land in chat logs, model training data, and session histories. Catastrophic. |
| **Don't let AI touch infra** | Manual execution only | Defeats the purpose. Teams lose the velocity AI promises. |

Every approach either exposes credentials or blocks AI adoption. Venya is the fourth option.

---

## How Venya Works

```
Human: "The Reston datacenter NAS appears to be offline."
          │
          ▼
┌──────────────────┐     ┌───────────────────┐     ┌────────────────────┐
│   AI Agent       │────▶│  Venya Server     │────▶│  Executor Daemon   │
│  (Claude Code)   │     │                   │     │ (on executor host) │
│                  │     │  1. Wraps secret  │     │                    │
│  Never sees      │     │     with sentinel │     │  2. Unwraps in     │
│  the password    │     │     markers       │     │     sandbox        │
│                  │     │                   │     │                    │
│  Sees: exit code │◀────│  3. Relays via    │◀────│  4. Filters output │
│  + filtered      │     │     mTLS          │     │     (Rust filter)  │
│  output          │     │                   │     │                    │
└──────────────────┘     └───────────────────┘     └────────────────────┘
```

1. **The human asks the AI to do something** — e.g., "The Reston datacenter NAS appears to be offline."
2. **The AI discovers available resources** — calls Venya's MCP tools to list executors and secrets (metadata only, never values)
3. **The AI constructs the command** — e.g., `sshpass -f /run/secrets/venya/12 ssh nas-admin@192.0.2.40 get-volume-status reston-data-01` — the stored password is consumed as a file inside the sandbox, never pasted into the command
4. **Venya handles the rest:**
   - Server decrypts the secret and wraps it with cryptographic sentinel markers
   - Server relays the command + wrapped secret to the executor over mutual TLS
   - Executor materializes the secret as a read-only file inside the isolated sbx microVM (`/run/secrets/venya/<id>`, mode 0400) — the command consumes it there; the plaintext exists only transiently in executor-host RAM (tmpfs staging, never disk), zeroed and deleted at run end
   - A Rust-based output filter scans stdout/stderr for any leaked secret values and replaces them with `[REDACTED:<id>]` markers before the AI ever sees it
5. **The AI reads the filtered output** — it sees the command succeeded, sees the volume-status report, but never sees the password
6. **Every step is logged** — the audit trail records who authorized the session, what command ran, on which executor, and when

When the first probe fails, the agent adapts — switches executors, escalates, triggers a controlled failover — and every step lands in the audit trail, still without touching a credential value. **See how it ends: the full narrated incident, every call and its exact output → [docs/example-workflow.md](docs/example-workflow.md)**

---

## Why Venya Is Different

### Zero-Knowledge Secret Injection
The AI agent never touches plaintext credentials. Not in its context window. Not in transit. Not in output. The secret is decrypted server-side, wrapped with sentinel markers, relayed over mTLS, and unwrapped only inside the executor's host daemon — the plaintext lives in RAM-backed tmpfs (never disk) and is consumed inside the sandbox. The Rust filter ensures that even if a command accidentally echoes a credential in its output, it's replaced with `[REDACTED:<id>]` before the AI ever sees it.

**To our knowledge, no other platform pairs this with the other four elements.** Existing secrets managers hand plaintext to the requesting process; several agent-credential tools now achieve this one element on its own — the [published comparison](docs/security-landscape.md) names them. Venya's difference is the combination.

### FIDO2 Security Key Binding
Every session begins with a physical security key press. The AI agent cannot initiate a session — only a human pressing a FIDO2 key can authorize access. Sessions expire after 4 hours. Token refresh happens automatically, and an idle-expired session renews within the 4-hour hard cap — no token, refresh, or agent action can extend a session past the cap (operators can raise the cap only through the documented server setting; see [docs/ease-of-use.md](docs/ease-of-use.md)). When the session is past the cap, the AI gets an actionable error: *"Ask the user to re-authenticate."*

### mTLS Between Server and Executor
The Venya server communicates with executor daemons over mutual TLS. Both sides verify each other's certificates: the executor's relay listener requires a client certificate (`CERT_REQUIRED`) chained to the core CA and allow-listed by CN, and the core dials the executor with its own client certificate. If an executor's certificate is revoked, the server refuses to relay commands; if the executor's credential is revoked or expired (or the core holds no registered certificate for it at all), the dial is refused before any command leaves the core. The executor's own relay listener adds the last refusal: once the daemon holds a revocation answer that says revoked — or has received no answer at all since it started — new connections to :8443 are closed at accept, before a single request byte is read. If someone spoofs an executor, the mTLS handshake fails before any secret is transmitted. Verification is per connection and per operation (session, role gate, single-use elevation token) — identity is never inferred from network position.

**Honest scope of that enforcement (do not over-read it):** a revoked credential is refused *when the request is served, not when the connection opens*. The TLS handshake still completes and the refused peer receives no HTTP response. Connection-layer revocation enforcement (a CRL consulted during the handshake, at the proxy or in the TLS stack) is a separate, unadopted design — and nothing in this product publishes a CRL Distribution Point by default, so no document here should be read as saying one exists.

### Egress Control
Commands run inside an sbx microVM with deny-by-default networking. The executor reads an operator-defined allowlist (`/etc/venya/egress-allowlist.txt`) and only permits connections to approved destinations. If a compromised command tries to phone home to an attacker's server, the connection is blocked at the sandbox level. DNS is restricted to the operator's resolver.

**Who enforces it, and what it can see.** Venya registers the per-host allow rules; the denying is done by **Docker's `sbx` proxy**, a layer-7 egress inspector that terminates sandbox HTTPS and presents certificates minted by its own CA, pre-installed in the sandbox image's trust store. So the block is on **content**: a destination that is not allowed is refused on the request, but the tunnel to it is set up first, which means **destination and SNI can leave the sandbox even when the payload is denied**. And because that proxy sits in the middle of every HTTPS session a sandbox opens, **a certificate check run from inside a sandbox tells you about the proxy, not about the server you think you reached.**

### Complete Audit Trail
Every command execution is logged:
- **Who** authorized the session (FIDO2-enrolled user)
- **What** command was executed (full command string)
- **Where** it ran (executor ID)
- **When** it ran (timestamp)
- **What secrets** were injected (secret IDs, never values)

Both human operators (via `venya audit` CLI) and AI agents (via the `get_audit` MCP tool) can query the audit log. Callers holding admin or an auditor-tier role see the full log; all others see only their own events. The log is append-only by database enforcement — a dedicated runtime role is revoked `UPDATE`/`DELETE` on the audit table (see the Security Guarantees table below and docs/deployment-config.md).

### MCP Protocol Native
Venya speaks the Model Context Protocol — the open standard for connecting AI assistants to external tools. It works with Claude Code, Cursor, and any MCP-compatible client. No proprietary lock-in. No vendor-specific API.

---

## Security Guarantees

The table below states what the product enforces. For what a beta release does not do yet, and what an operator does about each, see [docs/beta-known-limitations.md](docs/beta-known-limitations.md).

| Guarantee | How It's Enforced |
|-----------|-------------------|
| AI never sees plaintext credentials | Server-side wrapping + executor-side unwrapping + Rust output filter |
| Sessions require human authorization | FIDO2 security key binding (WebAuthn) |
| Sessions are time-limited | 4-hour hard cap, 15-minute idle window, 5-minute access tokens |
| Executor identity is verified | Mutual TLS with certificate chain validation |
| Compromised executors are blocked | A revoked credential is refused when the request is served — by the core's relay dial, by the executor's inbound gates, by the daemon's own revocation poll, and by the executor's relay listener at connection-accept time. This is post-handshake enforcement, not connection-layer CRL enforcement (see the note below) |
| Data exfiltration is prevented | sbx sandbox with deny-by-default egress allowlisting: Venya registers the per-host allows, Docker's `sbx` layer-7 proxy denies everything else. The proxy terminates sandbox HTTPS with its own CA (pre-installed in the image trust store) to make that decision, so it blocks content — a denied destination can still see a tunnel, and its name and SNI leave the sandbox; a certificate chain verified inside a sandbox is verified against that proxy (see Egress Control) |
| Every action is traceable | Append-only audit log with user, executor, command, timestamp |
| Secrets are encrypted at rest | Envelope encryption — per-secret DEK wrapped with AES-256-KW; payload ChaCha20-Poly1305 |

---

## Roles & Permissions

Human callers get a role tier: **read**, **read-write**, or **auditor**
(created with `venya role create <name> --permissions <tier>`, assigned by
an admin; the seeded `admin` role holds read-write).

- **read** — metadata listings and masked secret reads. No audit-log access.
- **read-write** — everything above plus writes: create/delete secrets,
  create sessions, execute commands. Audit-log access included.
- **auditor** — the compliance tier: read visibility across secrets, roles
  and executors (metadata) plus full audit-log access, with an affirmative
  deny on secret **values**. An auditor-only caller gets a 403 on any value
  read — even with a valid elevation token, refused before the token is
  consumed, and every refusal is audit-logged. Elevation is not issued to
  auditor-only callers at all, so they cannot self-add FIDO2 credentials
  (an admin provisions them).

The auditor tier is **exclusive by design** (separation of duties): any
role grant or tier flip that would combine auditor with another tier is
refused with 409 and audit-logged, so audit independence is enforced by
construction. This design supports NIST SP 800-53 Rev 5 **AC-5**
(separation of duties), **AU-3/AU-6** (audit-record content and review —
denials are logged, auditors see the full trail including their own
denials), and PCI DSS **10.2.1** (failed-access logging) — aligned with,
not certified by; attestation requires an assessor. Auditor-tier holders
see the full audit log (all users' events), like the `admin` role; other
callers see only their own events. Details:
[docs/auditor-role.md](docs/auditor-role.md).

---

## Who Is Venya For?

**Infrastructure teams who want to use AI without compromising security.**

If your team is:
- Using Claude Code, Cursor, or similar AI coding assistants
- Managing fleets of servers, databases, or cloud infrastructure
- Concerned about handing credentials to AI agents
- Operating in regulated environments where audit trails are mandatory
- Tired of the choice between "move fast with AI" and "stay secure"

Venya is the bridge.

---

## Getting Started

Venya is currently in **beta** — the design-partner program, by application: we screen for feedback fit, not a quota.

### Quick Start (5-Minute Demo)

See Venya in action: **[Alpha Demo Guide](docs/alpha-demo.md)** — hands-on in 5 minutes, or the **[narrated incident walkthrough](docs/example-workflow.md)** — what an agent session looks like start to finish.

### Full Installation

Artifacts (installers, tarballs, SHA-256 sidecars) are published on the **[Releases page](https://github.com/tabith-llc/venya/releases)**. Install one-liners (core/executor: Ubuntu 24.04 only; the Workstation CLI additionally runs on Debian 13, macOS, and Windows):

```bash
# Core server (root)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_DB_PASSWORD=<strong-db-password> \
  VENYA_DB_PASSPHRASE=<server-encryption-passphrase> bash -s

# Executor (root; enrollment token from the core admin; a Docker account is REQUIRED — sbx pulls its agent
# template from Docker Hub. Piped installs need VENYA_DOCKER_USERNAME/VENYA_DOCKER_API_KEY, or download the
# script and run it interactively for hidden-prompt entry — the key is handled stdin-only, never argv/disk.
# See installation.md §3.)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_SERVER_URL=https://<core-host> VENYA_EXECUTOR_ID=<executor-id> \
  VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token> bash -s

# Workstation CLI (non-root; Ubuntu 24.04, Debian 13, or macOS — verified on macOS 26.6.2 arm64 and Debian 13)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-cli.sh | VENYA_SKIP_PROMPT=yes bash
```

```powershell
# Workstation CLI (Windows) — machine-wide install, requires Administrator;
# standard users run the CLI afterward. Interactive desktop only (headless unsupported).
# Download install-venya-cli.ps1 from the Releases page, then run:
powershell -ExecutionPolicy Bypass -File install-venya-cli.ps1
```

Integrity: pin `VENYA_TARBALL_SHA256` (hashes on the release page) for strict verification; unset, the installer fetches the `.sha256` sidecar from the same origin as a corruption guardrail and fail-closes.

Core and executor must run on separate hosts (or separate VMs on one physical machine) — see [Host Trust Model](#host-trust-model).

Workstation CLI config file: `~/.config/venya/config.json` on Linux, `~/Library/Application Support/venya/config.json` on macOS, `%APPDATA%\venya\config.json` on Windows. FIDO2 needs no extra setup on macOS (native IOKit HID transport, no root) or Windows (platform WebAuthn API — standard-user capable, interactive desktop required); on Linux the installer prints udev rules if `/dev/hidraw*` is not user-readable.

Production deployment guide: **[Installation Guide](docs/installation.md)**

### Prerequisites

- Linux — Ubuntu 24.04 LTS (core/executor; tested target, installers assume it). Workstation CLI additionally supports Debian 13 and macOS (verified macOS 26.6.2 arm64)
- Windows — **Workstation CLI only** (core and executor are Linux). Machine-wide install via `install-venya-cli.ps1` requires Administrator; standard users run the CLI after install. FIDO2 ceremonies work for standard users via the platform WebAuthn API (verified Windows 11 25H2). Interactive desktop only — headless Windows is unsupported
- PostgreSQL — installed automatically by the core installer (16 on Ubuntu 24.04)
- Python 3.14 — pinned (`>=3.14,<3.15`); provisioned automatically via uv
- FIDO2 security key — Tabith LLC recommends Yubico YubiKey® for Venya
- Docker Sandboxes (sbx) — installed automatically by the executor installer; **a Docker account is required** (username + API key/access token at install time, stdin-only): sbx pulls its agent template from Docker Hub, so executor installs need a Docker account and outbound access to Docker Hub. **Executor hosts need hardware-virtualization access (`/dev/kvm`) — sbx runs microVMs; VM deployments require nested virtualization enabled**
- MCP-compatible AI client (Claude Code, Cursor)

### Components

| Package | Purpose |
|---------|---------|
| `packages/core` | Shared library — IAM models, encryption engine, migrations |
| `packages/server` | FastAPI core server — REST API, FIDO2 ceremonies, secrets, audit |
| `packages/executor` | Remote daemon — sandboxed execution, secret injection, redaction |
| `packages/cli` | Workstation CLI (`venya`) — admin, enrollment, execution client |
| `packages/mcp` | MCP server (`venya-mcp`) — exposes Venya tools to LLM clients |
| `packages/venya-contract` | Frozen relay wire contract — shared request/response models (`extra="forbid"`) that prevent silent field drift between core and executor |
| Rust filter extension | Output redaction (`[REDACTED:...]` markers) before return |
| Installer / uninstaller scripts | `install-venya-{core,executor,cli}.sh` + matching `uninstall-venya-*.sh` (see `install-scripts-README.md`) |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         Venya Architecture                       │
│                                                                  │
│  ┌──────────┐    ┌───────────────┐    ┌───────────────────────┐  │
│  │ AI Agent │    │ Venya Server  │    │ Executor Daemon       │  │
│  │ (Claude, │───▶│ (Core)        │───▶│ (executor host)       │  │
│  │ Cursor)  │    │               │    │                       │  │
│  │          │    │ • Secret store│    │ • sbx sandbox         │  │
│  │ MCP stdio│    │ • FIDO2 auth  │    │ • Secret injection    │  │
│  │ transport│    │ • Audit log   │    │ • Rust output filter  │  │
│  │          │    │ • mTLS relay  │    │ • Egress allowlist    │  │
│  └──────────┘    └───────────────┘    └───────────────────────┘  │
│                         │                         │              │
│                    ┌────┴──────┐                  │ SSH          │
│                    │PostgreSQL │             ┌────┴─────────┐    │
│                    │(secrets   │             │ Target hosts │    │
│                    │encrypted) │             └──────────────┘    │
│                    └───────────┘                                 │
└──────────────────────────────────────────────────────────────────┘
```

**Technical deep dive:** [Architecture Documentation](docs/architecture.md)

---

## Testing

Full A-Z testing is ongoing. Venya is validated end-to-end from a clean
hypervisor: VM provision → core/executor/CLI install from hash-verified
tarballs → FIDO2 identity bootstrap (with wrong-key and replay negatives) →
secret creation → an MCP `run_command` that consumes the secret with the value
redacted from all output. Live full-lifecycle runs are re-verified against
each release's bytes (evidence in the per-release records);
the unit suites across all six packages (cli / core / server / executor / mcp /
venya-contract, Python 3.14) are green — absolute counts deliberately live in
the per-release records, not here (they rot with every merge).

- **Run it yourself:** the [Full-Lifecycle Test Plan](docs/full-lifecycle-test.md)
  is fully self-contained — commands, gates, failure modes, verification
  queries, results template — and ships with an
  [interactive MCP driver](docs/mcp-manual-drive.py) so you can drive the
  tools by hand and see the redaction proof yourself.
- **Verified MCP clients:** [opencode](https://opencode.com) and local LLMs
  via [omlx.ai](https://omlx.ai) — both drive `venya-mcp` as a stdio server.
- **Hardware:** FIDO2 ceremonies verified with Yubico Security Keys.
- **Longer timeouts for testing:** default session idle is 15 min inside a 4 h
  hard cap, and executor enrollment tokens expire in 30 min. For relaxed test
  runs, append to `/opt/venya/.env` on the core, restart, and **re-login**
  (existing sessions keep their original expiry):

  ```bash
  echo 'VENYA_SESSION__SESSION_TIMEOUT=28800' | sudo tee -a /opt/venya/.env
  echo 'VENYA_SESSION__MAX_SESSION_DURATION=28800' | sudo tee -a /opt/venya/.env
  echo 'VENYA_EXECUTOR_ENROLLMENT__TOKEN_TTL_SECONDS=14400' | sudo tee -a /opt/venya/.env
  sudo systemctl restart venya-core
  ```

  Raise the idle window and the hard cap **together**: a
  `VENYA_SESSION__SESSION_TIMEOUT` above `VENYA_SESSION__MAX_SESSION_DURATION`
  (default 14400 s = 4 h) is rejected while the config is built, so the core
  **refuses to start** rather than simply keeping the shorter window. What each
  knob costs you is tabulated in [docs/ease-of-use.md](docs/ease-of-use.md).

---

## FAQ

**Is Venya open source?**

Venya is licensed under the Business Source License (BSL) 1.1 — source-available, not OSI open source. You may use, modify, and create derivative works (including for production), provided your organization's total consolidated revenue is below **US $10 million** per year and you do not offer Venya to third parties on a hosted or embedded basis in order to compete with Tabith LLC's commercial offerings. At or above the revenue threshold — or for competing hosted/embedded offerings — a commercial license is required: **info@tabith.com**.

Each version converts to **MPL 2.0** four years after that version's first public distribution (the Change Date is defined per version) — older versions become open source over time.

This is the same licensing model used by HashiCorp (Vault, Terraform).

**Can the AI agent extract secrets by crafting clever commands?**

No. The agent never receives plaintext: the secret is injected only inside the sandbox — a per-session tmpfs file at `/run/secrets/venya/<id>` (0400, zeroed after the run; the env/askpass/sudo consumption shapes ride the same file-mediated transport) — and every byte of stdout/stderr passes two redaction stages (the executor's Rust filter, then the server-side definitive filter, which fails closed) that replace secret values with `[REDACTED:<id>]` markers before the output returns. A command that `cat`s the secret demonstrates the filter, not a bypass. Network exfiltration is blocked by deny-by-default egress allowlisting; the sandbox boundary is the containment — see the [full FAQ](docs/faq.md).

**What if the AI agent goes rogue?**

Three layers of defense:
1. **Egress control** — the sandbox blocks outbound connections to non-allowlisted destinations. Data can't leave.
2. **Session cap** — sessions expire after 4 hours. The agent can't maintain indefinite access.
3. **Audit trail** — every command is logged with the authorizing user's identity. Rogue behavior is recorded in full and reviewable in the audit trail — through review of the log, not live intrusion detection.

**How is this different from HashiCorp Vault or CyberArk?**

Vault and CyberArk store secrets and hand plaintext to whoever has a valid token. If an AI agent has a Vault token, it can read every secret in plaintext and exfiltrate it. Venya's zero-knowledge injection model means the agent never receives plaintext — it only sees the result of the command that used the credential. The secret traverses the system inside cryptographic sentinel wrappers and is only unwrapped inside the sandboxed execution environment.

Full FAQ: [docs/faq.md](docs/faq.md)

---

## About

**Venya** is a product of [Tabith LLC](https://tabith.com/), built by IT engineers with decades of experience managing systems at scale — from Unix administration of dozens of servers to coding for platforms handling billions of dollars in revenue.

We built Venya because we lived the problem. We managed the infrastructure. We held the credentials. We watched teams struggle with the tension between automation and security. We didn't find a solution, so we built one.

Visit [venya.ai](https://venya.ai/) to learn more or apply for beta access.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Alpha Demo Guide](docs/alpha-demo.md) | 5-minute end-to-end demo |
| [Example Workflow](docs/example-workflow.md) | Narrated incident-response walkthrough — every MCP call and its exact output |
| [Full-Lifecycle Test Plan](docs/full-lifecycle-test.md) | A-Z validation from clean hypervisor to MCP use-a-secret proof |
| [Installation Guide](docs/installation.md) | Full deployment instructions |
| [Beta Known Limitations](docs/beta-known-limitations.md) | What works in a beta release, what does not yet, and what an operator does about each |
| [CLI Reference](docs/cli-reference.md) | Every `venya` command and argument — generated from the parser, test-enforced against drift |
| [Architecture](docs/architecture.md) | Technical deep dive |
| [Deployment Configuration](docs/deployment-config.md) | Required config fields, env-var mapping, validation timing |
| [The Auditor Role](docs/auditor-role.md) | The auditor permission tier: full audit visibility, no secret values, audited denials |
| [Making Venya Easier to Use](docs/ease-of-use.md) | Deliberate relaxations: the scp worked recipe, per-knob gain/loss catalog, the never-relax list |
| [Deployment Sizing Guide](docs/deployment-sizing.md) | How many executors you need + measured CPU/RAM/disk/throughput figures |
| [Cert & Key Rotation Runbook](docs/cert-rotation-runbook.md) | Rotation procedures for every certificate and key, source-cited |
| [Firewall & Network Requirements](docs/FIREWALL.md) | Ports/protocols per host type — *(beta, untested)* |
| [Backup & Restore](docs/BACKUPS.md) | What to back up, the crypto pairings, restore + backup security — *(restore procedure validated by physical drill, 2026-09-30, on 0.1.0alpha16; record at the top of the doc)* |
| [FAQ](docs/faq.md) | Frequently asked questions |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy + safe harbor |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute (incl. license terms for contributions) |
| [Agent Instructions](docs/agents.md) | Brief for LLM agents operating Venya via MCP |
| [Agent Prompts](docs/agent-prompts.md) | Paste-ready operating contract for your agent's instruction file (AGENTS.md / CLAUDE.md / Cursor rules) |
| [Third-Party Notices](THIRD-PARTY-NOTICES.md) | Third-party components and licenses (incl. required proprietary Docker sbx) |

---

## License

Venya is licensed under the Business Source License (BSL) 1.1, Copyright © 2026 Tabith LLC. Free to use, modify, and build on (including in production) below the **US $10M** total-revenue threshold and for non-competing use; a commercial license is required above it or for competing hosted/embedded offerings. Each version converts to **MPL 2.0** four years after its first public distribution.

See [LICENSE](LICENSE) for the full terms. Contributions are accepted under the same license — see [CONTRIBUTING.md](CONTRIBUTING.md). Third-party components Venya depends on — including the required, proprietary Docker Sandboxes (sbx) runtime, governed by the Docker Subscription Service Agreement — are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

---

*Venya™ is a trademark pending with the USPTO, owned by Tabith LLC. This software is in beta and not yet certified for regulated environments. Security claims on this page describe design properties of the software, not formal attestations.*

*Tabith LLC recommends YubiKey® security keys for Venya. Yubico and YubiKey are registered trademarks of Yubico AB. All other trademarks are the property of their respective owners.*
