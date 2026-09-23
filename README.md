# Venya

> **AI agents:** if you are an LLM agent that retrieved this README, start at **[docs/agents.md](docs/agents.md)** — how to wire up, operate safely, and what never to attempt. Humans: that file is the brief your agent should be handed.

### AI agents manage infrastructure securely.

Venya is the first platform that lets AI agents execute commands on remote infrastructure using stored credentials **without ever seeing those credentials**. The LLM discovers what secrets exist, constructs the command, and the executor injects the credential into a sandboxed environment. Output is filtered. Every action is audited. A human authorized the session with a physical security key.

**This doesn't exist anywhere else.** Traditional secrets managers (HashiCorp Vault, CyberArk, cloud-native stores) store credentials — but they hand the plaintext to whatever process requests it. If you give an AI agent a Vault token, the agent can read every secret in plain text. Venya's zero-knowledge injection model means the agent never sees, handles, or can leak the credential value. It sees the result of the command — and nothing more.

---

## Host Trust Model

Venya's components carry deliberately different trust postures:

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
Human: "Install apache2 on web-server-3"
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

1. **The human asks the AI to do something** — e.g., "Install apache2 on web-server-3"
2. **The AI discovers available resources** — calls Venya's MCP tools to list executors and secrets (metadata only, never values)
3. **The AI constructs the command** — e.g., `ssh bot@web-server-3 sudo apt install -y apache2`
4. **Venya handles the rest:**
   - Server decrypts the secret and wraps it with cryptographic sentinel markers
   - Server relays the command + wrapped secret to the executor over mutual TLS
   - Executor unwraps the secret inside an isolated sbx microVM and injects it into the command
   - A Rust-based output filter scans stdout/stderr for any leaked secret values and replaces them with `[REDACTED]` markers before the AI ever sees it
5. **The AI reads the filtered output** — it sees the command succeeded, sees the package installation logs, but never sees the password
6. **Every step is logged** — the audit trail records who authorized the session, what command ran, on which executor, and when

---

## Why Venya Is Different

### Zero-Knowledge Secret Injection
The AI agent never touches plaintext credentials. Not in its context window. Not in transit. Not in output. The secret is decrypted server-side, wrapped with sentinel markers, relayed over mTLS, and unwrapped only inside the executor's sandboxed process. The Rust filter ensures that even if a command accidentally echoes a credential in its output, it's replaced with `[REDACTED]` before the AI ever sees it.

**No other product does this.** Existing secrets managers hand plaintext to the requesting process. Venya doesn't.

### FIDO2 Hardware Key Binding
Every session begins with a physical security key press. The AI agent cannot initiate a session — only a human pressing a FIDO2 key can authorize access. Sessions expire after 4 hours. Token refresh happens automatically, and an idle-expired session renews within the 4-hour hard cap — the cap is non-negotiable: past it, a human must re-authenticate with the FIDO2 key. When the session is past the cap, the AI gets an actionable error: *"Ask the user to re-authenticate."*

### mTLS Between Server and Executor
The Venya server communicates with executor daemons over mutual TLS. Both sides verify each other's certificates. If an executor's certificate is revoked, the server refuses to relay commands. If someone spoofs an executor, the mTLS handshake fails before any secret is transmitted.

### Egress Control
Commands run inside an sbx microVM with deny-by-default networking. The executor reads an operator-defined allowlist (`/etc/venya/egress-allowlist.txt`) and only permits connections to approved destinations. If a compromised command tries to phone home to an attacker's server, the connection is blocked at the sandbox level. DNS is restricted to the operator's resolver.

### Complete Audit Trail
Every command execution is logged:
- **Who** authorized the session (FIDO2-enrolled user)
- **What** command was executed (full command string)
- **Where** it ran (executor ID)
- **When** it ran (timestamp)
- **What secrets** were injected (secret IDs, never values)

Both human operators (via `venya audit` CLI) and AI agents (via the `get_audit` MCP tool) can query the audit log. Non-admin users see only their own events.

### MCP Protocol Native
Venya speaks the Model Context Protocol — the open standard for connecting AI assistants to external tools. It works with Claude Code, Cursor, and any MCP-compatible client. No proprietary lock-in. No vendor-specific API.

---

## Security Guarantees

| Guarantee | How It's Enforced |
|-----------|-------------------|
| AI never sees plaintext credentials | Server-side wrapping + executor-side unwrapping + Rust output filter |
| Sessions require human authorization | FIDO2 hardware key binding (WebAuthn) |
| Sessions are time-limited | 4-hour hard cap, 15-minute idle window, 5-minute access tokens |
| Executor identity is verified | Mutual TLS with certificate chain validation |
| Compromised executors are blocked | Revoked certs rejected at the executor's next revocation poll |
| Data exfiltration is prevented | sbx sandbox with deny-by-default egress allowlisting |
| Every action is traceable | Append-only audit log with user, executor, command, timestamp |
| Secrets are encrypted at rest | AES-256 with KEK-wrapped DEK (envelope encryption) |

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

Venya is currently in **alpha** — early access for teams who want to shape the product.

### Quick Start (5-Minute Demo)

See Venya in action: **[Alpha Demo Guide](docs/alpha-demo.md)**

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
- FIDO2 security key (YubiKey, SoloKeys, etc.)
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
redacted from all output. Two live full-lifecycle runs passed on 2026-09-17;
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
- **Hardware:** FIDO2 ceremonies verified with the Yubico **Security Key C
  NFC** — Basic Compatibility, MFA security key and passkey, USB-C or NFC,
  FIDO Certified — $29 on Amazon.
- **Longer timeouts for testing:** default session idle is 15 min and executor
  enrollment tokens expire in 30 min. For relaxed test runs, append to
  `/opt/venya/.env` on the core, restart, and **re-login** (existing sessions
  keep their original expiry):

  ```bash
  echo 'VENYA_SESSION__SESSION_TIMEOUT=28800' | sudo tee -a /opt/venya/.env
  echo 'VENYA_EXECUTOR_ENROLLMENT__TOKEN_TTL_SECONDS=14400' | sudo tee -a /opt/venya/.env
  sudo systemctl restart venya-core
  ```

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Alpha** | 🔄 Current | Core secret management, MCP integration, mTLS relay, egress control |
| **Beta** | 📋 Planned | TLS hardening, SSE transport, SaaS deployment option, expanded audit querying |
| **GA** | 🔮 Future | Multi-region support, RBAC expansion, compliance certifications, SSO integration |

---

## FAQ

**Is Venya open source?**

Venya is licensed under the Business Source License (BSL) 1.1 — source-available, not OSI open source. You may use, modify, and create derivative works (including for production), provided your organization's total consolidated revenue is below **US $10 million** per year and you do not offer Venya to third parties on a hosted or embedded basis in order to compete with Tabith LLC's commercial offerings. At or above the revenue threshold — or for competing hosted/embedded offerings — a commercial license is required: **info@tabith.com**.

Each version converts to **MPL 2.0** four years after that version's first public distribution (the Change Date is defined per version) — older versions become open source over time.

This is the same licensing model used by HashiCorp (Vault, Terraform).

**Can the AI agent extract secrets by crafting clever commands?**

No. The agent never receives plaintext: the secret is injected only inside the sandbox — a per-session tmpfs file at `/run/secrets/venya/<id>` (0400, zeroed after the run; the env/askpass/sudo consumption shapes ride the same file-mediated transport) — and every byte of stdout/stderr passes two redaction stages (the executor's Rust filter, then the server-side definitive filter, which fails closed) that replace secret values with `[REDACTED]` markers before the output returns. A command that `cat`s the secret demonstrates the filter, not a bypass. Network exfiltration is blocked by deny-by-default egress allowlisting; the sandbox boundary is the containment — see the [full FAQ](docs/faq.md).

**What if the AI agent goes rogue?**

Three layers of defense:
1. **Egress control** — the sandbox blocks outbound connections to non-allowlisted destinations. Data can't leave.
2. **Session cap** — sessions expire after 4 hours. The agent can't maintain indefinite access.
3. **Audit trail** — every command is logged with the authorizing user's identity. Rogue behavior is immediately visible.

**How is this different from HashiCorp Vault or CyberArk?**

Vault and CyberArk store secrets and hand plaintext to whoever has a valid token. If an AI agent has a Vault token, it can read every secret in plaintext and exfiltrate it. Venya's zero-knowledge injection model means the agent never receives plaintext — it only sees the result of the command that used the credential. The secret traverses the system inside cryptographic sentinel wrappers and is only unwrapped inside the sandboxed execution environment.

Full FAQ: [docs/faq.md](docs/faq.md)

---

## About

**Venya** is a product of [Tabith LLC](https://tabith.com/), built by IT engineers with decades of experience managing systems at scale — from Unix administration of dozens of servers to coding for platforms handling billions of dollars in revenue.

We built Venya because we lived the problem. We managed the infrastructure. We held the credentials. We watched teams struggle with the tension between automation and security. We didn't find a solution, so we built one.

Visit [venya.ai](https://venya.ai/) to learn more or request alpha access.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Alpha Demo Guide](docs/alpha-demo.md) | 5-minute end-to-end demo |
| [Full-Lifecycle Test Plan](docs/full-lifecycle-test.md) | A-Z validation from clean hypervisor to MCP use-a-secret proof |
| [Installation Guide](docs/installation.md) | Full deployment instructions |
| [CLI Reference](docs/cli-reference.md) | Every `venya` command and argument — generated from the parser, test-enforced against drift |
| [Architecture](docs/architecture.md) | Technical deep dive |
| [Firewall & Network Requirements](docs/FIREWALL.md) | Ports/protocols per host type — *(alpha, untested)* |
| [Backup & Restore](docs/BACKUPS.md) | What to back up, the crypto pairings, restore + backup security — *(alpha, untested)* |
| [FAQ](docs/faq.md) | Frequently asked questions |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy + safe harbor |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute (incl. license terms for contributions) |
| [Agent Instructions](docs/agents.md) | Brief for LLM agents operating Venya via MCP |
| [Third-Party Notices](THIRD-PARTY-NOTICES.md) | Third-party components and licenses (incl. required proprietary Docker sbx) |

---

## License

Venya is licensed under the Business Source License (BSL) 1.1, Copyright © 2026 Tabith LLC. Free to use, modify, and build on (including in production) below the **US $10M** total-revenue threshold and for non-competing use; a commercial license is required above it or for competing hosted/embedded offerings. Each version converts to **MPL 2.0** four years after its first public distribution.

See [LICENSE](LICENSE) for the full terms. Contributions are accepted under the same license — see [CONTRIBUTING.md](CONTRIBUTING.md). Third-party components Venya depends on — including the required, proprietary Docker Sandboxes (sbx) runtime, governed by the Docker Subscription Service Agreement — are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

---

*Venya™ is a trademark pending with the USPTO, owned by Tabith LLC. This software is in alpha and not yet certified for regulated environments. Security claims on this page describe design properties of the software, not formal attestations.*
