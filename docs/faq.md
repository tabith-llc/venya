# Venya FAQ

Expanded answers; the short forms live in the [README](../README.md).

## Product

**What is Venya, in one sentence?**
A secrets broker for humans and AI agents: credentials stay in the vault,
commands that need them run in sandboxed executors, and everything is
FIDO2-authorized and audited.

**Does Venya replace SSH or my vault?**
No. Executors still reach targets over SSH with real credentials — the
difference is that those credentials live in Venya, are injected per-command
inside a sandbox, and are never revealed to the operator or the LLM. Venya
replaces the *workflow* of handing credentials to people and agents.

**Who is it for?**
Teams letting AI coding agents (Claude Code, Cursor, any MCP client) touch
real infrastructure, and teams in regulated environments that need
per-command attribution. See the README's "Who Is Venya For?".

## Security

**Can the AI agent extract secrets by crafting clever commands?**
The agent never receives plaintext: wrapped material routes server →
executor, unwraps only inside the sbx sandbox as a tmpfs file
(`/run/secrets/venya/<id>`), and all stdout/stderr pass a Rust redaction
filter that replaces secret material with `[REDACTED:...]` before it
returns. A command that `cat`s the secret demonstrates the filter, not a
bypass (see the [alpha demo](alpha-demo.md)). Exfiltration over the network
is blocked by deny-by-default egress allowlisting.

**What if the agent goes rogue?**
Three layers: egress control (nothing leaves except allowlisted
destinations), session caps (15-minute idle window, 4-hour hard cap,
5-minute tokens — an agent cannot renew a human's authorization), and the
audit trail (every command attributed to the FIDO2-authenticated human who
authorized the session).

**Is the redaction filter bypassable via encodings?**
The filter matches secret byte patterns in command output; the sentinel
wrapping and per-session hash registry cover the injected values themselves.
This is defense that assumes the sandbox boundary holds — which is why
egress is deny-by-default and the executor runs seccomp-confined without
CAP_IPC_LOCK.

**How are executors authenticated?**
X.509 client certificates issued by the core at enrollment (single-use
bootstrap token, stored hashed, ~30-minute TTL). Rotation supported;
revocation propagates via the executor's revocation-list polling. The core
dials executors' relay listeners over mTLS with a CN-allowlisted
relay client certificate — fail-closed in both directions.

**What happens if the core is compromised?**
Secrets are envelope-encrypted at rest (KEK-wrapped DEK); the Admin CA key
is encrypted at rest; executors hold no vault plaintext between executions
(tmpfs, zeroed after each run). CA-key backup uses Shamir splitting
(`venya admin split-ca-key`) so no single backup artifact reconstructs the
key.

## Authentication

**Which security keys work?**
Any FIDO2/WebAuthn USB HID key. YubiKey and TrustKey devices are the tested
references. Non-root key access on Linux may need a udev rule — the
workstation installer prints the exact commands if your user cannot reach
`/dev/hidraw*`.

**Can I use passwords or TOTP?**
No. There is no password pathway for humans — that is the point. Lost key =
the one-time recovery code (printed at enrollment) or admin re-enrollment.

**Why do sessions expire so aggressively?**
Because an LLM client holds the session token. Short idle windows and a hard
4-hour cap bound what a compromised or runaway client can do; re-authorization
always means a human touching a physical key.

## Deployment

**What platforms are supported?**
Ubuntu 24.04 LTS is the tested server target; workstations are Linux
(macOS/Windows CLI support is tracked, not shipped). Python 3.14 is pinned
and provisioned automatically — you do not install it.

**Can Venya run air-gapped?**
Not turnkey yet. Full offline installation is a tracked beta goal; the
installers currently fetch toolchains and packages at install time. A local
mirror procedure exists for alpha sites — contact info@tabith.com.

**Does Venya install anything on my target hosts?**
Nothing. Targets are reached over SSH from executors, exactly as an operator
would.

**How does it scale?**
Executors scale horizontally (independent daemons, own certificates). The
core is single-node in alpha; HA (replication of PostgreSQL + CA material)
is a beta track item.

**Is there Docker?**
Executors use Docker Sandboxes (sbx) microVMs for command isolation —
installed by the executor installer. The core itself is a systemd service,
not a container, in alpha.

## Alpha status

**What is known-broken or rough in alpha?**
The honest list: `venya store` needs a field fix (seed secrets via the API —
the demo doc shows the exact call); documentation and packaging are still
maturing; the offline story is manual. APIs and config formats may change
between alpha releases — the CHANGELOG will carry user-facing notes from the
first tagged release.

**How do I get access?**
Request alpha access via [venya.ai](https://venya.ai/) or info@tabith.com.

**How do I report a security problem?**
[SECURITY.md](../SECURITY.md) — direct email, 48-hour acknowledgment, safe
harbor for good-faith research. Do not file public issues.

## Licensing & contributing

**Is Venya open source?**
It is *source available* under BUSL 1.1 — deliberately not OSI open source
during the commercial window. Free to use, modify, and run in production
below US $10M consolidated revenue and for non-competing use; each version
converts to MPL 2.0 at its Change Date (2031-01-01) or fourth anniversary,
whichever comes first. Full terms: [LICENSE](../LICENSE).

**Can I contribute?**
Yes — [CONTRIBUTING.md](../CONTRIBUTING.md). Contributions are licensed
under the same BUSL terms.

**Can I resell Venya or offer it as a service?**
Hosted/embedded offerings that compete with the Licensor's commercial
offerings require a commercial license: info@tabith.com. We are reasonable —
ask.
