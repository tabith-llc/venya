# Making Venya Easier to Use

Venya ships locked. That is not shyness about features — it is the product.
Venya exists so machines (AI agents, automation) can do work with real
credentials while never holding them, and the only way to keep that promise
is to start every control closed and let a human open exactly what they
mean to open.

Wanting less friction is legitimate. Not every deployment is a regulated
enterprise, and a small team running Venya on its own network may rationally
trade a little openness for a lot of convenience. This document is for
that choice. Every relaxation below is a real, supported door in the
product: we state what you gain, what you give up, and exactly where to set
it. There is no "turn everything down" switch, and there never will be —
relaxation here is deliberate and per-knob, because a blanket mode would
destroy the exact property you installed Venya for.

Two ground rules make the rest simple:

- **Every door has a named cost.** If a section cannot tell you what you
  give up, it is not a relaxation — it is a bug, and we want to hear about it.
- **The never-relax list is short and real.** See the last section. Those
  items are load-bearing walls, not furniture: removing them does not make
  Venya laxer, it makes Venya not Venya.

## Where settings live, and when they take effect

| Surface | Where | Takes effect |
|---------|-------|--------------|
| Command policy (admin) | admin API `POST /api/v1/admin/command-policy`; CLI `venya admin set-command-policy <preset>` / `add-allowed-command <path>` | executors apply the change on their next heartbeat (about 30 seconds); the change itself is audit-logged (`command_policy_changed`) |
| Command policy (per executor, at boot) | `/etc/venya/executor.toml` `[command_validator]` | executor restart; the server row takes over from the first heartbeat after that |
| Sandbox egress | `/etc/venya/egress-allowlist.txt` on each executor | the next command run — the file is read fresh at every sandbox creation, no restart needed |
| Core server settings | `/opt/venya/.env` (`VENYA_...` keys) — the file is `$VENYA_ENV_DIR/.env` when `VENYA_ENV_DIR` is set | core service restart (`systemctl restart venya-core`) |
| Executor settings | `/etc/venya/executor.toml` or `VENYA_EXECUTOR_*` environment | executor service restart |

## The worked example: "allow scp"

The most common ease-of-use ask: file transfer. Out of the box, a sandboxed
`scp` fails. It fails twice over, and both layers are doors you can open on
purpose.

**The locked default (what you see when nothing is relaxed):** the run is
refused before anything executes — the call comes back as a 503 and nothing
left the sandbox. The refusal reason is written to the executor's local
journal and to the executor's local audit spool as a `command_rejected`
event, which names the pattern (`Dangerous pattern blocked: 'scp '`).
That local record is your proof the default worked, not a mystery; it does
not currently appear in the server audit log.

**Why it is blocked — exactly two enforceable layers:**

1. **The command policy.** The default dangerous-pattern list includes
   `scp` and `rsync`, and pattern checks run *before* the preset branch —
   so these names are blocked under `strict`, `balanced`, and even
   `permissive`. (Stated precisely: `scp` and `rsync` are the blocked
   names. `ssh` and `sftp` are not on the pattern list — they are gated
   only by egress, layer 2. And `scp` run on the *far side* of an `ssh`
   command is a remote-side action, outside the local scan by design —
   if a task only needs to move files between two remote hosts, the
   remote-side form already works with no relaxation.)
2. **The sandbox egress policy.** The sandbox is deny-by-default: a command
   can open an outbound connection only to a host listed in
   `/etc/venya/egress-allowlist.txt` (plus the DNS resolver, which is
   always allowed so hostnames can resolve). An unlisted scp target fails
   at connect time even after layer 1 is relaxed.

### Step 1 — relax the command policy

Open the narrow door first. If you run the `strict` preset, add just the
one binary:

```bash
venya admin add-allowed-command /usr/bin/scp
```

If you run `balanced` or `permissive` (the default is `balanced`), the
pattern list is what blocks scp, and it is replaced as a whole: the policy
row stores your list *instead of* the built-in one. Send the built-in list
minus the two names you want open:

```
POST /api/v1/admin/command-policy
{
  "preset": "balanced",
  "custom_dangerous_patterns": [
    "rm -rf", "dd ", "dd if=", "mkfs", "fdisk", "shred",
    "nc", "ncat",
    "sudo", "su ", "su:", "chmod 4755", "setuid",
    "mount", "insmod", "modprobe"
  ]
}
```

Notes that matter:

- Pattern matching is whole-word: each entry is matched as a word, not a
  substring, so `dd` blocks the command name `dd` without touching words
  that merely contain it.
- Omitting `custom_dangerous_patterns` keeps the built-in list; supplying
  one **replaces** it entirely — a list that drops `rm -rf` along with
  `scp` silently un-blocks `rm -rf` too. Keep the pattern list under the
  same review discipline as firewall rules.
- The CLI's `set-command-policy` sets the preset and can write the pattern
  lists itself: `--custom-allowed` sets the allowed-commands list,
  `--custom-dangerous` the dangerous-pattern list. Each flag **replaces**
  the stored list whole; an omitted flag leaves that stored list untouched.
- Executors pick the change up on their next heartbeat (~30 s), and the
  write is audit-logged with actor and content.

### Step 2 — open the network path

On each executor that should reach the transfer target, add the
destination to the egress allowlist:

```
# /etc/venya/egress-allowlist.txt  (on the executor host)
files.internal.example
192.0.2.0/24
```

- One entry per line: an IP, an IPv4 CIDR, or a hostname. `#` starts a
  comment; blank lines are ignored.
- A hostname entry also needs DNS: the configured DNS resolver is always
  allowed inside the sandbox for exactly this purpose.
- No restart, no reload. The file is read at every sandbox creation, so the
  edit applies to the very next command run.
- Invalid entries are refused at install time if you seed the file with
  `VENYA_EGRESS_ALLOW` during setup; later hand-edits are used as-is, so
  keep each line exact.

### Verify

- **Locked (paired negative):** with no relaxation, the run must fail with a
  503 before anything connects, and the executor's local audit spool must
  show a `command_rejected` event naming the pattern. That combination is
  the default working correctly.
- **Relaxed:** after both steps, the command reaches the sandbox and runs.
  A failure after relaxation is a different kind of event — the executor's
  local audit spool no longer shows `command_rejected`, and the executor
  journal shows a connection or execution error instead. That difference
  is your confirmation that the doors, and only the doors you opened,
  changed the behavior. If the journal says the transfer client cannot be
  found, the binary is absent from the pinned sandbox image itself — that
  is an image-content question, not a policy one.
- Both halves of the story are recorded: `command_rejected` events for
  refusals live in the executor's local audit spool, and
  `command_policy_changed` for the policy change itself lands in the
  server audit log.

### What you gave up

- The sandboxed workload can now move files to wherever you allowed, which
  is also where a misbehaving or prompt-injected workload can exfiltrate up
  to the same size and scope. The narrower the allowlist entry (one host,
  not a /16), the less this costs.
- Dropping `scp`/`rsync` from the pattern list removes those guardrails for
  **every** command through that policy, not just yours — the pattern layer
  cannot distinguish "the scp I meant" from "the scp the model hallucinated."

One honest scope note: first-connect host keys. Fresh sandboxes carry no
`known_hosts`, so the first `ssh`/`scp` to a host fails the host-key check
unless the command opts in (for example `-o StrictHostKeyChecking=accept-new`).
That is the transport protecting you, and it stays exactly as described here
regardless of which knobs you turn.

## Knob catalog

Every row: what you gain, what you lose, where it is set, and the shipped
default. Nothing here is a judgment — take what your deployment needs.

### Command policy doors

| Knob | You gain | You lose | Where | Default |
|------|----------|----------|-------|---------|
| Preset `strict → balanced` | any command in the trusted system paths runs without per-command allowlisting | the "nothing runs unless named" property | server policy row (CLI/API), or executor `[command_validator] preset` | `balanced` |
| Preset `balanced → permissive` | commands outside the trusted paths run | the trusted-path floor (pattern blocks still apply) | same | — |
| Replace `custom_dangerous_patterns` | named patterns un-blocked fleet-wide (e.g. scp, rsync, nc) | each dropped pattern, for every command, everywhere the policy applies | admin API (full-list replace) | built-in list |
| `add-allowed-command <path>` | one exact binary allowed under `strict` | almost nothing — this is the smallest door | CLI / admin API | empty allowlist |

### Network doors

| Knob | You gain | You lose | Where | Default |
|------|----------|----------|-------|---------|
| Egress allowlist entries | sandboxed commands reach the listed hosts | exfiltration prevention toward those hosts | `/etc/venya/egress-allowlist.txt` (next run, no restart) | empty — only the DNS resolver is reachable |
| `VENYA_EGRESS_ALLOW` at install | the same, seeded during setup | same, from the first run onward | executor installer environment | unset = teaching-empty file |

(The DNS resolver itself is not a door — it is a required input with no
default, and the executor refuses to start rather than guess your network.
Keep it true; everything hostname-based depends on it.)

### Session, login, and enrollment doors

| Knob | You gain | You lose | Where | Default |
|------|----------|----------|-------|---------|
| `VENYA_SESSION__SESSION_TIMEOUT` | longer idle window before re-auth | window an unattended live session stays usable | `/opt/venya/.env` | 900 s (15 min) |
| `VENYA_SESSION__ACCESS_TOKEN_TTL` | fewer token refreshes | lifetime a captured bearer token stays usable | `/opt/venya/.env` | 300 s (5 min) |
| `VENYA_SESSION__MAX_SESSION_DURATION` | longer authorized working blocks | the session hard cap — the backstop under every other timeout | `/opt/venya/.env` | 14400 s (4 h) |
| `VENYA_RATE_LIMIT__ENFORCE=false` | no request tiering at all: the auth tier, the per-IP tier, the break-glass tier and its failure backoff, and the admin-certificate mint tier are all skipped | every HTTP request tier in one switch — including the cap on admin-credential minting (`POST /api/v1/admin/certs/issue`) and on break-glass recovery (`/api/v1/recovery`). It does not reach the account lockout inside the core engine, which keeps its own limits | `/opt/venya/.env` | enforced |
| `VENYA_RATE_LIMIT__IP_RATE_LIMIT` | more requests per client IP before a 429 | the generic per-IP ceiling — any path this middleware does not classify falls to this tier, so raising it loosens the limit on everything unclassified | `/opt/venya/.env` | 1000 per minute |
| `VENYA_RATE_LIMIT__AUTH_REQUESTS_PER_MINUTE` | more headroom for login and enrollment traffic | the tight tier on `/api/v1/auth/*` and `/api/v1/enrollment/*` — the tier that exists because password guessing is the cheap attack | `/opt/venya/.env` | 20 per minute |
| `VENYA_RATE_LIMIT__BREAK_GLASS_REQUESTS_PER_HOUR` | more recovery attempts per hour | the cap on `/api/v1/recovery`, and with it the bound on repeated failed recoveries | `/opt/venya/.env` | 5 per hour |
| `VENYA_RATE_LIMIT__CERT_ISSUANCE_REQUESTS_PER_HOUR` | more admin-certificate mints per hour | the cap on `POST /api/v1/admin/certs/issue`, counted per account rather than per IP — one mint costs one security-key touch, so the number is small on purpose | `/opt/venya/.env` | 5 per hour |
| `VENYA_RATE_LIMIT__MAX_ATTEMPTS`, `VENYA_RATE_LIMIT__WINDOW_SECONDS`, `VENYA_RATE_LIMIT__LOCKOUT_REINSTATE_MINUTES` | nothing today — these three keys are read into the server configuration and no shipped code path uses them | no cost, because no effect: the account lockout runs on the core engine's own limits (5 failed attempts, a 300-second window, a 15-minute lockout) and does not read these values | `/opt/venya/.env` | 5 / 300 s / 15 min (inert as overrides) |
| `VENYA_EXECUTOR_ENROLLMENT__REQUIRE_TOKEN=false` | executors can register without a minted token | the gate that stops any host reaching the core from claiming executor identity | `/opt/venya/.env` | token required |
| `VENYA_EXECUTOR_ENROLLMENT__TOKEN_TTL_SECONDS` | a relaxed enrollment window for batches | time a lost/stolen enrollment token stays usable | `/opt/venya/.env` | 1800 s |
| `VENYA_FIDO2__ENROLLMENT_TOKEN_TTL` | enroll without racing the timer | same trade, for user-enrollment tokens | `/opt/venya/.env` | 15 minutes |

### Comfort doors (usually cost almost nothing — stated anyway)

| Knob | You gain | You lose | Where | Default |
|------|----------|----------|-------|---------|
| `VENYA_CLOCK_SKEW__*` tolerances | hosts without tight time sync stop failing token/cert checks | expired tokens/certs are accepted a little longer | `/opt/venya/.env` | 60 s tokens / 60 s certs |
| `VENYA_EXECUTION_TIMEOUT` | slow first runs finish instead of timing out at the client | you wait longer on a genuinely dead path | workstation environment | 340 s |
| `VENYA_SBX_CREATE_TIMEOUT` | a cold sandbox image pull completes instead of aborting | same, on the executor | executor environment | 240 s |
| `VENYA_SBX_TIMEOUT` | a hung sandbox command releases the executor instead of holding it: one command at a time is admitted, so a bound below an hour is the difference between "a slow command" and "this executor is offline" | you cut off a legitimately long command — set it above the longest command you actually run, and remember the client fuses are shorter (relay 300 s, CLI/MCP 340 s), so a bound above those is invisible to the operator who is waiting | executor environment | 3600 s (1 hour) |
| `log_level = "debug"` / `VENYA_DEBUG` | full exception detail when diagnosing | noisier logs; internal detail lands in log files | executor config / environment — an explicit `--log-level` on the command line outranks both (#647) | `info`, unset |
| `VENYA_CORS__ORIGINS` | your own browser app can call the API | the cross-origin deny-by-default that protects browser callers | `/opt/venya/.env` | `http://localhost` |
| `VENYA_MAX_REQUEST_BODY_BYTES` | larger request payloads (bulk operations) | the memory-exhaustion floor the cap provides | `/opt/venya/.env` | 1 MiB |
| `VENYA_TRUSTED_PROXIES` | correct client IPs (and accurate rate-limiting/audit IPs) behind your proxy | any host you add may assert client IPs via forwarded headers | `/opt/venya/.env` | `127.0.0.1` only |

## Never relax

These are not ease-of-use knobs. There is no supported way to turn them
off, and no configuration in this document reaches them. Each one is a
load-bearing wall: the guarantee next to it is the reason Venya can let
agents near production credentials at all.

- **TLS verification.** It is the difference between "we dialed the real
  core" and "we dialed whoever owns the wire." If it ever fails, fix the
  certificate chain — never the verification.
- **Certificate validation (mutual TLS).** Executor identity *is* the
  authorization boundary for running commands. Skip validating it and any
  network neighbor can impersonate your executors with a borrowed
  certificate of no origin.
- **Hardcoded credentials and defaults.** Venya ships with none, on
  purpose — required values (database passphrase, DNS resolver, recovery
  pepper) fail loudly instead of guessing, because a default that works
  out of the box is the first thing an attacker types.

One more, stated once: the sandbox's deny-by-default egress is the
starting position, not an inconvenience to route around. Relax it by
*adding* the hosts you need (that is what the allowlist is for) — never by
removing the default itself, because deny-by-default is the one control
that limits what a misled or compromised sandboxed command can carry away.

---

*How to read the rest of the docs from here: security behavior in depth is
in [architecture.md](architecture.md) and the [FAQ](faq.md); the full
configuration surface is in [deployment-config.md](deployment-config.md);
the forced-default end of the spectrum is the [auditor role](auditor-role.md).*
