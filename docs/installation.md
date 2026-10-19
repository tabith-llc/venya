# Venya Installation Guide

Full deployment guide for the alpha. Venya runs on dedicated Linux VMs or
bare metal. All artifacts — installers, tarballs, SHA-256 sidecars — are
published on the GitHub releases page:
https://github.com/tabith-llc/venya/releases. The `releases/latest/download`
URLs used below always resolve to the current release; pin
`VENYA_TARBALL_SHA256` (hashes on the release page) for strict integrity.

## Topology

| Node | Role | Installer |
|---|---|---|
| Core server (1) | FastAPI secret store + API behind nginx TLS, PostgreSQL, CA authority | `install-venya-core.sh` |
| Executor host (1..n) | Sandboxed command execution daemon, secret injection, redaction | `install-venya-executor.sh` |
| Operator workstation | `venya` CLI + `venya-mcp` (FIDO2 key attached here) | `install-venya-cli.sh` |
| Target hosts | The machines commands ultimately run on (via SSH from executors) | none |

For help sizing a deployment (executor count, measured CPU/RAM/disk/throughput),
see the [Deployment Sizing Guide](deployment-sizing.md).

Requirements: Ubuntu 24.04 LTS (tested target) on servers; PostgreSQL and
nginx are installed automatically by the core installer; Python 3.14 is
provisioned automatically via `uv`; a FIDO2 security key (YubiKey, TrustKey,
etc.) for every human operator. **Executor hosts additionally require
hardware-virtualization access (`/dev/kvm`, `kvm` group)** — sbx runs each
command in a microVM. If the executor itself is a virtual machine, nested
virtualization must be enabled in the hypervisor; without it the install
completes but every sandboxed execution fails. Executor hosts also need a few
GiB free on the state volume — the installer warms the agent template at
install time (a throwaway `sbx create`), and the pull fails below ~3.5 GiB
free (observed floor).

**Host separation is enforced, not advisory.** Each installer detects the
OTHER component system-wide and **refuses (exit 1) before any prompt or
change** — `VENYA_SKIP_PROMPT=yes` does not bypass it. Co-location would merge
the trust anchor into the treated-as-compromised zone (both services run as
the same `venya` user; see the README's Host Trust Model). Same-component
re-runs remain supported (the idempotency contract, §1).

## 1. Install the core server

On the core VM (root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_DB_PASSWORD=<strong-db-password> \
  VENYA_DB_PASSPHRASE=<server-encryption-passphrase> \
  bash -s
```

`VENYA_DB_PASSPHRASE` has NO default and is **required for unattended
(piped) installs** — the installer aborts with an actionable error without it
(interactive runs are prompted; re-runs reuse the stored value and an explicit
value must MATCH it).

It also carries a **minimum length of 15 Unicode code points**, counted as you
type them and not as bytes, so a passphrase in any alphabet counts the same. The
installer asks that question where the value resolves and **before it changes
anything on the host**, mirroring the core's own boot door
(`MIN_PASSPHRASE_CODE_POINTS` in `packages/core/src/core/engine/backend.py`): a
short passphrase can no longer walk an install halfway and only fail at service
start. The floor is measured on the final value, so a **re-run that reuses a
stored passphrase under it refuses at that same gate** — repairing such an install
is a deliberate reinstall, never a silent rotation of the stored key-encryption
key. The 64-code-point maximum is stated and NOT enforced: a longer passphrase is
accepted and used.

The installer is SHA-256-gated and fail-closed: with `VENYA_TARBALL_SHA256`
set it verifies against that pin (strict integrity — required on every
non-https origin, recommended everywhere else); unset on an https origin, it
fetches the `.sha256` sidecar from the same origin as the tarball (corruption
guardrail); unset on a non-https origin, it aborts before any fetch or write
(#375, #328). Any fetch failure or mismatch aborts the install.

What it creates: locked `venya` service account; nginx TLS termination
(internal CA-signed cert, admin mTLS enforcement); PostgreSQL role/database;
Python 3.14 venv with core+server+cli packages; runtime config at
`/opt/venya/.env` (the ONLY config source — no TOML files); the Venya root
CA (`/var/lib/venya/ca/`), an Admin CA with an encrypted key, and an admin
client certificate (`/etc/venya/admin/`); database migrations; and the
`venya-core.service` systemd unit.

Key environment variables (all optional):

| Variable | Default | Purpose |
|---|---|---|
| `VENYA_TARBALL_SHA256` | (sidecar fetch) | integrity gate — recommended; if unset, the installer fetches the `.sha256` sidecar from the same origin and aborts on fetch failure or mismatch. Required (no sidecar fallback) whenever the tarball origin is not https:// — file:// paths (#327) and plain-http:// sources alike (#375, #328). |
| `VENYA_DB_PASSWORD` | (prompt) | PostgreSQL password |
| `VENYA_DB_PASSPHRASE` | (prompt) | server encryption passphrase — NO default (the former dev default was removed 2026-09-19 (`803acd9`, first shipped 2026-09-20 on the pre-beta alpha line, tag `v0.1.0alpha12` — that line is withdrawn by owner order 2026-10-18, so the tag names the release that proved it, not one to install from) and a **15 Unicode code-point minimum** (counted as typed, not as bytes) refused by the installer before any mutation, the same floor the core enforces at boot; 64 is stated as the maximum, not enforced; on re-runs the stored value is reused and an explicit value must MATCH it or the install aborts, and a re-run reusing a stored passphrase under the floor refuses at that gate |
| `CORE_HOSTNAME` | `$(hostname)` | TLS cert SAN and relay CN base |
| `VENYA_ADMIN_MTLS_ENABLED` | `true` | admin client-cert enforcement |
| `VENYA_ADMIN_CA_PASSPHRASE` | auto-generated | stored in `/etc/venya/venya-core.env` (0640) |

Verify:

```bash
curl -sk https://<core-host>/api/v1/health
# {"status":"ok","version":"<server-version>","checks":{"ca":"ok","admin_ca":"ok"}}
```

The metrics scrape endpoint is open on the same fresh install with no further step — run this
**on the core host**, because it binds loopback only (#653):

```bash
curl -s http://127.0.0.1:10011/metrics | grep -c '^# TYPE venya_'
```

A non-zero count is the counters being operator-readable; the `venya-core` journal carries one
`Prometheus metrics server started on 127.0.0.1:10011` line at boot. The port, how to change it,
and how to close it are in [deployment-config.md](deployment-config.md).

`/api/v1/health` is the canonical liveness endpoint (public, unauthenticated, version-only — it must never grow into a config dump). Bare `/health` is served as an alias returning the identical payload, for monitoring tools and load balancers that probe `/health` by convention. Both are unauthenticated and counted under the generic per-IP rate-limit tier (no health-specific exemption); every other unknown path still returns 401, so route existence is not disclosed to unauthenticated callers.

**Re-runs are the idempotency contract.** Re-running an installer on a live
host reuses stored secrets (`.env` stays byte-identical; an explicitly passed
passphrase must MATCH the stored one or the install aborts — and if the stored
file itself is gone, the installer still authenticates the existing database
role before any write, aborting rather than rotating its password silently)
and redeploys the packages.

**A core re-run that meets a running service briefly stops it on purpose.**
Before database migrations, `install-venya-core.sh` stops
`venya-core.service` behind a named `NOTICE`, because the schema must not move
under a process still running the previous build (ticket
`installer-stale-process-window-before-service-sync`); the same run brings the
service back up on the deployed bytes further down. Plan for that short
interruption — while the unit is held stopped the core is not answering, so
requests are refused rather than misanswered by old code over a newer schema.
The guard is the unit being active, not the version moving: every re-run that
meets a running service takes the pause (a same-version re-run's migrations
change nothing, but the stop still happens), and a first install has no unit
yet and never stops.

The run then **restarts the service when the process predates the new bytes** —
a loud NOTICE names both timestamps — and no manual `systemctl restart` is
needed after a re-run (landed at `6b6f2af`; the pre-GitLab ticket slug was
`installer-rerun-no-service-restart`).

**The fresh-bytes proof is a gate on the success claim, not a transcript note.**
`venya_service_freshness` compares the running process's start time against
that run's deploy stamp and answers FRESH, STALE or UNDECIDABLE, and the
summary consumes the answer: FRESH prints
`PROOF-OF-FRESH-BYTES: ... verification probes the NEW process` and the run
closes with `Installation verified successfully`; UNDECIDABLE (a stamp that
could not be read, a start time that did not parse) prints
`VERIFICATION NOT CLAIMED` naming the reason, and the install still completes
— a host whose clock we cannot read is not reported broken; STALE prints the
same line as an error and the run exits 1 instead of attesting a verification
it cannot stand behind. Read the ordering with this: the sync above restarts a
stale unit *before* the proof runs, so on the ordinary re-run you meet the
attestation, not the refusal — the STALE and UNDECIDABLE arms govern what the
sync did not leave healthy. Check for the PROOF line in the transcript before
trusting any acceptance probe. Upgrading between released versions? See
[UPGRADE.md](UPGRADE.md) — the drill-tested in-place upgrade runbook.

## 2. Bootstrap the first admin (workstation, FIDO2)

Install the workstation bundle first (section 4), then:

```bash
venya setup <core-host>
venya init <admin-user-id>
```

`venya setup` saves the server URL and installs the core's CA certificate
(fetched from `/.well-known/venya-ca.crt`, written 0600 beside `config.json`,
SHA-256 fingerprint printed for out-of-band verification). All later CLI
commands then verify TLS against it automatically — no `SSL_CERT_FILE`
needed. `venya config set-server <url>` remains for the offline case
(URL only, no cert fetch).

Touch the security key when prompted. A **recovery code is printed once** —
store it securely; it is the only way back if the key is lost. Migrations
already ran at install time; `venya init` never migrates.

The pair at `/etc/venya/admin/` is the core's **own** admin credential: it names
that core, not a person, and it does not leave that host. A person's admin
certificate is minted on the workstation itself, by a security-key ceremony —
the same four commands the installer's closing banner prints:

```bash
venya setup <core-host>       # one-time: the server URL and the core CA
venya login <your-user-id>    # a user that exists on this core, key enrolled
venya admin cert status       # read-local: prints time left, sends nothing
venya admin cert renew        # one touch mints a fresh 60-minute certificate
```

Check `status` before a long job and renew if it would expire inside your window;
a job that outlives its certificate fails with the same command named in the
refusal. On Windows the ceremony opens only from an interactive desktop session,
not from a remote or scheduled shell.

What serves `venya admin ...` today, because the shapes are not interchangeable: on an
install with admin mTLS enabled (the default, §3) the administrator path needs a client
certificate, and the pair that carries one today is the core's own machine-plane pair
presented on that core. A signed-in session that carries the administrator role does not
open that path by itself — an admin request with no client certificate is refused 403
(`_validate_admin_mtls`, `packages/server/src/server/middleware/auth.py`); the session-only
shape serves admin commands only where an install turns admin mTLS off. The one shipped
exception is the mint itself: `POST /api/v1/admin/certs/issue` is session-shaped by ruling
(RF-6 §2.2), which is why `venya admin cert renew` runs from a login session and nothing
else in the admin set does. The certificate
`venya admin cert renew` mints is written with its key encrypted at rest, and the
CLI cannot yet load an encrypted administrator key for admin mTLS — §3 states that
pairing rule once, and #565 Part B owns the read-side work that closes it.

Two lifetimes, because the two credentials are not the same credential:

- **a person's certificate lives 60 minutes**
  (`ADMIN_SHORT_CERT_LIFETIME_SECONDS`, `packages/server/src/server/ca.py`, the
  short-cert constant that sits beside the Admin CA constants);
- **the core's machine-plane pair lives 90 days** (`ADMIN_CERT_VALIDITY_DAYS = 90`,
  same module — the Admin CA constants block — consumed by
  `AdminCAManager.sign_admin_cert`), and every core installer run re-mints it.

What that 90-day number means for installs made before the copy instruction was
retired — the published age-out date, its arithmetic, and what that date does
*not* do — is stated once, in
[cert-rotation-runbook.md](cert-rotation-runbook.md) §0.1.

**[Record, #565 AC5, ruling R7-Q1 (ruled on row #565): this section used to carry a `sudo cat`
copy step for that pair. An s84 doc audit had booked the handoff as a pattern
"the CLI cannot read", and that accusation was not true — measured against the
shipped read path the key the step copied loads fine, because R7-Q1 makes that
plaintext-at-rest shape the design. What the ruling did not do was release the
handoff: carrying the key to a workstation unencrypted "remains a defect and
stays in the fix set" (role-dir destination, enforced modes, a stated
backup-exclusion requirement). RF-10 retired the installer's copy instruction on
2026-10-12 (`2b70210`, merge `832c11c`); this changeset retires this section's
copy of it, so the ceremony above is the whole workstation procedure now.]**

If you do hold an admin key file on a workstation, keep it **outside your home
directory** and at mode `0600` on the key. Sync, backup, and desktop-index agents
read home directories by default, and the admin **key** authorizes admin operations
*without a security-key touch* — a group- or other-readable key is a credential
anyone on the machine can borrow. On POSIX systems the CLI prints one `warning:`
line on stderr (and proceeds — it never blocks) when the key it is about to use
grants read to group or other; `chmod 600` and a path outside the home clears
it. **Windows has no such check** (NTFS has no POSIX mode bits), so secure the
key there with NTFS ACLs instead — the CLI stays silent on that platform rather
than claiming a mode it cannot read.

## 3. Install executors

Executors need a single-use enrollment token minted by an admin. With admin
mTLS enabled (the default), the admin client cert alone authorizes these
operations **server-side** — from the core that holds its own machine-plane pair
(`VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY`, §2). Both headless paths below run on a
core with no browser (CLI gate fix `d59a068` + `VENYA_SERVER_URL` resolution
fix `3f3ed1b`, dev/unreleased; physically verified 2026-09-20).

Which key they work with, stated because the two admin key shapes are not
interchangeable here: the pair under `/etc/venya/admin/` that the core installer
mints is written **unencrypted at rest** (`AdminCAManager.sign_admin_cert`,
`server/ca.py`), and that is the accepted posture by ruling — #565 R7-Q1, ruled on
that row: site 1 is exempt by design, the `0600` root-owned mode is the control,
and the exemption is retired only by the CSR or TPM-sealing changeset, never
inherited elsewhere. The CLI's admin mTLS read path
(`api_client.py::_build_ssl_context`) supplies no passphrase, so a key of that
shape loads and a renewed one does not: `venya admin cert renew` and
`venya admin generate-admin-cert` write their leaf key **encrypted** (#547a), and
until the read-side work lands (#565 Part B) that pair cannot serve these
commands. Measured on the shipped code at this file's base: the installer-minted
key loads; the renewed shape raises `APIClientError` at the context build. The
renewal-side limit is written up once in
[cert-rotation-runbook.md](cert-rotation-runbook.md) §0; this section points at it
rather than restating it.

- The **CLI** (installer-banner shape) — note `VENYA_SERVER_URL` is required
  unless a stored config names the server:

```bash
SSL_CERT_FILE=/var/lib/venya/ca/ca.crt \
VENYA_SERVER_URL=https://<core-host> \
VENYA_ADMIN_CERT=/etc/venya/admin/admin.crt VENYA_ADMIN_KEY=/etc/venya/admin/admin.key \
venya admin executor-enroll <executor-id>
```

- Or the cert-only API path directly:

```bash
sudo -u venya curl -sk -X POST \
  --cert /etc/venya/admin/admin.crt --key /etc/venya/admin/admin.key \
  https://<core-host>/api/v1/admin/executors/<executor-id>/enroll
# → {"enrollment_token": "enrl_exec_...", "expires_in_seconds": 1800, ...}
```

The token expires in ~30 minutes and is consumed on first **successful**
registration — a rejected attempt (expired, invalid, revoked, bound to a
different id, unresolvable executor-id) consumes nothing; what a failing
install burns is the **wall clock** (apt/Docker/sbx steps run before
registration). The TTL is server-configurable:
`executor_enrollment.token_ttl_seconds` (raise it for slow or air-gapped
installs). If the token expires, re-mint and re-run — the installer re-run is
fast (idempotent: apt/Docker/sbx steps skip or cache):

```bash
# re-mint on a core (admin mTLS), then re-run the executor installer with the fresh token
venya admin executor-enroll <executor-id>          # add --output-dir for offline/air-gapped CA copy
```

The core
**requires a token for executor registration by default**
(`executor_enrollment.require_token`, enforced since 2026-09-20) — tokenless
registration attempts are rejected 400 with an actionable error.
**`<executor-id>` is a contract**: it becomes the client-certificate SAN and
the hostname cores dial for relay calls — it must resolve from every core,
and must match the pattern `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`.

**Hostname strategy (executor-id resolution).** Resolution is checked
**from each core** at registration (the server rejects unresolvable ids 400 —
before the token gate, so a rejection burns nothing) and used at every relay
dial. Two sanctioned strategies:

- **DNS**: a record for `<executor-id>` pointing at the executor's IP — the
  clean option wherever DNS exists.
- **Core-side `/etc/hosts`** (the dev fleet's recipe — no DNS needed): on
  **every core host**:

  ```bash
  echo "<executor-ip> <executor-id>" >> /etc/hosts
  ```

  **Minimal alpha recipe (one core host + one executor VM, no DNS):** pick a
  dedicated executor-id — not the executor's own hostname (Ubuntu's
  `127.0.1.1 <hostname>` self-entry makes the installer's local pre-check pass
  trivially while saying nothing about the core's view) — and map it to the
  executor VM's real IP **on the core side**:

  ```bash
  echo "192.0.2.50 venya-exec-1" >> /etc/hosts    # ON THE CORE; executor's real IP, never a loopback variant
  ```

The executor installer pre-checks local resolvability of the id and prints
this remedy, but local resolution is only a proxy — the authoritative view is
each core's.

Then on the executor VM (root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_SERVER_URL=https://<core-host> \
  VENYA_EXECUTOR_ID=<executor-id> \
  VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token> \
  bash -s
# Docker credentials are REQUIRED for sandbox execution — see "Docker account
# credentials" below (piped installs: VENYA_DOCKER_USERNAME/VENYA_DOCKER_API_KEY,
# or run the downloaded script interactively for the hidden prompt).
```

**Deferred registration (bootstrap token file).** If install-time registration
does not run (core unreachable → CA not installed), the installer writes the
token to `/var/lib/venya/executor/bootstrap-token` (0600 venya:venya) — the
canonical bootstrap location, inside the daemon unit's `ReadWritePaths`
(`/etc/venya` itself is read-only to the daemon). The daemon registers
automatically at service start once the core is reachable, then deletes the
token file. Retry at any time: `sudo systemctl restart venya-executor`.

**Legacy `[bootstrap]` recovery (runbook).** Pre-migration installs kept the
token in a `[bootstrap]` section of `/etc/venya/executor.toml`. The daemon
still READS that location but cannot rewrite the read-only config: after a
successful daemon-side registration it logs `remove the [bootstrap] section
manually; the enrollment token is already consumed server-side` and continues
— no crash-loop. Operator recovery: as root, delete the `[bootstrap]` section
from `/etc/venya/executor.toml`. The residue is a spent single-use token only,
but remove it as hygiene.

**CA trust chain — how the executor gets its trust anchor (two paths).**
The executor installer acquires the core's CA certificate in one of two ways,
and the two paths have different trust properties (documented per ticket
`executor-installer-ca-fetch-insecure-tofu` #23 — this is a documentation of
the bootstrap design, not a change to it):

1. **Pre-copied CA file (recommended for security-sensitive deployments).**
   Set `VENYA_VENYA_CA_FILE=/path/to/ca.crt` (the `venya admin executor-enroll
   --output-dir <dir>` bundle writes `core-server-ca.crt` beside the token and
   prints a `SHA256` bundle fingerprint — verify that fingerprint against the
   core before copying: `sha256sum /var/lib/venya/ca/ca.crt` on the core).
   The installer installs the file you verified — no network fetch of the
   trust anchor is involved.
2. **Online fetch fallback (convenience TOFU).** With no pre-copied file, the
   installer fetches `/.well-known/venya-ca.crt` from the core over an
   **unverified** TLS connection (`curl --insecure`) and installs it as the
   trust anchor. This is trust-on-first-use: it works on a fresh LAN install,
   but an attacker positioned between the executor host and the core **during
   this one fetch** could substitute their own CA, and every later "verified"
   chain would descend from the substituted anchor. The post-install
   connections themselves are fully verified against whatever anchor was
   installed — the exposure is the install moment only.

   If this fallback cannot reach the core, the CA is not installed and
   registration defers to daemon start (above); the installer warns and prints
   the pre-copy remedy. Use path 1 wherever the network between executor and
   core is not fully trusted (cross-tenant networks, the internet, or any
   segment you would not run a plain-HTTP mirror on). A hardening option
   (fingerprint-pin env with fail-closed comparison) is tracked as a separate
   ruling on ticket #23 and is **not** current installer behavior.

**Docker account credentials are required.** The sbx sandbox runtime pulls
its agent template from Docker: the installer prompts for a Docker username
and API key/access token (interactive runs), or takes
`VENYA_DOCKER_USERNAME` + `VENYA_DOCKER_API_KEY` (piped/non-interactive
runs). The token is handled **stdin-only** — never in process arguments,
never written by the installer (sbx keeps it in its own credential store
under the service account's home). Without credentials the installer
**fails closed**; `VENYA_SKIP_DOCKER_LOGIN=yes` forces a degraded install
(executor runs, but every sandbox execution fails 503 until
`sudo -H -u venya sbx login` is done by hand).

The installer also starts `venya-sandboxd.service` (the sbx daemon,
persistent across reboots, ordered before `venya-executor.service`) and
initializes the sbx global network policy to **deny-all** (per-sandbox
allow rules come from the egress allowlist at execution time). The installer
then **warms the agent template** with a throwaway sandbox (multi-GiB pull,
once per host) so the first relayed command is seconds-scale; a failed warm
is non-fatal — loud warning, and the first command falls back to the cold
pull path.

The sandbox DNS resolver is explicit config — `VENYA_DNS_RESOLVER` (required,
no default; strict IPv4, validated before any write). It is always allowed
for sandbox egress; hostname targets resolve only when the hostname itself is
listed in the egress allowlist (the sandbox DNS proxy authorizes per domain).
Re-runs reuse the value
already stored in `/etc/venya/executor.toml` (the toml write overwrites on every
run, so the installer preserves the stored value rather than re-guessing). Find
yours with `resolvectl status` or `grep nameserver /etc/resolv.conf`. An
executor without a configured resolver **refuses to start** (Venya never guesses
your network). **Upgrading:** add `dns_resolver = "<ip>"` to
`/etc/venya/executor.toml` BEFORE restarting the executor.

The installer's apt list includes `sshpass`: sandbox ssh-password injection
shapes (`sshpass -f <secret-file> ssh ...`) need it inside the sandbox, and
the executor copies the host binary in at sandbox create. Hosts provisioned
out-of-band without it get a loud WARNING at sandbox create and those shapes
fail 127 in-sandbox.

Hostname resolution: the installer uses the provisioned `/etc/hosts` entry
for the core if present, else DNS. If the core hostname resolves neither way,
the installer **fails closed** and tells you to set `VENYA_CORE_IP=<ip>` —
it never guesses an IP (a wrong guess silently misroutes mTLS). An explicit
`VENYA_CORE_IP` always wins over an existing hosts entry.

Core hosts entries are matched by FIELD, not by pattern (`#490`): the installer
reads and updates the entry whose **second whitespace field is exactly the core
hostname**, and it leaves every other line of the file byte-for-byte as it found
it. An explicit `VENYA_CORE_IP` must be a bare IPv4 address (four dot-separated
numeric octets) — anything else aborts the install with a named error before a
single line is written, so no value can smuggle extra host mappings into the
file.

| Variable | Default | Purpose |
|---|---|---|
| `VENYA_HOSTS_FILE` | `/etc/hosts` | The hosts file the installer reads and updates for the core entry. A test/packaging seam (it is what the #490 cells point at a fixture); leave it unset on a real host. When set it must name an EXISTING writable regular file — a mistyped path aborts the install with "Nothing was written." rather than creating a file no resolver reads. |

What it creates: `venya` service account; Rust toolchain + the compiled
redaction filter (`venya_filter.*.so`); Python venv (executor+core+cli);
sbx (Docker Sandboxes) CLI; mTLS certificate registration with the core at
install time; egress allowlist (`/etc/venya/egress-allowlist.txt`,
deny-by-default); `venya-executor.service` with seccomp profile; and the
secrets tmpfs mount.

Verify:

```bash
systemctl is-active venya-executor        # active
ss -tln | grep 8443                        # relay listener bound
journalctl -u venya-executor -n 20         # heartbeat POST ... 200 OK
```

## 4. Install the workstation bundle

On each operator workstation (Linux, **non-root — no sudo**; the installer
refuses root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-cli.sh | \
  VENYA_SKIP_PROMPT=yes bash
```

Installs `venya` (CLI) and `venya-mcp` (MCP server for LLM clients) as
isolated `uv tool` venvs with shims in `~/.local/bin`. Set
`VENYA_INSTALL_MCP=no` for CLI-only. If the FIDO2 key is not reachable as
your user, the installer prints the exact udev/plugdev commands to fix it.

**Windows:** use `install-venya-cli.ps1` from the same release (run as
Administrator — machine-wide install to `C:\Program Files\Venya`; per-user
state under `%APPDATA%\venya\`). Uninstall: `uninstall-venya-cli.ps1`.
Elevated **install**, unelevated **use**: the Administrator terminal is for the
install (and uninstall) only — run every `venya` command, FIDO2 ceremonies
included, from a standard (non-elevated) terminal.
FIDO2 ceremonies on Windows go through the platform API and require an
interactive desktop session — a remote session (SSH, WinRM, or Run-as over
SSH) is not one, because the platform API needs a foreground window, so
ceremonies are typed at the machine's own console. Standard (non-admin)
users are supported for ceremonies. macOS is handled by the same `.sh`
installer (IOKit HID — no
udev rules needed).

Renewal follows the same rule: `venya admin cert renew` mints a fresh admin
certificate on a login session plus one security-key ceremony, so on Windows it
is a console action like the one above. The Windows ceremony-and-renewal path,
and the physical cells it still owes, are gathered in
[win11-admin-cert.md](win11-admin-cert.md). What that renewed pair can and cannot
serve today is stated once, in the opening note of
[cert-rotation-runbook.md](cert-rotation-runbook.md); flag table:
[cli-reference.md](cli-reference.md).

**macOS workstation + core in a lima VM:** the server certificate is issued
for `CORE_HOSTNAME` (default: the VM's `$(hostname)`, e.g. `lima-venya-ubuntu`),
while lima forwards the VM's :443 to the mac's localhost — so TLS hostname
verification fails until the mac resolves that name to the forwarded port.
Fix: add `127.0.0.1 <vm-hostname>` to the mac's `/etc/hosts` (field-verified
report, 2026-09-19), or install the core with `CORE_HOSTNAME` set to a name
the mac already resolves. Do NOT disable verification.

Day-one:

```bash
venya setup <core-host>
venya login <user-id>
```

## 5. Enroll regular users

Run this on the core with its machine-plane pair (that site-1 shape; see §3 for
what the CLI can and cannot load):

```bash
VENYA_ADMIN_CERT=/etc/venya/admin/admin.crt VENYA_ADMIN_KEY=/etc/venya/admin/admin.key \
venya admin create-user <user-id> --roles user
```

The response carries a 15-minute single-use enrollment token; the user runs
`venya enroll <token>` on their own workstation with their own key.

## 6. MCP client wiring (LLM operators)

After wiring, paste the operating contract from
[agent-prompts.md](agent-prompts.md) into your agent's instruction file
(AGENTS.md / CLAUDE.md / Cursor rules) — the distilled brief for agents
driving Venya, pinned by test to the live tool surface.

```json
{
  "mcpServers": {
    "venya": {
      "command": "venya-mcp",
      "env": {
        "VENYA_CONFIG": "/home/you/.config/venya/config.json",
        "VENYA_CA_CERT": "/home/you/.config/venya/ca.crt"
      }
    }
  }
}
```

`VENYA_CA_CERT` is required at startup (fail-closed TLS; the internal CA is
not in the system trust store). It is the file `venya setup` installs beside
`config.json`.

### opencode

Project-level config (`opencode.json` in your working directory) or global
(`~/.config/opencode/opencode.json`). Note the different shape — opencode
does not use the `mcpServers` convention:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "venya": {
      "type": "local",
      "command": ["/home/you/.local/bin/venya-mcp"],
      "enabled": true,
        "environment": {
          "VENYA_CONFIG": "/home/you/.config/venya/config.json",
          "VENYA_CA_CERT": "/home/you/.config/venya/ca.crt"
        }
    }
  }
}
```

Restart opencode after config changes (config loads once at startup). The
tools are model-invoked, not slash commands: ask "list the venya secrets",
don't type `/list_secrets`. On 401/expired: `venya login <user-id>` (key
touch) and retry — the MCP server reads the refreshed token from the same
`VENYA_CONFIG` file.

### Next: create a secret and prove the redaction path

With the client wired, run the 5-minute end-to-end demo —
[alpha-demo.md](alpha-demo.md): `venya store` a secret, consume it with a
masked `run_command` (`[REDACTED:…]` in the output), verify the audit trail,
then drive the same flow from your MCP client.

## Uninstalling

One uninstaller per artifact, published alongside the installers:

```bash
# core / executor VMs (root)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-core.sh | sudo VENYA_SKIP_PROMPT=yes bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-executor.sh | sudo VENYA_SKIP_PROMPT=yes bash

# workstation (non-root; VENYA_PURGE_CONFIG=yes also removes ~/.config/venya)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-cli.sh | VENYA_SKIP_PROMPT=yes bash
```

The core uninstaller also drops the PostgreSQL database and role. Shared
infrastructure (nginx/postgres/sbx packages) is kept; revoking a removed
executor's certificate is a core-side admin operation. Uninstallers are
**self-contained** — they embed their own helpers and fetch nothing at runtime,
so they work offline and after the serving origin is gone.

## Air-gapped networks

Full offline installation is a tracked beta goal, not yet turnkey: the
installers fetch Python toolchains and package dependencies at install time.
For air-gapped alpha sites, contact info@tabith.com — a local mirror
procedure exists but is not yet packaged.

The offline tarball path (`file://` source or `/tmp`/`/opt` fallback) and any
plain-`http://` source require an out-of-band `VENYA_TARBALL_SHA256` pin — a
hash read from the same origin would be self-attesting (#327, widened to every
non-https origin by #375/#328: the installers abort before any fetch or
write). Supply-chain boundary: pinned hash = integrity+authenticity;
same-origin `.sha256` sidecar (https origins only) = corruption guardrail
only, not a security boundary.

## Troubleshooting

- `502` from nginx immediately after core install: give the backend a few
  seconds to bind; re-probe `api/v1/health`.
- **The metrics scrape door is closed on a core that is otherwise healthy:** a journal line
  `Metrics scrape endpoint is dark: could not bind 127.0.0.1:<port>` names the port the unit
  asks for and the OS reason. This is not a failed install and the core is serving — the port is
  held by something else on this host (`EADDRINUSE`), or it is below 1024 and the unit grants no
  `CAP_NET_BIND_SERVICE` (`EACCES`). Both are facts about the host, so the service does not exit
  over them (`Restart=always` would loop it for an observability surface) and the refusal is
  logged on every boot that hits it. Free the port, or name another in a drop-in:
  `sudo systemctl edit venya-core` → `[Service]` → `Environment=VENYA_METRICS_PORT=<port>`, then
  `sudo systemctl daemon-reload && sudo systemctl restart venya-core`. A `VENYA_METRICS_PORT`
  that is not a usable port number at all is different and does stop the service — see
  [deployment-config.md](deployment-config.md).
- **First** `run_command`/`venya run` after an executor install is
  seconds-scale: the installer warms the sbx agent template at install time
  (throwaway sandbox, after Docker auth and policy init). If the warm failed
  or was skipped (`VENYA_SKIP_DOCKER_LOGIN=yes` degraded install), the first
  sandbox create pulls the multi-GiB template instead: ~60–90 s on a fast
  uplink — slow, but inside the timeout chain (executor create cap 240 s <
  relay 300 s < nginx 330 s < client 340 s). On uplinks slower than the
  create cap, the first create fails with an explicit executor-side error;
  re-run the installer (idempotent) or warm by hand with a throwaway
  `sbx create` + `sbx rm --force` pair. Whenever a run looks like it failed,
  check the executor journal (`journalctl -u venya-executor`) and the
  target's actual state before retrying.
- `503` with `You are not authenticated to Docker` in the executor journal:
  sbx login missing/expired — rerun the installer with Docker credentials or
  `sudo -H -u venya sbx login` on the executor. That failure string is the
  vendor's own wording (https://docs.docker.com/ai/sandboxes/troubleshooting/,
  accessed 2026-10-09). The `503` itself is Venya's own mapping of an
  unauthenticated executor — it is not a status code the vendor returns.
- `503` with `global network policy has not been initialized`: run
  `sudo -H -u venya sbx policy init deny-all` on the executor (the
  installer does this automatically since the 2026-09 fix).
- `503` on otherwise-valid commands: the executor's trusted-path validation
  requires commands to resolve into trusted directories (`/usr/bin`,
  `/usr/sbin`, `/bin`, `/sbin`) — absolute paths like `/bin/echo` always
  qualify; bare names are resolved via PATH and accepted if they land in a
  trusted dir; shell builtins are rejected by design. A leading `--`
  separator on `venya run` is consumed by the CLI (not sent to the
  executor) and is safe to pass.
- `Host key verification failed` / TLS failures between components: the CA
  must be provisioned, never verification disabled. Re-run
  `venya setup <core-host>` on each workstation after any core reinstall —
  it re-fetches `/.well-known/venya-ca.crt` over the wire (the CA is
  regenerated only if absent — an uninstall or a fresh machine mints a new
  one; a plain reinstall reuses the existing CA but re-signs the server
  leaf cert).
- Admin endpoints return 403: admin mTLS is enforced — the credential that
  answers this today is the core's own machine-plane pair, presented through
  `VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY` on that core (§3); it is not a copy kept on
  a workstation, and §2 names the ceremony a person's credential comes from.
  Distinguish that from the load failure, which is the other thing that can go
  wrong here: if the pair was refreshed by `venya admin cert renew` or
  `venya admin generate-admin-cert`, its key is encrypted at rest and this CLI
  has no passphrase path for it yet (#565 Part B), and the command exits 1
  before any request is sent with
  `Failed to load the admin mTLS client cert/key pair (…)`, carried behind the
  command's own prefix (`Create user failed: …`). No server answered that one —
  §3 names the key shape that does load.
  **[Correction, #565 AC5: this bullet used to stop at the sentence above it, and
  the reading it invited — that an unreadable renewed pair shows up as a 403 — is
  not what the shipped code does. The pair never reaches the server, so the server
  never gets to say 403. Recorded with the ruling cite R7-Q1 on row #565 and the Part B
  reference rather than deleted, so the earlier wording stays visible.]**
- Executor relay rejects the core (403 at handshake): the core's relay
  client-cert CN must be `<core-hostname>-relay` and listed in the
  executor's `relay_client_ids` — both are derived from the same hostname;
  mismatches happen only when core and executor disagree about
  `CORE_HOSTNAME`/`VENYA_SERVER_URL`.
