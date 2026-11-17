# Venya Installation Guide

Full deployment guide for the Venya beta. Venya runs on dedicated Linux VMs or
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

Requirements: Ubuntu 26.04 LTS is the tested target for core and executor on servers; PostgreSQL and
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
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-core.sh -o /tmp/install-venya-core.sh
sudo bash /tmp/install-venya-core.sh
```

At a terminal the installer asks for the DB password and the server encryption passphrase with hidden input, so
neither one is ever typed on a command line. Without a terminal — provisioning, a serial console — fetch the
script the same way, open a root shell with `sudo -i`, and run it there with the assignments in front of the
command; that shape needs no `-E` at all:

```bash
sudo -i
VENYA_SKIP_PROMPT=yes VENYA_DB_PASSWORD='<strong-db-password>' \
  VENYA_DB_PASSPHRASE='<server-encryption-passphrase>' bash /tmp/install-venya-core.sh
```

**Where a variable goes depends on what it is.** Control variables — `VENYA_SKIP_PROMPT`, `VENYA_SERVER_URL`,
`VENYA_EXECUTOR_ID`, `VENYA_TARBALL`, `VENYA_TARBALL_SHA256`, `VENYA_EGRESS_ALLOW`, the `VENYA_PURGE_*` switches —
hold no secret, so assign them to `sudo` itself and pipe:

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-core.sh | \
  sudo VENYA_SKIP_PROMPT=yes bash -s
```

That is the shape Ubuntu 26.04 — the tested target this release names — actually delivers, and it is the one this
page published backwards until now. Its `sudo` is `sudo-rs 0.2.13`, the stock rule is `Defaults env_reset`, and
`-E` is refused outright with `sudo: preserving the entire environment is not supported, '-E' is ignored`, so a
value written in front of `sudo` reaches the installer as nothing at all there (measured on Ubuntu 26.04; the
three positions count 0, 0 and 1 deliveries respectively). It also works on hosts with classic `sudo`, so one
form covers both. Classic `sudo` additionally accepts the other position when its rule matches the command `ALL`
(its manual: "If the command matched is ALL, the SETENV tag is implied for that command") and refuses `-E` with
`sorry, you are not allowed to preserve the environment` where the rule names specific commands or carries
`NOSETENV`.

Secret-bearing variables — `VENYA_DB_PASSWORD`, `VENYA_DB_PASSPHRASE`, `VENYA_ADMIN_CA_KEY_PASSPHRASE`,
`VENYA_CA_KEY_PASSPHRASE`, `VENYA_RECOVERY_CODE_PEPPER`, `VENYA_EXECUTOR_ENROLLMENT_TOKEN`,
`VENYA_DOCKER_API_KEY` — never go after `sudo`: written there each one is an argument of the `sudo` process, and
that process lives for the whole install with its command line readable to other local accounts (`#756`). The two
shapes at the top of this section are how they arrive: the hidden prompt, or a root shell. A re-run needs
neither, because the installer reuses what it stored — `VENYA_DB__PASSPHRASE=` in `/opt/venya/.env` (`0600`
root:root) and the two CA passphrases in `/etc/venya/venya-core.env` (`0640 root:venya`) — and an explicit value
that disagrees with the stored one stops the run instead of rotating the key quietly. What the installers do not
offer is a third way: no installer flag takes a secret (`--yes` and `--env-file` are not implemented), no `_FILE`
name is a value seam (they are paths to cert and key material), and a written bootstrap token is read by the
executor daemon for deferred registration, never back by the installer. So in the `sudo -i` shape the values are
typed once and land in that root shell's history — which is why the terminal prompt is the recommended form. (The
note below covers the prompting rule.)

`VENYA_DB_PASSPHRASE` has NO default and is **required for unattended
(piped) installs** — the installer aborts with an actionable error without it
(interactive runs are prompted; re-runs reuse the stored value and an explicit
value must MATCH it).

It also carries a **minimum length of 15 characters**. The
installer asks that question where the value resolves and **before it changes
anything on the host**, mirroring the core's own boot door
(`MIN_PASSPHRASE_CODE_POINTS` in `packages/core/src/core/engine/backend.py`): a
short passphrase can no longer walk an install halfway and only fail at service
start. The floor is measured on the final value, so a **re-run that reuses a
stored passphrase under it refuses at that same gate** — repairing such an install
is a deliberate reinstall, never a silent rotation of the stored key-encryption
key. The 64-character length is an allowance and NOT a limit: a longer passphrase is
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
| `VENYA_DB_PASSPHRASE` | (prompt) | server encryption passphrase — NO default (the former dev default was removed 2026-09-19 (`3c74b80`, first shipped 2026-09-20 on the pre-beta alpha line, tag `v0.1.0alpha12` — that line is withdrawn by owner order 2026-10-18, so the tag names the release that proved it, not one to install from) and a **15-character minimum** refused by the installer before any mutation, the same floor the core enforces at boot; 64 is the length Venya guarantees to support, not an enforced maximum; on re-runs the stored value is reused and an explicit value must MATCH it or the install aborts, and a re-run reusing a stored passphrase under the floor refuses at that gate |
| `CORE_HOSTNAME` | `$(hostname)` | TLS cert SAN and relay CN base |
| `VENYA_ADMIN_MTLS_ENABLED` | `true` | admin client-cert enforcement |
| `VENYA_ADMIN_CA_PASSPHRASE` | auto-generated | stored in `/etc/venya/venya-core.env` (0640), and reused from it on a re-run. The two CA-key passphrases (`VENYA_CA_KEY_PASSPHRASE` and this one) travel with the CA when the core uninstaller keeps it: they are copied to `/var/lib/venya/ca/ca-key-passphrases.env` (0600 root) before `/etc/venya` is removed, so a later unattended reinstall can still open the CA it finds there. `VENYA_PURGE_CA=yes` removes both together, and a reinstall that can find no passphrase stops before it changes anything (#749, #770) |

Verify:

```bash
curl -sS https://<core-host>/api/v1/health
# (no -k needed: the core installer puts the Venya CA in this host's system trust store)
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

### How the two product roles get created

Every core start re-applies the two roles the product ships with — `admin` and `user` — if
they are missing. It is a get-or-create run at startup (`server/role_seed.py`), so a normal
boot writes nothing; it writes only when a row is absent, and each row it creates emits a
`role_created` audit event beside the operator-facing one the admin API emits. Nothing is
needed from you and no reinstall is involved: a core whose `roles` table was emptied — by a
hand-cleared database, or a restore that brought users but not roles — heals its own role
rows on the next `systemctl restart venya-core`, and the boot journal names them:

```bash
journalctl -u venya-core -b | grep -m1 "Re-applied missing product roles"
# Jun 01 09:00:01 core-1 venya-server[1234]: Re-applied missing product roles at startup: admin, user
```

Two things this does NOT do, so the boundary is on the record: **migrations never seed
roles** (migration `001` creates the `roles` table and its unique constraint and inserts no
rows — the installer runs migrations, and they create the table, and that is all), and the
re-apply **never changes a role that already exists** — it will not re-permission, rename,
overwrite, or delete `admin`, `user`, or any role you created yourself. It creates the two
named rows and stops there.

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
needed after a re-run (landed at `c0ed801`; the pre-GitLab ticket slug was
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

Touch the security key when prompted. **When your browser or password manager offers to save a
passkey, decline it** — choose the hardware security key, so its PIN prompt appears. A manager
that answers first enrolls the manager: the credential is created in its store, your key is left
with nothing, and the PIN prompt this page tells you to expect never shows. The same instruction
is printed on the enrollment page itself, because this is a step you cannot take from a manual
later.

A **recovery code is printed once** —
store it securely; it is the only way back if the key is lost. Migrations
already ran at install time; `venya init` never migrates. The first-comer rule this step depends on
is a disclosed limitation, not a bug: see [beta-known-limitations.md](beta-known-limitations.md),
entry **"Bootstrap is trust-on-first-use"**.

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
`venya admin cert renew` mints is written with its key encrypted at rest, and the CLI
opens that encrypted key for admin mTLS with the passphrase from
`VENYA_ADMIN_CA_KEY_PASSPHRASE` (#565 Part B) — §3 states that pairing rule once.

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
core with no browser (CLI gate fix `6e546e5` + `VENYA_SERVER_URL` resolution
fix `7164b67`, dev/unreleased; physically verified 2026-09-20).

Which key they work with, stated because the two admin key shapes are not
interchangeable here: the pair under `/etc/venya/admin/` that the core installer
mints is written **unencrypted at rest** (`AdminCAManager.sign_admin_cert`,
`server/ca.py`), and that is the accepted posture by ruling — #565 R7-Q1, ruled on
that row: site 1 is exempt by design, the `0600` root-owned mode is the control,
and the exemption is retired only by the CSR or TPM-sealing changeset, never
inherited elsewhere. The CLI's admin mTLS read path
(`api_client.py::_build_ssl_context`) hands the TLS layer a passphrase callback that
reads `VENYA_ADMIN_CA_KEY_PASSPHRASE` (#565 Part B), so both shapes load: the
installer-minted key is plaintext and needs no passphrase at all, and
`venya admin cert renew` and `venya admin generate-admin-cert` write their leaf key
**encrypted** (#547a) and are presented by any command whose environment carries that
variable. With the variable unset, empty or whitespace-only the dial REFUSES before
anything is sent and names the key file — it never falls back to storing or asking for
plaintext. Measured on the shipped code at this file's base: both keys load through the
same builder, and an encrypted key with no configured passphrase raises `APIClientError`
at the context build. The renewal-side rule is written up once in
[cert-rotation-runbook.md](cert-rotation-runbook.md) §0; this section points at it
rather than restating it.

- The **CLI** — run it as the `venya` service account. This is the shape the core
  installer's closing banner prints, and every part of it is load-bearing:

```bash
# ON THE CORE. /opt/venya is the default install directory — use yours if you chose another.
sudo -u venya env PATH="/opt/venya/.venv/bin:$PATH" \
  SSL_CERT_FILE=/var/lib/venya/ca/ca.crt \
  VENYA_SERVER_URL=https://<core-host> \
  VENYA_ADMIN_CERT=/etc/venya/admin/admin.crt \
  VENYA_ADMIN_KEY=/etc/venya/admin/admin.key \
  /opt/venya/.venv/bin/venya admin executor-enroll <executor-id>
```

Why each piece has to be there — the short form people reach for first is the one
that fails, and it fails for three separate reasons:

- **`sudo -u venya`.** The admin pair sits in `/etc/venya/admin`, which the core
  installer creates `install -d -m 0700 -o venya -g venya`, and the CA sits under a
  `/var/lib/venya/ca` pinned at `700`. **An ordinary login cannot read either
  directory, so no amount of `chmod`-ing your own copy fixes it — running as the
  `venya` identity is the recipe.** That mode is deliberate (#610: `install -d`
  re-applies the mode on every run, and a group bit left the machine-plane key
  directory group-writable on every re-run). Do not widen it.
  Expect the refusal to arrive as a shell error, not a venya one. On the default
  install directory `/opt/venya` is itself `drwxr-x--- venya:venya`, so an ordinary
  login cannot even execute `/opt/venya/.venv/bin/venya`: the shell says
  `Permission denied` and the exit status is **126**, one step ahead of the pair
  above. That is this control working, not a broken install. The fix is the
  `venya` identity, never a `chmod` on your own copy.
- **The assignments go inside `env`, not in front of `sudo`.** `sudo`'s `env_reset`
  does not carry your shell's variables across the privilege change, so an
  `export`-ed `SSL_CERT_FILE` arrives unset. And putting the assignment after
  `sudo` (`sudo -u venya SSL_CERT_FILE=… venya …`) depends on a `setenv` grant that
  the stock sudoers does not give, so on a default install it refuses outright. The
  `env …` form the installer's banner prints works under both.
- **`SSL_CERT_FILE` named explicitly.** The CLI picks its trust anchor from
  `SSL_CERT_FILE`, and only then from the `ca.crt` beside the config file in **the
  home directory the command actually runs in** (`api_client.py::_resolve_tls_anchor`,
  which checks `os.environ["SSL_CERT_FILE"]` first and falls back to
  `config.ca_path`). The CA that §2's `venya setup` wrote sits beside
  *your* `config.json`; a mint run under a different account does not look there, and
  it dies before sending a request with `no Venya TLS trust anchor is configured` —
  naming a `ca.crt` path under some other home. Passing `SSL_CERT_FILE` inside the
  `env` list is what makes the trust anchor travel with the privilege change.

The banner also prints a one-time shape — install the anchor into an account-owned
config directory so a later call finds it without `SSL_CERT_FILE`:

```bash
sudo -u venya /opt/venya/.venv/bin/venya config set-server https://<core-host>
sudo mkdir -p /home/venya/.config/venya
sudo cp /var/lib/venya/ca/ca.crt /home/venya/.config/venya/ca.crt
sudo chown venya:venya /home/venya/.config/venya/ca.crt
```

**Read the fallback caveat before you rely on it.** The CLI looks for that `ca.crt`
under *whatever home the command actually runs in*, and a `sudo -u` change does not
always move `HOME`. The refusal is explicit about where it looked — it prints
`no SSL_CERT_FILE set and no config-dir CA at <path>` naming the home that was
actually searched (`api_client.py::_resolve_tls_anchor`). If that path is not the
directory you wrote to, do not chase permissions: pass `SSL_CERT_FILE` in the `env`
list, as the block above does. That is why the mint is given with the anchor named
explicitly.

The bare form — `VENYA_ADMIN_CERT=… VENYA_ADMIN_KEY=… venya admin executor-enroll
<executor-id>` typed as your own login — is what the product's own error text names
when an install has no token (`install-venya-executor.sh`: *"Mint one from an admin
workstation: venya admin executor-enroll <executor-id>"*), and on a headless core it
is not runnable as written: the pair is unreadable to you, and with no admin pair
loaded the CLI falls back to an interactive FIDO2 login, which dies on a machine with
no workstation key.

**Then check the mint produced a token, not just a directory.** With `--output-dir`,
the command creates that directory **before** it dials the core
(`commands.py::cmd_admin_executor_enroll`, the #616 ordering), so the directory
sitting there is not evidence of a token — it also exists when the mint failed. A
failed mint does print `Enrollment failed:` on stderr and exits non-zero, but a shell
that swallows the output loses that. Verify the file itself:

```bash
sudo -u venya test -s /secure/enroll/token && echo "token present"
sudo -u venya ls -l /secure/enroll/    # token 0600, directory 0700, plus core-server-ca.crt / admin-ca.crt
```

Pick the output directory so the **`venya`** identity can create it, not so yours
can — the command runs as `venya` and makes that directory as `venya`. A path
inside your own home directory is refused outright, with
`Enrollment failed: cannot create --output-dir <path>: Permission denied. Nothing
was minted.` and exit status 1. That refusal is the ordering above doing its job:
nothing was minted, so a failed run leaves no stale token to clean up.

Without `--output-dir` the token is printed to stdout and written nowhere, so capture
it from the output instead of looking for a file.

- Or the cert-only API path directly:

```bash
sudo -u venya curl -sS -X POST \
  --cacert /var/lib/venya/ca/ca.crt \
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
fast (idempotent: apt/Docker/sbx steps skip or cache). Re-mint with the
`sudo -u venya env …` command above, then re-run the executor installer with the
fresh token; add `--output-dir <dir>` to write the token and both CA certs into a
directory for transfer (the offline/air-gapped shape).

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

  **Minimal two-node recipe (one core host + one executor VM, no DNS):** pick a
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
# A fresh executor: the enrollment token has no prompt path in this installer — it is required in the
# environment before anything is written — so a root shell is the shape that carries it without putting the
# token in sudo's command line. Mint the token immediately before the run: single-use, ~30 minutes.
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-executor.sh -o /tmp/install-venya-executor.sh
sudo -i
VENYA_SKIP_PROMPT=yes VENYA_SERVER_URL=https://<core-host> VENYA_EXECUTOR_ID=<executor-id> \
  VENYA_EXECUTOR_ENROLLMENT_TOKEN='<token>' bash /tmp/install-venya-executor.sh
```

```bash
# Re-run of an executor that already holds its client certificate: no token is needed, and at a terminal the
# installer asks with hidden input for the executor key passphrase and the Docker API key.
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-executor.sh -o /tmp/install-venya-executor.sh
sudo VENYA_SERVER_URL=https://<core-host> bash /tmp/install-venya-executor.sh
# Docker credentials are REQUIRED for sandbox execution — see "Docker account
# credentials" below (piped installs: VENYA_DOCKER_USERNAME/VENYA_DOCKER_API_KEY,
# or run the downloaded script interactively for the hidden prompt).
```

`VENYA_SERVER_URL` is required on every run and is not a secret, so it is assigned to `sudo`. A token written
after `sudo` is an argument of the `sudo` process and stays readable in its command line for the whole install,
which is why the fresh-install shape above opens a root shell instead (`#756`); the cost there is that the token
lands in that root shell's history, and there is no hidden prompt for a token today. `VENYA_EXECUTOR_ID` may be
left out only when a terminal is there to confirm the answer: unattended it defaults to the host's own name and
says so (`#745`).

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
`VENYA_INSTALL_MCP=no` for CLI-only. On Linux, systemd already grants the user
logged in at the console access to FIDO2 security keys, so a key plugged into
this machine normally needs no setup; if the installer finds a key your user
cannot reach it names that device and a grant scoped to that device alone.

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

Run this on the core with its machine-plane pair, **as `venya`** — the same shape as
the §3 mint, including the `env` assignments inside `sudo` and an explicit
`SSL_CERT_FILE` (that site-1 credential pair; see §3 for what the CLI can and cannot
load):

```bash
sudo -u venya env PATH="/opt/venya/.venv/bin:$PATH" \
  SSL_CERT_FILE=/var/lib/venya/ca/ca.crt \
  VENYA_SERVER_URL=https://<core-host> \
  VENYA_ADMIN_CERT=/etc/venya/admin/admin.crt \
  VENYA_ADMIN_KEY=/etc/venya/admin/admin.key \
  /opt/venya/.venv/bin/venya admin create-user <user-id> --roles user
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
touch) at a terminal — a server that started with no token picks that login up
on its next call, no restart needed. A server that already holds a session
dials that session and nothing else, so a re-login is taken up by restarting
opencode, which starts the server fresh. The full rule, for every MCP client,
is under "When the Venya session behind the MCP server expires" below.

### pi

`pi` is another stdio MCP client. It talks to `venya-mcp` the same way; what
differs is where its config lives and that the server exposes a small, named
tool set rather than a large catalogue.

Log in first. The MCP server authenticates with **your user access token** — the
one `venya login` writes into `config.json` — not with an admin certificate:

```bash
venya setup <core-host>
venya login <user-id>
```

Then register the server in pi's **user-level** config
(`~/.pi/agent/mcp.json`), which is where credentials belong:

```bash
pi mcp add venya --exposure direct \
  --env VENYA_CONFIG="$HOME/.config/venya/config.json" \
  --env VENYA_CA_CERT="$HOME/.config/venya/ca.crt" \
  --description "Run commands on Venya executors, list secrets, read the audit trail" \
  -- venya-mcp
```

Check it without starting a session. `pi mcp list` connects to every enabled
server, prints its state and tools, and exits 1 if an entry is invalid or a
server did not connect:

```bash
pi mcp list
```

You should see four tools — `run_command`, `list_executors`, `list_secrets`,
`get_audit` — registered to pi as `mcp__venya__run_command` and so on. Then
start `pi` and use them by asking: "list the venya secrets", "run `uptime` on
exec-3". They are model-invoked, not slash commands. `/mcp` inside a session
shows each server's state, tool count, and the tail of stderr if it failed to
start; run `/reload` after adding or changing a server outside the session.

Two pi-specific choices in that command:

- **`--exposure direct`.** pi's own default for an MCP server is `codemode`,
  which keeps Venya's four tools one step away from the model's direct view;
  Venya recommends `direct` so they can be called by name. The mode list,
  what each mode costs, and how to change the choice are under "Choosing
  exposure" below.
- **user-level vs project config.** Add `-l` to write this project's
  `.pi/mcp.json` instead of the user-level file. pi reads the project file only
  after you grant project trust, and a project entry replaces a user-level
  entry of the same name. Keep the Venya entry user-level unless every user of
  the repo should carry its token path.

If the server shows as failed, read which prerequisite it stopped on: the
startup checks the session token first, then the CA, so it prints exactly one of
`No Venya session token found: there is no session file at <path> … then start
the MCP server again.` (log in — the file at
`VENYA_CONFIG`, default `~/.config/venya/config.json`, is missing) or
`Venya CA certificate not found. Set the VENYA_CA_CERT environment variable …`
(the CA file `venya setup` installs beside `config.json` is not being passed).
There is no way to skip either one: `VENYA_TLS_VERIFY=false` is an alpha debug
mode that warns and its shipped message says "never use in production".
`venya-mcp` answers `--version` and `--help`, but takes no flag that changes how
it runs — an unknown one exits 2 before the server starts — so `pi mcp list` and
`/mcp` are how you read why a server did not come up; `/mcp` shows the full
connection error and the tail of stderr from a failed stdio server. On
401/expired: the server says what to do in its own words — *"Run `venya login
<USER_ID>` and approve your security key"* — and names the session file it read, so a
request aimed at the wrong path is visible to you. A server that started with no
token picks that login up on its next call; no restart is needed. A server that
already holds a session dials that session and nothing else: it reads the file
again, and when the file now holds a different token it says so and declines to use
it, because nothing in that file names the login that wrote it. So a re-login that
lands mid-session is taken up by `/mcp reconnect venya`, which restarts the stdio
server for you in pi.

#### Choosing exposure — pi's four modes

The modes belong to pi; Venya only recommends one. The list below was read at
pi's own faces on the installed harness (pi 1.5.2): the MCP docs page section
"Control tool exposure", and `pi mcp add --help`, which prints
`--exposure <mode>` as `codemode (default), deferred, direct, or hidden`.

| Exposure | What the model sees and can invoke |
|---|---|
| `codemode` (pi's default) | Tools are callable from pi's codemode scripts — which find them with `searchTools()`, `describeTool()`, or `ALL_TOOLS` — but they are neither declared to the model nor listed in the codemode description. pi turns the `codemode` tool on for you when such a server connects. |
| `deferred` | Tools are not declared until `tool_search` loads a match for the next model call. pi turns `tool_search` on for you when such a server connects. |
| `direct` | Tools are declared to the model like a built-in tool, and are still callable from codemode scripts. |
| `hidden` | Registered but unreachable — present plumbing, no path in. |

`codemode-deferred` is accepted as an alias for `codemode`. A `toolExposure`
map overrides the server-level choice tool by tool (exact names win over
`*` patterns, first match wins among patterns) — that is how you declare one
or two tools of a large server and keep the rest script-only. Servers whose
tools are `codemode` or `deferred` still appear by name in the system
prompt's `mcp_servers` section, with a line on how to reach them; what the
model does NOT get is the tool declarations themselves.

The cost of a wrong choice is not a failed connection — a `codemode` server
connects fine and lists fine. The cost is indirection: your agent has to
search for the tool and script the call instead of simply calling it by name,
and many won't. Venya's server offers four small, named tools, so the
registration above uses `--exposure direct`. Read the state back with
`pi mcp list`; the server line names the exposure and the scope (shape read
from pi's CLI source at the same face — the second line is the transport, and
your server's tool list comes from the server itself):

```text
venya: connected, 4 tools (direct, global)
  venya-mcp
  tools: run_command, list_executors, list_secrets, get_audit
```

If that line reads `(codemode, global)` while you expected calls by name, you
have a registration to change, not a broken server. Tools whose own exposure
differs from the server's are marked in the list, e.g.
`get_audit [hidden]`.

Three ways to change the choice — pi's own verbs, all read at pi 1.5.2:

1. **Re-register.** Run the `pi mcp add venya --exposure <mode> …` command
   above again with a different `--exposure`: `add` on an existing name
   replaces its entry.
2. **In a session.** `/mcp`, select the server, change exposure. The change
   is saved to the file that defines that server.
3. **Out of a session.** Edit `exposure` in `~/.pi/agent/mcp.json` — or in
   `.pi/mcp.json` if you registered with `-l`/`--local`, which pi reads only
   after you grant project trust — then run `/reload` in any open session.
   A project entry without `command`/`url` overrides only `enabled`,
   `exposure`, and `toolExposure` of the user-level server of the same name,
   which is how one project can keep Venya `direct` while another keeps it
   script-only.

#### When the Venya session behind the MCP server expires

The MCP server authenticates with **your user access token** — the same one
`venya login` writes — so your session's lifetime is its lifetime. When calls
start coming back 401, work the three faces in this order:

1. **Log in at a terminal:** `venya login <user-id>` and approve your security
   key. This mints a fresh token into the session file.
2. **Know what the running server can see.** The rule, stated as shipped in the
   paragraph above: a server that started with no token picks that login up on
   its next call; no restart is needed. A server that already holds a session
   dials that session and nothing else — it re-reads the file, and when the
   file now holds a different token it says so and declines to use it, because
   nothing in that file names the login that wrote it.
3. **Take a re-login into a session that is already running:** in pi,
   `/mcp reconnect venya` restarts the stdio server, which then reads the file
   fresh (a config edit takes `/reload` instead). opencode has no reconnect
   verb — restart opencode itself.

The failure text is written to be triaged, not guessed. Each session message
names the session file it read and which state it found there: there is no
session file at that path; the file holds no access token; or the token it
read was refused by the core. The first two are never-held states and say so —
nothing expired and the core refused no request — and only the third is a
genuine expiry. `venya config show` gives the disk face:
`Access Token: [set] (refreshed automatically on the next call)`, or
`Access Token: [not set]` naming `venya login` as the way back; and a failed
background refresh keeps your stored token, so a transient refusal never costs
you the mint ceremony again.

And the general shape of the trap, worth carrying across the whole page:
**disk state and running state are different faces.** An installer can replace
`venya-mcp` on disk while the process that started earlier keeps answering
from the old code, exactly as a login can rewrite the session file while a
running server dials only the session it obtained itself — and says so, rather
than quietly acting as the new login. A `--version`-style claim should
therefore name which face it read — the file on disk, or the process in
memory — and when the two disagree, restarting or reconnecting the server
(step 3) is what makes them agree again.

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

The core uninstaller also drops the PostgreSQL database and role. It **keeps
`/var/lib/venya/ca`** — the estate CA the rest of the estate was enrolled against,
and its keys — and copies the two CA-key passphrases from `/etc/venya/venya-core.env`
to `/var/lib/venya/ca/ca-key-passphrases.env` (0600 root) in the same act, because a
kept key whose passphrase was deleted cannot be installed over (`#770`). The run
prints the path it left behind; remove the CA and its passphrase deliberately with
`VENYA_PURGE_CA=yes`, which is a separate choice from `VENYA_SKIP_PROMPT` (`#749`).
The executor
uninstaller **keeps `/var/lib/venya`** — the executor CA and its enrollment state —
and says so in its own output; remove it deliberately with
`VENYA_PURGE_STATE=yes` (`#757`). Either of them refuses to run against a state
directory that is a symlink, before removing anything (`#755`, `#757`). Shared
infrastructure (nginx/postgres/sbx packages) is kept; revoking a removed
executor's certificate is a core-side admin operation. Uninstallers are
**self-contained** — they embed their own helpers and fetch nothing at runtime,
so they work offline and after the serving origin is gone.

## Air-gapped networks

Offline installation — installers that fetch nothing at install time, for
customers on air-gapped networks — is **coming soon**: it is **not part of
beta1**, and no scheduled release carries it yet. Beta1's installers fetch
Python toolchains and package dependencies at install time, so a beta1
install requires internet.
For air-gapped beta sites, contact info@tabith.com — a local mirror
procedure exists but is not yet packaged. Air-gapped and fully offline
installation is a committed roadmap capability, not a present feature; guided
air-gap deployment is planned at the Professional tier when it ships.

The offline tarball path (`file://` source or `/tmp`/`/opt` fallback) and any
plain-`http://` source require an out-of-band `VENYA_TARBALL_SHA256` pin — a
hash read from the same origin would be self-attesting (#327, widened to every
non-https origin by #375/#328: the installers abort before any fetch or
write). Supply-chain boundary: pinned hash = integrity+authenticity;
same-origin `.sha256` sidecar (https origins only) = corruption guardrail
only, not a security boundary.

## Troubleshooting

- **`400 Role '<name>' not found` on a grant, `403 Admin role not found` for a human
  session, and `503 Admin role not found — admin role must exist before recovery` from the
  break-glass door all mean the same thing on an older build: the `admin`/`user` rows were
  missing from the `roles` table.** They no longer stay missing: every core start re-creates
  any absent seed role — see [How the two product roles get created](#how-the-two-product-roles-get-created).
  On a core running a build without that re-apply, restart the service on the new build, and
  do not reach for `venya init` as the repair: that path writes a pending-admin row too.

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
  trusted dir; whatever does not resolve is refused as "command not in
  trusted paths" — there is no builtin table, so the rule is RESOLUTION, not
  shell-ness: `echo`, `true`, `test`, `printf` have real binaries and PASS,
  while `cd`, `export`, `source`, `eval` have none and are refused. A leading `--`
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
