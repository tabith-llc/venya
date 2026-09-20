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
| Core server (1) | FastAPI vault + API behind nginx TLS, PostgreSQL, CA authority | `install-venya-core.sh` |
| Executor host (1..n) | Sandboxed command execution daemon, secret injection, redaction | `install-venya-executor.sh` |
| Operator workstation | `venya` CLI + `venya-mcp` (FIDO2 key attached here) | `install-venya-cli.sh` |
| Target hosts | The machines commands ultimately run on (via SSH from executors) | none |

Requirements: Ubuntu 24.04 LTS (tested target) on servers; PostgreSQL and
nginx are installed automatically by the core installer; Python 3.14 is
provisioned automatically via `uv`; a FIDO2 security key (YubiKey, TrustKey,
etc.) for every human operator. **Executor hosts additionally require
hardware-virtualization access (`/dev/kvm`, `kvm` group)** — sbx runs each
command in a microVM. If the executor itself is a virtual machine, nested
virtualization must be enabled in the hypervisor; without it the install
completes but every sandboxed execution fails. Executor hosts also need a few
GiB free on the state volume before the first `sbx create` — the agent-template
pull fails below ~3.5 GiB (observed floor).

## 1. Install the core server

On the core VM (root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_DB_PASSWORD=<strong-db-password> \
  bash -s
```

The installer is SHA-256-gated and fail-closed: with `VENYA_TARBALL_SHA256`
set it verifies against that pin (strict integrity — recommended); unset, it
fetches the `.sha256` sidecar from the same origin as the tarball (corruption
guardrail). Any fetch failure or mismatch aborts the install.

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
| `VENYA_TARBALL_SHA256` | (sidecar fetch) | integrity gate — recommended; if unset, the installer fetches the `.sha256` sidecar from the same origin and aborts on fetch failure or mismatch |
| `VENYA_DB_PASSWORD` | (prompt) | PostgreSQL password |
| `VENYA_DB_PASSPHRASE` | (prompt) | server encryption passphrase — NO default (the former dev default was removed 2026-09-20); on re-runs the stored value is reused and an explicit value must MATCH it or the install aborts |
| `CORE_HOSTNAME` | `$(hostname)` | TLS cert SAN and relay CN base |
| `VENYA_ADMIN_MTLS_ENABLED` | `true` | admin client-cert enforcement |
| `VENYA_ADMIN_CA_PASSPHRASE` | auto-generated | stored in `/etc/venya/venya-core.env` (0640) |

Verify:

```bash
curl -sk https://<core-host>/api/v1/health
# {"status":"ok","checks":{"ca":"ok","admin_ca":"ok"}}
```

**Re-runs are the idempotency contract.** Re-running an installer on a live
host reuses stored secrets (`.env` stays byte-identical; an explicitly passed
passphrase must MATCH the stored one or the install aborts), redeploys the
packages, and **restarts the running service when the process predates the
new bytes** — a loud NOTICE names both timestamps and a PROOF-OF-FRESH-BYTES
line attests the verification probed the new process (ticket
`installer-rerun-no-service-restart`). No manual `systemctl restart` is
needed after a re-run; check for the PROOF line in the transcript before
trusting any acceptance probe.

## 2. Bootstrap the first admin (workstation, FIDO2)

Install the workstation bundle first (section 4), then:

```bash
curl -sk https://<core-host>/.well-known/venya-ca.crt -o ~/.config/venya-ca.crt
venya config set-server https://<core-host>
SSL_CERT_FILE=~/.config/venya-ca.crt venya init <admin-user-id>
```

Touch the security key when prompted. A **recovery code is printed once** —
store it securely; it is the only way back if the key is lost. Migrations
already ran at install time; `venya init` never migrates.

Copy the admin mTLS certificate pair to the workstation (needed for
`venya admin ...` commands):

```bash
ssh <core-vm> "sudo cat /etc/venya/admin/admin.crt" > admin-cert/admin.crt
ssh <core-vm> "sudo cat /etc/venya/admin/admin.key" > admin-cert/admin.key
chmod 600 admin-cert/admin.key
```

## 3. Install executors

Executors need a single-use enrollment token minted by an admin. With admin
mTLS enabled (the default), the admin client cert alone authorizes these
operations **server-side** — from any workstation holding the cert
(`VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY`). Both headless paths below work on a
core with no browser (CLI gate fix `d59a068` + `VENYA_SERVER_URL` resolution
fix `3f3ed1b`, dev/unreleased; physically verified 2026-09-20):

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

The token expires in ~30 minutes and is consumed on first use. The core
**requires a token for executor registration by default**
(`executor_enrollment.require_token`, enforced since 2026-09-20) — tokenless
registration attempts are rejected 400 with an actionable error.
**`<executor-id>` is a contract**: it becomes the client-certificate SAN and
the hostname cores dial for relay calls — it must resolve from every core,
and must match the pattern `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`.

Then on the executor VM (root):

```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes \
  VENYA_SERVER_URL=https://<core-host> \
  VENYA_EXECUTOR_ID=<executor-id> \
  VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token> \
  bash -s
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
allow rules come from the egress allowlist at execution time).

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
FIDO2 ceremonies on Windows go through the platform API and require an
interactive desktop session; standard (non-admin) users are supported for
ceremonies. macOS is handled by the same `.sh` installer (IOKit HID — no
udev rules needed).

**macOS workstation + core in a lima VM:** the server certificate is issued
for `CORE_HOSTNAME` (default: the VM's `$(hostname)`, e.g. `lima-venya-ubuntu`),
while lima forwards the VM's :443 to the mac's localhost — so TLS hostname
verification fails until the mac resolves that name to the forwarded port.
Fix: add `127.0.0.1 <vm-hostname>` to the mac's `/etc/hosts` (field-verified
report, 2026-09-19), or install the core with `CORE_HOSTNAME` set to a name
the mac already resolves. Do NOT disable verification.

Day-one:

```bash
venya config set-server https://<core-host>
SSL_CERT_FILE=~/.config/venya-ca.crt venya login <user-id>
```

## 5. Enroll regular users

```bash
SSL_CERT_FILE=~/.config/venya-ca.crt \
VENYA_ADMIN_CERT=admin-cert/admin.crt VENYA_ADMIN_KEY=admin-cert/admin.key \
venya admin create-user <user-id> --roles user
```

The response carries a 15-minute single-use enrollment token; the user runs
`venya enroll <token>` on their own workstation with their own key.

## 6. MCP client wiring (LLM operators)

```json
{
  "mcpServers": {
    "venya": {
      "command": "venya-mcp",
      "env": {
        "VENYA_CONFIG": "/home/you/.config/venya/config.json",
        "VENYA_CA_CERT": "/home/you/.config/venya-ca.crt"
      }
    }
  }
}
```

`VENYA_CA_CERT` is required at startup (fail-closed TLS; the internal CA is
not in the system trust store).

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
        "VENYA_CA_CERT": "/home/you/.config/venya-ca.crt"
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
executor's certificate is a core-side admin operation.

## Air-gapped networks

Full offline installation is a tracked beta goal, not yet turnkey: the
installers fetch Python toolchains and package dependencies at install time.
For air-gapped alpha sites, contact info@tabith.com — a local mirror
procedure exists but is not yet packaged.

## Troubleshooting

- `502` from nginx immediately after core install: give the backend a few
  seconds to bind; re-probe `api/v1/health`.
- **First** `run_command`/`venya run` after an executor install times out
  client-side: the first sandbox create pulls the agent template (~60 s+).
  The command usually still completes server-side — check the executor
  journal (`journalctl -u venya-executor`) and the target's actual state
  before retrying; the warm rerun is seconds-scale.
- `503` with `Not authenticated to Docker` in the executor journal: sbx
  login missing/expired — rerun the installer with Docker credentials or
  `sudo -H -u venya sbx login` on the executor.
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
  must be provisioned, never verification disabled. Re-fetch
  `/.well-known/venya-ca.crt` after any core reinstall (the CA is
  regenerated only if absent — an uninstall or a fresh machine mints a new
  one; a plain reinstall reuses the existing CA but re-signs the server
  leaf cert).
- Admin endpoints return 403: admin mTLS is enforced — pass
  `VENYA_ADMIN_CERT`/`VENYA_ADMIN_KEY` from the current core install.
- Executor relay rejects the core (403 at handshake): the core's relay
  client-cert CN must be `<core-hostname>-relay` and listed in the
  executor's `relay_client_ids` — both are derived from the same hostname;
  mismatches happen only when core and executor disagree about
  `CORE_HOSTNAME`/`VENYA_SERVER_URL`.
