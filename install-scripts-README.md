# Venya HTTP Install Scripts

Installation scripts for Venya components, published as GitHub release assets (https://github.com/tabith-llc/venya/releases). The dev LAN server (below) mirrors them for VM provisioning.

## Scripts

### `install-venya-core.sh`

Installs the Venya Core server on a fresh VM. Includes:

- **venya** service account (nologin + locked; no password)
- System packages: `curl`, `sudo`
- **Nginx** reverse proxy (installed first for TLS)
- **PostgreSQL** (user, database, trust auth for localhost)
- Python virtual environment + core/server packages
- Code fixes (database_url, imports, timezone handling)
- Configuration: `.env`, Nginx site config
- Nginx CA trust installation
- Database migrations
- `venya-core.service` systemd unit

**Usage:**
```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_DB_PASSWORD=<strong-db-password> \
  VENYA_DB_PASSPHRASE=<server-encryption-passphrase> bash -s
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_DB_PASSWORD` | (prompt) | PostgreSQL venya user password |
| `VENYA_DB_PASSPHRASE` | (reuse / prompt) | Server encryption passphrase — no default. Re-run: reused from `$INSTALL_DIR/.env`; an explicit value must match the stored one or the install aborts. Fresh install: prompted (interactive) or required (unattended) |
| `VENYA_RECOVERY_PEPPER` | (reuse / random) | Recovery-code pepper — reused from `.env` on re-run (mismatch aborts); strong random when unset on a fresh install |
| `VENYA_TARBALL` | `https://github.com/tabith-llc/venya/releases/latest/download/venya-core-install.tar.gz` | Tarball URL |
| `VENYA_TARBALL_SHA256` | (optional) | Pin expected sha256 (strict integrity). Unset: fetched from `<tarball>.sha256` on the same origin (corruption guardrail); fail-closed |
| `CORE_HOSTNAME` | `$(hostname)` | Hostname for TLS/Nginx (auto-detected by default) |
| `TLS_MODE` | `internal` | Nginx TLS mode (internal = self-signed, manual = provide certs) |
| `VENYA_ADMIN_MTLS_ENABLED` | `true` | Enforce admin mTLS (admin client cert required) |
| `VENYA_ADMIN_IDENTITY` | (empty) | Admin CN identity for the admin CA |
| `VENYA_ADMIN_CA_PASSPHRASE` | (empty) | Passphrase protecting the admin CA key |

### `install-venya-executor.sh`

Installs the Venya Executor daemon on a fresh VM. Includes:

- **venya** service account (nologin + locked; no password)
- System packages: `curl`, `sudo`, `build-essential`, `sshpass`
- **Rust** toolchain (venya user)
- Python virtual environment + executor/core packages
- Rust extension build (`venya_filter.so`)
- Code fixes (same as core)
- **sbx** CLI (Docker Sandboxes)
- Configuration: `executor.toml`
- `venya-executor.service` systemd unit

**Usage:**
```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_SERVER_URL=https://<core-host> VENYA_EXECUTOR_ID=<executor-id> \
  VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token> bash -s
```

Docker credentials are REQUIRED for sandbox execution (`VENYA_DOCKER_USERNAME`
+ `VENYA_DOCKER_API_KEY`, see the table) — a piped install without them fails
closed unless `VENYA_SKIP_DOCKER_LOGIN=yes` (documented degraded install). To
keep the API key out of argv/shell history entirely, download the script and
run it from an interactive session so the key is entered at the hidden prompt
(stdin-only handling, never argv/disk).

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_TARBALL` | `https://github.com/tabith-llc/venya/releases/latest/download/venya-executor-install.tar.gz` | Tarball URL |
| `VENYA_TARBALL_SHA256` | (optional) | Pin expected sha256 (strict integrity). Unset: fetched from `<tarball>.sha256` on the same origin (corruption guardrail); fail-closed |
| `VENYA_EXECUTOR_ID` | `venya-exec-1` | Executor identifier — CONTRACT: used as the relay dial hostname + client-cert SAN; must be resolvable from every core |
| `VENYA_SERVER_URL` | (required — no default) | Core server URL; unset aborts with an actionable error (the server hostname cannot be guessed) |
| `VENYA_EXECUTOR_ENROLLMENT_TOKEN` | (empty) | Bootstrap enrollment token — enables mTLS cert registration and heartbeat bootstrap at install time |
| `VENYA_DOCKER_USERNAME` | (prompt if TTY) | Docker account for sbx agent-template pulls |
| `VENYA_DOCKER_API_KEY` | (prompt if TTY) | Docker access token — stdin-only handling, never argv/disk; required unless already authenticated |
| `VENYA_SKIP_DOCKER_LOGIN` | (empty) | `yes` = degraded install (executor runs; sandbox executes fail 503 until `sudo -H -u venya sbx login`) |
| `VENYA_EGRESS_ALLOW` | (empty) | Optional seed for `/etc/venya/egress-allowlist.txt` — comma/space-separated IPs, CIDRs, hostnames (e.g. `203.0.113.0/24,nas.example.com`). Unset: file written empty by design (fail-closed: all sandbox egress blocked except DNS; edit it, effective on the next command run). Any invalid entry aborts the install — never half-applied |
| `VENYA_DNS_RESOLVER` | (required, no default; re-runs reuse the stored toml value) | Resolver IP always allowed for sandbox egress — strict IPv4, validated before any write; find it via `resolvectl status` / `/etc/resolv.conf` |

### `install-venya-cli.sh`

Installs the Venya workstation client bundle for the current operator user. **No sudo** — refuses to run as root. Includes:

- **uv** (if missing, into `~/.local/bin`)
- `venya-cli` via `uv tool install` (isolated venv, `venya` shim in `~/.local/bin`)
- `venya-mcp` via `uv tool install` (isolated venv, `venya-mcp` shim; `VENYA_INSTALL_MCP=no` skips)
- FIDO2 `/dev/hidraw*` access check with actionable udev/plugdev instructions

**Usage (on the operator workstation):**
```bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/install-venya-cli.sh | VENYA_SKIP_PROMPT=yes bash
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompt |
| `VENYA_INSTALL_MCP` | `yes` | Set to `no` to install only the CLI (skip `venya-mcp`) |
| `VENYA_TARBALL` | `https://github.com/tabith-llc/venya/releases/latest/download/venya-cli-install.tar.gz` | Tarball URL (workstation bundle: `packages/cli` + `packages/mcp`) |
| `VENYA_TARBALL_SHA256` | (optional) | Pin expected sha256 (strict integrity). Unset: fetched from `<tarball>.sha256` on the same origin (corruption guardrail); fail-closed |

### `install-venya-cli.ps1` (Windows)

Windows equivalent of `install-venya-cli.sh`, for PowerShell 5.1 and later.
Installs the same bundle **machine-wide — run from an Administrator terminal**
(a standard user cannot create the install root or the uv Python junction;
ticket `windows-uv-junction-standard-user`). Standard users need no rights to
USE the CLI afterward.

- **uv** (pinned, sha256-verified) + a uv-managed CPython 3.14, under the install root (default `C:\Program Files\Venya`; override with `VENYA_INSTALL_DIR`)
- `venya-cli` and `venya-mcp` as isolated `uv tool` venvs under the install root, with `venya` / `venya-mcp` shims on the machine `PATH`
- Per-user state (server URL, access token, CA cert) in `%APPDATA%\venya\`
- Uses the built-in `curl.exe` and `tar.exe` (bsdtar) — no extra tooling, no compiler

**Usage (on the operator workstation):**
```powershell
powershell -ExecutionPolicy Bypass -File install-venya-cli.ps1
```

Same environment variables as `install-venya-cli.sh`, set PowerShell-style:
```powershell
$env:VENYA_TARBALL = "http://<build-host>:8080/venya-cli-install.tar.gz"
$env:VENYA_TARBALL_SHA256 = "<sha256>"
$env:VENYA_SKIP_PROMPT = "yes"
.\install-venya-cli.ps1
```

> **FIDO2 on Windows.** `venya init`, `venya login`, `venya enroll` and
> `venya credential add` go through the Windows platform WebAuthn API and work
> for **standard (non-admin) users** — but only in an **interactive desktop
> session**: never over SSH/WinRM, because the platform API needs a foreground
> window handle. Only the machine-wide installer/uninstaller are admin-run
> (ticket `windows-fido2-requires-elevation`, CLOSED — the platform-API path
> shipped in alpha.10).
>
> Authenticator **reset** and **PIN management** are out of scope on Windows; the
> platform API exposes only `make_credential` / `get_assertion`. Customer IT owns
> those steps via the vendor's own tool.

*Serving note:* `create-tarball-and-serve.sh` serves both `.ps1` files when the
built ref contains them, and omits them (with a `WARN`, removing any stale copy)
for older refs. They are GitHub release assets since `v0.1.0-alpha.10` (the
15-asset manifest; pre-Windows tags legitimately carry 13).

### Uninstallers

Each artifact has a matching uninstaller (served from the same origin).
Uninstallers are **self-contained** — they embed their own helper functions and
fetch nothing at runtime (ticket `uninstaller-fetch-origin-lan-default`), so
they work offline and after the serving origin is gone:

| Script | Runs as | Removes | Keeps |
|---|---|---|---|
| `uninstall-venya-core.sh` | root (on core VM) | service+unit, nginx site, /opt/venya, /etc/venya, /var/lib/venya (CA keys), well-known CA, trust entries, PostgreSQL db+role, venya user | nginx/postgresql OS packages |
| `uninstall-venya-executor.sh` | root (on executor VM) | service+mount+seccomp units, /opt/venya, /etc/venya (mTLS key), /var/lib/venya, trust entries, venya user (Rust/uv/sbx state) | sbx/docker packages, /etc/hosts (provisioning-owned); revoke the cert on the core separately |
| `uninstall-venya-cli.sh` | operator user (no sudo) | uv tools `venya-cli` + `venya-mcp` and shims; optionally `~/.config/venya` (`VENYA_PURGE_CONFIG=yes`) | uv itself |
| `uninstall-venya-cli.ps1` | Administrator (Windows, machine-wide) | the install root (pinned uv, uv-managed Python, both tool venvs, shims), its bin dir from the MACHINE PATH; optionally the invoking user's `%APPDATA%\venya` (`VENYA_PURGE_CONFIG=yes`) | other users' per-profile config (a find-command is printed, not run) |

**Usage:**
```bash
# Core VM / Executor VM
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-core.sh | sudo VENYA_SKIP_PROMPT=yes bash
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-executor.sh | sudo VENYA_SKIP_PROMPT=yes bash

# Operator workstation (no sudo)
curl -fsSL https://github.com/tabith-llc/venya/releases/latest/download/uninstall-venya-cli.sh | VENYA_SKIP_PROMPT=yes VENYA_PURGE_CONFIG=yes bash
```

## Deployment

### Build and serve

```bash
cd /path/to/venya-installer
./create-tarball-and-serve.sh --ref <tag-or-commit>   # deterministic: builds from the git ref
./create-tarball-and-serve.sh                         # DEPRECATED working-tree mode (rollback only)
```

This creates three tarballs (`venya-core-install.tar.gz`, `venya-executor-install.tar.gz`, and the minimal `venya-cli-install.tar.gz` — `packages/cli` + `packages/mcp`), copies the install scripts **and the shared `venya-common.sh` library** to the serving directory, and starts an HTTP server on port 8080. In `--ref` mode every served byte (tarballs, scripts, `venya-common.sh`, this README) comes from the committed ref — the working tree is never consulted.

The piped install one-liners below work because the install scripts self-fetch `venya-common.sh` from the same origin as `VENYA_TARBALL` when it is not next to the script (no-`$0` case, i.e. `curl | sudo bash`).

### Deterministic rebuild from a published tag

Release tarballs from `v0.1.0-alpha.6` onward are `git archive` outputs — **byte-reproducible from any clone of the tag**. Anyone can verify a published asset:

```bash
git clone git@github.com:tabith-llc/venya.git && cd venya
TAG=v0.1.0-alpha.6   # any release tag ≥ alpha.6
cd /tmp
git -C venya archive --format=tar --prefix=./ "$TAG" | gzip -n > venya-core-install.tar.gz
git -C venya archive --format=tar --prefix=./ "$TAG" packages/cli packages/mcp | gzip -n > venya-cli-install.tar.gz
BASE=https://github.com/tabith-llc/venya/releases/download/$TAG
curl -fsSLO $BASE/venya-core-install.tar.gz.sha256
curl -fsSLO $BASE/venya-cli-install.tar.gz.sha256
sha256sum -c venya-core-install.tar.gz.sha256 venya-cli-install.tar.gz.sha256
```

Notes: the executor tarball is byte-identical to the core tarball by design (whole-tree archive; component choice happens at install time). Byte-stability requires `gzip -n` (strips the timestamp) and the same git major version. `--prefix=./` is load-bearing: the installers extract with `tar --strip-components=1`, which consumes the `./` component — an unprefixed archive loses every top-level file (the v0.1.0-alpha.5 defect; its assets match the recipe without `--prefix=./`). Local `git archive` output carries no `pax_global_header` entry (that record appears only in GitHub-generated tarballs).

### Install from a local build mirror (override the GitHub defaults)

The build script serves the tag-built tarballs + scripts on the build host's
network. Point installs at that mirror with `VENYA_TARBALL` (the scripts
self-fetch `venya-common.sh` from the same origin):

```bash
MIRROR=http://<build-host>:8080

# Core VM
curl -fsSL $MIRROR/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_TARBALL=$MIRROR/venya-core-install.tar.gz bash

# Executor VM
curl -fsSL $MIRROR/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_TARBALL=$MIRROR/venya-executor-install.tar.gz bash

# Operator workstation (no sudo)
curl -fsSL $MIRROR/install-venya-cli.sh | \
  VENYA_SKIP_PROMPT=yes VENYA_TARBALL=$MIRROR/venya-cli-install.tar.gz bash

# Stop the mirror server (on the build host)
pkill -f 'python3 -m http.server 8080'
```

## Dependency Summary

| Dependency | Core | Executor |
|---|---|---|
| `curl` | Yes | Yes |
| `sudo` | Yes | Yes |
| `build-essential` | No | Yes |
| `Rust / cargo` | No | Yes |
| `Nginx` | Yes | No |
| `PostgreSQL` | Yes | No |
| `sbx CLI` | No | Yes |

## Post-Install

### Core

```bash
sudo systemctl start venya-core
curl -sk https://<core-hostname>/api/v1/health
# Expected: {"status":"ok","version":"<server-version>","checks":{...}}
# (bare /health serves the identical payload as an alias)
```

### Executor

```bash
# mTLS registration happens AT INSTALL TIME when VENYA_EXECUTOR_ENROLLMENT_TOKEN
# was provided (admin mints one on a core: venya admin executor-enroll <executor-id>).
# The installer writes /etc/venya/executor/{executor.crt,executor.key,ca.crt}.
sudo systemctl start venya-executor      # already started by the installer; use after a manual stop
journalctl -u venya-executor -n 20       # heartbeat POST ... 200 OK
```

Deferred registration (no token at install time, or core unreachable → CA not
installed): the token is written to `/var/lib/venya/executor/bootstrap-token`
and the daemon registers automatically at service start once the core is
reachable — retry with `sudo systemctl restart venya-executor`.

### Service account (both)

`venya` is a **locked, nologin service account** — no interactive login (ssh/console/PAM) and no password is set. Root operates it with `sudo -u venya <cmd>` or an interactive `sudo -u venya bash` (break-glass; the account's own shell is nologin, so `su - venya` is refused by design).
