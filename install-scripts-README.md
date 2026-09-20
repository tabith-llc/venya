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
  VENYA_SKIP_PROMPT=yes VENYA_DB_PASSWORD=<strong-db-password> bash -s
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
- System packages: `curl`, `sudo`, `build-essential`
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

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_TARBALL` | `https://github.com/tabith-llc/venya/releases/latest/download/venya-executor-install.tar.gz` | Tarball URL |
| `VENYA_TARBALL_SHA256` | (optional) | Pin expected sha256 (strict integrity). Unset: fetched from `<tarball>.sha256` on the same origin (corruption guardrail); fail-closed |
| `VENYA_EXECUTOR_ID` | `venya-exec-1` | Executor identifier — CONTRACT: used as the relay dial hostname + client-cert SAN; must be resolvable from every core |
| `VENYA_SERVER_URL` | `https://venya-core` | Core server URL |
| `VENYA_EXECUTOR_ENROLLMENT_TOKEN` | (empty) | Bootstrap enrollment token — enables mTLS cert registration and heartbeat bootstrap at install time |
| `VENYA_DOCKER_USERNAME` | (prompt if TTY) | Docker account for sbx agent-template pulls |
| `VENYA_DOCKER_API_KEY` | (prompt if TTY) | Docker access token — stdin-only handling, never argv/disk; required unless already authenticated |
| `VENYA_SKIP_DOCKER_LOGIN` | (empty) | `yes` = degraded install (executor runs; sandbox executes fail 503 until `sudo -H -u venya sbx login`) |

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

Windows equivalent of `install-venya-cli.sh`, for PowerShell 5.1 and later. Installs
the same bundle; **no administrator rights are needed for the install itself.**

- **uv** (if missing, into `%USERPROFILE%\.local\bin`; uv persists that directory in the user `PATH`)
- `venya-cli` and `venya-mcp` via `uv tool install` (isolated venvs under `%APPDATA%\uv\tools`)
- Config lands in `%APPDATA%\venya\config.json`
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

> **FIDO2 limitation on Windows.** Since Windows 10 1903 the OS restricts raw
> CTAP/HID access to elevated processes. Until the platform WebAuthn API path
> lands, `venya init`, `venya login` and `venya credential add` require an
> **Administrator** terminal, and only work in an interactive desktop session —
> not over SSH or WinRM, because the platform API needs a foreground window
> handle. A standard (non-admin) user sees a misleading `No FIDO2 devices found`.
> Tracked as ticket `windows-fido2-requires-elevation`.
>
> Authenticator **reset** and **PIN management** are out of scope on Windows; the
> platform API exposes only `make_credential` / `get_assertion`. Customer IT owns
> those steps via the vendor's own tool.

*Serving note:* `create-tarball-and-serve.sh` serves both `.ps1` files when the
built ref contains them, and omits them (with a `WARN`, removing any stale copy)
for older refs. They are not yet GitHub release assets — adding them is a
`RELEASES.md` step.

### Uninstallers

Each artifact has a matching uninstaller (served from the same origin):

| Script | Runs as | Removes | Keeps |
|---|---|---|---|
| `uninstall-venya-core.sh` | root (on core VM) | service+unit, nginx site, /opt/venya, /etc/venya, /var/lib/venya (CA keys), well-known CA, trust entries, PostgreSQL db+role, venya user | nginx/postgresql OS packages |
| `uninstall-venya-executor.sh` | root (on executor VM) | service+mount+seccomp units, /opt/venya, /etc/venya (mTLS key), /var/lib/venya, trust entries, venya user (Rust/uv/sbx state) | sbx/docker packages, /etc/hosts (provisioning-owned); revoke the cert on the core separately |
| `uninstall-venya-cli.sh` | operator user (no sudo) | uv tools `venya-cli` + `venya-mcp` and shims; optionally `~/.config/venya` (`VENYA_PURGE_CONFIG=yes`) | uv itself |
| `uninstall-venya-cli.ps1` | operator user (Windows, no admin) | uv tools `venya-cli` + `venya-mcp` and shims; optionally `%APPDATA%\venya` (`VENYA_PURGE_CONFIG=yes`) | uv itself and the `.local\bin` `PATH` entry |

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
cd /media/dust/dust-ext1/projects/venya-installer
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

### Install on VMs (dev LAN server — override the GitHub defaults)

```bash
# Core VM
curl -fsSL http://10.27.27.35:8080/install-venya-core.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_TARBALL=http://10.27.27.35:8080/venya-core-install.tar.gz bash

# Executor VM
curl -fsSL http://10.27.27.35:8080/install-venya-executor.sh | sudo \
  VENYA_SKIP_PROMPT=yes VENYA_TARBALL=http://10.27.27.35:8080/venya-executor-install.tar.gz bash

# Operator workstation (no sudo)
curl -fsSL http://10.27.27.35:8080/install-venya-cli.sh | \
  VENYA_SKIP_PROMPT=yes VENYA_TARBALL=http://10.27.27.35:8080/venya-cli-install.tar.gz bash

# Stop the server
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
# Expected: {"status":"ok"}
```

### Executor

```bash
# 1. Generate mTLS certs on core server
# 2. Copy ca.crt, executor.crt, executor.key to /etc/venya/executor/
sudo systemctl start venya-executor
```

### Service account (both)

`venya` is a **locked, nologin service account** — no interactive login (ssh/console/PAM) and no password is set. Root operates it with `sudo -u venya <cmd>` or an interactive `sudo -u venya bash` (break-glass; the account's own shell is nologin, so `su - venya` is refused by design).
