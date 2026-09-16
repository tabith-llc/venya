# Venya HTTP Install Scripts

Installation scripts for Venya components, served via HTTP for VM provisioning.

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
curl -fsSL http://10.27.27.35:8080/install-venya-core.sh | sudo bash
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_DB_PASSWORD` | (prompt) | PostgreSQL venya user password |
| `VENYA_DB_PASSPHRASE` | `venya_test_passphrase_2024` | Server encryption passphrase |
| `VENYA_TARBALL` | `http://10.27.27.35:8080/venya-core-install.tar.gz` | Tarball URL |
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
curl -fsSL http://10.27.27.35:8080/install-venya-executor.sh | sudo bash
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_INSTALL_DIR` | `/opt/venya` | Install location |
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompts |
| `VENYA_TARBALL` | `http://10.27.27.35:8080/venya-executor-install.tar.gz` | Tarball URL |
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
curl -fsSL http://10.27.27.35:8080/install-venya-cli.sh | VENYA_TARBALL_SHA256=<cli-sha256> bash
```

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `VENYA_SKIP_PROMPT` | (empty) | Set to `yes` to skip confirmation prompt |
| `VENYA_INSTALL_MCP` | `yes` | Set to `no` to install only the CLI (skip `venya-mcp`) |
| `VENYA_TARBALL` | `http://10.27.27.35:8080/venya-cli-install.tar.gz` | Tarball URL (workstation bundle: `packages/cli` + `packages/mcp`) |
| `VENYA_TARBALL_SHA256` | (required) | SHA-256 of the CLI tarball; aborts without it |

### Uninstallers

Each artifact has a matching uninstaller (served from the same origin):

| Script | Runs as | Removes | Keeps |
|---|---|---|---|
| `uninstall-venya-core.sh` | root (on core VM) | service+unit, nginx site, /opt/venya, /etc/venya, /var/lib/venya (CA keys), well-known CA, trust entries, PostgreSQL db+role, venya user | nginx/postgresql OS packages |
| `uninstall-venya-executor.sh` | root (on executor VM) | service+mount+seccomp units, /opt/venya, /etc/venya (mTLS key), /var/lib/venya, trust entries, venya user (Rust/uv/sbx state) | sbx/docker packages, /etc/hosts (provisioning-owned); revoke the cert on the core separately |
| `uninstall-venya-cli.sh` | operator user (no sudo) | uv tools `venya-cli` + `venya-mcp` and shims; optionally `~/.config/venya` (`VENYA_PURGE_CONFIG=yes`) | uv itself |

**Usage:**
```bash
# Core VM / Executor VM
curl -fsSL http://10.27.27.35:8080/uninstall-venya-core.sh | sudo VENYA_SKIP_PROMPT=yes bash
curl -fsSL http://10.27.27.35:8080/uninstall-venya-executor.sh | sudo VENYA_SKIP_PROMPT=yes bash

# Operator workstation (no sudo)
curl -fsSL http://10.27.27.35:8080/uninstall-venya-cli.sh | VENYA_SKIP_PROMPT=yes VENYA_PURGE_CONFIG=yes bash
```

## Deployment

### Build and serve

```bash
cd /media/dust/dust-ext1/projects/venya-installer
./create-tarball-and-serve.sh
```

This creates three tarballs (`venya-core-install.tar.gz`, `venya-executor-install.tar.gz`, and the minimal `venya-cli-install.tar.gz` — `packages/cli` only), copies the install scripts **and the shared `venya-common.sh` library** to the serving directory, and starts an HTTP server on port 8080.

The piped install one-liners below work because the install scripts self-fetch `venya-common.sh` from the same origin as `VENYA_TARBALL` when it is not next to the script (no-`$0` case, i.e. `curl | sudo bash`).

### Install on VMs

```bash
# Core VM
curl -fsSL http://10.27.27.35:8080/install-venya-core.sh | sudo bash

# Executor VM
curl -fsSL http://10.27.27.35:8080/install-venya-executor.sh | sudo bash

# Operator workstation (no sudo)
curl -fsSL http://10.27.27.35:8080/install-venya-cli.sh | VENYA_TARBALL_SHA256=<cli-sha256> bash

# Stop the server
pkill -f 'python3 -m http.server 8080'
```

## Dependency Summary

| Dependency | Core | Executor | Debug Tools |
|---|---|---|---|
| `curl` | Yes | Yes | — |
| `sudo` | Yes | Yes | — |
| `build-essential` | No | Yes | — |
| `Rust / cargo` | No | Yes | — |
| `Nginx` | Yes | No | — |
| `PostgreSQL` | Yes | No | — |
| `sbx CLI` | No | Yes | — |
| Debug packages | — | — | Yes |

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
