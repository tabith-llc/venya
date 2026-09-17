#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

set -euo pipefail

###############################################################################
# Venya Workstation CLI Installer
#
# Installs the Venya workstation client bundle for the CURRENT (non-root)
# operator user:
#   - uv (if missing) into ~/.local/bin
#   - venya-cli via `uv tool install` (isolated venv, `venya` shim)
#   - venya-mcp via `uv tool install` (isolated venv, `venya-mcp` shim;
#     set VENYA_INSTALL_MCP=no to skip)
#
# No sudo required. Refuses to run as root — the tools are per-user.
#
# Environment variables:
#   VENYA_SKIP_PROMPT     - Set to "yes" to skip the confirmation prompt
#   VENYA_INSTALL_MCP     - Set to "no" to install only the CLI (default: both)
#   VENYA_TARBALL         - URL of the venya-cli tarball (default: latest GitHub
#                           release asset — https://github.com/tabith-llc/venya/
#                           releases/latest/download/venya-cli-install.tar.gz)
#   VENYA_TARBALL_SHA256  - Pin the expected sha256 (recommended: strict integrity).
#                           If unset, the installer fetches <tarball-url>.sha256 from
#                           the same origin as a corruption guardrail; fail-closed.
###############################################################################

# --- Defaults ---
TARBALL_URL="${VENYA_TARBALL:-https://github.com/tabith-llc/venya/releases/latest/download/venya-cli-install.tar.gz}"

# --- Source common library ---
# Direct execution: the library sits next to the script. Piped execution
# (curl | bash): $0 has no directory — fetch from the tarball origin.
COMMON_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$COMMON_DIR/venya-common.sh" ]; then
    source "$COMMON_DIR/venya-common.sh"
else
    FETCH_DIR="$(mktemp -d)"
    trap 'rm -rf "$FETCH_DIR"' EXIT
    echo "Fetching shared installer library from ${TARBALL_URL%/*}/venya-common.sh" >&2
    curl -fsSL "${TARBALL_URL%/*}/venya-common.sh" -o "$FETCH_DIR/venya-common.sh" || exit 1
    source "$FETCH_DIR/venya-common.sh"
fi

venya_print_colors

if [ "$(id -u)" = "0" ]; then
    error "Do not run as root. The CLI installs per-user (uv tool, ~/.local/bin)."
    error "Run as the operator user: bash install-venya-cli.sh"
    exit 1
fi

if [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
    read -r -p "Install venya CLI for user $(id -un)? [Y/n] " answer
    if [[ "$answer" =~ ^[Nn] ]]; then
        info "Aborted."
        exit 0
    fi
fi

info "Installing Venya CLI for $(id -un)..."

# --- uv (per-user) ---
export PATH="$HOME/.local/bin:$PATH"
venya_install_uv

# --- Download + verify (sha256: explicit pin, else same-origin sidecar; fail-closed) ---
venya_download_tarball cli

# --- Extract (workstation bundle: packages/cli + packages/mcp) ---
EXTRACT_DIR="$(mktemp -d)"
tar xzf "$TARBALL_FILE" -C "$EXTRACT_DIR"
rm -f "$TARBALL_FILE"

if [ ! -f "$EXTRACT_DIR/packages/cli/pyproject.toml" ]; then
    error "Tarball layout unexpected: packages/cli/pyproject.toml not found."
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

# --- Install via uv tool (isolated venvs + ~/.local/bin shims) ---
info "Installing venya-cli via uv tool..."
uv tool install --force --python 3.14 "$EXTRACT_DIR/packages/cli" > /dev/null

INSTALL_MCP="${VENYA_INSTALL_MCP:-yes}"
if [ "$INSTALL_MCP" != "no" ]; then
    if [ ! -f "$EXTRACT_DIR/packages/mcp/pyproject.toml" ]; then
        error "Tarball layout unexpected: packages/mcp/pyproject.toml not found (VENYA_INSTALL_MCP != no)."
        rm -rf "$EXTRACT_DIR"
        exit 1
    fi
    info "Installing venya-mcp via uv tool..."
    uv tool install --force --python 3.14 "$EXTRACT_DIR/packages/mcp" > /dev/null
fi
rm -rf "$EXTRACT_DIR"

# --- Verify ---
if ! command -v venya > /dev/null 2>&1; then
    error "venya shim not found on PATH after install."
    error "Ensure $HOME/.local/bin is on your PATH (run: uv tool update-shell)"
    exit 1
fi
venya --help > /dev/null
info "venya CLI installed: $(command -v venya)"
if [ "$INSTALL_MCP" != "no" ]; then
    if ! command -v venya-mcp > /dev/null 2>&1; then
        error "venya-mcp shim not found on PATH after install."
        exit 1
    fi
    # No --help probe: venya-mcp is a stdio server (would block). Import check instead.
    MCP_PY="$(uv tool dir)/venya-mcp/bin/python"
    if [ -x "$MCP_PY" ] && ! "$MCP_PY" -c "import venya_mcp.server" 2> /dev/null; then
        error "venya-mcp installed but its server module fails to import."
        exit 1
    fi
    info "venya-mcp installed: $(command -v venya-mcp)"
fi

# --- FIDO2 access check (Linux: /dev/hidraw perms; macOS: IOKit HID, no setup) ---
if [ "$(uname -s)" = "Darwin" ]; then
    info "FIDO2 on macOS uses IOKit HID — no udev rules or root required."
    info "Plug in the security key before first venya login/enroll."
else
    HIDRAW_RW=0
    for d in /dev/hidraw*; do
        if [ -r "$d" ] && [ -w "$d" ]; then
            HIDRAW_RW=1
            break
        fi
    done
    if [ "$HIDRAW_RW" != "1" ]; then
        warn "No read/write access to /dev/hidraw* — FIDO2 key will not be reachable as this user."
        warn "Fix (one-time, needs sudo):"
        warn "  echo 'KERNEL==\"hidraw*\", SUBSYSTEM==\"hidraw\", MODE=\"0660\", GROUP=\"plugdev\"' | sudo tee /etc/udev/rules.d/60-fido2.rules"
        warn "  sudo udevadm control --reload-rules && sudo udevadm trigger"
        warn "  sudo usermod -aG plugdev $(id -un)   # then re-login"
    fi
fi

# Platform-appropriate default CA cert location (instructional, not enforced)
if [ "$(uname -s)" = "Darwin" ]; then
    CA_CERT="$HOME/Library/Application Support/venya/venya-ca.crt"
else
    CA_CERT="$HOME/.config/venya-ca.crt"
fi

echo ""
echo "============================================"
echo "  Venya CLI installed for $(id -un)"
echo "============================================"
echo ""
echo "Day-one commands:"
echo "  venya config set-server https://<core-host>"
echo "  curl -sk https://<core-host>/.well-known/venya-ca.crt -o $CA_CERT"
echo "  SSL_CERT_FILE=$CA_CERT venya init <user-id>    # create the first admin account (FIDO2 key required)"
echo "  SSL_CERT_FILE=$CA_CERT venya login <user-id>"
if [ "$INSTALL_MCP" != "no" ]; then
    echo ""
    echo "MCP (LLM clients) — point the client at the venya-mcp shim and provide:"
    echo "  VENYA_CONFIG=<path>/config.json  (server_url + access_token from venya login)"
    echo "  VENYA_CA_CERT=$CA_CERT  (required at startup)"
fi
echo ""
