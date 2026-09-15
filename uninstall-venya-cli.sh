#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

set -euo pipefail

###############################################################################
# Venya Workstation CLI Uninstaller
#
# Removes what install-venya-cli.sh created for the CURRENT user:
#   - the venya-cli and venya-mcp uv tools (shims in ~/.local/bin)
#   - optionally ~/.config/venya (config + stored access token)
#
# No sudo. Refuses to run as root — the tool is per-user.
#
# Environment variables:
#   VENYA_SKIP_PROMPT  - Set to "yes" to skip the confirmation prompt
#   VENYA_PURGE_CONFIG - Set to "yes" to also delete ~/.config/venya
#                        (default: ask; without a TTY, config is KEPT)
###############################################################################

# --- Source common library (same pattern as the installers) ---
COMMON_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$COMMON_DIR/venya-common.sh" ]; then
    source "$COMMON_DIR/venya-common.sh"
else
    FETCH_ORIGIN="${VENYA_FETCH_ORIGIN:-http://10.27.27.35:8080}"
    FETCH_DIR="$(mktemp -d)"
    trap 'rm -rf "$FETCH_DIR"' EXIT
    echo "Fetching shared installer library from $FETCH_ORIGIN/venya-common.sh" >&2
    curl -fsSL "$FETCH_ORIGIN/venya-common.sh" -o "$FETCH_DIR/venya-common.sh" || exit 1
    source "$FETCH_DIR/venya-common.sh"
fi

venya_print_colors

if [ "$(id -u)" = "0" ]; then
    error "Do not run as root. The CLI is installed per-user (uv tool)."
    exit 1
fi

export PATH="$HOME/.local/bin:$PATH"

if [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
    read -r -p "Remove the venya CLI for user $(id -un)? [Y/n] " answer
    [[ "$answer" =~ ^[Nn] ]] && { info "Aborted."; exit 0; }
fi

PURGE="${VENYA_PURGE_CONFIG:-}"
if [ -z "$PURGE" ]; then
    if [ -t 0 ]; then
        read -r -p "Also delete ~/.config/venya (server URL + stored access token)? [y/N] " answer
        [[ "$answer" =~ ^[Yy] ]] && PURGE=yes || PURGE=no
    else
        PURGE=no
        info "Non-interactive: keeping ~/.config/venya (set VENYA_PURGE_CONFIG=yes to remove)."
    fi
fi

if command -v uv > /dev/null 2>&1; then
    uv tool uninstall venya-cli > /dev/null 2>&1 || warn "uv tool uninstall reported nothing to remove (venya-cli)."
    uv tool uninstall venya-mcp > /dev/null 2>&1 || true
else
    warn "uv not found — removing shims/venvs manually."
    rm -rf "$HOME/.local/share/uv/tools/venya-cli" "$HOME/.local/bin/venya"
    rm -rf "$HOME/.local/share/uv/tools/venya-mcp" "$HOME/.local/bin/venya-mcp"
fi

if [ "$PURGE" = "yes" ]; then
    rm -rf "$HOME/.config/venya"
    info "Removed ~/.config/venya."
fi

if command -v venya > /dev/null 2>&1; then
    error "venya still resolves at $(command -v venya) — inspect manually."
    exit 1
fi
if command -v venya-mcp > /dev/null 2>&1; then
    error "venya-mcp still resolves at $(command -v venya-mcp) — inspect manually."
    exit 1
fi

info "Venya CLI uninstalled for $(id -un)."
