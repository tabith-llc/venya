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
#   - optionally the platform config dir (config + stored access token):
#
# No sudo. Refuses to run as root — the tool is per-user.
#
# Environment variables:
#   VENYA_SKIP_PROMPT  - Set to "yes" to skip the confirmation prompt
#   VENYA_PURGE_CONFIG - Set to "yes" to also delete the platform config
#                        dir (~/.config/venya on Linux, ~/Library/Application Support/venya
#                        on macOS). A config dir that is a symlink is refused (#758):
#                        the run stops there and touches neither the link nor its
#                        target.
#                        (default: ask; without a TTY, config is KEPT)
###############################################################################

# --- Self-contained helpers (inlined from venya-common.sh, which stays the
# source of truth — keep in sync if these ever change). NO fetch fallback by
# design: an uninstaller must work with any origin down or air-gapped, and
# fetch-and-source is a supply-chain surface this path does not need.
# (Ticket uninstaller-fetch-origin-lan-default: the old fallback defaulted to
# the dev LAN origin, breaking every piped customer uninstall.)
venya_print_colors() {
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'

    info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
    warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
    error() { echo -e "${RED}[ERROR]${NC} $*"; }
}

venya_print_colors

if [ "$(id -u)" = "0" ]; then
    error "Do not run as root. The CLI is installed per-user (uv tool)."
    exit 1
fi

export PATH="$HOME/.local/bin:$PATH"

if [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
    # #399: read on a closed/EOF stdin aborts under set -e with zero output.
    # Gate the non-TTY case loudly first, before any removal — same contract
    # as the #389 install-side gate. Deletion is destructive: no auto-proceed.
    if [ ! -t 0 ]; then
        error "non-interactive session: set VENYA_SKIP_PROMPT=yes to confirm removal"
        exit 1
    fi
    read -r -p "Remove the venya CLI for user $(id -un)? [Y/n] " answer
    [[ "$answer" =~ ^[Nn] ]] && { info "Aborted."; exit 0; }
fi

PURGE="${VENYA_PURGE_CONFIG:-}"
if [ -z "$PURGE" ]; then
    if [ -t 0 ]; then
        read -r -p "Also delete the venya config dir (server URL + stored access token)? [y/N] " answer
        [[ "$answer" =~ ^[Yy] ]] && PURGE=yes || PURGE=no
    else
        PURGE=no
        info "Non-interactive: keeping the venya config dir (set VENYA_PURGE_CONFIG=yes to remove)."
    fi
fi

if command -v uv > /dev/null 2>&1; then
    uv tool uninstall venya-cli > /dev/null 2>&1 || warn "uv tool uninstall reported nothing to remove (venya-cli)."
    uv tool uninstall venya-mcp > /dev/null 2>&1 || true
    UV_TOOLS_DIR="$(uv tool dir 2>/dev/null)" || UV_TOOLS_DIR=""
else
    warn "uv not found — removing shims/venvs manually."
    UV_TOOLS_DIR=""
fi

# #390: uv's env + shim removal is receipt-driven (uv-receipt.toml). On a
# de-registered or de-contented tool env `uv tool uninstall` reports "is not
# installed" and removes NOTHING, leaving the ~/.local/bin shims resolving to
# a broken launcher. Always clear the installer's writer sites ourselves; the
# verify below still fails loud (exit 1) if anything resolves afterwards.
: "${UV_TOOLS_DIR:=$HOME/.local/share/uv/tools}"
rm -rf "${UV_TOOLS_DIR:?}/venya-cli" "${UV_TOOLS_DIR:?}/venya-mcp"
rm -f "$HOME/.local/bin/venya" "$HOME/.local/bin/venya-mcp"

if [ "$PURGE" = "yes" ]; then
    # Platform matrix must match the installer (install-venya-cli.sh Darwin/
    # Linux branch) and venya_cli.api_client.default_config_dir():
    #   Darwin -> $HOME/Library/Application Support/venya
    #   Linux/other -> $HOME/.config/venya
    # (Windows tokens live in %APPDATA%\venya and are removed by
    #  uninstall-venya-cli.ps1 — this bash script never runs there.)
    case "$(uname -s)" in
        Darwin) VENYA_CONFIG_DIR="$HOME/Library/Application Support/venya" ;;
        *)      VENYA_CONFIG_DIR="$HOME/.config/venya" ;;
    esac

    # #758 (a): a config dir that is a symlink is not this user's config. `rm -rf`
    # on a symlink unlinks the NAME and succeeds, so the run printed "Removed …"
    # while the server URL and stored access token at the target stood untouched.
    # Same -L test venya-common.sh ships for a symlinked file:// tarball (#327) and
    # the one #755 put on the core uninstaller's state paths; -L is an lstat, so a
    # dangling link is caught where -e would read "gone".
    if [ -L "$VENYA_CONFIG_DIR" ]; then
        link_target="$(readlink -f -- "$VENYA_CONFIG_DIR" 2> /dev/null || true)"
        error "Config dir is a symlink: $VENYA_CONFIG_DIR${link_target:+ -> $link_target} — refusing to follow it (#758)."
        error "That path and what it points at were NOT touched; the tool and shim removals above already ran. Repoint it at a real directory, or remove what it points at yourself."
        exit 1
    fi

    # #758 (b): prove the removal instead of asserting it. `rm -f` semantics report
    # success for an operand that was never there, and the only later checks in this
    # script are PATH tests (`command -v`), not a directory test — so the old line
    # printed for a directory that did not exist. Absence is read after the removal,
    # on -e and -L together, and the success line is conditional on that proof.
    CONFIG_DIR_PRESENT="no"
    if [ -e "$VENYA_CONFIG_DIR" ] || [ -L "$VENYA_CONFIG_DIR" ]; then
        CONFIG_DIR_PRESENT="yes"
    fi
    rm -rf "$VENYA_CONFIG_DIR"
    if [ "$CONFIG_DIR_PRESENT" != "yes" ]; then
        info "No config dir at $VENYA_CONFIG_DIR — nothing to remove."
    elif [ -e "$VENYA_CONFIG_DIR" ] || [ -L "$VENYA_CONFIG_DIR" ]; then
        error "$VENYA_CONFIG_DIR still present after removal — inspect manually."
        exit 1
    else
        info "Removed $VENYA_CONFIG_DIR."
    fi
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
