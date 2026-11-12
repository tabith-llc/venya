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
#                           REQUIRED (no sidecar fallback) when the tarball source is
#                           NOT https (file:// or plain http://) — #375/#327.
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
    # #360 (installer-common-self-fetch-unhashed): VERIFY before source. The
    # serve-time runner sed-embeds the expected sha256 into the placeholder
    # below; VENYA_COMMON_SHA256 is the operator pin and wins over it. With
    # neither (raw-checkout bytes without embedding), fall back to the origin
    # sidecar; if that is unobtainable too, abort FAIL-CLOSED — an unverified
    # library is never sourced as root (mirrors the #327 tarball guard).
    # #368: the placeholder-as-literal NEVER appears contiguous outside the
    # assignment default — the split-quote idiom below is invisible to the
    # serve-time sed, so only the ${VENYA_COMMON_SHA256:-...} default is
    # substituted and the guard cannot self-null into self-attestation.
    EXPECTED_COMMON_SHA="${VENYA_COMMON_SHA256:-__VENYA_COMMON_SHA256__}"
    if [ "$EXPECTED_COMMON_SHA" = '__VENYA''_COMMON_SHA256__' ]; then
        EXPECTED_COMMON_SHA=""
    fi
    if [ -z "$EXPECTED_COMMON_SHA" ]; then
        echo "No embedded/pinned common-library hash — fetching sidecar ${TARBALL_URL%/*}/venya-common.sh.sha256" >&2
        curl -fsSL "${TARBALL_URL%/*}/venya-common.sh.sha256" -o "$FETCH_DIR/venya-common.sh.sha256" || {
            echo "[ERROR] VENYA_COMMON_SHA256 unset and no hash sidecar at the origin — refusing to source an unverified library." >&2
            exit 1
        }
        EXPECTED_COMMON_SHA="$(awk '{print $1}' "$FETCH_DIR/venya-common.sh.sha256")"
    fi
    ACTUAL_COMMON_SHA="$(sha256sum "$FETCH_DIR/venya-common.sh" | awk '{print $1}')"
    if [ "$ACTUAL_COMMON_SHA" != "$EXPECTED_COMMON_SHA" ]; then
        echo "[ERROR] venya-common.sh SHA-256 MISMATCH — expected $EXPECTED_COMMON_SHA, got $ACTUAL_COMMON_SHA. Refusing to source." >&2
        exit 1
    fi
    echo "venya-common.sh verified (sha256 $ACTUAL_COMMON_SHA)" >&2
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
# #744: keep the PATH this script was handed, before the export below. The
# login-shell probe in the verify section answers with it, so the check reads
# the operator's shell and not this process's own edit.
VENYA_PATH_INHERITED="$PATH"
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

# --- Login-shell probe (#744) ---
# The export above puts ~/.local/bin on THIS process's PATH, so a bare
# `command -v` measures the installer, not the operator: it answers "found"
# even in a shell that can never resolve the name. This probe re-runs bash as a
# LOGIN shell with the PATH this script inherited, so the answer is what a new
# terminal sees. A non-bash operator shell reads its own startup file; the
# remedy text below names the line for that case too.
# Prints the resolved path; prints nothing when the login shell resolves none.
venya_login_shell_path() {
    local _name="$1" _found
    _found="$(PATH="$VENYA_PATH_INHERITED" bash -lc 'command -v -- "$1"' _ "$_name" 2>/dev/null | tail -n 1 || true)"
    # A startup file that prints can land anything in _found: only an executable
    # path counts as a resolution.
    if [ -n "$_found" ] && [ -x "$_found" ]; then
        printf '%s' "$_found"
    fi
}

# Reachable remedy: this sits on the branch the PATH export cannot mask.
# uv tool update-shell edits the operator's login files, so it is named for them
# to run and is never run here.
venya_print_path_remedy() {
    warn "Shims installed, but a new login shell does not resolve:$1"
    warn "Add this line to your shell startup file (~/.profile or ~/.bashrc for bash,"
    warn "~/.zshrc for zsh, ~/.config/fish/config.fish for fish):"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    warn "Then open a new terminal. Or run this, which edits those files for you:"
    warn "  uv tool update-shell"
}

# --- Verify ---
# Two distinct facts: the shim exists (install worked), and a fresh login shell
# resolves the name (the operator can type it). Only the second one is reported
# as "installed:".
LOGIN_UNRESOLVED=""
VENYA_SHIM="$(command -v venya 2>/dev/null || true)"
if [ -z "$VENYA_SHIM" ]; then
    error "venya shim not found on PATH after install — uv tool install created no shim."
    error "Ensure $HOME/.local/bin is on your PATH (run: uv tool update-shell)"
    exit 1
fi
"$VENYA_SHIM" --help > /dev/null
VENYA_LOGIN_SHIM="$(venya_login_shell_path venya)"
if [ -n "$VENYA_LOGIN_SHIM" ]; then
    info "venya CLI installed: $VENYA_LOGIN_SHIM (proven in a login shell)"
else
    LOGIN_UNRESOLVED="$LOGIN_UNRESOLVED venya"
    info "venya CLI shim installed at $VENYA_SHIM — a login shell does NOT resolve 'venya' yet."
fi
if [ "$INSTALL_MCP" != "no" ]; then
    MCP_SHIM="$(command -v venya-mcp 2>/dev/null || true)"
    if [ -z "$MCP_SHIM" ]; then
        error "venya-mcp shim not found on PATH after install — uv tool install created no shim."
        error "Ensure $HOME/.local/bin is on your PATH (run: uv tool update-shell)"
        exit 1
    fi
    # No --help probe: venya-mcp is a stdio server (would block). Import check instead.
    MCP_PY="$(uv tool dir)/venya-mcp/bin/python"
    if [ -x "$MCP_PY" ]; then
        if ! "$MCP_PY" -c "import venya_mcp.server" 2> /dev/null; then
            error "venya-mcp installed but its server module fails to import."
            exit 1
        fi
        # #396 contract: claims gate on verification — the installed claim
        # prints only after the import check actually ran (and passed; the
        # error + exit path above fails loud otherwise).
        MCP_LOGIN_SHIM="$(venya_login_shell_path venya-mcp)"
        if [ -n "$MCP_LOGIN_SHIM" ]; then
            info "venya-mcp installed: $MCP_LOGIN_SHIM (proven in a login shell)"
        else
            LOGIN_UNRESOLVED="$LOGIN_UNRESOLVED venya-mcp"
            info "venya-mcp shim installed at $MCP_SHIM — a login shell does NOT resolve 'venya-mcp' yet."
        fi
    else
        # Absent interpreter = NOT verified: disclose degraded, no claim.
        warn "venya-mcp import check SKIPPED - interpreter missing at $MCP_PY; venya-mcp install is UNVERIFIED."
    fi
fi

if [ -n "$LOGIN_UNRESOLVED" ]; then
    venya_print_path_remedy "$LOGIN_UNRESOLVED"
fi

# --- FIDO2 access check (Linux: hidraw usage-page classifier; macOS: IOKit HID registry) ---
if [ "$(uname -s)" = "Darwin" ]; then
    # The same classifier the Linux arm uses, read out of IOKit instead of sysfs.
    # It used to assert "no udev rules or root required" without observing anything,
    # so a Mac with no key printed the same two lines as a Mac with one, and a
    # physical run could only score the banner. A FIDO device is identified by HID
    # usage page 0xF1D0, which ioreg -l prints in decimal as 61904; 61440 is 0xF000
    # and must not answer for a key, exactly as a keyboard must not on Linux.
    # macOS has no per-device file permission to test: IOKit HID is opened by the
    # console user with no udev rule and no root, so the honest statement is made
    # once, on the path where a key was actually seen.
    # VENYA_IOREG_FILE names a saved "ioreg -r -c IOHIDDevice -l" dump so the cells
    # can drive both branches without a Mac; the default is the live call.
    if [ -n "${VENYA_IOREG_FILE:-}" ]; then
        HID_IOREG_OUT="$(cat -- "$VENYA_IOREG_FILE" 2> /dev/null || true)"
    else
        HID_IOREG_OUT="$(ioreg -r -c IOHIDDevice -l 2> /dev/null || true)"
    fi
    HID_FIDO_COUNT="$(printf '%s\n' "$HID_IOREG_OUT" | grep -c '"PrimaryUsagePage" = 61904' || true)"
    if [ "${HID_FIDO_COUNT:-0}" -gt 0 ]; then
        info "FIDO2 key visible via IOKit HID — usage page 0xF1D0 matched $HID_FIDO_COUNT node(s)."
        info "macOS needs no udev rule and no root for it — plug in the security key before first venya login/enroll."
    fi
else
    # A security key is identified by its HID usage page (0xF1D0), not by the mere
    # existence of a /dev/hidraw node: a keyboard or a joystick on that bus used to
    # answer for a FIDO key here, and a host with no HID nodes at all warned too,
    # because an unmatched glob runs the loop body once with the literal pattern.
    # The two roots are overridable so the #748 cells can drive both branches
    # without hardware; the defaults are the real paths.
    HIDRAW_CLASS="${VENYA_HIDRAW_CLASS_DIR:-/sys/class/hidraw}"
    HIDRAW_DEV="${VENYA_HIDRAW_DEV_DIR:-/dev}"
    HID_OK=""      # a FIDO node this user can read and write
    HID_NODE=""    # the first FIDO node this user cannot reach
    HID_ID=""      # its device identity, so the warning names a device, not a bus
    for sysdir in "$HIDRAW_CLASS"/hidraw*; do
        [ -d "$sysdir" ] || continue
        node="$HIDRAW_DEV/${sysdir##*/}"
        [ -e "$node" ] || continue
        # Short item 06 D0 F1 = Usage Page (0xF1D0, FIDO), read out of the same
        # sysfs attribute systemd's own fido_id classifier uses. A kernel that
        # does not expose it classifies nothing, and so stays silent here too.
        LC_ALL=C grep -a -qF -- $'\x06\xd0\xf1' "$sysdir/device/report_descriptor" 2> /dev/null || continue
        if [ -r "$node" ] && [ -w "$node" ]; then
            HID_OK="$node"
            break
        fi
        if [ -z "$HID_NODE" ]; then
            HID_NODE="$node"
            HID_ID="$(cat "$sysdir/device/modalias" 2> /dev/null || true)"
        fi
    done
    if [ -n "$HID_OK" ]; then
        info "FIDO2 key reachable at $HID_OK"
    elif [ -n "$HID_NODE" ]; then
        warn "FIDO2 key present at $HID_NODE${HID_ID:+ ($HID_ID)} — not readable/writable as $(id -un), so venya cannot reach it."
        warn "The key belongs to the machine it is plugged into, and systemd grants the user logged"
        warn "in at that console access to security keys already. If this shell is not that user,"
        warn "run venya there. To grant just this device instead:"
        warn "  sudo chown $(id -un) $HID_NODE   # until the key is unplugged; needs no udev rule"
    fi
fi

# Platform-appropriate config dir (instructional, not enforced) — `venya setup`
# installs the core CA cert here as ca.crt
if [ "$(uname -s)" = "Darwin" ]; then
    VENYA_CONFIG_DIR="$HOME/Library/Application Support/venya"
else
    VENYA_CONFIG_DIR="$HOME/.config/venya"
fi

echo ""
echo "============================================"
echo "  Venya CLI installed for $(id -un)"
echo "============================================"
echo ""
if [ -n "$LOGIN_UNRESOLVED" ]; then
    # Stated before the commands, not after: an operator whose shell cannot
    # resolve the name would meet "command not found" on the first line below.
    echo "The day-one commands need a shell that resolves 'venya' — add the PATH line above,"
    echo "then open a new terminal before typing any of them."
    echo ""
fi
echo "Day-one commands:"
echo "  venya setup <core-host>    # save the server URL + install the core CA cert (fingerprint printed for verification)"
echo "  venya init <user-id>       # create the first admin account (FIDO2 key required)"
echo "  venya login <user-id>"
if [ "$INSTALL_MCP" != "no" ]; then
    echo ""
    echo "MCP (LLM clients) — point the client at the venya-mcp shim and provide:"
    echo "  VENYA_CONFIG=$VENYA_CONFIG_DIR/config.json  (server_url + access_token from venya login)"
    echo "  VENYA_CA_CERT=$VENYA_CONFIG_DIR/ca.crt  (installed by venya setup; required at startup)"
fi
echo ""
