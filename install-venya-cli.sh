#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Workstation CLI Installer
#
# Installs the `venya` CLI for the CURRENT (non-root) operator user:
#   - uv (if missing) into ~/.local/bin
#   - venya-cli via `uv tool install` (isolated venv, shim in ~/.local/bin)
#
# No sudo required. Refuses to run as root — the tool is per-user.
#
# Environment variables:
#   VENYA_SKIP_PROMPT     - Set to "yes" to skip the confirmation prompt
#   VENYA_TARBALL         - URL of the venya-cli tarball
#                           (default: http://10.27.27.35:8080/venya-cli-install.tar.gz)
#   VENYA_TARBALL_SHA256  - REQUIRED. sha256 of the tarball; aborts without it.
###############################################################################

# --- Defaults ---
TARBALL_URL="${VENYA_TARBALL:-http://10.27.27.35:8080/venya-cli-install.tar.gz}"

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

# --- Download + verify (hard-fails without VENYA_TARBALL_SHA256) ---
venya_download_tarball cli

# --- Extract (minimal tarball: packages/cli only) ---
EXTRACT_DIR="$(mktemp -d)"
tar xzf "$TARBALL_FILE" -C "$EXTRACT_DIR"
rm -f "$TARBALL_FILE"

if [ ! -f "$EXTRACT_DIR/packages/cli/pyproject.toml" ]; then
    error "Tarball layout unexpected: packages/cli/pyproject.toml not found."
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

# --- Install via uv tool (isolated venv + ~/.local/bin shim) ---
info "Installing venya-cli via uv tool..."
uv tool install --force --python 3.14 "$EXTRACT_DIR/packages/cli" > /dev/null
rm -rf "$EXTRACT_DIR"

# --- Verify ---
if ! command -v venya > /dev/null 2>&1; then
    error "venya shim not found on PATH after install."
    error "Ensure $HOME/.local/bin is on your PATH (run: uv tool update-shell)"
    exit 1
fi
venya --help > /dev/null
info "venya CLI installed: $(command -v venya)"

# --- FIDO2 non-root access check (actionable, never silently requires root) ---
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

echo ""
echo "============================================"
echo "  Venya CLI installed for $(id -un)"
echo "============================================"
echo ""
echo "Day-one commands:"
echo "  venya config set-server https://<core-host>"
echo "  curl -sk https://<core-host>/.well-known/venya-ca.crt -o ~/.config/venya-ca.crt"
echo "  SSL_CERT_FILE=~/.config/venya-ca.crt venya login <user-id>"
echo ""
