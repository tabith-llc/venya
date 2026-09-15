#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Executor Uninstaller
#
# Removes everything install-venya-executor.sh created on this machine:
#   - venya-executor service + secrets tmpfs mount + seccomp profile + units
#   - /opt/venya, /etc/venya (executor.toml, executor certs, egress allowlist)
#   - /var/lib/venya (executor CA), /var/log/venya
#   - Venya CA trust-store entries (+ update-ca-certificates)
#   - venya service account (home carries Rust toolchain, uv, sbx state)
#
# NOT removed (shared infrastructure / provisioning-owned):
#   - sbx/docker OS packages (dpkg -r docker-sbx yourself if desired)
#   - the /etc/hosts core entry (written by provisioning as well)
#   - the executor's registration ON THE CORE: revoke it there with
#     `venya admin revoke-executor <executor-id>` (or it expires with the core DB)
#
# Environment variables:
#   VENYA_SKIP_PROMPT - Set to "yes" to skip the confirmation prompt
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
venya_check_root

if [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
    echo "This will REMOVE Venya Executor from $(hostname): service, /opt/venya,"
    read -r -p "/etc/venya (incl. mTLS key), /var/lib/venya, and the venya user. Proceed? [y/N] " answer
    [[ "$answer" =~ ^[Yy] ]] || { info "Aborted."; exit 0; }
fi

info "Stopping venya-executor..."
systemctl disable --now venya-executor > /dev/null 2>&1 || true
systemctl stop tmp-venya_secrets.mount > /dev/null 2>&1 || true
rm -f /etc/systemd/system/venya-executor.service \
      /etc/systemd/system/tmp-venya_secrets.mount \
      /etc/systemd/system/venya-executor.seccomp
systemctl daemon-reload

info "Removing CA trust entries..."
rm -f /usr/local/share/ca-certificates/venya-local-ca.crt \
      /usr/local/share/ca-certificates/venya-root-ca.crt
update-ca-certificates > /dev/null 2>&1 || true

info "Removing directories..."
rm -rf /opt/venya /etc/venya /var/lib/venya /var/log/venya

info "Removing venya service account (Rust, uv, sbx state)..."
userdel -r venya 2> /dev/null || true

info "Venya Executor uninstalled."
echo "Kept: sbx/docker packages, /etc/hosts (provisioning-owned)."
echo "Remember: revoke this executor's cert on the core if it stays online:"
echo "  venya admin revoke-executor <executor-id>"
