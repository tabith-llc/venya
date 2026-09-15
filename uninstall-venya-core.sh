#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Venya Core Uninstaller
#
# Removes everything install-venya-core.sh created on this machine:
#   - venya-core systemd service + unit
#   - Nginx site (sites-available/enabled + client-CA files) and reload
#   - /opt/venya, /etc/venya, /var/lib/venya, /var/log/venya
#   - /var/www/.well-known/venya-ca.crt
#   - Venya CA trust-store entries (+ update-ca-certificates)
#   - PostgreSQL database + role (venya)
#   - venya service account (and home)
#
# NOT removed (shared infrastructure): nginx/postgresql OS packages,
# uv/Python installed for other users. Executor registrations that pointed
# at this core become stale rows in the (dropped) database — nothing to do.
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
    echo "This will REMOVE Venya Core from $(hostname): service, /opt/venya,"
    echo "/etc/venya, /var/lib/venya (CA keys!), nginx site, trust entries,"
    read -r -p "the PostgreSQL database 'venya', and the venya user. Proceed? [y/N] " answer
    [[ "$answer" =~ ^[Yy] ]] || { info "Aborted."; exit 0; }
fi

info "Stopping venya-core..."
systemctl disable --now venya-core > /dev/null 2>&1 || true
rm -f /etc/systemd/system/venya-core.service
systemctl daemon-reload

info "Removing nginx site..."
rm -f /etc/nginx/sites-enabled/venya /etc/nginx/sites-available/venya
rm -f /etc/nginx/ssl/client-ca.crt /etc/nginx/ssl/client-ca-bundle.crt
rmdir /etc/nginx/ssl 2> /dev/null || true
if nginx -t > /dev/null 2>&1; then
    systemctl reload nginx || true
else
    warn "nginx config test failed after removal — inspect manually."
fi

info "Removing CA trust entries..."
rm -f /usr/local/share/ca-certificates/venya-root-ca.crt \
      /usr/local/share/ca-certificates/venya-local-ca.crt
update-ca-certificates > /dev/null 2>&1 || true

info "Removing directories..."
rm -rf /opt/venya /etc/venya /var/lib/venya /var/log/venya
rm -f /var/www/.well-known/venya-ca.crt

info "Dropping PostgreSQL database and role..."
if systemctl is-active --quiet postgresql; then
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS venya;" > /dev/null 2>&1 || warn "DROP DATABASE failed — check manually."
    sudo -u postgres psql -c "DROP ROLE IF EXISTS venya;" > /dev/null 2>&1 || warn "DROP ROLE failed (open connections?) — check manually."
else
    warn "PostgreSQL not running — skipped DB/role drop."
fi

info "Removing venya service account..."
userdel -r venya 2> /dev/null || true

info "Venya Core uninstalled."
echo "Kept (shared infrastructure): nginx + postgresql packages."
