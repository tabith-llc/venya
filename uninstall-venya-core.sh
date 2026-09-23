#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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

# --- Self-contained helpers (inlined from venya-common.sh, which stays the
# source of truth — keep in sync if these ever change). NO fetch fallback by
# design: an uninstaller must work with any origin down or air-gapped, and
# fetch-and-source at root is a supply-chain surface this path does not need.
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

venya_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (or with sudo)."
        exit 1
    fi
}

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
