#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

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
    echo "This will REMOVE Venya Executor from $(hostname): service, /opt/venya,"
    read -r -p "/etc/venya (incl. mTLS key), /var/lib/venya, and the venya user. Proceed? [y/N] " answer
    [[ "$answer" =~ ^[Yy] ]] || { info "Aborted."; exit 0; }
fi

info "Stopping venya-executor..."
systemctl disable --now venya-executor > /dev/null 2>&1 || true
systemctl stop tmp-venya_secrets.mount > /dev/null 2>&1 || true
systemctl disable --now venya-sandboxd > /dev/null 2>&1 || true
rm -f /etc/systemd/system/venya-executor.service \
      /etc/systemd/system/tmp-venya_secrets.mount \
      /etc/systemd/system/venya-executor.seccomp \
      /etc/systemd/system/venya-sandboxd.service
rm -rf /etc/systemd/system/venya-executor.service.d
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
