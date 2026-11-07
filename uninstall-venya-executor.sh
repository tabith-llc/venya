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
#   - /var/log/venya
#   - /var/lib/venya (executor CA + enrollment state) — ONLY with
#     VENYA_PURGE_STATE=yes, see the header below
#   - Venya CA trust-store entries (+ update-ca-certificates)
#   - venya service account (home carries Rust toolchain, uv, sbx state)
#
# NOT removed by default (#757): /var/lib/venya — it carries the executor's
# trust anchor and its 0600 bootstrap token, and a routine software removal is
# not an instruction to destroy either. Whatever this run leaves there is
# printed at the end.
#
# NOT removed (shared infrastructure / provisioning-owned):
#   - sbx/docker OS packages (dpkg -r docker-sbx yourself if desired)
#   - the /etc/hosts core entry (written by provisioning as well)
#   - the executor's registration ON THE CORE: revoke it there with
#     `venya admin revoke-executor <executor-id>` (or it expires with the core DB)
#
# Environment variables:
#   VENYA_SKIP_PROMPT - Set to "yes" to skip the confirmation prompt
#   VENYA_PURGE_STATE - Set to "yes" to remove /var/lib/venya too (the executor
#                       CA and its enrollment state). The default is KEEP: this
#                       uninstaller removes the state directory only on that
#                       explicit instruction, and when it does not, it says so
#                       instead of printing the completion line alone. A
#                       separate choice from the one above — skipping the prompt
#                       does not purge the state, and purging the state does not
#                       skip the prompt (#757).
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

# #757: the same mechanism #755 closed for the core uninstaller reaches this file
# too. `rm -rf` on a symlink unlinks the NAME, not the tree the name points at,
# and `[ -e ]` on that name then reads false — so against a linked /var/lib/venya
# this script emptied no state, named no survivor, and printed "Venya Executor
# uninstalled." with rc 0. Refuse before any removal, on the same -L test
# venya-common.sh ships for a symlinked file:// tarball (#327): -L is an lstat, so
# a dangling link is refused as well, where -e would read "gone".
STATE_TYPE_REFUSED=""
for state_path in /var/lib/venya /var/lib/venya/executor; do
    [ -L "$state_path" ] || continue
    link_target="$(readlink -f -- "$state_path" 2> /dev/null || true)"
    error "State path is a symlink: $state_path${link_target:+ -> $link_target} — refusing to follow it (#757)."
    STATE_TYPE_REFUSED="${STATE_TYPE_REFUSED:+$STATE_TYPE_REFUSED, }$state_path"
done
if [ -n "$STATE_TYPE_REFUSED" ]; then
    error "Nothing was removed: $STATE_TYPE_REFUSED is not a real directory. Repoint it at a directory on this machine, or run this uninstaller where the state actually lives."
    exit 1
fi

# /var/lib/venya carries the executor CA and the 0600 bootstrap token written by
# install-venya-executor.sh. Keeping it is the default: removing software is not
# an instruction to destroy a trust anchor. VENYA_SKIP_PROMPT answers a prompt;
# it does not authorise this.
PURGE_STATE="no"
if [ "${VENYA_PURGE_STATE:-}" = "yes" ]; then
    PURGE_STATE="yes"
fi

# Read before any removal, so the closing report and the verify block can tell
# "kept" from "never installed here".
STATE_PRESENT="no"
if [ -e /var/lib/venya ]; then
    STATE_PRESENT="yes"
fi

if [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
    # #399: read on a closed/EOF stdin aborts under set -e with zero output.
    # Gate the non-TTY case loudly first, before any removal — same contract
    # as the #389 install-side gate. Deletion is destructive: no auto-proceed.
    if [ ! -t 0 ]; then
        error "non-interactive session: set VENYA_SKIP_PROMPT=yes to confirm removal"
        exit 1
    fi
    echo "This will REMOVE Venya Executor from $(hostname): service, /opt/venya,"
    echo "/etc/venya (incl. mTLS key), /var/log/venya, and the venya user."
    if [ "$PURGE_STATE" = "yes" ]; then
        echo "VENYA_PURGE_STATE=yes: /var/lib/venya goes too — the executor CA and"
        echo "its enrollment state, including the bootstrap token."
    else
        echo "/var/lib/venya (the executor CA and enrollment state) is kept. Set"
        echo "VENYA_PURGE_STATE=yes to remove it."
    fi
    read -r -p "Proceed? [y/N] " answer
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
rm -rf /opt/venya /etc/venya /var/log/venya
# Each arm states at the point of action what happened to the state directory,
# and a directory that was never here gets its own line instead of silence
# (#758's cli-uninstaller idiom).
if [ "$STATE_PRESENT" != "yes" ]; then
    info "No state dir at /var/lib/venya — nothing to remove."
elif [ "$PURGE_STATE" = "yes" ]; then
    rm -rf /var/lib/venya
    info "Removed /var/lib/venya including the executor CA (VENYA_PURGE_STATE=yes)."
else
    info "Kept /var/lib/venya (executor CA and enrollment state) — set VENYA_PURGE_STATE=yes to remove it."
fi

info "Removing venya service account (Rust, uv, sbx state)..."
userdel -r venya 2> /dev/null || true

# #396: never claim success before the removals are proven — same contract as
# the cli-uninstaller-incomplete-rc0 verify block. Every survivor prints its
# own [ERROR] and fails the run; the warns above stay as guidance.
VERIFY_FAILED=0
for path_item in /etc/systemd/system/venya-executor.service \
                 /etc/systemd/system/tmp-venya_secrets.mount \
                 /etc/systemd/system/venya-executor.seccomp \
                 /etc/systemd/system/venya-sandboxd.service \
                 /etc/systemd/system/venya-executor.service.d \
                 /opt/venya /etc/venya /var/log/venya \
                 /usr/local/share/ca-certificates/venya-local-ca.crt \
                 /usr/local/share/ca-certificates/venya-root-ca.crt; do
    # -L beside -e (#757, the same pairing #755 put on the core uninstaller and
    # #758 on the cli one): a leftover that is a dangling symlink reads "gone" to
    # -e alone, and this loop is what stands between a partial run and the
    # completion line below.
    if [ -e "$path_item" ] || [ -L "$path_item" ]; then
        error "$(basename "$path_item") still present at $path_item — inspect manually."
        VERIFY_FAILED=1
    fi
done
if id -u venya > /dev/null 2>&1; then
    error "venya user still present — inspect manually."
    VERIFY_FAILED=1
fi
# /var/lib/venya is verified by mode, not by the list above: purged means gone,
# kept means still there — a keep that silently lost the state is the worse
# failure, so it is checked too (#755's sibling carries the same two arms).
if [ "$PURGE_STATE" = "yes" ]; then
    if [ -e /var/lib/venya ] || [ -L /var/lib/venya ]; then
        error "/var/lib/venya still present after VENYA_PURGE_STATE=yes — inspect manually."
        VERIFY_FAILED=1
    fi
elif [ "$STATE_PRESENT" = "yes" ] && [ ! -e /var/lib/venya ]; then
    error "/var/lib/venya missing although no removal was asked for — state dir lost without VENYA_PURGE_STATE=yes."
    VERIFY_FAILED=1
fi
if [ "$VERIFY_FAILED" -ne 0 ]; then
    error "Venya Executor uninstall incomplete — see [ERROR] lines above."
    exit 1
fi

info "Venya Executor uninstalled."
if [ "$PURGE_STATE" = "yes" ]; then
    echo "Removed as asked (VENYA_PURGE_STATE=yes): /var/lib/venya"
elif [ "$STATE_PRESENT" = "yes" ]; then
    echo "Left in place: /var/lib/venya (the executor CA and enrollment state)."
    echo "To remove it deliberately, re-run with VENYA_PURGE_STATE=yes."
fi
echo "Kept: sbx/docker packages, /etc/hosts (provisioning-owned)."
echo "Remember: revoke this executor's cert on the core if it stays online:"
echo "  venya admin revoke-executor <executor-id>"
