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
#   - /opt/venya, /etc/venya, /var/log/venya
#   - /var/lib/venya, except /var/lib/venya/ca (see VENYA_PURGE_CA below)
#   - /var/backups/venya (pre-upgrade pg_dump snapshots from installer re-runs)
#
# When the CA is kept, the two CA-key passphrase lines from
# /etc/venya/venya-core.env are copied to /var/lib/venya/ca/ca-key-passphrases.env
# (0600 root) before anything is removed, because an encrypted key whose passphrase
# was just deleted is not a preserved CA. VENYA_PURGE_CA=yes removes both together.
#   - /var/www/.well-known/venya-ca.crt
#   - Venya CA trust-store entries (+ update-ca-certificates)
#   - PostgreSQL database + role (venya)
#   - venya service account (and home)
#
# NOT removed (shared infrastructure): nginx/postgresql OS packages,
# uv/Python installed for other users. Executor registrations that pointed
# at this core become stale rows in the (dropped) database — nothing to do.
# The estate CA under /var/lib/venya/ca is kept as well: the rest of the estate
# was enrolled against it, and every certificate signed by it stops verifying
# when it goes. Whatever this run leaves behind is printed at the end.
#
# Environment variables:
#   VENYA_SKIP_PROMPT - Set to "yes" to skip the confirmation prompt
#   VENYA_PURGE_CA    - Set to "yes" to remove /var/lib/venya/ca too. A separate
#                       choice, separate from the one above: skipping the prompt
#                       does not purge the CA, and purging the CA does not skip
#                       the prompt.
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

# /var/lib/venya/ca holds the estate root CA and the admin CA. Dropping it takes
# the trust of every other host down with this service's, so it needs its own
# opt-in, named for what it removes. VENYA_SKIP_PROMPT answers a prompt; it does
# not authorise this.
PURGE_CA="no"
if [ "${VENYA_PURGE_CA:-}" = "yes" ]; then
    PURGE_CA="yes"
fi

# Read before any removal, so the closing report and the verify block can tell
# "kept" from "never installed here".
CA_PRESENT="no"
if [ -d /var/lib/venya/ca ]; then
    CA_PRESENT="yes"
fi

# #755: a state path that is a symlink is not this machine's state, and neither
# removal arm can see that. `find` with the default -P does not follow a symlink
# given as its starting point, and `rm -rf` on a symlink unlinks the NAME, not
# the tree it points at. So against a linked /var/lib/venya the preserve sweep
# removed nothing, the survivor probe named nothing, and the run still printed
# "Venya Core uninstalled."; on the VENYA_PURGE_CA=yes arm it reported the
# estate CA gone while the key material stayed on disk. Refuse both paths before
# anything is touched, on the same -L test venya-common.sh uses for a symlinked
# file:// tarball (#327) — a dangling link is refused too, because -L is an lstat
# and reads true where -e would read "gone".
STATE_TYPE_REFUSED=""
for state_path in /var/lib/venya /var/lib/venya/ca; do
    [ -L "$state_path" ] || continue
    link_target="$(readlink -f -- "$state_path" 2> /dev/null || true)"
    error "State path is a symlink: $state_path${link_target:+ -> $link_target} — refusing to follow it (#755)."
    STATE_TYPE_REFUSED="${STATE_TYPE_REFUSED:+$STATE_TYPE_REFUSED, }$state_path"
done
if [ -n "$STATE_TYPE_REFUSED" ]; then
    error "Nothing was removed: $STATE_TYPE_REFUSED is not a real directory. Repoint it at a directory on this machine, or run this uninstaller where the state actually lives."
    exit 1
fi

# --- Finding 244: keep what unlocks the CA this run keeps -------------------------------
# /etc/venya/venya-core.env holds the two CA-key passphrases and this script removes
# /etc/venya, while #749 keeps /var/lib/venya/ca. The default run therefore used to leave
# an encrypted CA key whose passphrase had just been deleted: the published unattended
# reinstall minted a fresh passphrase beside its own "Admin CA already exists - preserved"
# and stopped at admin-cert signing, with the venv built and no unit. Both lines are
# carried into the directory that survives, BEFORE anything is removed, and the run stops
# before touching state when that cannot be done. VENYA_PURGE_CA=yes takes the CA and the
# passphrase down together, so the purge arm needs none of this.
CA_PRESERVED_FILE="/var/lib/venya/ca/ca-key-passphrases.env"
CORE_ENV_FILE="/etc/venya/venya-core.env"
CA_PRESERVED_STATE="no"
CA_PRESERVED_LINES=0
if [ "$PURGE_CA" != "yes" ] && [ "$CA_PRESENT" = "yes" ]; then
    if [ -L "$CORE_ENV_FILE" ]; then
        error "Passphrase source is a symlink: $CORE_ENV_FILE — refusing to read a CA key passphrase through it (#755)."
        error "Nothing was removed: put the real file back, or re-run with VENYA_PURGE_CA=yes to remove the CA with everything else."
        exit 1
    fi
    # The destination needs the same test as the source: a shell `>` follows a symlinked
    # destination (open O_WRONLY|O_CREAT|O_TRUNC on the resolved path), the directory is
    # service-account-owned with no sticky bit, and this script runs as root — so an
    # unguarded write here could land both passphrases outside the CA directory, truncate
    # whatever the link named, and the chmod/chown below would act on that target too.
    if [ -L "$CA_PRESERVED_FILE" ]; then
        error "Passphrase destination is a symlink: $CA_PRESERVED_FILE — refusing to write a CA key passphrase through it (#755)."
        error "Nothing was removed: remove the link, or re-run with VENYA_PURGE_CA=yes to remove the CA with everything else."
        exit 1
    fi
    if [ -f "$CORE_ENV_FILE" ] && grep -qE '^VENYA_(ADMIN_)?CA_KEY_PASSPHRASE=' "$CORE_ENV_FILE" 2> /dev/null; then
        # D-2 (leg 1213): create, do not write into. `> $CA_PRESERVED_FILE` is
        # O_CREAT|O_TRUNC on whatever name already sits there — a regular file the
        # directory's owning account created and still holds open keeps its inode,
        # takes both passphrase lines, and then passes every end-state check below,
        # while that reader gets them back. So: write to a fresh unpredictable name,
        # set mode and owner while the name is ours alone, and land it with mv -T.
        # rename(2) REPLACES the destination rather than following it, which also
        # closes the swap window between the -L guard above and this write (probes
        # D/E at leg 1213). The #381 fresh-inode form in install-venya-core.sh is
        # this same guarantee; the rm -f there is enough for a root-owned path, and
        # mv -T is the form for one this account shares a directory with.
        CA_PRESERVED_TMP="$(mktemp "$CA_PRESERVED_FILE.XXXXXX" 2> /dev/null || true)"
        if [ -z "$CA_PRESERVED_TMP" ]; then
            error "Could not create a fresh passphrase file beside $CA_PRESERVED_FILE."
            error "Nothing was removed. Either copy $CORE_ENV_FILE aside and re-run, or re-run with"
            error "VENYA_PURGE_CA=yes to remove the CA as well — a kept CA you cannot open is the state this fixes."
            exit 1
        fi
        if ! grep -E '^VENYA_(ADMIN_)?CA_KEY_PASSPHRASE=' "$CORE_ENV_FILE" > "$CA_PRESERVED_TMP" \
            || ! chmod 0600 "$CA_PRESERVED_TMP" \
            || ! chown root:root "$CA_PRESERVED_TMP" \
            || ! mv -T "$CA_PRESERVED_TMP" "$CA_PRESERVED_FILE"; then
            rm -f "$CA_PRESERVED_TMP" 2> /dev/null || true
            error "Could not preserve the CA key passphrases at $CA_PRESERVED_FILE."
            error "Nothing was removed. Either copy $CORE_ENV_FILE aside and re-run, or re-run with"
            error "VENYA_PURGE_CA=yes to remove the CA as well — a kept CA you cannot open is the state this fixes."
            exit 1
        fi
        CA_PRESERVED_LINES="$(grep -cE '^VENYA_(ADMIN_)?CA_KEY_PASSPHRASE=' "$CA_PRESERVED_FILE" 2> /dev/null || true)"
        CA_PRESERVED_STATE="yes"
    elif [ -f "$CA_PRESERVED_FILE" ]; then
        # A second uninstall over a CA an earlier run already preserved: nothing new to carry.
        CA_PRESERVED_STATE="already"
    else
        CA_PRESERVED_STATE="absent"
    fi
fi

if [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
    # #399: read on a closed/EOF stdin aborts under set -e with zero output.
    # Gate the non-TTY case loudly first, before any removal — same contract
    # as the #389 install-side gate. Deletion is destructive: no auto-proceed.
    if [ ! -t 0 ]; then
        error "non-interactive session: set VENYA_SKIP_PROMPT=yes to confirm removal"
        exit 1
    fi
    echo "This will REMOVE Venya Core from $(hostname): service, /opt/venya,"
    echo "/etc/venya, /var/lib/venya (except the CA), nginx site, trust entries,"
    echo "the PostgreSQL database 'venya', and the venya user."
    if [ "$PURGE_CA" = "yes" ]; then
        echo "VENYA_PURGE_CA=yes: /var/lib/venya/ca goes too, and with it every"
        echo "certificate the rest of the estate was enrolled against."
    else
        echo "/var/lib/venya/ca (the estate CA) is kept. Set VENYA_PURGE_CA=yes"
        echo "to remove it."
        if [ "$CA_PRESERVED_STATE" = "yes" ]; then
            echo "So are its key passphrases: $CA_PRESERVED_FILE ($CA_PRESERVED_LINES line(s), 0600 root)."
        elif [ "$CA_PRESERVED_STATE" = "already" ]; then
            echo "Its key passphrases were preserved by an earlier run: $CA_PRESERVED_FILE."
        elif [ "$CA_PRESERVED_STATE" = "absent" ]; then
            echo "No CA key passphrase is on this machine, so none can be kept: a reinstall"
            echo "over this CA must supply VENYA_CA_KEY_PASSPHRASE and VENYA_ADMIN_CA_PASSPHRASE."
        fi
    fi
    read -r -p "Proceed? [y/N] " answer
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
rm -rf /opt/venya /etc/venya /var/log/venya
if [ "$PURGE_CA" = "yes" ]; then
    rm -rf /var/lib/venya
    info "Removed /var/lib/venya including the estate CA (VENYA_PURGE_CA=yes)."
else
    # Everything the service owned under the state dir goes; the CA directory
    # is the one thing left in place.
    if [ -d /var/lib/venya ]; then
        find /var/lib/venya -mindepth 1 -maxdepth 1 ! -name ca -exec rm -rf {} +
    fi
fi
rm -rf /var/backups/venya
info "Removed /var/backups/venya (pre-upgrade database backups)."
rm -f /var/www/.well-known/venya-ca.crt

info "Dropping PostgreSQL database and role..."
PG_WAS_ACTIVE=0
if systemctl is-active --quiet postgresql; then
    PG_WAS_ACTIVE=1
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS venya;" > /dev/null 2>&1 || warn "DROP DATABASE failed — check manually."
    sudo -u postgres psql -c "DROP ROLE IF EXISTS venya;" > /dev/null 2>&1 || warn "DROP ROLE failed (open connections?) — check manually."
    sudo -u postgres psql -c "DROP ROLE IF EXISTS venya_audit;" > /dev/null 2>&1 || warn "DROP ROLE venya_audit failed (open connections?) — check manually."
    # Remove the venya_audit peer-auth config lines (marker-guarded; warn-only, never fatal).
    for d in /etc/postgresql/*/main; do
        [ -d "$d" ] || continue
        sudo -u postgres sed -i "/^venya_map venya venya_audit$/d" "$d/pg_ident.conf" 2>/dev/null || warn "pg_ident.conf cleanup failed in $d — check manually."
        sudo -u postgres sed -i "/venya_audit.*peer map=venya_map/d" "$d/pg_hba.conf" 2>/dev/null || warn "pg_hba.conf cleanup failed in $d — check manually."
    done
    # #396: reload is advisory — warn, never silently abort the rest of the run.
    sudo -u postgres psql -c "SELECT pg_reload_conf();" > /dev/null 2>&1 || warn "pg_reload_conf failed — marker lines apply on the next PostgreSQL restart."
else
    warn "PostgreSQL not running — skipped DB/role drop."
fi

info "Removing venya service account..."
userdel -r venya 2> /dev/null || true

# #396: never claim success before the removals are proven — same contract as
# the cli-uninstaller-incomplete-rc0 verify block. Every survivor prints its
# own [ERROR] and fails the run; the warns above stay as guidance.
VERIFY_FAILED=0
for path_item in /etc/systemd/system/venya-core.service \
                 /opt/venya /etc/venya /var/log/venya /var/backups/venya \
                 /var/www/.well-known/venya-ca.crt \
                 /usr/local/share/ca-certificates/venya-root-ca.crt \
                 /usr/local/share/ca-certificates/venya-local-ca.crt; do
    # -L beside -e (#755): a leftover that is a dangling symlink reads "gone" to
    # -e alone, and this loop is what stands between a partial run and the
    # success line. Same idiom as cleanup_install_temps in venya-common.sh.
    if [ -e "$path_item" ] || [ -L "$path_item" ]; then
        error "$(basename "$path_item") still present at $path_item — inspect manually."
        VERIFY_FAILED=1
    fi
done
if id -u venya > /dev/null 2>&1; then
    error "venya user still present — inspect manually."
    VERIFY_FAILED=1
fi
# The state directory is verified by mode: purged means gone, kept means the CA
# is still there and nothing else is.
if [ "$PURGE_CA" = "yes" ]; then
    if [ -e /var/lib/venya ] || [ -L /var/lib/venya ]; then
        error "/var/lib/venya still present after VENYA_PURGE_CA=yes — inspect manually."
        VERIFY_FAILED=1
    fi
else
    if [ "$CA_PRESENT" = "yes" ] && [ ! -d /var/lib/venya/ca ]; then
        error "estate CA missing at /var/lib/venya/ca — removed without VENYA_PURGE_CA=yes."
        VERIFY_FAILED=1
    fi
    while IFS= read -r leftover; do
        [ -n "$leftover" ] || continue
        error "$(basename "$leftover") still present at $leftover — inspect manually."
        VERIFY_FAILED=1
    done < <(find /var/lib/venya -mindepth 1 -maxdepth 1 ! -name ca 2> /dev/null || true)
    # Finding 244: the CA and the material that opens it are kept as one pair, so the pair
    # is verified as one pair. A preserved key with no preserved passphrase is the state
    # this run exists to prevent, and a broad mode is the state #606/#610 prevent.
    if [ "$CA_PRESERVED_STATE" = "yes" ] || [ "$CA_PRESERVED_STATE" = "already" ]; then
        if [ -L "$CA_PRESERVED_FILE" ]; then
            # The reporting half of the same guard: [ -f ] and stat -c '%a' both FOLLOW a
            # symlink, so a planted link at this name would certify its target as the
            # preserved pair. Refuse on lstat before anything follows it.
            error "$CA_PRESERVED_FILE is a symlink — cannot verify the preserved passphrase through it (#755)."
            VERIFY_FAILED=1
        elif [ ! -f "$CA_PRESERVED_FILE" ]; then
            error "ca-key-passphrases.env missing at $CA_PRESERVED_FILE — the preserved CA cannot be opened."
            VERIFY_FAILED=1
        elif [ "$(stat -c '%a' "$CA_PRESERVED_FILE" 2> /dev/null)" != "600" ]; then
            error "$CA_PRESERVED_FILE is not mode 0600 — a CA key passphrase is not broadly readable."
            VERIFY_FAILED=1
        fi
    fi
fi
if [ "$PG_WAS_ACTIVE" = "1" ]; then
    DB_PRESENT="$(sudo -u postgres psql -tAc "SELECT count(*) FROM pg_database WHERE datname='venya';" 2> /dev/null)" || DB_PRESENT="probe-failed"
    if [ "$DB_PRESENT" = "probe-failed" ]; then
        error "cannot verify 'venya' database removal — inspect manually."
        VERIFY_FAILED=1
    elif [ "$DB_PRESENT" != "0" ]; then
        error "'venya' database still present — inspect manually."
        VERIFY_FAILED=1
    fi
    ROLE_PRESENT="$(sudo -u postgres psql -tAc "SELECT count(*) FROM pg_roles WHERE rolname IN ('venya','venya_audit');" 2> /dev/null)" || ROLE_PRESENT="probe-failed"
    if [ "$ROLE_PRESENT" = "probe-failed" ]; then
        error "cannot verify 'venya'/'venya_audit' role removal — inspect manually."
        VERIFY_FAILED=1
    elif [ "$ROLE_PRESENT" != "0" ]; then
        error "'venya' or 'venya_audit' role still present — inspect manually."
        VERIFY_FAILED=1
    fi
fi
if [ "$VERIFY_FAILED" -ne 0 ]; then
    error "Venya Core uninstall incomplete — see [ERROR] lines above."
    exit 1
fi

info "Venya Core uninstalled."
if [ "$PURGE_CA" = "yes" ]; then
    echo "Removed as asked (VENYA_PURGE_CA=yes): /var/lib/venya"
elif [ "$CA_PRESENT" = "yes" ]; then
    echo "Left in place: /var/lib/venya/ca (the estate CA)."
    if [ "$CA_PRESERVED_STATE" = "yes" ]; then
        echo "Left in place: $CA_PRESERVED_FILE ($CA_PRESERVED_LINES passphrase line(s), 0600 root) — the"
        echo "material that opens that CA's keys, kept beside it so an unattended reinstall"
        echo "can read it. Remove it and the CA becomes unreadable."
    elif [ "$CA_PRESERVED_STATE" = "already" ]; then
        echo "Already preserved by an earlier run: $CA_PRESERVED_FILE (0600 root)."
    elif [ "$CA_PRESERVED_STATE" = "absent" ]; then
        warn "No CA key passphrase found on this machine ($CORE_ENV_FILE is gone), so none was kept:"
        warn "the CA stays encrypted and unreadable to a reinstall that does not supply its passphrase."
    fi
    echo "To remove the CA and its preserved passphrase deliberately, re-run with VENYA_PURGE_CA=yes."
fi
echo "Kept (shared infrastructure): nginx + postgresql packages."
