#!/usr/bin/env bash

# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

set -euo pipefail

# #317: close every create-then-chmod window (install-venya-core.sh writes
# secrets at :454/:493/:565/:605/:807 before their chmod lands). Deliberate
# world-readables (public certs, nginx-served CA copy) all carry explicit
# chmod 644/755 lines and still win. Child processes inherit; sudo does NOT
# reset the caller umask — covered.
umask 077

###############################################################################
# Venya Core Installer
#
# Installs Venya Core on a fresh VM:
#   - venya user, system packages, Nginx, PostgreSQL
#   - Python venv, server + core packages
#   - .env, Nginx site config
#   - venya-core.service
#
# Environment variables:
#   VENYA_INSTALL_DIR   - Install location (default: /opt/venya)
#   VENYA_SKIP_PROMPT   - Set to "yes" to skip the confirmation prompt
#   VENYA_DB_PASSWORD   - PostgreSQL venya user password (prompts if unset;
#                         on re-run an explicit value must MATCH the password
#                         stored in .env's VENYA_DB_URL or the install aborts)
#   VENYA_DB_PASSPHRASE - Server encryption passphrase — NO DEFAULT. Re-run:
#                         reused from $INSTALL_DIR/.env (an explicit env value
#                         must MATCH the stored one or the install aborts).
#                         Fresh install: prompted (interactive) or required (unattended).
#   VENYA_RECOVERY_PEPPER - Recovery-code pepper — reused from .env on re-run;
#                         strong random when unset on a fresh install.
#   VENYA_TARBALL       - Tarball URL (default: latest GitHub release asset —
#                         https://github.com/tabith-llc/venya/releases/latest/download/venya-core-install.tar.gz)
#   VENYA_TARBALL_SHA256 - Pin the expected sha256 (recommended: strict integrity).
#                         If unset, the installer fetches <tarball-url>.sha256 from the
#                         same origin as a corruption guardrail and fail-closes on error.
#                         REQUIRED (no sidecar fallback) when the tarball source is NOT
#                         https (file:// or plain http://) — #375/#327.
#   CORE_HOSTNAME      - Hostname for TLS/Nginx (default: $(hostname))
#   TLS_MODE            - Nginx TLS mode (default: internal)
###############################################################################

# --- Defaults ---
# DB_PASSPHRASE and RECOVERY_PEPPER deliberately have NO defaults — they are
# acquired below (stored-reuse on re-run > explicit env > prompt/random).
TARBALL_URL="${VENYA_TARBALL:-https://github.com/tabith-llc/venya/releases/latest/download/venya-core-install.tar.gz}"
CORE_HOSTNAME="${CORE_HOSTNAME:-$(hostname)}"
TLS_MODE="${TLS_MODE:-internal}"

# Admin mTLS
ADMIN_MTLS_ENABLED="${VENYA_ADMIN_MTLS_ENABLED:-true}"
ADMIN_IDENTITY="${VENYA_ADMIN_IDENTITY:-}"
ADMIN_CA_PASSPHRASE="${VENYA_ADMIN_CA_PASSPHRASE:-}"

# --- Source common library ---
# Direct execution: the library sits next to the script. Piped execution
# (curl | sudo bash): $0 has no directory — fetch from the tarball origin.
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
    # #475: sourcing the library installs the registry below, and the single
    # EXIT trap set after this block REPLACES the FETCH_DIR trap set above
    # (bash holds one EXIT trap per shell). Hand the directory to the list
    # here, so the pre-source trap covers the fetch and the list covers it
    # from here on.
    register_install_temp "$FETCH_DIR"
fi

# --- One EXIT trap for every temp this installer creates (#475) ---
# `set -euo pipefail` ends this script wherever it stands, so temp cleanup
# cannot live only in the inline `rm` calls the success paths reach. There is
# ONE trap, and it drains the list that venya-common.sh defines and the sites
# below fill — per-file traps would replace each other, not add up. The
# inline removals stay (they free the large files mid-install); this trap is
# what makes an abort leave nothing behind.
trap 'cleanup_install_temps' EXIT

venya_print_colors
venya_check_root
venya_check_no_colocation core
venya_determine_install_dir /opt/venya
venya_check_existing

info "Installing Venya Core to $INSTALL_DIR"

# Remove the inert server.toml from any prior install. Runs only after the
# reinstall gate (venya_check_existing), so an aborted install leaves it in place.
# The server reads /opt/venya/.env, never this file (core-server-toml-inert).
rm -f /etc/venya/server.toml

# --- Upgrade support: capture the INSTALLED version BEFORE anything is
# replaced (ticket installer-upgrade-version-guard-and-backup). The old venv
# survives until the venv rebuild, but the source tree is
# overwritten in place by venya_extract_tarball — this is the last reliable
# readout point. Empty = fresh install (or an install predating this guard).
INSTALLED_VERSION=""
if [ -x "$INSTALL_DIR/.venv/bin/python" ]; then
    INSTALLED_VERSION=$("$INSTALL_DIR/.venv/bin/python" -c \
        "from importlib.metadata import version; print(version('core'))" 2>/dev/null || true)
    [ -n "$INSTALLED_VERSION" ] && info "Installed version: $INSTALLED_VERSION"
fi

# --- Server encryption passphrase (VENYA_DB_PASSPHRASE) — NO DEFAULT ---
# The KEK protecting every encrypted DB secret derives from this value (the
# server fails fast at boot when it is missing). A published default would be
# a published KEK, and silently rotating it on re-run would orphan every
# encrypted row — so precedence is: stored value from .env wins on re-run (an
# explicit env that DISAGREES aborts loudly with state intact) > explicit env
# > TTY prompt > error when unattended. Runs before any system mutation.
#
# #570 blank-is-unset, DENY and never TRIM. A value made only of whitespace
# carries no material, so it answers the "was a passphrase supplied?" question
# exactly as unset does — prompt on a TTY, the existing error when unattended,
# no new sentence for either half. The test reads a whitespace-stripped COPY
# (`${DB_PASSPHRASE//[[:space:]]/}`); DB_PASSPHRASE itself is never rewritten, so
# a passphrase whose spaces are content stays byte-for-byte on the way to the env
# file and still opens the database it sealed. That distinction is the #554 lesson:
# trimming here would silently change what a legitimate passphrase is.
#
# Stored-blank on a re-run, stated rather than left to inference (AC4): a blank
# line already in .env is still recognised as a stored value and is PRESERVED, not
# silently replaced — replacing it would rotate the KEK and orphan every envelope
# wrapped under it, which is the very failure this ladder exists to prevent. Such an
# install is caught fail-closed one step later instead: the boot gate
# (`core/engine/backend.py` `BackendConfig`) now refuses a whitespace-only
# passphrase as not-supplied, so the core will not serve on a space-derived KEK.
# Repairing the stored blank is then a deliberate, operator-present act, not a
# side effect of re-running the installer.
DB_PASSPHRASE="${VENYA_DB_PASSPHRASE:-}"
DB_PASSPHRASE_SUPPLIED="${DB_PASSPHRASE//[[:space:]]/}"
STORED_ENV_FILE="$INSTALL_DIR/.env"
STORED_DB_PASSPHRASE=""
if [ -f "$STORED_ENV_FILE" ]; then
    STORED_DB_PASSPHRASE=$(sed -n 's/^VENYA_DB__PASSPHRASE=//p' "$STORED_ENV_FILE" | head -n1)
fi
if [ -n "$STORED_DB_PASSPHRASE" ]; then
    # #570: the LEFT half of this test asks the SUPPLIED copy, because the ruling is that a
    # whitespace-only VENYA_DB_PASSPHRASE takes the SAME path as unset. As shipped it did
    # not: one space over a stored real passphrase tripped the rotation abort and told the
    # operator their re-run would orphan encrypted rows, when nothing was being rotated —
    # the stored value is taken verbatim three lines below. The RIGHT half stays a
    # byte-for-byte comparison on both sides: this is the supplied? decision, never a
    # normalization, and a stored value whose spaces are content is still the secret that
    # opens the database. A blank line already in .env stays handled as the header above
    # describes: preserved, not replaced.
    if [ -n "$DB_PASSPHRASE_SUPPLIED" ] && [ "$DB_PASSPHRASE" != "$STORED_DB_PASSPHRASE" ]; then
        error "VENYA_DB_PASSPHRASE does not match the stored value in $STORED_ENV_FILE."
        error "Rotating it would make existing encrypted DB secrets undecryptable."
        error "Aborting — no changes made."
        exit 1
    fi
    DB_PASSPHRASE="$STORED_DB_PASSPHRASE"
    info "Existing install: reusing stored server passphrase from $STORED_ENV_FILE."
elif [ -z "$DB_PASSPHRASE_SUPPLIED" ]; then
    if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
            venya_read_secret_confirm "Enter server encryption passphrase" DB_PASSPHRASE
    else
        error "VENYA_DB_PASSPHRASE is required for unattended install (stdin is not a TTY)."
        exit 1
    fi
fi

# --- Recovery-code pepper — same stored-reuse rule: rotating it on re-run
# would silently invalidate every issued recovery code. Fresh install:
# explicit env > strong random (never human-memorized, like the CA passphrases).
RECOVERY_PEPPER="${VENYA_RECOVERY_PEPPER:-}"
STORED_RECOVERY_PEPPER=""
if [ -f "$STORED_ENV_FILE" ]; then
    STORED_RECOVERY_PEPPER=$(sed -n 's/^VENYA_RECOVERY_CODE_PEPPER=//p' "$STORED_ENV_FILE" | head -n1)
fi
if [ -n "$STORED_RECOVERY_PEPPER" ]; then
    if [ -n "$RECOVERY_PEPPER" ] && [ "$RECOVERY_PEPPER" != "$STORED_RECOVERY_PEPPER" ]; then
        error "VENYA_RECOVERY_PEPPER does not match the stored value in $STORED_ENV_FILE."
        error "Rotating it would invalidate all issued recovery codes."
        error "Aborting — no changes made."
        exit 1
    fi
    RECOVERY_PEPPER="$STORED_RECOVERY_PEPPER"
    info "Existing install: reusing stored recovery pepper from $STORED_ENV_FILE."
elif [ -z "$RECOVERY_PEPPER" ]; then
    RECOVERY_PEPPER=$(openssl rand -base64 32)
    info "Fresh install: generated a random recovery pepper."
fi

# --- PostgreSQL role password (VENYA_DB_PASSWORD) ---
# Fresh install: prompted (interactive) or required (unattended) — the
# exists-guarded CREATE USER below makes the explicit env the initial
# password, nothing to compare against. Re-run: an explicit env that
# DISAGREES with the password stored in .env's VENYA_DB_URL aborts loudly
# with state intact, BEFORE any mutation — the CREATE USER exists-guard
# would otherwise leave the PG role on the old password while .env gets the
# new one, diverging server DB auth into a boot loop (ticket
# installer-db-password-rerun-mismatch). Same no-silent-rotation semantics
# as the passphrase/pepper guards above; rotation is a deliberate manual act
# named in the abort message. Raw-string comparison matches the raw URL
# write below — passwords containing @ or : break the URL at write time
# regardless (pre-existing wart, recorded in the ticket, NOT fixed here).
# Re-run reuse (ticket installer-rerun-db-password-no-reuse, option (a)):
# the stored .env is authoritative for the DB password exactly like the
# other four secrets — an unattended re-run must not demand it. Option (b)
# (skip-on-existing-DB) was investigated and rejected: the template below
# rewrites VENYA_DB_URL/VENYA_DB__DATABASE_URL on EVERY run and the
# migrations + server boot read them. Fresh installs (no stored .env)
# still prompt / require the env. An explicitly-passed value must still
# MATCH the stored one (the unchanged elif below) — no silent rotation.
if [ -z "${VENYA_DB_PASSWORD:-}" ] && [ -f "$STORED_ENV_FILE" ]; then
    VENYA_DB_PASSWORD=$(sed -n 's|^VENYA_DB_URL=postgresql://venya:\(.*\)@localhost/venya$|\1|p' "$STORED_ENV_FILE" | head -n1)
    if [ -n "$VENYA_DB_PASSWORD" ]; then
        info "Existing install: reusing stored PostgreSQL password from $STORED_ENV_FILE (VENYA_DB_URL)."
    else
        warn "Could not parse a stored password from $STORED_ENV_FILE's VENYA_DB_URL — falling through to prompt/env."
    fi
fi
if [ -z "${VENYA_DB_PASSWORD:-}" ]; then
    if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
            venya_read_secret_confirm "Enter PostgreSQL password for venya user" VENYA_DB_PASSWORD
    else
        error "VENYA_DB_PASSWORD is required for unattended install (stdin is not a TTY)."
        exit 1
    fi
elif [ -f "$STORED_ENV_FILE" ]; then
    STORED_DB_PASSWORD=$(sed -n 's|^VENYA_DB_URL=postgresql://venya:\(.*\)@localhost/venya$|\1|p' "$STORED_ENV_FILE" | head -n1)
    if [ -n "$STORED_DB_PASSWORD" ] && [ "$VENYA_DB_PASSWORD" != "$STORED_DB_PASSWORD" ]; then
        error "VENYA_DB_PASSWORD does not match the password stored in $STORED_ENV_FILE (VENYA_DB_URL)."
        error "The PostgreSQL role keeps its original password on re-run; proceeding would"
        error "diverge .env from the role and break server DB auth. Aborting — no changes made."
        error "To continue, either:"
        error "  1. Re-run with the stored password (see VENYA_DB_URL in $STORED_ENV_FILE), or"
        error "  2. Rotate deliberately: sudo -u postgres psql -c \"ALTER USER venya WITH PASSWORD '<new>'\""
        error "     then re-run the installer with VENYA_DB_PASSWORD='<new>'."
        exit 1
    fi
fi

# --- Fail-closed config-injection gate (ticket #326) ---
# These operator values interpolate into the runtime .env (pydantic
# BaseSettings): a newline-bearing value splits into EXTRA VENYA_* lines,
# quotes/backslashes break the CORS/JSON arrays and the admin-CA python -c
# child, and a raw '@' truncates the postgresql:// userinfo (sqlalchemy
# _parse_url: password group [^@]*). None of these characters are valid in
# these fields: reject LOUD, exit 1, BEFORE any sink write.
venya_guard_injection "CORE_HOSTNAME" "$CORE_HOSTNAME" '"' '\' ' '
venya_guard_injection "VENYA_DB_PASSWORD" "$VENYA_DB_PASSWORD" '@'
venya_guard_injection "VENYA_DB_PASSPHRASE" "$DB_PASSPHRASE"
venya_guard_injection "VENYA_RECOVERY_PEPPER" "$RECOVERY_PEPPER"
if [ -n "$ADMIN_IDENTITY" ]; then
    venya_guard_injection "VENYA_ADMIN_IDENTITY" "$ADMIN_IDENTITY" '"' '\'
fi

# Ignored-knob notice (ticket core-install-silently-ignores-egress-allow-knob
# #382): VENYA_EGRESS_ALLOW seeds the EXECUTOR installer's egress allowlist —
# it is consumed only by the venya_write_egress_allowlist call in
# install-venya-executor.sh. A core run that carries it (copy-pasted executor
# recipe) drops the value silently; warn once, change nothing (fail-open UX,
# no behavior delta — shape (a), lead rec).
if [ -n "${VENYA_EGRESS_ALLOW:-}" ]; then
    warn "VENYA_EGRESS_ALLOW applies to the executor installer only — ignoring on core."
fi

# --- Create venya service account (no password, nologin, locked) ---
venya_create_user

# --- Install system packages ---
venya_install_system_pkgs curl sudo

# --- Install Nginx (core-specific) ---
info "Installing Nginx reverse proxy..."
if ! command -v nginx &>/dev/null; then
    venya_apt install -y -qq nginx
    info "Nginx installed: $(nginx -v 2>&1)"
else
    info "Nginx already installed: $(nginx -v 2>&1)"
fi

# --- Install uv for venya user ---
venya_install_uv_user

# --- Install Python 3.14 for venya user ---
venya_install_python314

# --- Download and extract tarball ---
venya_download_tarball core

# --- Upgrade support: version guard BEFORE any mutation (ticket
# installer-upgrade-version-guard-and-backup). The incoming version is peeked
# from the tarball without extracting, so a refused downgrade leaves ZERO
# changes. Alembic migrations never reverse automatically — old code on a
# newer schema is undefined behavior, hence refuse-by-default. sort -V is a
# pragmatic PEP 440 approximation for the 0.1.0aN/bN scheme; the escape knob
# is the calibration edge for odd builds.
INCOMING_VERSION=$(tar -xzOf "$TARBALL_FILE" --wildcards '*/packages/core/pyproject.toml' 2>/dev/null \
    | sed -n 's/^version = "\(.*\)"$/\1/p' | head -n1)
if [ -z "$INCOMING_VERSION" ]; then
    warn "Could not read the core version from the tarball — skipping the version guard (sha256 verification already passed)."
elif [ -z "$INSTALLED_VERSION" ]; then
    info "Fresh install of version $INCOMING_VERSION"
elif [ "$INSTALLED_VERSION" = "$INCOMING_VERSION" ]; then
    info "Version: $INSTALLED_VERSION (same-version re-run)"
elif [ "$(printf '%s\n%s\n' "$INSTALLED_VERSION" "$INCOMING_VERSION" | sort -V | head -n1)" = "$INCOMING_VERSION" ]; then
    if [ "${VENYA_ALLOW_DOWNGRADE:-}" = "yes" ]; then
        warn "DOWNGRADE $INSTALLED_VERSION -> $INCOMING_VERSION allowed by VENYA_ALLOW_DOWNGRADE=yes."
        warn "The database schema is NOT downgraded; old code on a new schema is unsupported."
    else
        error "Refusing to downgrade: installed $INSTALLED_VERSION, tarball $INCOMING_VERSION."
        error "Alembic migrations never run in reverse automatically — old code on a newer"
        error "schema is undefined behavior. If this is deliberate: VENYA_ALLOW_DOWNGRADE=yes."
        exit 1
    fi
else
    info "Upgrade: $INSTALLED_VERSION -> $INCOMING_VERSION"
fi

venya_extract_tarball

# --- Apply shared code fixes (patch source BEFORE building) ---
venya_apply_code_fixes

# --- Build Python venv ---
venya_create_venv "venya-core-requirements.txt"

# --- Verify deployed code ---
venya_verify_deployment core

# --- Create directories ---
venya_create_directories

# --- Admin mTLS bootstrap (core-specific) ---
ADMIN_CA_DIR="/var/lib/venya/ca/admin-ca"
ADMIN_CERT_DIR="/etc/venya/admin"

if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    info "Configuring admin mTLS..."

    # Passphrase acquisition: prompt when interactive, strong random when
    # piped/unattended. Either way the gate below tests EMPTINESS (`-z`), not
    # materiality — an all-whitespace value is truthy to `-z` and would be accepted
    # here. #570 states this plainly because the word that used to sit in this comment,
    # "validated", reads like a coverage claim about the whole tree and is not one: the
    # admin CA plane is issue 554's row (server/ca.py, cli), and the DB plane is the
    # ladder above. Nobody needs to memorize a CA key passphrase, so unattended keeps
    # the strong random default; typing is for delivery hygiene, not for replacing
    # randomness.
    #
    # Re-run idempotency (ticket installer-rerun-admin-ca-passphrase-mismatch):
    # an existing install PRESERVES the encrypted admin CA key (has_ca guard
    # below), so a re-run must reuse the passphrase already stored in the
    # EnvironmentFile — regenerating the credential makes the preserved key
    # undecryptable and aborts the run at sign_admin_cert. Precedence:
    # explicit VENYA_ADMIN_CA_PASSPHRASE env (operator override; a WRONG value
    # still fails loudly downstream — never silently swallowed) > stored >
    # prompt > random. sed extraction, not source: no other line of the env
    # file is executed, and base64 '=' padding survives the prefix-only sub.
    if [ -z "$ADMIN_CA_PASSPHRASE" ] && [ -f /etc/venya/venya-core.env ]; then
        ADMIN_CA_PASSPHRASE=$(sed -n 's/^VENYA_ADMIN_CA_KEY_PASSPHRASE=//p' /etc/venya/venya-core.env | head -n1)
        if [ -n "$ADMIN_CA_PASSPHRASE" ]; then
            info "Existing install: reusing stored admin CA passphrase from /etc/venya/venya-core.env."
        fi
    fi
    if [ -z "$ADMIN_CA_PASSPHRASE" ]; then
        if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
                venya_read_secret_confirm "Admin CA key passphrase" ADMIN_CA_PASSPHRASE
        else
            ADMIN_CA_PASSPHRASE=$(openssl rand -base64 32)
            info "Unattended install: generated a random admin CA passphrase."
        fi
    fi

    # #326 F-1: gate the finalized admin passphrase (covers explicit env +
    # stored-reuse; prompt/random are line-based). Runs BEFORE the python
    # admin-CA child and before the EnvironmentFile write.
    venya_guard_injection "ADMIN_CA_PASSPHRASE" "$ADMIN_CA_PASSPHRASE"

    # Derive default identity
    if [ -z "$ADMIN_IDENTITY" ]; then
        ADMIN_IDENTITY="admin@${CORE_HOSTNAME}"
    fi
    # Derived identity gets the same gate (#326: composition runs AFTER the
    # entry guard when VENYA_ADMIN_IDENTITY was unset).
    venya_guard_injection "ADMIN_IDENTITY" "$ADMIN_IDENTITY" '"' '\'


    # Create directories (#358: pinned parents the sudo -u venya children
    # below must traverse — bare mkdir -p under the entry umask 077 left
    # /var/lib/venya and /etc/venya 0700 root:root; the leaf pins keep the
    # old chmod 700 + chown venya semantics). The later
    # "install -d -m 0755 /etc/venya" (#317 status-quo pin) re-pins that
    # parent's mode after this block; idempotent.
    install -d -m 0750 -g venya /var/lib/venya /var/lib/venya/ca
    install -d -m 0770 -o venya -g venya "$ADMIN_CA_DIR"
    install -d -m 0750 -g venya /etc/venya
    install -d -m 0770 -o venya -g venya "$ADMIN_CERT_DIR"

    # Generate admin CA. The passphrase crosses the sudo boundary on STDIN —
    # never via export (sudo's env_reset strips it) and never on argv (visible
    # in /proc/*/cmdline). The child reads it into VENYA_ADMIN_CA_KEY_PASSPHRASE
    # and the manager is wired to that exact var name (matches app.py runtime +
    # the startup enforcement). Path passed as a positional so nothing
    # interpolates inside the single-quoted child script.
    sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" bash -c '
        IFS= read -r VENYA_ADMIN_CA_KEY_PASSPHRASE
        export VENYA_ADMIN_CA_KEY_PASSPHRASE
        exec python -c "
from pathlib import Path
from server.ca import AdminCAManager
from server.config import CASecurityConfig
cm = AdminCAManager(Path(\"$1\"), CASecurityConfig(key_passphrase_env=\"VENYA_ADMIN_CA_KEY_PASSPHRASE\"))
if not cm.has_ca:
    cm.initialize()
    print(\"Admin CA initialized\")
else:
    print(\"Admin CA already exists - preserved\")
"
    ' _ "$ADMIN_CA_DIR" <<<"$ADMIN_CA_PASSPHRASE"

    # Mint the MACHINE-PLANE admin credential (RF-6 §6.3, §10.7 item 1; ruling 1
    # "split"). This pair is the core's own credential for its admin surface: it is
    # long-lived, its identity is hostname-shaped, and the CA writes the two-plane
    # marker as `machine` at mint (server/ca.py PLANE_MACHINE). It is NOT a person's
    # credential and it is never copied off the core — a human gets a short-lived
    # certificate through the security-key ceremony on a workstation instead
    # (`venya login <user-id>`, then `venya admin cert renew`).
    #
    # The unpack below is byte-compatible with sign_admin_cert's
    # (cert, key_pem, cert_pem) return on purpose: the caller-interlock cell
    # (packages/server/tests/test_bootstrap_mint_interlock_rf7.py) asserts this is
    # the ONE allowed call site of the key-returning mint. Retiring the human
    # handoff does NOT retire this mint.
    #
    # sign_admin_cert loads the CA key — now encrypted — so this block needs the
    # passphrase on stdin too (identical carry). $1=ca_dir $2=cert_dir $3=identity,
    # all positional.
    sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" bash -c '
        IFS= read -r VENYA_ADMIN_CA_KEY_PASSPHRASE
        export VENYA_ADMIN_CA_KEY_PASSPHRASE
        exec python -c "
import sys
from pathlib import Path
from server.ca import AdminCAManager
from server.config import CASecurityConfig
cm = AdminCAManager(Path(\"$1\"), CASecurityConfig(key_passphrase_env=\"VENYA_ADMIN_CA_KEY_PASSPHRASE\"))
cert, key_pem, cert_pem = cm.sign_admin_cert(sys.argv[1])
Path(\"$2/admin.crt\").unlink(missing_ok=True)
Path(\"$2/admin.key\").unlink(missing_ok=True)
Path(\"$2/admin.crt\").write_bytes(cert_pem)
Path(\"$2/admin.key\").write_bytes(key_pem)
Path(\"$2/admin.crt\").chmod(0o644)
Path(\"$2/admin.key\").chmod(0o600)
print(\"Admin cert generated for \" + sys.argv[1])
" "$3"
    ' _ "$ADMIN_CA_DIR" "$ADMIN_CERT_DIR" "$ADMIN_IDENTITY" <<<"$ADMIN_CA_PASSPHRASE"

    info "Admin CA ready; machine-plane admin credential minted for $ADMIN_IDENTITY (never copied off this core — see the banner at the end of the run)"

fi

# --- Install and setup PostgreSQL (core-specific) ---
# VENYA_DB_PASSWORD acquired in the secrets zone above (pre-mutation, with
# the re-run mismatch guard).
info "Installing PostgreSQL..."
venya_apt install -y -qq postgresql

info "Setting up PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Create the venya DB role if missing. Password is fed to psql on stdin (here-doc)
# so it never appears on any process's /proc/*/cmdline (M-59, same pattern as M-56).
# #379 auth probe (unconditional on file state; URL-parameterized): a partial wipe
# (DROP DATABASE without DROP ROLE) leaves the cluster-wide role alive on its old
# password while a fresh install carries a new one; the stored-.env mismatch guard
# above cannot see that (the .env is gone). Prove authentication BEFORE any
# mutation; rotation stays a deliberate manual act. dbname=postgres deliberately —
# the target DB may not exist yet. PGPASSWORD travels as env, never argv.
VENYA_DB_HOST=localhost           # HA re-sources this one knob
VENYA_DB_PORT=5432
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='venya'" 2>/dev/null | grep -q 1; then
    if ! PGPASSWORD="$VENYA_DB_PASSWORD" psql "host=$VENYA_DB_HOST port=$VENYA_DB_PORT user=venya dbname=postgres" \
            -tAc 'SELECT 1' > /dev/null 2>&1; then
        error "The PostgreSQL role 'venya' exists but does not authenticate with the password this install will use."
        error "A partial wipe can leave the cluster role on its previous password; proceeding would"
        error "diverge .env from the role and break server DB auth. Aborting — no changes made."
        error "To continue, either:"
        error "  1. Re-run with the role's actual password, or"
        error "  2. Rotate deliberately: sudo -u postgres psql -c \"ALTER USER venya WITH PASSWORD '<new>'\""
        error "     then re-run the installer with VENYA_DB_PASSWORD='<new>'."
        exit 1
    fi
    info "Existing PostgreSQL role 'venya' authenticated with the supplied password — proceeding."
else
    VENYA_DB_PASSWORD_SQL=${VENYA_DB_PASSWORD//\'/\'\'}
    sudo -u postgres psql > /dev/null 2>&1 <<PSL_EOT
SET standard_conforming_strings = on;
CREATE USER venya WITH PASSWORD '$VENYA_DB_PASSWORD_SQL';
PSL_EOT
fi

sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='venya'" 2>/dev/null | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE venya OWNER venya;" > /dev/null 2>&1

# Runtime DB role (issue #66 G9 — DB-enforced append-only audit trail): the
# server connects as venya_audit via peer auth over the local socket — NO
# password, so /opt/venya/.env holds no runtime DB credential. Migrations
# still run as the owner role 'venya' over TCP (migration step below).
# Migration 031_audit_append_only_grants fails loud if this role is missing.
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='venya_audit'" 2>/dev/null | grep -q 1 || \
    sudo -u postgres psql -c "CREATE ROLE venya_audit LOGIN;" > /dev/null 2>&1

# --- Active PostgreSQL cluster resolution (issue #496) ---
# Selection used to be `ls -d /etc/postgresql/*/main | head -n1`, which takes
# the LOWEST installed version by sort order — not the cluster the server
# actually runs. On a host carrying more than one PostgreSQL major the
# venya_map peer map landed in an inactive cluster and venya-core died at
# startup on peer auth while the installer reported the step successful.
#
# Ruled shape (s77-ruling-496-recon R1-R4): resolve the ONLINE cluster from
# `pg_lsclusters` (Debian/Ubuntu packaging), fall back to the running server's
# own `SHOW config_file` when that tool is absent, and ABORT with the
# candidate list whenever resolution is not exactly one cluster — an installer
# writing a peer map must never guess its target. Diagnostics go to stderr via
# error()/warn(); the function's stdout carries the single chosen path only.
venya_resolve_pg_cluster() {
    local _root="/etc/postgresql"
    local _line="" _ver="" _cluster="" _port="" _status="" _rest=""
    local _d="" _chosen="" _cands=""
    local _online=0

    if command -v pg_lsclusters > /dev/null 2>&1; then
        # Primary (R1): the packaging tool knows each cluster's state.
        # Columns: Ver Cluster Port Status Owner Data-directory Log-file.
        local _lsc_out=""
        if ! _lsc_out=$(pg_lsclusters --no-header); then
            error "pg_lsclusters --no-header failed — cannot resolve the active PostgreSQL cluster." >&2
            return 1
        fi
        while IFS= read -r _line; do
            [ -n "$_line" ] || continue
            read -r _ver _cluster _port _status _rest <<< "$_line"
            _cands="${_cands}  ${_root}/${_ver}/${_cluster} [status: ${_status:-unknown}]"$'\n'
            if [ "$_status" = "online" ]; then
                _online=$((_online + 1))
                _chosen="${_root}/${_ver}/${_cluster}"
            fi
        done <<< "$_lsc_out"

        if [ "$_online" -gt 1 ]; then
            # R2: ambiguity is fatal, never guessed.
            error "More than one PostgreSQL cluster reports status 'online' — refusing to guess which one to configure:" >&2
            printf '%s' "$_cands" >&2
            error "Exactly one online cluster is supported; stop the others (pg_ctlcluster <ver> <cluster> stop) and re-run." >&2
            return 1
        fi
        if [ "$_online" -eq 1 ] && [ ! -d "$_chosen" ]; then
            error "pg_lsclusters reports an online cluster at '$_chosen' but that config dir is missing:" >&2
            printf '%s' "$_cands" >&2
            return 1
        fi
    else
        # R1 fallback: packaging without pg_lsclusters (non-Debian) — ask the
        # running server where its own config lives, then take that file's
        # directory. Parameter expansion, no external command, no ls parsing.
        local _cfg=""
        if ! _cfg=$(sudo -u postgres psql -tAc 'SHOW config_file'); then
            error "pg_lsclusters is absent and 'SHOW config_file' did not answer — cannot resolve the active PostgreSQL cluster." >&2
            return 1
        fi
        _cfg="${_cfg%[[:space:]]}"
        if [ -z "$_cfg" ]; then
            error "'SHOW config_file' returned no path — the server did not answer the probe." >&2
        else
            _chosen="${_cfg%/*}"
        fi
        for _d in "$_root"/*/main; do
            [ -d "$_d" ] || continue
            _cands="${_cands}  ${_d}"$'\n'
        done
    fi

    if [ -z "$_chosen" ]; then
        error "No ACTIVE PostgreSQL cluster resolved." >&2
        if [ -n "$_cands" ]; then
            error "Cluster config dirs on disk:" >&2
            printf '%s' "$_cands" >&2
        else
            error "No cluster config dirs exist under $_root." >&2
        fi
        return 1
    fi
    if [ ! -d "$_chosen" ]; then
        error "Resolved cluster config dir is missing: $_chosen" >&2
        return 1
    fi
    printf '%s\n' "$_chosen"
}

# R3: a stale venya_map marker left in a cluster the server does NOT run is a
# live foot-gun for the next resolution pass, so strip the stray markers from
# the inactive clusters after selecting. Best-effort and warn-only — cleanup
# never aborts an install (same shape as the core uninstaller's loop).
venya_strip_inactive_pg_markers() {
    local _active="$1"
    local _d
    for _d in /etc/postgresql/*/main; do
        if [ ! -d "$_d" ]; then
            continue
        fi
        if [ "$_d" = "$_active" ]; then
            continue
        fi
        if [ -f "$_d/pg_ident.conf" ]; then
            sudo -u postgres sed -i "/^venya_map venya venya_audit$/d" "$_d/pg_ident.conf" \
                || warn "pg_ident.conf marker cleanup failed in $_d — check manually."
        fi
        if [ -f "$_d/pg_hba.conf" ]; then
            sudo -u postgres sed -i "/venya_audit.*peer map=venya_map/d" "$_d/pg_hba.conf" \
                || warn "pg_hba.conf marker cleanup failed in $_d — check manually."
        fi
    done
    return 0
}

PG_MAIN_DIR=$(venya_resolve_pg_cluster) || PG_MAIN_DIR=""
if [ -z "$PG_MAIN_DIR" ]; then
    error "PostgreSQL main config dir not found — cannot install the venya_audit peer map."
    exit 1
fi
# R3 (issue #496): keep the NON-active clusters marker-free after the target
# is chosen; warn-only, the install proceeds either way.
venya_strip_inactive_pg_markers "$PG_MAIN_DIR"
# pg_ident peer map: OS user 'venya' -> DB role 'venya_audit' (marker-guarded idempotent).
if ! grep -q "^venya_map venya venya_audit" "$PG_MAIN_DIR/pg_ident.conf" 2>/dev/null; then
    sudo -u postgres bash -c "echo 'venya_map venya venya_audit' >> '$PG_MAIN_DIR/pg_ident.conf'"
fi
# pg_hba line MUST precede the default "local all all peer" (first match wins).
if ! grep -q "venya_audit.*peer map=venya_map" "$PG_MAIN_DIR/pg_hba.conf" 2>/dev/null; then
    if grep -q "^local[[:space:]]\+all[[:space:]]\+all[[:space:]]\+peer" "$PG_MAIN_DIR/pg_hba.conf"; then
        sudo -u postgres sed -i "/^local[[:space:]]\+all[[:space:]]\+all[[:space:]]\+peer/i local   venya           venya_audit                         peer map=venya_map" "$PG_MAIN_DIR/pg_hba.conf"
    else
        error "Default 'local all all peer' line not found in pg_hba.conf — insert 'local venya venya_audit peer map=venya_map' before the first matching local line manually."
    fi
fi
sudo -u postgres psql -c "SELECT pg_reload_conf();" > /dev/null 2>&1

# --- Server binds to localhost only — nginx terminates TLS ---
BIND_ADDRESS="127.0.0.1"
info "Server will bind to: $BIND_ADDRESS (Nginx handles TLS)"

# /etc/venya holds runtime files (venya-core.env, tls/). The server reads config
# from /opt/venya/.env only — server.toml was never read at runtime and is no longer
# written (core-server-toml-inert).
# #317 umask 077 guard: /etc/venya is root-owned and the venya daemon must
# traverse it (its inner dirs/files are individually protected) — pin the
# mode the old inherited 0755 provided, explicitly.
install -d -m 0755 /etc/venya

# --- Root/executor CA key passphrase (VENYA_CA_KEY_PASSPHRASE) ---
# The root CA signs executor certs, so its key must be encrypted at rest
# (SEC-001 invariant; sibling of the admin-CA fix 3667c6e). Same acquisition +
# re-run-idempotency precedence as the admin CA: explicit env (operator
# override; a WRONG value fails loudly downstream at decrypt) > stored in the
# EnvironmentFile (re-run reuse -- the encrypted ca.key is PRESERVED by the
# CA-gen guard below, so regenerating the passphrase would make it undecryptable)
# > TTY prompt > strong random. Generated BEFORE the EnvironmentFile write so it
# can be delivered there and used by the CA-gen + openssl signing below.
CA_KEY_PASSPHRASE="${VENYA_CA_KEY_PASSPHRASE:-}"
if [ -z "$CA_KEY_PASSPHRASE" ] && [ -f /etc/venya/venya-core.env ]; then
    CA_KEY_PASSPHRASE=$(sed -n 's/^VENYA_CA_KEY_PASSPHRASE=//p' /etc/venya/venya-core.env | head -n1)
    if [ -n "$CA_KEY_PASSPHRASE" ]; then
        info "Existing install: reusing stored root CA passphrase from /etc/venya/venya-core.env."
    fi
fi
if [ -z "$CA_KEY_PASSPHRASE" ]; then
    if [ -t 0 ] && [ "${VENYA_SKIP_PROMPT:-}" != "yes" ]; then
            venya_read_secret_confirm "Root CA key passphrase" CA_KEY_PASSPHRASE
    else
        CA_KEY_PASSPHRASE=$(openssl rand -base64 32)
        info "Unattended install: generated a random root CA passphrase."
    fi
fi

# #326 F-1: gate the finalized root-CA passphrase (explicit env + stored
# reuse branches; prompt/random are line-based). Runs before the
# EnvironmentFile write and before every openssl/python consumer.
venya_guard_injection "CA_KEY_PASSPHRASE" "$CA_KEY_PASSPHRASE"

# --- Write .env (core-specific) ---
# Operator-added config keys survive regeneration (ticket
# installer-rerun-env-custom-keys-clobbered): the template below owns
# MANAGED_ENV_KEYS only; every other line starting at column 0 with VENYA_
# in an existing .env (e.g. VENYA_SESSION__* tuning) is captured here and
# re-appended after the template blocks. The five SECRETS keep their own
# stored-reuse blocks above — this is for non-secret operator config.
MANAGED_ENV_KEYS="VENYA_HOST VENYA_DB_URL VENYA_DB__DATABASE_URL VENYA_DB__PASSPHRASE VENYA_FIDO2__RP_ID VENYA_FIDO2__RP_NAME VENYA_CORS__ORIGINS VENYA_RECOVERY_CODE_PEPPER VENYA_ADMIN_MTLS__ENABLED VENYA_ADMIN_MTLS__CA_CERT VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS VENYA_MTLS_CERT VENYA_MTLS_KEY VENYA_INNER_MTLS__ENABLED VENYA_INNER_MTLS__CERT_FILE VENYA_INNER_MTLS__KEY_FILE VENYA_INNER_MTLS__CLIENT_CA_FILE"
PRESERVED_ENV_LINES=""
if [ -f "$STORED_ENV_FILE" ]; then
    PRESERVED_ENV_LINES=$(awk -F= -v managed="$MANAGED_ENV_KEYS" '
        BEGIN { n = split(managed, m, " "); for (i = 1; i <= n; i++) skip[m[i]] = 1 }
        /^VENYA_/ && !($1 in skip)
    ' "$STORED_ENV_FILE")
fi
# #381: delete-then-create — a truncating > over an incumbent .env keeps its
# stale mode; the chmod 600 below remains the final-state pin.
rm -f "$INSTALL_DIR/.env"
{
    printf 'VENYA_HOST=127.0.0.1\n'
    printf 'VENYA_DB_URL=postgresql://venya:%s@localhost/venya\n' "$VENYA_DB_PASSWORD"  # pragma: allowlist secret
    printf 'VENYA_DB__DATABASE_URL=postgresql://venya_audit@/venya?host=/var/run/postgresql\n'
    printf 'VENYA_DB__PASSPHRASE=%s\n' "$DB_PASSPHRASE"
    printf 'VENYA_FIDO2__RP_ID=%s\n' "$CORE_HOSTNAME"
    printf 'VENYA_FIDO2__RP_NAME=Venya Core\n'
    printf 'VENYA_CORS__ORIGINS=["https://%s"]\n' "$CORE_HOSTNAME"
    printf 'VENYA_RECOVERY_CODE_PEPPER=%s\n' "$RECOVERY_PEPPER"
} > "$INSTALL_DIR/.env"

if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    # NOTE: the admin passphrase is NOT written to .env. pydantic reads .env into
    # the settings object, not into os.environ — and ca.py/app.py read os.environ.
    # Passphrases reach the daemon via the 0640 EnvironmentFile below.
    # VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS is the MACHINE-PLANE allowlist only
    # (RF-6 §3.2, §10.7 item 4; ruling 2 "two-plane identity model"). A
    # machine-plane leaf must name one of these identities byte-for-byte; a
    # human-plane leaf is PERSON-shaped and the list does not apply to it — what
    # authorizes a human on every use is require_admin's role lookup
    # (middleware/auth.py). Seeding it from $ADMIN_IDENTITY stays: dropping it
    # fails the machine plane closed (auth.py refuses 403 on an empty list).
    {
        printf 'VENYA_ADMIN_MTLS__ENABLED=true\n'
        printf 'VENYA_ADMIN_MTLS__CA_CERT="%s/admin-ca.crt"\n' "$ADMIN_CA_DIR"
        printf 'VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS=["%s"]\n' "$ADMIN_IDENTITY"
    } >> "$INSTALL_DIR/.env"
fi

if [ -n "$PRESERVED_ENV_LINES" ]; then
    {
        echo "# --- operator-added keys preserved across re-run (installer) ---"
        printf '%s\n' "$PRESERVED_ENV_LINES"
    } >> "$INSTALL_DIR/.env"
    info "Preserved $(printf '%s\n' "$PRESERVED_ENV_LINES" | wc -l) operator-added .env key(s) across regeneration."
fi

# Runtime passphrase delivery: a 0640 root:venya EnvironmentFile that systemd
# (PID1, as root) reads into the service's os.environ — the only thing ca.py
# reads. Replaces the old inline Environment= injection into the 0644 unit (which
# leaked the secret to every local user). Values are unquoted base64: systemd
# strips quotes but unquoted avoids any version-dependent ambiguity, and base64
# has no systemd-special chars. The ROOT CA passphrase is ALWAYS delivered (the
# root CA is generated unconditionally and signs executor certs at runtime); the
# ADMIN CA passphrase is appended only when admin mTLS is enabled. Written before
# the CA-gen/openssl-signing below so a re-run can reuse it (idempotency above).
# #326 F-1: printf writers — values pass as ARGUMENTS (Layer 2), the
# newline/CR split that made this a systemd Environment= injection sink
# is rejected at finalization above (Layer 1; fail-closed cannot brick:
# a newline-bearing passphrase could never round-trip this file anyway).
# #381: fresh inode (chmod 0640 below stays the final-state pin)
rm -f /etc/venya/venya-core.env
printf 'VENYA_CA_KEY_PASSPHRASE=%s\n' "$CA_KEY_PASSPHRASE" > /etc/venya/venya-core.env
if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    printf 'VENYA_ADMIN_CA_KEY_PASSPHRASE=%s\n' "$ADMIN_CA_PASSPHRASE" >> /etc/venya/venya-core.env
fi
chown root:venya /etc/venya/venya-core.env
chmod 0640 /etc/venya/venya-core.env

# .env holds the DB password + passphrase — always root/venya-only, even without mTLS.
chmod 600 "$INSTALL_DIR/.env"
chown venya:venya "$INSTALL_DIR/.env"

info ".env written to $INSTALL_DIR/.env"

# --- Generate Venya CA (Python) and sign server cert (openssl CLI) ---
info "Generating Venya CA and signing server TLS certificate..."
mkdir -p /etc/venya/tls
chown venya:venya /etc/venya/tls

# Generate CA with Python (CAManager works for generation)
sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" \
    python -c "
import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import UTC, datetime, timedelta

ca_dir = Path('/var/lib/venya/ca')
ca_dir.mkdir(parents=True, exist_ok=True)
os.chmod(str(ca_dir), 0o700)

ca_key_path = ca_dir / 'ca.key'
ca_cert_path = ca_dir / 'ca.crt'

# #505: CA existence is BOTH files, not the key file alone. A re-install on a
# host whose CA directory lost ca.crt but kept ca.key used to print 'preserved'
# and then abort at the relay-cert guard with no way to self-heal. If the key
# survives, re-issue the certificate FROM THE INCUMBENT KEY — never regenerate
# the key, because that invalidates every certificate the fleet already holds.
key_exists = ca_key_path.exists()
cert_exists = ca_cert_path.exists()

if key_exists and cert_exists:
    print('CA already exists - preserved')
else:
    passphrase = sys.stdin.readline().rstrip(chr(10)).encode()
    if not passphrase:
        raise SystemExit('VENYA_CA_KEY_PASSPHRASE empty - refusing to write a plaintext CA key')
    if key_exists:
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=passphrase)
    else:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_key_path.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(passphrase)))
        ca_key_path.chmod(0o600)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Venya'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Venya Certificate Authority'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'Venya Root CA'),
    ])
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
    builder = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, key_encipherment=False, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False))
    ca_cert = builder.sign(ca_key, hashes.SHA256())
    # #381 idiom: unlink before the write so a truncating write never inherits
    # an incumbent inode's mode (no-op when the file is absent)
    ca_cert_path.unlink(missing_ok=True)
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_cert_path.chmod(0o644)
    print('CA certificate re-issued from existing key' if key_exists else 'CA generated (key encrypted)')
" <<<"$CA_KEY_PASSPHRASE"

# Sign server cert with openssl CLI (cryptography 50.0.1 Rust backend bug:
# builder.sign() rejects valid ECPrivateKey from _rust.openssl.ec module)
openssl ecparam -genkey -name prime256v1 -noout -out /etc/venya/tls/server.key
chown venya:venya /etc/venya/tls/server.key
chmod 600 /etc/venya/tls/server.key

SERVER_CSR=$(mktemp /tmp/venya-server-XXXXXX.csr)   # #317: static /tmp name = symlink-clobber hazard
register_install_temp "$SERVER_CSR"   # #475: backstop if a sign step aborts before the rm below
openssl req -new -key /etc/venya/tls/server.key -out "$SERVER_CSR" \
    -subj "/O=Venya/CN=$CORE_HOSTNAME"

VENYA_CA_KEY_PASSPHRASE="$CA_KEY_PASSPHRASE" openssl x509 -req -in "$SERVER_CSR" \
    -CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key \
    -passin env:VENYA_CA_KEY_PASSPHRASE \
    -CAcreateserial -out /etc/venya/tls/server.crt -days 365 \
    -extfile <(echo "subjectAltName=DNS:$CORE_HOSTNAME")

chown venya:venya /etc/venya/tls/server.crt
chmod 644 /etc/venya/tls/server.crt
rm -f "$SERVER_CSR"

info "Server TLS certificate signed with Venya CA"

# --- Relay client cert: self-provisioned from the Venya CA ---
# The core presents this client cert when calling the executor relay listener.
# CN="${CORE_HOSTNAME}-relay" is the canonical relay identity; the executor
# installer derives the same value for relay_client_ids.
# The CA key is ENCRYPTED (BestAvailableEncryption, VENYA_CA_KEY_PASSPHRASE), so
# openssl signs with -passin env:VENYA_CA_KEY_PASSPHRASE — the value travels in
# the process environment (root-readable /proc/PID/environ), NEVER on argv
# (/proc/*/cmdline is world-readable). If the CA is missing, fail the install
# here — not at the physical e2e.
if [ ! -f /var/lib/venya/ca/ca.crt ] || [ ! -f /var/lib/venya/ca/ca.key ]; then
    error "Venya CA missing at /var/lib/venya/ca (ca.crt/ca.key) — cannot sign relay client cert"
    exit 1
fi

RELAY_DIR="/etc/venya/relay"
mkdir -p "$RELAY_DIR"
chown venya:venya "$RELAY_DIR"
chmod 700 "$RELAY_DIR"

openssl ecparam -genkey -name prime256v1 -noout -out "$RELAY_DIR/relay-client.key"
chown venya:venya "$RELAY_DIR/relay-client.key"
chmod 600 "$RELAY_DIR/relay-client.key"

RELAY_CSR=$(mktemp /tmp/venya-relay-XXXXXX.csr)   # #317: static /tmp name = symlink-clobber hazard
register_install_temp "$RELAY_CSR"   # #475: backstop if a sign/purpose check exits before the rm below
openssl req -new -key "$RELAY_DIR/relay-client.key" \
    -out "$RELAY_CSR" \
    -subj "/O=Venya/CN=${CORE_HOSTNAME}-relay"

# SKI + AKI are non-optional: Python 3.14 ssl rejects a chain without an
# Authority Key Identifier (33bc4b4); a lenient s_client smoke masks the
# absence. EKU is clientAuth-only: the core relay cert never serves a server
# role (the executor leaf is dual-purpose by design — do not "unify").
VENYA_CA_KEY_PASSPHRASE="$CA_KEY_PASSPHRASE" openssl x509 -req -in "$RELAY_CSR" \
    -CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key \
    -passin env:VENYA_CA_KEY_PASSPHRASE \
    -CAcreateserial -out "$RELAY_DIR/relay-client.crt" -days 365 \
    -extfile <(printf 'extendedKeyUsage=clientAuth\nsubjectAltName=DNS:%s-relay\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "${CORE_HOSTNAME}")

chown venya:venya "$RELAY_DIR/relay-client.crt"
chmod 644 "$RELAY_DIR/relay-client.crt"
rm -f "$RELAY_CSR"

# Self-check: fail the install loudly on a half-wired relay cert.
if ! openssl verify -CAfile /var/lib/venya/ca/ca.crt "$RELAY_DIR/relay-client.crt" >/dev/null 2>&1; then
    error "Relay client cert failed verification against the Venya CA"
    exit 1
fi
ACTUAL_RELAY_CN=$(openssl x509 -in "$RELAY_DIR/relay-client.crt" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')
if [ "$ACTUAL_RELAY_CN" != "${CORE_HOSTNAME}-relay" ]; then
    error "Relay client cert CN mismatch: expected '${CORE_HOSTNAME}-relay', got '${ACTUAL_RELAY_CN}'"
    exit 1
fi

# Purpose self-check: assert the asymmetric-EKU contract (client Yes / server
# No) at install time. `openssl verify` does NOT check EKU, so without this an
# EKU/SAN defect would surface only at the deploy stop-check, not at install.
PURPOSE_OUT=$(openssl x509 -in "$RELAY_DIR/relay-client.crt" -noout -purpose 2>/dev/null)
if ! printf '%s\n' "$PURPOSE_OUT" | grep -qE '^[[:space:]]*SSL client[[:space:]]+: Yes'; then
    error "Relay client cert purpose self-check failed: expected 'SSL client : Yes'"
    exit 1
fi
if ! printf '%s\n' "$PURPOSE_OUT" | grep -qE '^[[:space:]]*SSL server[[:space:]]+: No'; then
    error "Relay client cert purpose self-check failed: expected 'SSL server : No'"
    exit 1
fi

info "Relay client certificate signed and verified: CN=${CORE_HOSTNAME}-relay (client Yes / server No)"

# --- Inner mTLS channel keypair (#314 end-to-end-mtls-header-trust-removal) ---
# One keypair, BOTH roles: nginx presents it as a CLIENT to uvicorn
# (proxy_ssl_certificate) and uvicorn's SERVER cert is the same file (nginx
# verifies it via proxy_ssl_trusted_certificate). CN/subjectAltName identify
# the loopback channel only; no app-layer identity is asserted from it (ruled
# Q6 — uvicorn discards the inner peer after TLS verification).
INNER_DIR="/etc/venya/tls"

openssl ecparam -genkey -name prime256v1 -noout -out "$INNER_DIR/inner.key"
chown venya:venya "$INNER_DIR/inner.key"
chmod 600 "$INNER_DIR/inner.key"

INNER_CSR=$(mktemp /tmp/venya-inner-XXXXXX.csr)   # #317: static /tmp name = symlink-clobber hazard
register_install_temp "$INNER_CSR"   # #475: backstop if a sign/purpose check exits before the rm below
openssl req -new -key "$INNER_DIR/inner.key" \
    -out "$INNER_CSR" \
    -subj "/O=Venya/CN=${CORE_HOSTNAME}-inner"

# SKI + AKI non-optional (F1: Python 3.14 ssl rejects AKI-less chains; lenient
# s_client masks it). extfile newline-separated (F2). EKU BOTH roles (the
# relay-cert single-purpose convention deliberately does NOT carry over —
# this leaf serves and authenticates on the same loopback channel).
VENYA_CA_KEY_PASSPHRASE="$CA_KEY_PASSPHRASE" openssl x509 -req -in "$INNER_CSR" \
    -CA /var/lib/venya/ca/ca.crt -CAkey /var/lib/venya/ca/ca.key \
    -passin env:VENYA_CA_KEY_PASSPHRASE \
    -CAcreateserial -out "$INNER_DIR/inner.crt" -days 365 \
    -extfile <(printf 'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,DNS:%s,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "${CORE_HOSTNAME}")

chown venya:venya "$INNER_DIR/inner.crt"
chmod 644 "$INNER_DIR/inner.crt"
rm -f "$INNER_CSR"

# F1-F4 self-checks — strict mechanism, never a lenient smoke:
if ! openssl verify -CAfile /var/lib/venya/ca/ca.crt "$INNER_DIR/inner.crt" >/dev/null 2>&1; then
    error "Inner channel cert failed verification against the Venya CA"
    exit 1
fi
ACTUAL_INNER_CN=$(openssl x509 -in "$INNER_DIR/inner.crt" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')
if [ "$ACTUAL_INNER_CN" != "${CORE_HOSTNAME}-inner" ]; then
    error "Inner channel cert CN mismatch: expected '${CORE_HOSTNAME}-inner', got '${ACTUAL_INNER_CN}'"
    exit 1
fi
PURPOSE_OUT=$(openssl x509 -in "$INNER_DIR/inner.crt" -noout -purpose 2>/dev/null)
printf '%s\n' "$PURPOSE_OUT" | grep -qE '^[[:space:]]*SSL client[[:space:]]+: Yes' || { error "Inner cert purpose: expected 'SSL client : Yes'"; exit 1; }
printf '%s\n' "$PURPOSE_OUT" | grep -qE '^[[:space:]]*SSL server[[:space:]]+: Yes' || { error "Inner cert purpose: expected 'SSL server : Yes'"; exit 1; }

# F1 application at the RUNTIME verifier (uvicorn is Python ssl, not openssl):
# loopback handshake smoke with python3 -m ssl is unavailable; the functional
# proof is the post-restart health fetch (P4's final step). Install-time this
# cell is the openssl verify above; the PYTHON-side verification smoke happens
# FLEET-WINDOW as the first nginx→uvicorn fetch (see FLEET checklist).
info "Inner mTLS keypair signed and verified: CN=${CORE_HOSTNAME}-inner (client Yes / server Yes)"

# Functional wiring: the server reads .env at runtime. The appended values are
# non-secret paths only.
cat >> "$INSTALL_DIR/.env" << EOF
VENYA_MTLS_CERT=$RELAY_DIR/relay-client.crt
VENYA_MTLS_KEY=$RELAY_DIR/relay-client.key
VENYA_INNER_MTLS__ENABLED=true
VENYA_INNER_MTLS__CERT_FILE=/etc/venya/tls/inner.crt
VENYA_INNER_MTLS__KEY_FILE=/etc/venya/tls/inner.key
VENYA_INNER_MTLS__CLIENT_CA_FILE=/var/lib/venya/ca/ca.crt
EOF

# Install Venya CA into system trust store
# Clean stale symlinks/files from previous installs
rm -f /etc/ssl/certs/venya-*.pem
rm -f /etc/ssl/certs/$(openssl x509 -in /var/lib/venya/ca/ca.crt -noout -subject_hash 2>/dev/null).*
rm -f /usr/local/share/ca-certificates/venya-*.crt /usr/local/share/ca-certificates/venya-*.der
cp /var/lib/venya/ca/ca.crt /usr/local/share/ca-certificates/venya-root-ca.crt
chmod 644 /usr/local/share/ca-certificates/venya-root-ca.crt
update-ca-certificates > /dev/null 2>&1
info "Venya CA installed to system trust store"

# Copy CA cert to servable path for executor bootstrap
# #317 umask 077 guard: nginx WORKERS (www-data) serve this dir — the file
# inside already gets explicit chmod 644; the DIR needs the traverse bit.
mkdir -p /var/www/.well-known
chmod 755 /var/www/.well-known
cp /var/lib/venya/ca/ca.crt /var/www/.well-known/venya-ca.crt
chmod 644 /var/www/.well-known/venya-ca.crt
info "CA cert served at /.well-known/venya-ca.crt"

# --- Write Nginx config (core-specific) ---
mkdir -p /etc/nginx/ssl

# Copy Admin CA to Nginx-readable location (www-data can't traverse /var/lib/venya/ca)
if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    cp /var/lib/venya/ca/admin-ca/admin-ca.crt /etc/nginx/ssl/client-ca.crt
    chmod 644 /etc/nginx/ssl/client-ca.crt
    ADMIN_CA_PATH="/etc/nginx/ssl/client-ca.crt"
else
    rm -f /etc/nginx/ssl/client-ca.crt
    ADMIN_CA_PATH=""
fi

# Create CA bundle: Venya Root CA + Admin CA (when admin mTLS is on).
# Nginx needs both to verify admin client certs (Admin CA) and executor certs (Root CA).
# #314 F7 (owner ruling Q1(b)): fail loud, scoped per admin-mTLS state — the old
# "|| true" silently produced an empty/truncated bundle when an input was missing.
if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    if ! cat /var/lib/venya/ca/ca.crt /etc/nginx/ssl/client-ca.crt > /etc/nginx/ssl/client-ca-bundle.crt; then
        error "Failed to build /etc/nginx/ssl/client-ca-bundle.crt — client-CA inputs missing/unreadable"
        exit 1
    fi
else
    if ! cat /var/lib/venya/ca/ca.crt > /etc/nginx/ssl/client-ca-bundle.crt; then
        error "Failed to build /etc/nginx/ssl/client-ca-bundle.crt — root CA missing/unreadable"
        exit 1
    fi
fi
chmod 644 /etc/nginx/ssl/client-ca-bundle.crt

# #381: fresh inode — cat > over an incumbent vhost preserved its old mode
# (K30: re-install re-filled an incumbent 0644 inode under umask 077)
rm -f /etc/nginx/sites-available/venya
cat > /etc/nginx/sites-available/venya << EOF
server {
    listen 443 ssl;
    server_name $CORE_HOSTNAME;
    server_tokens off;

    ssl_certificate /etc/venya/tls/server.crt;
    ssl_certificate_key /etc/venya/tls/server.key;
    # GitLab #323: floor the TLS handshake at 1.2 (nginx default allows 1.0/1.1).
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_client_certificate /etc/nginx/ssl/client-ca-bundle.crt;
    ssl_verify_client optional;

    # The relay execute hop (POST /api/v1/executors/{id}/execute) can legitimately run
    # up to the server's 300s executor-relay timeout — a cold sbx agent-template pull
    # alone is ~65s. nginx's default proxy_read_timeout (60s) 504s before the server
    # responds even though the executor succeeds, so the client sees a gateway timeout
    # for a command that actually ran (and may retry -> double execution). 330s = the
    # 300s relay ceiling + 30s margin, so the server's own clean 503 "Executor timed
    # out" surfaces rather than an nginx 504 at the boundary. Set at server level so it
    # covers every proxied location without duplicating the X-Client-Cert-PEM header below
    # (ticket relay-cold-start-nginx-proxy-timeout).
    proxy_read_timeout 330s;
    proxy_send_timeout 330s;

    location /.well-known/venya-ca.crt {
        alias /var/www/.well-known/venya-ca.crt;
        default_type application/x-x509-ca-cert;
    }

    location /api/v1/health {
        proxy_pass https://127.0.0.1:8080;
        proxy_ssl_certificate /etc/venya/tls/inner.crt;
        proxy_ssl_certificate_key /etc/venya/tls/inner.key;
        proxy_ssl_trusted_certificate /var/lib/venya/ca/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 2;
        proxy_ssl_name localhost;
    }

    location / {
        proxy_pass https://127.0.0.1:8080;
        # Inner mTLS channel (#314): nginx authenticates to uvicorn...
        proxy_ssl_certificate /etc/venya/tls/inner.crt;
        proxy_ssl_certificate_key /etc/venya/tls/inner.key;
        proxy_ssl_trusted_certificate /var/lib/venya/ca/ca.crt;
        proxy_ssl_verify on;
        proxy_ssl_verify_depth 2;
        proxy_ssl_name localhost;
        # ...and forwards the OUTER verified client cert as HEADER CONTENT: the
        # stock nginx 1.13.5+ ssl_client_escaped_cert variable emits the PEM
        # URL-encoded. The app percent-decodes it and re-verifies it against its
        # own CA — content, never a path, so there is no filesystem/traversal
        # surface and no header is trusted as identity (crypto decision is the gate).
        proxy_set_header X-Client-Cert-PEM \$ssl_client_escaped_cert;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
# #381: explicit mode pin (K30 posture 0600 root:root; was umask-side-effect only)
chmod 600 /etc/nginx/sites-available/venya

# Enable site, disable default
ln -sf /etc/nginx/sites-available/venya /etc/nginx/sites-enabled/venya
rm -f /etc/nginx/sites-enabled/default

info "Nginx config written (TLS mode: $TLS_MODE, admin mTLS: $([ "$ADMIN_MTLS_ENABLED" = "true" ] && echo enabled || echo disabled))"

# --- Admin mTLS bootstrap instructions ---
if [ "$ADMIN_MTLS_ENABLED" = "true" ]; then
    echo ""
    echo "==============================================================="
    echo "  ADMIN mTLS IS ENABLED"
    echo "==============================================================="
    echo "  This core holds its own machine-plane admin credential at:"
    echo "    $ADMIN_CERT_DIR/admin.crt"
    echo "    $ADMIN_CERT_DIR/admin.key (0600 — it stays on this host)"
    echo ""
    echo "  Do not copy that pair to a workstation. It names this core, not a person."
    echo "  A person's admin certificate is short-lived and is minted on the workstation"
    echo "  itself, by a security-key ceremony:"
    echo ""
    echo "    venya setup <this-core>       # one-time: the server URL and the core CA"
    echo "    venya login <your-user-id>    # a user that exists on this core, key enrolled"
    echo "    venya admin cert status       # read-local: prints time left, sends nothing"
    echo "    venya admin cert renew        # one touch mints a fresh 60-minute certificate"
    echo ""
    echo "  Check status before a long job and renew if it would expire inside your"
    echo "  window; a job that outlives its certificate fails with the same command"
    echo "  named in the refusal. On Windows the ceremony opens only from an interactive"
    echo "  desktop session, not from a remote or scheduled shell."
    echo ""
    echo "  Admin CA passphrase stored in: /etc/venya/venya-core.env (0640 root:venya)."
    echo "  The venya-core service loads it via EnvironmentFile; it is NOT in .env"
    echo "  or the unit file. On an unattended install it was randomly generated."
    echo "  Read it (root) with: sudo cat /etc/venya/venya-core.env"
    echo ""
    echo "  Note on the renewed pair: its key is written encrypted at rest, and loading"
    echo "  an encrypted admin key for admin mTLS is the open read-side work (#565 Part"
    echo "  B). Until that lands, the headless admin pattern on this core is the"
    echo "  machine-plane pair above. With neither credential, admin endpoints answer 403."
    echo "  To disable: set VENYA_ADMIN_MTLS_ENABLED=false and reinstall."
    echo "==============================================================="
    echo ""
fi

# --- Executor enrollment token instructions ---
echo ""
echo "==============================================================="
echo "  EXECUTOR ENROLLMENT"
echo "==============================================================="
echo ""
echo "To register an executor, mint an enrollment token. On this HEADLESS core the"
echo "CLI must use the admin-mTLS form (a plain 'venya admin ...' falls back to an"
echo "interactive FIDO2 login and dies without a workstation key):"
echo ""
echo "  sudo -u venya env PATH=\"$INSTALL_DIR/.venv/bin:\$PATH\" \\"
echo "    VENYA_ADMIN_CERT=/etc/venya/admin/admin.crt \\"
echo "    VENYA_ADMIN_KEY=/etc/venya/admin/admin.key \\"
echo "    $INSTALL_DIR/.venv/bin/venya admin executor-enroll <executor-id>"
echo ""
echo "  One-time first-use setup for that command — point the venya user's CLI at"
echo "  this core and trust its CA:"
echo "    sudo -u venya $INSTALL_DIR/.venv/bin/venya config set-server https://$CORE_HOSTNAME"
echo "    sudo mkdir -p /home/venya/.config/venya"
echo "    sudo cp /var/lib/venya/ca/ca.crt /home/venya/.config/venya/ca.crt"
echo "    sudo chown venya:venya /home/venya/.config/venya/ca.crt"
echo ""
echo "Then pass the printed token to the executor operator."
echo "The token is consumed on first use and cannot be reused."
echo "The <executor-id> must RESOLVE from this core (it is the relay dial hostname"
echo "and the client-cert SAN) — registration and relay calls fail otherwise."
echo ""
echo "  Relay: the core relay-client cert was auto-provisioned at install"
echo "  (/etc/venya/relay/relay-client.crt, CN=${CORE_HOSTNAME}-relay)."
echo "  Point the executor installer at this hostname:"
echo "    VENYA_SERVER_URL=https://${CORE_HOSTNAME}"
echo ""
echo "==============================================================="
echo ""

# Start Nginx
# Ticket #454: the restart result used to be discarded and the success line
# printed anyway, so a core install could announce a reverse proxy that is
# not running. The restart rc and the unit state are now PROVED before the
# claim, and a failure shows the config test then exits non-zero.
# The is-active idiom is copied from venya-common.sh (venya_service_retry at
# :846 and venya_service_sync at :898); the `nginx -t` call shape already
# exists at uninstall-venya-core.sh:82.
info "Starting Nginx..."
systemctl enable nginx > /dev/null 2>&1
NGINX_RESTART_RC=0
systemctl restart nginx || NGINX_RESTART_RC=$?
if [ "$NGINX_RESTART_RC" -ne 0 ] || ! systemctl is-active --quiet nginx.service 2>/dev/null; then
    error "Nginx did not come up (restart rc=$NGINX_RESTART_RC, unit not active) — config test output:"
    nginx -t 2>&1 || error "nginx -t also failed — see the config-test output above"
    exit 1
fi
info "Nginx enabled and started"

# --- Pre-upgrade database backup (ticket installer-upgrade-version-guard-and-backup) ---
# Migrations are forward-only; the honest rollback is restore-from-backup.
# Taken ONLY on a version-changing re-run over an existing install: fresh
# installs have an empty DB, same-version re-runs have no schema delta.
# Failure aborts BEFORE any migration runs — no backup, no upgrade.
if [ -n "$INSTALLED_VERSION" ] && [ -n "$INCOMING_VERSION" ] && [ "$INSTALLED_VERSION" != "$INCOMING_VERSION" ]; then
    BACKUP_DIR="/var/backups/venya"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    BACKUP_FILE="$BACKUP_DIR/pre-upgrade-${INSTALLED_VERSION}-to-${INCOMING_VERSION}-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
    info "Backing up database before migrations -> $BACKUP_FILE"
    if ! sudo -u postgres pg_dump -d venya 2>/dev/null | gzip > "$BACKUP_FILE"; then
        error "Pre-upgrade pg_dump FAILED — aborting BEFORE migrations (no backup, no upgrade)."
        rm -f "$BACKUP_FILE"
        exit 1
    fi
    chmod 600 "$BACKUP_FILE"
    # Retention: keep the 3 newest pre-upgrade backups.
    ls -1t "$BACKUP_DIR"/pre-upgrade-*.sql.gz 2>/dev/null | tail -n +4 | while read -r old_backup; do
        rm -f "$old_backup"
    done
    info "Backup complete: $(du -h "$BACKUP_FILE" | cut -f1)"
fi

# --- Run database migrations (core-specific) ---
# #587: the schema must not move under a process that is still running the
# previous build. A re-run swaps packages at the top of this script and Python
# keeps the imports it loaded at its own start time, so until the fresh-bytes
# sync further down this file the live core is the OLD build — and the
# installer's own downgrade guard calls old code over a newer schema undefined
# behavior. Stop first; venya_service_sync below starts it again on the new
# bytes. The stop is announced because it is a deliberate, seconds-long outage
# on a version-changing re-run (owner ruling: LAND — stop before migration).
# Guarded: on a first install there is no unit yet, and `stop` there is a
# non-zero command under set -e — so a fresh install never stops and never
# aborts here.
if systemctl is-active --quiet venya-core.service 2>/dev/null; then
    warn "NOTICE: stopping venya-core.service BEFORE database migrations (#587) — the schema does not move under old code."
    warn "NOTICE: this core will not answer requests until the fresh-bytes line below restarts it."
    systemctl stop venya-core.service
fi
info "Running database migrations..."
# DB URL via stdin (here-doc): keeps $VENYA_DB_PASSWORD off every process's /proc/*/cmdline.
sudo -u venya env PATH="$INSTALL_DIR/.venv/bin:$PATH" bash -c '
  set -a; read -r VENYA_DB_URL
  cd "$1" && python -c "from core.migrations import _run_migrations; _run_migrations()"
' _ "$INSTALL_DIR" <<VENYA_EOT
postgresql://venya:$VENYA_DB_PASSWORD@localhost/venya
VENYA_EOT
info "Database migrations complete"

# --- Install systemd service (core-specific) ---
info "Installing systemd service..."
SYSTEMD_DIR="/etc/systemd/system"
# #381: delete-then-create + explicit pin (K31 0600 root:root; sed > over an
# incumbent unit file kept its stale mode)
rm -f "$SYSTEMD_DIR/venya-core.service"
sed "s|VENYA_ENV_DIR=/opt/venya|VENYA_ENV_DIR=$INSTALL_DIR|" "$INSTALL_DIR/systemd/venya-core.service" > "$SYSTEMD_DIR/venya-core.service"
chmod 600 "$SYSTEMD_DIR/venya-core.service"

# NOTE: no passphrase is injected into the unit here. The unit template carries
# EnvironmentFile=-/etc/venya/venya-core.env (0640 root:venya, written above),
# so the secret never lands in this 0600 root:root unit (#381 comment fix). The leading '-' makes
# it optional: admin-mTLS-disabled installs (no env file) still start cleanly.

systemctl daemon-reload
systemctl enable venya-core.service

# Fresh-bytes sync (ticket installer-rerun-no-service-restart): a re-run swaps
# site-packages under the LIVE process and `systemctl start` is a no-op on a
# running unit — detection (start-time vs deploy stamp) + restart with a loud
# notice, so verification below probes the NEW bytes, never the stale process.
touch "$INSTALL_DIR/.deploy-stamp"
venya_service_sync venya-core "$INSTALL_DIR/.deploy-stamp"

# --- Service retry ---
venya_service_retry venya-core
# #587: the outcome is consumed by the success claim below — STALE refuses it,
# UNDECIDABLE withholds it, FRESH proceeds.
VENYA_FRESHNESS_RC=0
VENYA_FRESHNESS_SERVICE=venya-core
venya_service_freshness venya-core "$INSTALL_DIR/.deploy-stamp" || VENYA_FRESHNESS_RC=$?

# --- Verification ---
venya_verify_install \
    /etc/nginx/sites-available/venya \
    /etc/systemd/system/venya-core.service

# --- Summary ---
echo ""
echo "============================================"
echo "  Venya Core installed to $INSTALL_DIR"
echo "============================================"
echo ""
echo "Manage the core server:"
echo "  systemctl start|stop|restart|status venya-core"
echo ""
echo "Nginx reverse proxy:"
echo "  Config: /etc/nginx/sites-available/venya"
echo "  TLS mode: $TLS_MODE"
echo "  Access: https://$CORE_HOSTNAME"
echo ""
echo "Next steps:"
echo "  1. Verify health: curl -sk https://$CORE_HOSTNAME/api/v1/health"
echo "  2. Enroll admin: open https://$CORE_HOSTNAME/enroll-admin in browser"
echo "  3. Mint an executor enrollment token (command above) with the admin"
echo "     credential."
echo "  4. Install the executor with VENYA_EXECUTOR_ENROLLMENT_TOKEN=<token>."
echo "     Registration happens inside that install; the token is single-use."
echo ""
