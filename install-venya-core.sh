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
    source "$FETCH_DIR/venya-common.sh"
fi

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
DB_PASSPHRASE="${VENYA_DB_PASSPHRASE:-}"
STORED_ENV_FILE="$INSTALL_DIR/.env"
STORED_DB_PASSPHRASE=""
if [ -f "$STORED_ENV_FILE" ]; then
    STORED_DB_PASSPHRASE=$(sed -n 's/^VENYA_DB__PASSPHRASE=//p' "$STORED_ENV_FILE" | head -n1)
fi
if [ -n "$STORED_DB_PASSPHRASE" ]; then
    if [ -n "$DB_PASSPHRASE" ] && [ "$DB_PASSPHRASE" != "$STORED_DB_PASSPHRASE" ]; then
        error "VENYA_DB_PASSPHRASE does not match the stored value in $STORED_ENV_FILE."
        error "Rotating it would make existing encrypted DB secrets undecryptable."
        error "Aborting — no changes made."
        exit 1
    fi
    DB_PASSPHRASE="$STORED_DB_PASSPHRASE"
    info "Existing install: reusing stored server passphrase from $STORED_ENV_FILE."
elif [ -z "$DB_PASSPHRASE" ]; then
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
    # piped/unattended. Either way validated non-empty — an empty passphrase
    # would silently yield an UNENCRYPTED admin CA key. Nobody needs to
    # memorize a CA key passphrase, so unattended keeps the strong random
    # default; typing is for delivery hygiene, not for replacing randomness.
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

    # Generate first admin cert. sign_admin_cert loads the CA key — now
    # encrypted — so this block needs the passphrase on stdin too (identical
    # carry). $1=ca_dir $2=cert_dir $3=identity, all positional.
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
Path(\"$2/admin.crt\").write_bytes(cert_pem)
Path(\"$2/admin.key\").write_bytes(key_pem)
Path(\"$2/admin.crt\").chmod(0o644)
Path(\"$2/admin.key\").chmod(0o600)
print(\"Admin cert generated for \" + sys.argv[1])
" "$3"
    ' _ "$ADMIN_CA_DIR" "$ADMIN_CERT_DIR" "$ADMIN_IDENTITY" <<<"$ADMIN_CA_PASSPHRASE"

    info "Admin CA and first admin cert generated for $ADMIN_IDENTITY"

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
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='venya'" 2>/dev/null | grep -q 1; then
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

PG_MAIN_DIR=$(ls -d /etc/postgresql/*/main 2>/dev/null | head -n1)
if [ -z "$PG_MAIN_DIR" ]; then
    error "PostgreSQL main config dir not found — cannot install the venya_audit peer map."
    exit 1
fi
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

if not ca_key_path.exists():
    passphrase = sys.stdin.readline().rstrip(chr(10)).encode()
    if not passphrase:
        raise SystemExit('VENYA_CA_KEY_PASSPHRASE empty - refusing to write a plaintext CA key')
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
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_cert_path.chmod(0o644)
    print('CA generated (key encrypted)')
else:
    print('CA already exists - preserved')
" <<<"$CA_KEY_PASSPHRASE"

# Sign server cert with openssl CLI (cryptography 50.0.1 Rust backend bug:
# builder.sign() rejects valid ECPrivateKey from _rust.openssl.ec module)
openssl ecparam -genkey -name prime256v1 -noout -out /etc/venya/tls/server.key
chown venya:venya /etc/venya/tls/server.key
chmod 600 /etc/venya/tls/server.key

SERVER_CSR=$(mktemp /tmp/venya-server-XXXXXX.csr)   # #317: static /tmp name = symlink-clobber hazard
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
    echo "  Your admin certificate is at:"
    echo "    $ADMIN_CERT_DIR/admin.crt"
    echo "    $ADMIN_CERT_DIR/admin.key"
    echo ""
    echo "  Copy these to your workstation:"
    echo "    scp root@${CORE_HOSTNAME}:$ADMIN_CERT_DIR/admin.crt ~/venya-admin.crt"
    echo "    scp root@${CORE_HOSTNAME}:$ADMIN_CERT_DIR/admin.key ~/venya-admin.key"
    echo ""
    echo "  Admin CA passphrase stored in: /etc/venya/venya-core.env (0640 root:venya)."
    echo "  The venya-core service loads it via EnvironmentFile; it is NOT in .env"
    echo "  or the unit file. On an unattended install it was randomly generated."
    echo "  Read it (root) with: sudo cat /etc/venya/venya-core.env"
    echo ""
    echo "  Until you do, admin endpoints will return 403."
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
info "Starting Nginx..."
systemctl enable nginx > /dev/null 2>&1
systemctl restart nginx > /dev/null 2>&1 || true
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
sed "s|VENYA_ENV_DIR=/opt/venya|VENYA_ENV_DIR=$INSTALL_DIR|" "$INSTALL_DIR/systemd/venya-core.service" > "$SYSTEMD_DIR/venya-core.service"

# NOTE: no passphrase is injected into the unit here. The unit template carries
# EnvironmentFile=-/etc/venya/venya-core.env (0640 root:venya, written above),
# so the secret never lands in this 0644 root:root unit. The leading '-' makes
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
venya_service_freshness venya-core "$INSTALL_DIR/.deploy-stamp"

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
