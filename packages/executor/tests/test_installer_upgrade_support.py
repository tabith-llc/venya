# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Interlock: core installer upgrade support (tickets
installer-upgrade-version-guard-and-backup, installer-rerun-env-custom-keys-clobbered,
installer-rerun-db-password-no-reuse — owner-commissioned 2026-09-26).

Text pins on install-venya-core.sh: the downgrade guard + escape knob, the
conditional pre-migration backup (abort-on-failure, retention), the
load-bearing ORDERING (capture before download, guard before venv rebuild,
backup before migrations), the .env preservation filter + complete managed-key
list, and the DB-password stored-reuse (prompt + mismatch-abort preserved).
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALLER = (REPO_ROOT / "install-venya-core.sh").read_text()

MANAGED_KEYS = [
    "VENYA_HOST",
    "VENYA_DB_URL",
    "VENYA_DB__DATABASE_URL",
    "VENYA_DB__PASSPHRASE",
    "VENYA_FIDO2__RP_ID",
    "VENYA_FIDO2__RP_NAME",
    "VENYA_CORS__ORIGINS",
    "VENYA_RECOVERY_CODE_PEPPER",
    "VENYA_ADMIN_MTLS__ENABLED",
    "VENYA_ADMIN_MTLS__CA_CERT",
    "VENYA_ADMIN_MTLS__KNOWN_ADMIN_IDS",
    "VENYA_MTLS_CERT",
    "VENYA_MTLS_KEY",
]


def test_downgrade_guard_with_escape_knob():
    assert "Refusing to downgrade: installed" in INSTALLER
    assert "VENYA_ALLOW_DOWNGRADE" in INSTALLER
    assert "Upgrade: $INSTALLED_VERSION -> $INCOMING_VERSION" in INSTALLER
    assert "same-version re-run" in INSTALLER


def test_preupgrade_backup_hook():
    assert "/var/backups/venya" in INSTALLER
    assert "sudo -u postgres pg_dump -d venya" in INSTALLER
    # fail-loud: no backup, no upgrade — abort BEFORE migrations
    assert "no backup, no upgrade" in INSTALLER
    # retention: keep the 3 newest
    assert "tail -n +4" in INSTALLER


def test_upgrade_step_ordering():
    # Capture while the old venv still exists — before the tarball replaces the tree.
    assert INSTALLER.index('INSTALLED_VERSION=""') < INSTALLER.index("venya_download_tarball core")
    # Guard fires before the destructive venv rebuild.
    assert INSTALLER.index("Refusing to downgrade") < INSTALLER.index("venya_create_venv")
    # Backup strictly before migrations.
    assert INSTALLER.index("pg_dump") < INSTALLER.index("_run_migrations")


def test_env_custom_key_preservation():
    assert "MANAGED_ENV_KEYS=" in INSTALLER
    assert "operator-added keys preserved across re-run" in INSTALLER
    # Every template key must be managed, or preservation would duplicate it.
    for key in MANAGED_KEYS:
        assert f"{key} " in INSTALLER.split('MANAGED_ENV_KEYS="', 1)[1].split('"', 1)[0] + " "
    # Paired negative: a known operator-tuning family must NOT be managed.
    managed_line = INSTALLER.split('MANAGED_ENV_KEYS="', 1)[1].split('"', 1)[0]
    assert "VENYA_SESSION__" not in managed_line


def test_db_password_stored_reuse_keeps_prompt_and_mismatch_abort():
    assert "reusing stored PostgreSQL password" in INSTALLER
    # Fresh/prompt path unchanged.
    assert "Enter PostgreSQL password for venya user" in INSTALLER
    assert "VENYA_DB_PASSWORD is required for unattended install" in INSTALLER
    # Explicit mismatch still aborts (no silent rotation).
    assert "does not match the password stored in" in INSTALLER
