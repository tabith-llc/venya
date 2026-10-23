# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Programmatic Alembic migrations for the core server.

Called by install-venya-core.sh at install time. The workstation CLI
(venya-cli) does not run migrations; a live server implies a migrated
database.
"""

import os
from pathlib import Path


def _run_migrations() -> None:
    """Run Alembic migrations programmatically (upgrade to head).

    Raises:
        RuntimeError: If VENYA_DB_URL is not set, alembic.ini is missing,
            or migrations fail.
    """
    from alembic import command
    from alembic.config import Config

    venya_db_url = os.environ.get("VENYA_DB_URL", "")
    if not venya_db_url:
        raise RuntimeError(
            "VENYA_DB_URL not set. Set it before running migrations.\n"
            "Example:\n"
            "  VENYA_DB_URL=postgresql://user:pass@host/db"
        )

    # Find alembic.ini relative to the core package root
    # __file__ = .../packages/core/src/core/migrations.py
    # parent x3 = .../packages/core/
    _pkg_root = Path(__file__).resolve().parent.parent.parent
    _alembic_ini = _pkg_root / "alembic.ini"
    if not _alembic_ini.exists():
        raise RuntimeError(f"alembic.ini not found at {_alembic_ini}")

    alembic_cfg = Config(str(_alembic_ini))

    # Resolve script_location relative to the alembic.ini directory
    # (Alembic doesn't do this automatically when run programmatically)
    ini_dir = _alembic_ini.parent
    current_script = alembic_cfg.get_main_option("script_location")
    if current_script and not Path(current_script).is_absolute():
        alembic_cfg.set_main_option("script_location", str(ini_dir / current_script))
    print("Running database migrations...")
    command.upgrade(alembic_cfg, "head")
    print("Database migrations complete.")
