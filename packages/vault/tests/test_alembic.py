"""Tests for Alembic migrations against SQLCipher."""

import os
import tempfile
from pathlib import Path

import pytest
import sqlcipher3.dbapi2
from alembic.config import Config
from alembic import command


@pytest.fixture
def db_env(tmp_path, monkeypatch):
    """Create a temporary database path and key for testing."""
    db_path = str(tmp_path / "test.db")
    db_key = "test_key_123"
    monkeypatch.setenv("VENYA_DB_PATH", db_path)
    monkeypatch.setenv("VENYA_DB_KEY", db_key)
    return {"db_path": db_path, "db_key": db_key}


def _get_alembic_cfg():
    """Get an Alembic Config pointing to the vault's alembic.ini."""
    pkg_root = Path(__file__).resolve().parent.parent
    alembic_ini = pkg_root / "alembic.ini"
    cfg = Config(str(alembic_ini))
    ini_dir = alembic_ini.parent
    current_script = cfg.get_main_option("script_location")
    if current_script and not Path(current_script).is_absolute():
        cfg.set_main_option("script_location", str(ini_dir / current_script))
    return cfg


def _get_tables(db_path: str, db_key: str) -> list[str]:
    """Query the database for table names."""
    conn = sqlcipher3.dbapi2.connect(db_path)
    cur = conn.cursor()
    cur.execute(f"PRAGMA key = '{db_key}'")
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r[0] for r in cur.fetchall()]
    conn.close()
    return tables


EXPECTED_TABLES = [
    "audit_events",
    "command_policies",
    "elevation_tokens",
    "enrollment_tokens",
    "executor_cert_revocations",
    "executor_certs",
    "key_rotation_jobs",
    "key_rotation_secrets",
    "key_versions",
    "rate_limit_failures",
    "role_members",
    "roles",
    "secret_roles",
    "secrets",
    "sessions",
    "users",
    "webauthn_credentials",
]


class TestUpgrade:
    """Test that upgrade creates all tables."""

    def test_upgrade_creates_all_tables(self, db_env):
        cfg = _get_alembic_cfg()
        command.upgrade(cfg, "head")

        tables = _get_tables(db_env["db_path"], db_env["db_key"])
        app_tables = [t for t in tables if t != "alembic_version"]

        assert len(app_tables) == len(EXPECTED_TABLES)
        for table in EXPECTED_TABLES:
            assert table in app_tables, f"Missing table: {table}"

    def test_upgrade_sets_alembic_version(self, db_env):
        cfg = _get_alembic_cfg()
        command.upgrade(cfg, "head")

        tables = _get_tables(db_env["db_path"], db_env["db_key"])
        assert "alembic_version" in tables

    def test_upgrade_creates_encrypted_database(self, db_env):
        cfg = _get_alembic_cfg()
        command.upgrade(cfg, "head")

        # Verify file is encrypted (not plaintext SQLite)
        with open(db_env["db_path"], "rb") as f:
            header = f.read(16)
        assert header != b"SQLite format 3\x00", "Database file is not encrypted"

    def test_wrong_key_rejected(self, db_env):
        cfg = _get_alembic_cfg()
        command.upgrade(cfg, "head")

        conn = sqlcipher3.dbapi2.connect(db_env["db_path"])
        cur = conn.cursor()
        cur.execute("PRAGMA key = 'wrong_key'")
        with pytest.raises(sqlcipher3.dbapi2.DatabaseError):
            cur.execute("SELECT name FROM sqlite_master")
        conn.close()


class TestDowngrade:
    """Test that downgrade drops all tables."""

    def test_downgrade_drops_all_tables(self, db_env):
        cfg = _get_alembic_cfg()
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")

        tables = _get_tables(db_env["db_path"], db_env["db_key"])
        app_tables = [t for t in tables if t != "alembic_version"]

        assert len(app_tables) == 0, f"Tables remain after downgrade: {app_tables}"


class TestIdempotency:
    """Test that running upgrade twice is a no-op."""

    def test_upgrade_twice_succeeds(self, db_env):
        cfg = _get_alembic_cfg()
        command.upgrade(cfg, "head")
        # Second upgrade should succeed without error
        command.upgrade(cfg, "head")

        tables = _get_tables(db_env["db_path"], db_env["db_key"])
        app_tables = [t for t in tables if t != "alembic_version"]
        assert len(app_tables) == len(EXPECTED_TABLES)


class TestWALMode:
    """Test that WAL journal mode is active."""

    def test_wal_mode_active(self, db_env):
        cfg = _get_alembic_cfg()
        command.upgrade(cfg, "head")

        conn = sqlcipher3.dbapi2.connect(db_env["db_path"])
        cur = conn.cursor()
        cur.execute(f"PRAGMA key = '{db_env['db_key']}'")
        cur.execute("PRAGMA journal_mode")
        mode = cur.fetchone()[0]
        conn.close()

        assert mode == "wal", f"Expected wal, got {mode}"
