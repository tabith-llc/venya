# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#597 AC7 — an EXISTING install converges: the orphan on-disk relay cert is adopted by the boot ingest.

The class this file exists to prove was named by the leg-264 census (`flash3-597-ac7-264-report.md`):
the shipped cells for the registry either MOCK the DB answer (`one_or_none` returns what the mock was
told) or BUILD the 040 schema directly, and NO cell constructs AC7's actual case — a store that arrived
at migration 040 by RUNNING the migration, a relay client certificate that already exists on disk, and
the boot ingest run over both. AC7's words: "a fresh install AND an existing install must both
converge"; the mechanism is `server/relay_registry.py:ingest_relay_credential`, called unconditionally
from the `app.py` lifespan on EVERY start, and migration 040 is pure DDL (proven by offline render,
same leg). This file drives that chain against a real store, zero mocks in the write path.

Paired negatives, per the house truth-table law (every claim above has the case that must NOT happen):
  - a second boot adds no row and re-stamps nothing (idempotence, not duplicate-or-re-issue);
  - the tolerant serial clause adopts an odd-spelled EXISTING row (no second row) and never adopts a
    DIFFERENT serial into the same row — both directions, or the clause is unproven;
  - a revoked row STAYS revoked after a boot ingest (a restart must not un-revoke — the load-bearing
    security negative);
  - no cert on disk → no row created and NO raise (an upgraded box with no relay material must boot).

No product source is edited by or required by this file; no CA key material, no guest, no fleet act.
Certificate generation is in-process (cryptography) into a temp dir — the same shape the shipped
`test_core_relay_registry_597.py` fixtures use, rebuilt here rather than imported, because this file
must stand alone on the merge table.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from core.utils.cert_serial import canonical_serial, serial_match_key

RELAY_SERIAL = 0xC0FFEE2468ACE
RELAY_CN = "testcore-relay"


def _make_relay_cert_pem(serial: int = RELAY_SERIAL, cn: str = RELAY_CN) -> str:
    """A real CA-signed relay leaf (CN=<host>-relay, clientAuth), same installer shape."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    _ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(0xCAFE)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return leaf.public_bytes(serialization.Encoding.PEM).decode()


def _cert_file(pem: str) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "relay-client.crt"
    p.write_text(pem)
    return p


def _fk_engine():
    """sqlite engine with declared constraints ENFORCED (PRAGMA ON, proven live by each caller)."""
    from sqlalchemy import create_engine, event

    eng = create_engine("sqlite:///:memory:")

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    return eng


def _store_at_migration_040(engine):
    """Build the store by RUNNING the real 040 migration — the upgraded-install face, not a mock.

    Same executed mechanism as the shipped reversibility cell in
    `test_core_relay_registry_597.py` (`m.op = Operations(MigrationContext.configure(conn));
    m.upgrade()`), reproduced here so this file stands alone; the connection's pragma is asserted
    live, not assumed, per that file's own lesson about green-by-accident engines.
    """
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    src = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "core"
        / "alembic"
        / "versions"
        / ("040_core_relay_credential_registry.py")
    )
    assert src.exists(), f"migration file moved: {src}"
    spec = importlib.util.spec_from_file_location("m040_ac7", str(src))
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    conn = engine.connect()
    assert int(conn.exec_driver_sql("PRAGMA foreign_keys").scalar()) == 1, "connect-listener did not fire"
    m.op = Operations(MigrationContext.configure(conn))
    m.upgrade()
    conn.commit()
    return conn


class _Backend:
    """Minimal real backend: a session factory bound to the migrated engine. No MagicMock in the write path."""

    def __init__(self, engine) -> None:
        from sqlalchemy.orm import sessionmaker

        self._sm = sessionmaker(bind=engine)

    def get_session(self):
        return self._sm()


def _config_for(cert_path: Path | None) -> SimpleNamespace:
    return SimpleNamespace(mtls_cert=str(cert_path) if cert_path else None, mtls=None)


def _rows(conn):
    return conn.exec_driver_sql(
        "SELECT serial_number, registered_at, revoked_at FROM core_relay_credentials"
    ).fetchall()


class TestAC7AdoptionOnUpgradedInstall:
    def test_orphan_cert_on_disk_is_adopted_by_the_boot_ingest(self) -> None:
        """THE AC7 POSITIVE. Migration-built store + on-disk cert + boot ingest ⇒ exactly one row,
        and its serial EQUALS the serial openssl itself reports for that file — AC7's actual claim."""
        from server.relay_registry import ingest_relay_credential

        cert = _cert_file(_make_relay_cert_pem())
        engine = _fk_engine()
        conn = _store_at_migration_040(engine)
        assert len(_rows(conn)) == 0, "store must start empty — that is the existing-install face"

        facts = ingest_relay_credential(_config_for(cert), _Backend(engine))

        assert facts is not None, "boot found nothing to register — the adoption the invariant promises"
        rows = _rows(conn)
        assert len(rows) == 1, f"expected exactly one adopted row, got {len(rows)}"
        stored = rows[0][0]
        assert stored == canonical_serial(
            RELAY_SERIAL
        ), f"stored serial {stored!r} is not the canonical write form of {RELAY_SERIAL:#x}"
        # Independent instrument: ask OpenSSL, not my own parser, what the file's serial is.
        out = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-serial", "-noout"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        openssl_hex = out.split("=", 1)[1]
        assert serial_match_key(stored) == serial_match_key(
            openssl_hex
        ), f"registry serial {stored!r} does not match what openssl reports ({openssl_hex!r}) for the SAME file"
        engine.dispose()

    def test_second_boot_is_idempotent_not_a_re_issue(self) -> None:
        """NEGATIVE 1. A second ingest over the same disk state: no new row, and the first row's
        registered_at is UNTOUCHED — an adopt that re-stamps would masquerade as a re-issue."""
        from server.relay_registry import ingest_relay_credential

        cert = _cert_file(_make_relay_cert_pem())
        engine = _fk_engine()
        conn = _store_at_migration_040(engine)

        assert ingest_relay_credential(_config_for(cert), _Backend(engine)) is not None
        first = _rows(conn)
        assert len(first) == 1
        assert ingest_relay_credential(_config_for(cert), _Backend(engine)) is not None
        second = _rows(conn)

        assert len(second) == 1, f"second boot grew the registry to {len(second)} rows — duplicate adoption"
        assert second[0][1] == first[0][1], "registered_at moved: a boot re-issued a row it should have left alone"
        assert second[0][0] == first[0][0]
        engine.dispose()

    def test_tolerant_clause_adopts_odd_spelling_and_refuses_to_collapse_a_different_serial(self) -> None:
        """NEGATIVE 2, both directions. A row stored in an odd spelling (upper + leading zeros —
        exactly the #481 class) must be MATCHED by a canonical boot (no second row), while a
        different serial must NOT be swallowed by the same tolerant clause (its own row appears,
        the pre-existing one is untouched)."""
        from server.relay_registry import ingest_relay_credential

        engine = _fk_engine()
        conn = _store_at_migration_040(engine)
        odd = format(RELAY_SERIAL, "020X")  # zero-padded UPPERCASE spelling of the SAME serial
        conn.exec_driver_sql(
            "INSERT INTO core_relay_credentials (serial_number, common_name, registered_at) VALUES (?, ?, ?)",
            (odd, RELAY_CN, dt.datetime.now(dt.UTC).isoformat()),
        )
        conn.commit()

        assert ingest_relay_credential(_config_for(_cert_file(_make_relay_cert_pem())), _Backend(engine)) is not None
        rows = _rows(conn)
        assert len(rows) == 1, f"odd-spelled existing row was not matched — boot created a duplicate: {rows}"
        assert rows[0][0] == odd, "the matched row's stored value was rewritten — present must mean present"

        # Other direction: a DIFFERENT serial must not be swallowed into the odd row.
        other_serial = 0x1122334455667788
        assert (
            ingest_relay_credential(
                _config_for(_cert_file(_make_relay_cert_pem(serial=other_serial, cn="othercore-relay"))),
                _Backend(engine),
            )
            is not None
        )
        rows = _rows(conn)
        assert len(rows) == 2, "a different serial was silently adopted INTO the existing row"
        assert {r[0] for r in rows} == {odd, canonical_serial(other_serial)}
        assert rows[0][0] == odd or rows[1][0] == odd, "the pre-existing odd row vanished or moved"
        engine.dispose()

    def test_revoked_row_stays_revoked_after_a_boot(self) -> None:
        """NEGATIVE 3 — THE SECURITY HALF. A credential revoked in the store and still present on
        disk must come back from the boot ingest with revoked_at EXACTLY as it was: adoption is a
        registration fact, never a re-activation. If a future change makes adopt == re-issue, this
        is the cell that reddens."""
        from server.relay_registry import ingest_relay_credential

        cert = _cert_file(_make_relay_cert_pem())
        engine = _fk_engine()
        conn = _store_at_migration_040(engine)

        assert ingest_relay_credential(_config_for(cert), _Backend(engine)) is not None
        revoked_at = dt.datetime.now(dt.UTC).isoformat()
        conn.exec_driver_sql(
            "UPDATE core_relay_credentials SET revoked_at = ?, revoke_reason = 'ac7-negative' "
            "WHERE serial_number = ?",
            (revoked_at, canonical_serial(RELAY_SERIAL)),
        )
        conn.commit()

        assert ingest_relay_credential(_config_for(cert), _Backend(engine)) is not None
        rows = _rows(conn)
        assert len(rows) == 1
        assert rows[0][2] is not None and str(rows[0][2]).startswith(
            revoked_at[:19]
        ), f"boot CLEARED the revocation (revoked_at={rows[0][2]!r}) — a restart must never un-revoke"
        engine.dispose()

    def test_no_cert_on_disk_creates_no_row_and_does_not_raise(self) -> None:
        """NEGATIVE 4. Upgraded box, no relay material at the resolved path: ingest returns None,
        the lifespan contract is 'warn, do not abort', and the table stays empty. A raise here
        would take a working core down for a bookkeeping gap."""
        from server.relay_registry import DEFAULT_RELAY_CERT_PATH, ingest_relay_credential

        if Path(DEFAULT_RELAY_CERT_PATH).exists():
            pytest.skip(f"{DEFAULT_RELAY_CERT_PATH} exists on this host — the no-cert shape cannot be constructed here")

        engine = _fk_engine()
        conn = _store_at_migration_040(engine)
        missing = Path(tempfile.mkdtemp()) / "absent-relay-client.crt"

        facts = ingest_relay_credential(_config_for(missing), _Backend(engine))

        assert facts is None
        assert len(_rows(conn)) == 0, "no cert on disk, yet the boot created a row"
        engine.dispose()
