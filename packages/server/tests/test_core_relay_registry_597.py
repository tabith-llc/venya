# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#597 — the core relay credential registry: model, migration, boot ingest, revoke verb.

The class this file exists to prove. Before #597 the credential the core presents when
it dials an executor's :8443 relay listener was minted by `install-venya-core.sh` with
`openssl` and entered no table, so it had no revocation path and the CRL the same CA
mints (`server/ca.py:generate_crl`, population `ExecutorCertRevocation`) could never
name it. Measured at s134 (`flash5-586-listener-door-s134-report.md`, CASE 2): a
`VERIFY_CRL_CHECK_LEAF` on the listener door ADMITS that peer, because the list has no
row for it. Population, not flag.

Two claims, each with its paired negative (the repo's truth-table law — a gate that
only passes the positive case is untested):

  A. THE STORE. A relay credential on disk becomes a registry row at core boot,
     idempotently, and a boot never un-revokes.
  B. THE VERB. Revoke acts on a registered serial and REFUSES an unregistered one
     (`REFUSE_UNREGISTERED`, default deny — issue 263's fail-open lesson).

Nothing here touches a guest or a fleet VM; the physical half is the named residual in
the leg report.
"""

from __future__ import annotations

import datetime as dt
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from core.utils.cert_serial import canonical_serial, serial_match_key
from fastapi import FastAPI
from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# fixtures: a real CA-signed relay credential, parsed not mocked
# ---------------------------------------------------------------------------

RELAY_SERIAL = 0xDEADBEEF1234


def _make_relay_cert_pem(serial: int = RELAY_SERIAL, cn: str = "core-1-relay") -> tuple[str, str]:
    """A real CA -> real leaf chain, same shape as the installer's (CN=<host>-relay, EKU clientAuth)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"), x509.NameAttribute(NameOID.COMMON_NAME, cn)]
            )
        )
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    return pem, ca_pem


@pytest.fixture(scope="module")
def relay_pem() -> str:
    return _make_relay_cert_pem()[0]


@pytest.fixture
def relay_cert_file(relay_pem: str) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "relay-client.crt"
    p.write_text(relay_pem)
    return p


# ---------------------------------------------------------------------------
# A. THE STORE — reading facts off the credential, and the invariant
# ---------------------------------------------------------------------------


class TestReadRelayCredentialFacts:
    """`read_relay_credential` — every registry field is READ from the certificate."""

    def test_serial_is_the_canonical_write_form_not_the_compare_key(self, relay_cert_file: Path) -> None:
        from server.relay_registry import read_relay_credential

        facts = read_relay_credential(relay_cert_file)
        # #481 law: a ROW stores canonical_serial (lowercase, padded >=16). Storing
        # serial_match_key here would put this table in the other module's vocabulary
        # and every padded/unpadded reader would have to know which one it got.
        assert facts.serial_number == canonical_serial(RELAY_SERIAL)
        assert facts.serial_number == facts.serial_number.lower()
        assert len(facts.serial_number) >= 16
        # and the compare key still identifies it, so lookups match any spelling (#481)
        assert serial_match_key(facts.serial_number) == serial_match_key(RELAY_SERIAL)

    def test_common_name_and_derived_hostname_match_the_installer_shape(self, relay_cert_file: Path) -> None:
        from server.relay_registry import read_relay_credential

        facts = read_relay_credential(relay_cert_file)
        assert facts.common_name == "core-1-relay"
        # install-venya-core.sh:1013 mints CN=${CORE_HOSTNAME}-relay
        assert facts.hostname == "core-1"

    def test_timestamps_are_offset_aware(self, relay_cert_file: Path) -> None:
        """Repo datetime law: no naive datetimes anywhere; a naive row breaks aware compares."""
        from server.relay_registry import read_relay_credential

        facts = read_relay_credential(relay_cert_file)
        assert facts.issued_at is not None and facts.issued_at.tzinfo is not None
        assert facts.not_after is not None and facts.not_after.tzinfo is not None
        assert facts.not_after > facts.issued_at

    def test_fingerprint_and_public_key_hash_are_distinct_and_stable(
        self, relay_cert_file: Path, relay_pem: str
    ) -> None:
        from server.relay_registry import read_relay_credential

        a = read_relay_credential(relay_cert_file)
        b = read_relay_credential(relay_cert_file)
        assert a.cert_fingerprint == b.cert_fingerprint, "same file must key the same"
        assert a.public_key_hash == b.public_key_hash
        assert a.cert_fingerprint != a.public_key_hash, (
            "fingerprint is of the CERTIFICATE, public_key_hash is of the SPKI — one value for both would "
            "silently merge 'this credential' and 'this key', which are different questions after a re-mint"
        )
        assert len(a.cert_fingerprint) == 64 and len(a.public_key_hash) == 64

    def test_signing_ca_is_recorded_from_the_aki_and_issuer(self, relay_cert_file: Path) -> None:
        from server.relay_registry import read_relay_credential

        facts = read_relay_credential(relay_cert_file)
        assert facts.signing_ca_subject == "Venya Test CA"
        assert facts.signing_ca_aki and len(facts.signing_ca_aki) >= 16

    # --- paired negatives: the refuse half ---

    def test_unparseable_bytes_are_refused_not_registered_as_empty(self, tmp_path: Path) -> None:
        from server.relay_registry import read_relay_credential

        junk = tmp_path / "relay-client.crt"
        junk.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n")
        with pytest.raises(ValueError, match="not a parseable certificate"):
            read_relay_credential(junk)

    def test_certificate_without_a_common_name_is_refused(self, tmp_path: Path) -> None:
        """A nameless credential cannot be registered — the CN is the join to relay_client_ids."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from server.relay_registry import read_relay_credential

        now = dt.datetime.now(dt.UTC)
        k = ec.generate_private_key(ec.SECP256R1())
        nameless = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NoCN")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Venya Test CA")]))
            .public_key(k.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1))
            .sign(k, hashes.SHA256())
        )
        p = tmp_path / "nameless.crt"
        p.write_bytes(nameless.public_bytes(serialization.Encoding.PEM))
        with pytest.raises(ValueError, match="no CommonName"):
            read_relay_credential(p)

    def test_missing_file_raises_oserror_not_silence(self, tmp_path: Path) -> None:
        from server.relay_registry import read_relay_credential

        with pytest.raises(OSError):
            read_relay_credential(tmp_path / "does-not-exist.crt")


class TestRegisterIsAnIdempotentUpsert:
    """`register_relay_credential` — a boot cannot duplicate a row or clear a revocation."""

    @staticmethod
    def _session():
        s = MagicMock()
        s.query.return_value.filter.return_value.one_or_none.return_value = None
        return s

    def test_first_boot_creates_the_row(self, relay_cert_file: Path) -> None:
        from server.relay_registry import read_relay_credential, register_relay_credential

        s = self._session()
        facts = read_relay_credential(relay_cert_file)
        assert register_relay_credential(s, facts) == "created"
        s.add.assert_called_once()
        s.commit.assert_called_once()

    def test_second_boot_adds_nothing_and_commits_nothing(self, relay_cert_file: Path) -> None:
        from server.relay_registry import read_relay_credential, register_relay_credential

        s = MagicMock()
        existing = SimpleNamespace(serial_number="x", revoked_at=None)
        s.query.return_value.filter.return_value.one_or_none.return_value = existing
        facts = read_relay_credential(relay_cert_file)
        assert register_relay_credential(s, facts) == "present"
        s.add.assert_not_called()
        s.commit.assert_not_called(), "an idempotent boot must not write"

    def test_revoked_row_survives_a_reboot_untouched(self, relay_cert_file: Path) -> None:
        """THE LOAD-BEARING NEGATIVE. A core must not be able to un-revoke itself by restarting.

        Asserted against the real column, not a flag: the update path that would clear
        revoked_at is the one this test forbids to exist.
        """
        from server.relay_registry import read_relay_credential, register_relay_credential

        s = MagicMock()
        revoked = SimpleNamespace(serial_number="x", revoked_at=dt.datetime.now(dt.UTC), revoke_reason="compromised")
        s.query.return_value.filter.return_value.one_or_none.return_value = revoked
        facts = read_relay_credential(relay_cert_file)

        outcome = register_relay_credential(s, facts)

        assert outcome == "present"
        assert revoked.revoked_at is not None, "boot cleared a revocation"
        assert revoked.revoke_reason == "compromised"
        # and nothing was written at all, so there is no "clears it later" path either
        s.add.assert_not_called()
        s.commit.assert_not_called()
        s.query.return_value.filter.return_value.one_or_none.assert_called_once()

    def test_lookup_uses_the_tolerant_match_clause_not_string_equality(self) -> None:
        """#481: equality on a serial column is how a revocation recorded green and did nothing.

        Read off the shipped source of the two places that look a relay serial up. A
        mock-driven behavioral version of this assertion cannot distinguish the clause
        from `==` without reimplementing SQLAlchemy, so the honest instrument here is
        the source shape — labelled as the source-shape check it is.
        """
        import inspect
        import re

        from server import relay_registry
        from server.routes import core_relay_certs

        sites = {
            "boot ingest": inspect.getsource(relay_registry.register_relay_credential),
            "revoke verb": inspect.getsource(core_relay_certs.admin_revoke_core_relay_cert),
        }
        for where, body in sites.items():
            assert "serial_match_clause" in body, f"{where} looks a serial up without the tolerant clause"
            # and no bare `Column.serial_number == ` compare survived beside it
            bare = re.search(r"CoreRelayCredential\.serial_number\s*==", body)
            assert bare is None, f"{where} still compares a serial by string equality: {bare.group(0) if bare else ''}"

    def test_tolerant_clause_is_the_one_the_project_standardized_on(self) -> None:
        """Positive control on the helper itself: prove the search can return a hit."""
        from core.utils.cert_serial import serial_match_clause
        from sqlalchemy import Column, String
        from sqlalchemy.sql.elements import BinaryExpression, BindParameter

        cl = serial_match_clause(Column("serial_number", String), f"{RELAY_SERIAL:016x}")
        assert isinstance(cl, BinaryExpression)
        assert "ltrim" in str(cl) and "upper" in str(cl), str(cl)
        assert isinstance(cl.right, BindParameter) and cl.right.effective_value == serial_match_key(
            RELAY_SERIAL
        ), "the helper's bound value is the uppercase compare key; the test double must read it the same way"


class TestBootIngestWiring:
    """The ingest runs at core startup, after the DB exists, and never kills a boot."""

    def test_lifespan_calls_the_ingest_after_the_database_is_up(self) -> None:
        """Wiring pin, labelled as the source-shape check it is.

        A correct, tested function nobody calls is a dead path — this repo's own
        `ctx is not defined` history is the evidence, and #597's invariant is worthless
        if the row is never written.
        """
        import inspect

        from server import app as app_module

        body = inspect.getsource(app_module.lifespan)
        assert "ingest_relay_credential" in body, "lifespan never registers the relay credential"
        assert body.index("init_db(") < body.index(
            "ingest_relay_credential"
        ), "the registry write must come AFTER the DB is initialized, or it writes to nothing"

    def test_ingest_failure_does_not_abort_the_boot(self, monkeypatch, relay_cert_file: Path) -> None:
        """A lost revocation path is a warning, not a dead core. The relay material itself
        is hard-validated earlier in startup, so this is not the same condition twice."""
        from server import relay_registry

        monkeypatch.setattr(
            relay_registry,
            "read_relay_credential",
            MagicMock(side_effect=ValueError("unreadable")),
        )
        cfg = SimpleNamespace(mtls_cert=str(relay_cert_file), mtls=None)
        # must not raise
        assert relay_registry.ingest_relay_credential(cfg, MagicMock()) is None

    def test_missing_credential_logs_the_unrevocable_state_loudly(self, caplog, tmp_path) -> None:
        import logging

        from server import relay_registry

        cfg = SimpleNamespace(mtls_cert=str(tmp_path / "absent.crt"), mtls=None)
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            assert relay_registry.ingest_relay_credential(cfg, MagicMock()) is None
        text = " ".join(r.getMessage() for r in caplog.records)
        assert "unrevocable" in text or "NOT updated" in text, f"a skipped registration must say so: {text!r}"

    def test_ingest_registers_the_real_file_end_to_end(self, relay_cert_file: Path) -> None:
        """The boot path over a real certificate, not a mock — facts + a create call."""
        from server import relay_registry

        captured: list = []

        def fake_register(session, facts):
            captured.append(facts)
            return "created"

        backend = MagicMock()
        backend.get_session.return_value = MagicMock()
        with patch.object(relay_registry, "register_relay_credential", fake_register):
            facts = relay_registry.ingest_relay_credential(
                SimpleNamespace(mtls_cert=str(relay_cert_file), mtls=None), backend
            )
        assert facts is not None and captured, "boot found nothing to register"
        assert captured[0].common_name == "core-1-relay"
        assert captured[0].serial_number == canonical_serial(RELAY_SERIAL)


# ---------------------------------------------------------------------------
# B. THE VERB — default deny is the control
# ---------------------------------------------------------------------------


def _verb_client(rows, audit_sink=None):
    """App with ONLY the #597 router mounted, auth overridden — the test_admin.py shape.

    `rows` is the registry population the verb sees. Built as a real query chain over a
    list so the route's filter is exercised, not stubbed at its return value.
    """
    from server.dependencies import get_current_user, get_db, require_admin
    from server.routes import core_relay_certs as m

    app = FastAPI()
    app.include_router(m.router, prefix="/api/v1")

    class FakeQuery:
        def __init__(self, data):
            self._data = list(data)

        def filter(self, clause):
            # The route must call serial_match_clause (proved by the rendered form in
            # test_lookup_uses_the_tolerant_match_clause...). Its right side is a
            # BindParameter carrying the UPPERCASE match key, so the fake resolves that
            # value and compares keys — never a plain string equality on the column.
            from core.utils.cert_serial import serial_match_key as _k
            from sqlalchemy.sql.elements import BindParameter

            right = getattr(clause, "right", None)
            val = None
            if isinstance(right, BindParameter):
                val = right.effective_value
            elif right is not None:
                val = getattr(right, "value", right)
            self._data = [] if val is None else [r for r in self._data if _k(r.serial_number) == _k(val)]
            return self

        def first(self):
            return self._data[0] if self._data else None

        def one_or_none(self):
            return self._data[0] if len(self._data) == 1 else None

        def order_by(self, *a, **k):
            return self

        def all(self):
            return list(self._data)

    db = MagicMock()
    db.query.side_effect = lambda model: FakeQuery(rows if model.__name__ == "CoreRelayCredential" else [])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_admin] = lambda: {"user_id": "test-admin"}
    app.dependency_overrides[get_current_user] = lambda: {"user_id": "test-admin"}
    return TestClient(app, raise_server_exceptions=False), db


def _row(**over):
    from core.iam.models import CoreRelayCredential

    r = CoreRelayCredential(
        serial_number=over.get("serial_number", canonical_serial(RELAY_SERIAL)),
        common_name=over.get("common_name", "core-1-relay"),
        hostname="core-1",
        cert_fingerprint="f" * 64,
        public_key_hash="p" * 64,
        signing_ca_subject="Venya Test CA",
        issued_at=dt.datetime.now(dt.UTC),
        not_after=dt.datetime.now(dt.UTC) + dt.timedelta(days=365),
        revoked_at=over.get("revoked_at"),
        revoke_reason=over.get("revoke_reason"),
    )
    return r


class TestRevokeVerbDefaultDeny:
    """The whole point of the row: an unregistered serial is REFUSED, never waved past."""

    def test_unregistered_serial_is_refused_with_the_named_reason(self) -> None:
        client, db = _verb_client(rows=[])
        resp = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": "aabbccdd", "reason": "lost"})

        assert (
            resp.status_code == 403
        ), f"unregistered revoke must be refused, got {resp.status_code}: {resp.text[:200]}"
        detail = resp.json()["detail"]
        from server.routes.core_relay_certs import REFUSE_UNREGISTERED

        assert REFUSE_UNREGISTERED in detail, detail
        # no row was written: the refusal must not leave a half-revocation behind
        db.add.assert_not_called()
        db.commit.assert_not_called()

    def test_empty_store_refuses_every_serial_it_is_handed(self) -> None:
        """The 263 lesson, asserted as a loop: an empty store is NOT an allowlist."""
        client, _db = _verb_client(rows=[])
        for serial in (
            "0",
            "0000000000000001",
            f"{RELAY_SERIAL:x}",
            f"{RELAY_SERIAL:X}",
            f"{RELAY_SERIAL:016x}",
        ):
            resp = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": serial})
            assert resp.status_code == 403, f"serial {serial} was allowed past an EMPTY registry"

    def test_refusal_names_the_remedy_not_just_the_denial(self) -> None:
        """ "403 and go away" is not an operator answer. The remedy is restart-or-register."""
        client, _ = _verb_client(rows=[])
        detail = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": "abcd"}).json()["detail"]
        assert "restart" in detail.lower() or "register" in detail.lower(), detail

    def test_registered_live_serial_is_revoked(self) -> None:
        row = _row(revoked_at=None)
        client, db = _verb_client(rows=[row])
        resp = client.post(
            "/api/v1/admin/core-relay-certs/revoke",
            json={"serial": canonical_serial(RELAY_SERIAL), "reason": "host decommissioned"},
        )
        assert resp.status_code == 200, resp.text[:300]
        body = resp.json()
        assert body["revoked"] is True
        assert body["already_revoked"] is False
        assert body["common_name"] == "core-1-relay"
        assert row.revoked_at is not None, "the verb returned success without stamping the row"
        assert row.revoke_reason == "host decommissioned"
        db.commit.assert_called()

    def test_revoked_serial_pads_and_cases_any_way_the_operator_typed_it(self) -> None:
        """#481 again: the SAME credential must be revocable whichever spelling is pasted."""
        for spelling in (
            f"{RELAY_SERIAL:x}",
            f"{RELAY_SERIAL:X}",
            f"{RELAY_SERIAL:016x}",
            f"0x{RELAY_SERIAL:x}",
            f"  {RELAY_SERIAL:X}  ",
        ):
            row = _row(revoked_at=None)
            client, _db = _verb_client(rows=[row])
            resp = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": spelling})
            assert resp.status_code == 200, f"{spelling!r} refused against a row that names it: {resp.text[:160]}"
            assert row.revoked_at is not None, f"{spelling!r} said revoked and did not stamp"

    def test_repeat_revoke_is_idempotent_and_records_the_no_op(self) -> None:
        when = dt.datetime.now(dt.UTC) - dt.timedelta(days=2)
        row = _row(revoked_at=when, revoke_reason="first")
        client, _db = _verb_client(rows=[row])
        resp = client.post(
            "/api/v1/admin/core-relay-certs/revoke", json={"serial": f"{RELAY_SERIAL:x}", "reason": "again"}
        )

        assert resp.status_code == 200
        assert resp.json()["already_revoked"] is True
        assert row.revoked_at == when, "a repeat revoke moved the original revocation time"
        assert row.revoke_reason == "first", "a repeat revoke overwrote the recorded reason"

    def test_twenty_byte_mint_class_round_trips_and_normalizes(self) -> None:
        """AC5 of #682 — a cell at the WIDTH THE CA ACTUALLY MINTS, not a short fixture.

        `server.ca` mints `int.from_bytes(os.urandom(20), "big") >> 1`: 159 bits, which renders as
        37-40 hex characters, and the odds of such a serial fitting in 16 hex are about 2^-95. The
        reason the old cap went unnoticed is that this file's `RELAY_SERIAL = 0xDEADBEEF1234` is an
        8-byte-class value, so every pre-existing cell exercised the one width the gate could satisfy.
        This cell mints at the real class and drives parse -> registry row -> `revoke` of the string
        `list` prints, carrying AC4's normalization arm on the same value: mixed case, an `0x` prefix
        and extra padding are all the SAME serial to the store, because one canonical form is taken at
        the write boundary (#481).
        """
        serial_int = int.from_bytes(os.urandom(20), "big") >> 1
        pem, _key = _make_relay_cert_pem(serial=serial_int)
        minted = canonical_serial(f"{serial_int:x}")
        assert 37 <= len(minted) <= 40, f"the mint class is 159 bits; got a {len(minted)}-hex serial"

        with tempfile.TemporaryDirectory() as td:
            cert = Path(td) / "relay-client.crt"
            cert.write_text(pem)
            from server.relay_registry import read_relay_credential

            facts = read_relay_credential(cert)
        assert facts.serial_number == minted, "the registry read lost digits of a 20-byte serial"

        for spelling in (minted, minted.upper(), f"0x{minted}", "0" * 8 + minted):
            client, _db = _verb_client(rows=[_row(serial_number=minted, revoked_at=None)])
            resp = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": spelling, "reason": "682-ac5"})
            assert resp.status_code == 200, f"{spelling[:24]!r} -> {resp.status_code}: {resp.text[:160]}"
            assert resp.json()["serial_number"] == minted, f"{spelling[:24]!r} canonicalized to the wrong serial"

    def test_serials_at_the_raised_cap_are_accepted_not_refused(self) -> None:
        """AC4 positive half: 17..64 hex are ordinary, and each needs its OWN registered row.

        The verb is default-deny, so a 403 here would be correct behaviour for an unknown serial and
        would prove nothing about the gate; a 200 proves the format gate let the request reach the
        lookup that then matched. `"0" * 17` is the shape this file's own negative cell used to reject.
        """
        for good in (
            "5803696f1234567890abcdef1234567890f69d0b",  # pragma: allowlist secret
            "0" * 17,
            "a" * 40,
            "f" * 64,
        ):
            client, _db = _verb_client(rows=[_row(serial_number=canonical_serial(good), revoked_at=None)])
            resp = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": good, "reason": "test"})
            assert resp.status_code == 200, f"{good!r} ({len(good)} chars) -> {resp.status_code}: {resp.text[:160]}"

    def test_malformed_serial_is_a_400_before_any_lookup(self) -> None:
        """The negative half of the #682 truth table, re-paired for the raised cap.

        `"0" * 17` sat here because 17 chars used to be over the cap. It is NOT over the 64-char
        ceiling now, so leaving it would assert a refusal the product no longer makes; it moves to 65
        (one past the store width) and the 17-char shape has its positive cell above. Empty,
        whitespace and non-hex are refused for the reason they always were: they are not hex serials.
        """
        client, db = _verb_client(rows=[_row(revoked_at=None)])
        for bad in ("", "   ", "nothex", "zz", "0" * 65, "a" * 65):
            resp = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": bad})
            assert resp.status_code == 400, f"{bad!r} -> {resp.status_code}"
            assert "64" in resp.json()["detail"], f"{bad!r} refused with the old cap in its message"
        db.query.assert_not_called(), "a 400 must be decided before the store is consulted"

    def test_unexpected_body_field_is_refused_not_ignored(self) -> None:
        """extra=forbid (#357): a typo'd flag on a security verb must not be silently dropped."""
        client, _ = _verb_client(rows=[_row(revoked_at=None)])
        resp = client.post(
            "/api/v1/admin/core-relay-certs/revoke",
            json={"serial": f"{RELAY_SERIAL:x}", "reason": "x", "revkoe": True},
        )
        assert resp.status_code == 422, resp.text[:200]

    def test_audit_row_names_the_registered_credential_it_revoked(self) -> None:
        row = _row(revoked_at=None)
        client, _db = _verb_client(rows=[row])
        with patch("server.routes.core_relay_certs.audit_lifecycle") as audit:
            resp = client.post(
                "/api/v1/admin/core-relay-certs/revoke", json={"serial": f"{RELAY_SERIAL:x}", "reason": "r"}
            )
        assert resp.status_code == 200
        from server.audit_lifecycle import CORE_RELAY_CERT_REVOKED

        args = audit.call_args.args
        assert args[1] == CORE_RELAY_CERT_REVOKED, f"wrong event name: {args[1]}"
        assert args[2] == "test-admin", "the audit row must name the acting admin"
        fields = args[3]
        assert fields["serial_number"] == canonical_serial(RELAY_SERIAL)
        assert fields["common_name"] == "core-1-relay"

    def test_refused_revoke_writes_no_revocation_audit_row(self) -> None:
        """The negative half of the audit claim: no event for an action that did not happen."""
        client, _db = _verb_client(rows=[])
        with patch("server.routes.core_relay_certs.audit_lifecycle") as audit:
            resp = client.post("/api/v1/admin/core-relay-certs/revoke", json={"serial": f"{RELAY_SERIAL:x}"})
        assert resp.status_code == 403
        audit.assert_not_called()

    def test_admin_auth_dependency_is_on_the_verb(self) -> None:
        """Route-level authz, proven from the app's own dependency map, not from prose."""
        from server.dependencies import require_admin
        from server.routes import core_relay_certs as m

        for route in m.router.routes:
            path = getattr(route, "path", "")
            if "core-relay-certs" not in path:
                continue
            deps = [d.call for d in route.dependant.dependencies]
            assert require_admin in deps, f"{path} is reachable without require_admin"

    def test_read_endpoint_reports_the_empty_store_without_implying_safety(self) -> None:
        client, _ = _verb_client(rows=[])
        resp = client.get("/api/v1/admin/core-relay-certs")
        assert resp.status_code == 200
        assert resp.json() == [], "an empty registry must read as empty, not as a default-allow"


class TestRegisterVerbDerivesFactsFromTheCertificate:
    """The explicit-register path reads the credential; it does not trust a typed serial."""

    def test_register_from_pem_creates_the_row_the_boot_would_have_created(self, relay_pem: str) -> None:
        client, _db = _verb_client(rows=[])
        with patch("server.relay_registry.register_relay_credential") as reg:
            reg.return_value = "created"
            resp = client.post("/api/v1/admin/core-relay-certs", json={"certificate_pem": relay_pem})
        assert resp.status_code == 201, resp.text[:300]
        assert resp.json()["created"] is True
        facts = reg.call_args.args[1]
        assert facts.common_name == "core-1-relay"
        assert facts.serial_number == canonical_serial(RELAY_SERIAL)

    def test_register_with_garbage_is_a_400(self) -> None:
        client, _ = _verb_client(rows=[])
        # long enough to pass the min_length shape gate, so it reaches the PARSER and the
        # parse refusal is what answers — a 422 here would be a schema rejection, not this.
        resp = client.post(
            "/api/v1/admin/core-relay-certs",
            json={"certificate_pem": "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"},
        )
        assert resp.status_code == 400, resp.text[:200]

    def test_register_leaves_no_temp_file_behind(self, relay_pem: str) -> None:
        """The submitted cert is staged on disk to reuse the ONE parser — so the stage is cleaned up."""
        import glob

        before = set(glob.glob("/tmp/venya-relay-cert-*"))
        client, _ = _verb_client(rows=[])
        with patch("server.relay_registry.register_relay_credential", return_value="created"):
            client.post("/api/v1/admin/core-relay-certs", json={"certificate_pem": relay_pem})
        left = set(glob.glob("/tmp/venya-relay-cert-*")) - before
        assert not left, f"register left submitted credential material on disk: {left}"


def _fk_engine(url: str = "sqlite:///:memory:"):
    """An sqlite engine that ENFORCES the constraints its schema declares (#634).

    SQLite leaves ``foreign_keys`` OFF per connection, so a bare engine accepts an orphan child row
    and honours no declared cascade: the DDL is present and never consulted, which makes any
    FK-shaped claim in a test green by accident. The connect-listener is the shape already shipped
    in ``packages/core/tests/test_migration_039_fk_cascade.py`` and ``test_secret_delete_fk.py``.
    """
    from sqlalchemy import create_engine, event

    eng = create_engine(url)

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    return eng


class TestMigrationAndModelAgree:
    """Alembic 040 must build exactly what models.py declares — the repo's model-is-truth law."""

    def test_migration_columns_match_the_model_exactly(self) -> None:
        import importlib.util

        from core.iam.models import CoreRelayCredential

        spec = importlib.util.spec_from_file_location(
            "m040",
            str(Path(core_alembic_dir()) / "040_core_relay_credential_registry.py"),
        )
        assert spec and spec.loader
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)

        src = Path(spec.origin).read_text()
        import re

        mig_cols = re.findall(r'sa\.Column\("(\w+)",\s*sa\.(\w+)', src)
        model_cols = {c.name: c for c in CoreRelayCredential.__table__.columns}
        assert {n for n, _ in mig_cols} == set(model_cols), (
            f"model/migration column drift: only-in-migration={ {n for n,_ in mig_cols} - set(model_cols)} "
            f"only-in-model={set(model_cols) - {n for n,_ in mig_cols}}"
        )

    def test_migration_is_reversible(self) -> None:
        """A fresh install runs `alembic upgrade head`; a rollback must not orphan the table.

        Executed against a real sqlite engine rather than read as text, because a
        downgrade() that references an index the upgrade never made raises at rollback
        time — which is the worst possible moment to learn it.
        """
        import importlib.util

        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        from sqlalchemy import inspect as sqlinspect

        spec = importlib.util.spec_from_file_location(
            "m040r",
            str(Path(core_alembic_dir()) / "040_core_relay_credential_registry.py"),
        )
        assert spec and spec.loader
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)

        engine = _fk_engine()
        conn = engine.connect()
        # The listener must be PROVEN live, not merely present: a connect hook that never fired, or
        # fired on a different connection, leaves every FK-shaped cell below green by accident.
        assert (
            int(conn.exec_driver_sql("PRAGMA foreign_keys").scalar()) == 1
        ), "connect-listener did not fire — foreign_keys is OFF on this connection"
        m.op = Operations(MigrationContext.configure(conn))
        m.upgrade()
        assert "core_relay_credentials" in sqlinspect(conn).get_table_names()
        m.op = Operations(MigrationContext.configure(conn))
        m.downgrade()
        assert "core_relay_credentials" not in sqlinspect(conn).get_table_names(), "downgrade left the table behind"
        conn.close()
        engine.dispose()

    def test_enforcement_arm_actually_rejects_an_orphan_child(self) -> None:
        """#634 — the arm is load-bearing, not decoration: a real orphan row is refused.

        Migration 040 declares zero foreign keys, so a listener attached to an engine that only ever
        runs 040 can never fail — which is exactly the shape this row calls theatre. The proof therefore
        runs against a probe pair on the SAME engine builder: the connection reports the pragma ON, and
        the database itself rejects a child whose parent does not exist.
        """
        from sqlalchemy.exc import IntegrityError

        engine = _fk_engine()
        with engine.connect() as conn:
            assert (
                int(conn.exec_driver_sql("PRAGMA foreign_keys").scalar()) == 1
            ), "connect-listener did not fire — foreign_keys is OFF on this connection"
            conn.exec_driver_sql("CREATE TABLE fk_probe_parent (id INTEGER PRIMARY KEY)")
            conn.exec_driver_sql(
                "CREATE TABLE fk_probe_child ("
                "id INTEGER PRIMARY KEY, "
                "parent_id INTEGER NOT NULL REFERENCES fk_probe_parent (id))"
            )
            conn.exec_driver_sql("INSERT INTO fk_probe_parent (id) VALUES (1)")
            conn.commit()
            with pytest.raises(IntegrityError):
                conn.exec_driver_sql("INSERT INTO fk_probe_child (id, parent_id) VALUES (2, 99)")
        engine.dispose()

    def test_migration_chains_to_the_head_it_was_cut_against(self) -> None:
        import importlib.util
        from pathlib import Path as P

        v = P(core_alembic_dir())
        specs = {}
        for f in sorted(v.glob("*.py")):
            s = importlib.util.spec_from_file_location(f.stem, str(f))
            assert s and s.loader
            mod = importlib.util.module_from_spec(s)
            s.loader.exec_module(mod)
            specs[mod.revision] = mod.down_revision
        # exactly one head: nothing else may claim 040 as its parent, and 040 must have one
        assert specs["040"] == "039", f"040 does not chain to the tip it was cut at: {specs['040']}"
        parents = [p for p in specs.values() if p]
        heads = [r for r in specs if r not in parents]
        # ADVANCED by the #684 leg, exactly as the 037-era head cell documents: the
        # invariant is ONE head, and the identifier is the acknowledgement that a
        # migration landed. 040 -> 041 (#684 admin credential registry)
        # -> 042 (#689 relay CN column-comment scrub).
        assert heads == ["042"], f"the version tree has more than one head: {heads}"


def core_alembic_dir() -> str:
    from pathlib import Path as P

    return str(P(__file__).resolve().parents[2] / "core" / "alembic" / "versions")
