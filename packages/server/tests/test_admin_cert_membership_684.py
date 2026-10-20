# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#684 — `admin revoke-admin-cert` must refuse a serial no credential holds.

**The defect.** The route validated the FORMAT of the operator's string, found nothing in
``AdminCertRevocation``, and blind-inserted a row anyway: ``venya admin revoke-admin-cert
--serial <any hex>`` exited 0 and wrote a revocation naming a serial no certificate ever
held, while the live admin credential kept transacting. Measured physically by ``flash6`` at
leg 232 against the sibling relay route, which refuses the identical string with
``REFUSE_UNREGISTERED``. Filed by ``clerk`` as issue 684 (HIGH), owner ruled "fix".

**Why this file is a truth table and not one assertion.** A membership gate has two ways to
fail, and both look correct in a single test: it can refuse everything (a gate that strands
the operator's own credential — strictly worse than the bug, which is the reason the
population table exists at all), or it can accept everything (the shipped lie). So every
arm here is paired, and the two halves that matter most are the ones a naive fix breaks:

| registry row | revocation row | outcome asserted |
|---|---|---|
| present | absent | 200, revoked, audit written |
| ABSENT | absent | **403, nothing written, NOTHING audited** |
| present/absent | present | 200, idempotent — the shipped face, unchanged |
| the operator's own live credential | absent | **200, still revocable** |

Real SQLite (precedent: ``test_executor_revocation_identity.py``), because the subject under
test is a three-table interaction — ``admin_credentials`` membership, ``admin_cert_revocations``
output, and ``audit_events`` — and a mocked session would pin the mocks, not the semantics.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from core.iam.models import (
    AdminCertRevocation,
    AdminCredential,
    AuditEvent,
    Base,
    Role,
    RoleMember,
    User,
)
from core.utils.cert_serial import canonical_serial
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from server.config import ServerConfig
from server.dependencies import get_backend, get_current_user, require_admin
from server.routes import admin as admin_routes
from server.routes import admin_certs as admin_certs_routes

ADMIN = {"user_id": "test-admin"}

#: A serial the population does NOT name. This is the exact shape #684 accepted: valid hex,
#: valid width, canonicalizable — and belonging to no certificate that ever existed.
UNKNOWN_SERIAL = "00000000deadbeef"


def _mint_admin_credential(cn="venya-core-3", serial=None):
    """A real, self-consistent admin leaf: the facts the registry must read OFF the cert."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Venya"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Admin"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert, key


@pytest.fixture()
def env(tmp_path):
    """Real SQLite + the admin routes, auth overridden. Returns (client, SessionLocal)."""
    engine = __import__("sqlalchemy").create_engine(f"sqlite:///{tmp_path / '684.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = __import__("sqlalchemy").orm.sessionmaker(bind=engine)

    seed = SessionLocal()
    seed.add(User(user_id="test-admin", auth_mode="password"))
    role = Role(name="operators", permissions="read-write", description="t")
    seed.add(role)
    seed.flush()
    seed.add(RoleMember(user_id="test-admin", role_id=role.id))
    seed.commit()
    seed.close()

    app = FastAPI()
    backend = MagicMock()
    backend.get_session.side_effect = lambda: SessionLocal()
    app.state.backend = backend
    app.state.config = ServerConfig(recovery_code_pepper="test-pepper")
    app.dependency_overrides[get_backend] = lambda: backend
    app.dependency_overrides[get_current_user] = lambda: ADMIN
    app.dependency_overrides[require_admin] = lambda: ADMIN
    app.include_router(admin_routes.router, prefix="/api/v1")
    # #684: the register remedy lives on the admin_certs router (beside the mint that now
    # writes its own population row), so the harness mounts both — same as app.py:221.
    app.include_router(admin_certs_routes.router, prefix="/api/v1")
    return TestClient(app), SessionLocal


def _revoke(client, serial, reason="rot"):
    return client.post("/api/v1/admin/certs/revoke", json={"serial": serial, "reason": reason})


def _revocation_rows(s, serial):
    return s.query(AdminCertRevocation).filter_by(serial_number=canonical_serial(serial)).all()


def _audit_rows(s):
    return s.query(AuditEvent).filter_by(event_type="admin_cert_revoked").all()


def _register(s, cert, source="test"):
    from server.admin_registry import facts_from_certificate, register_admin_credential

    outcome = register_admin_credential(s, facts_from_certificate(cert), source)
    s.commit()
    return outcome


# --------------------------------------------------------------------------------------
# Half 1 — the accept arm: a serial the population NAMES is revocable, and it is recorded.
# --------------------------------------------------------------------------------------


def test_known_serial_is_revoked_row_written_audit_emitted(env):
    """POPULATED + not yet revoked -> 200, one revocation row, one audit row.

    The positive control of the whole file: a gate that refused this arm would be the
    strand-the-operator failure, so this is asserted first and loudly.
    """
    client, SessionLocal = env
    cert, _key = _mint_admin_credential()
    serial = canonical_serial(cert.serial_number)
    s = SessionLocal()
    assert _register(s, cert) == "created"
    s.close()

    resp = _revoke(client, serial)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["revoked"] is True and body["already_revoked"] is False, body

    s = SessionLocal()
    assert len(_revocation_rows(s, serial)) == 1, "exactly one revocation row"
    rows = _audit_rows(s)
    assert len(rows) == 1, f"one admin_cert_revoked row expected, got {len(rows)}"
    fields = rows[0].fields
    assert serial in fields and "already_revoked" in fields, fields
    s.close()


def test_register_is_idempotent_and_never_rewrites_the_first_writer(env):
    """A second register of the same credential returns "present" and keeps ``source``.

    This is what makes the boot ingest safe to run on every start: a reboot cannot
    re-attribute a credential to a different writer, and cannot clear anything either
    (the same rule ``relay_registry.register_relay_credential`` holds for #597).
    """
    _client, SessionLocal = env
    cert, _key = _mint_admin_credential()
    s = SessionLocal()
    assert _register(s, cert, source="boot-disk") == "created"
    assert _register(s, cert, source="register-route") == "present"
    row = s.query(AdminCredential).one()
    assert row.source == "boot-disk", f"the second writer rewrote provenance: {row.source}"
    s.close()


# --------------------------------------------------------------------------------------
# Half 2 — the REFUSE arm: the defect itself. Nothing written, and NOTHING audited.
# --------------------------------------------------------------------------------------


def test_unknown_serial_is_refused_and_nothing_is_written(env):
    """#684 directly: valid hex, valid width, no credential -> 403, no row, no audit.

    Before this change the same call returned 200 and created a revocation row naming a
    serial no certificate ever held.
    """
    client, SessionLocal = env
    before = SessionLocal()
    assert before.query(AdminCredential).count() == 0
    before.close()

    resp = _revoke(client, UNKNOWN_SERIAL, reason="trunc-probe")
    assert resp.status_code == 403, f"an unregistered serial must not be revocable: {resp.status_code} {resp.text}"
    detail = resp.json()["detail"]
    assert "REFUSE_UNREGISTERED_ADMIN_CERT" in detail, detail
    assert canonical_serial(UNKNOWN_SERIAL) in detail, f"the refusal must name the serial: {detail}"

    s = SessionLocal()
    assert len(_revocation_rows(s, UNKNOWN_SERIAL)) == 0, "a refused revoke writes NO revocation row"
    assert _audit_rows(s) == [], "a refused revoke emits NO audit event (AC4)"
    s.close()


def test_refusal_leaves_the_live_credential_transacting(env):
    """The paired statement the defect's harm depends on: refusing the unknown does NOT
    disturb the credential that IS live. The registry row survives, unrevoked."""
    client, SessionLocal = env
    cert, _key = _mint_admin_credential()
    live = canonical_serial(cert.serial_number)
    s = SessionLocal()
    _register(s, cert)
    s.close()

    resp = _revoke(client, UNKNOWN_SERIAL)
    assert resp.status_code == 403

    s = SessionLocal()
    assert s.query(AdminCredential).filter_by(serial_number=live).one() is not None
    assert len(_revocation_rows(s, live)) == 0, "the live credential must be untouched by a refused probe"
    s.close()

    # and it is STILL revocable afterwards — the refusal did not gate the plane shut
    resp2 = _revoke(client, live)
    assert resp2.status_code == 200, resp2.text


# --------------------------------------------------------------------------------------
# Half 3 — idempotency, the shipped face: unchanged, and NOT broken by the membership gate.
# --------------------------------------------------------------------------------------


def test_already_revoked_stays_idempotent(env):
    """Second call on a revoked serial -> 200, already_revoked=True, still ONE row.

    flash6 measured ``already present`` as the shipped behavior and the dispatch says do
    not change it. The repeat is checked BEFORE membership, so a credential revoked by a
    boot predating this population still answers truthfully instead of erroring — the
    idempotency does not depend on when the row was written.
    """
    client, SessionLocal = env
    cert, _key = _mint_admin_credential()
    serial = canonical_serial(cert.serial_number)
    s = SessionLocal()
    _register(s, cert)
    s.close()

    assert _revoke(client, serial).status_code == 200
    resp = _revoke(client, serial, reason="second")
    assert resp.status_code == 200, resp.text
    assert resp.json()["already_revoked"] is True, resp.json()

    s = SessionLocal()
    assert len(_revocation_rows(s, serial)) == 1, "the repeat added no second row"
    # both attempts are recorded (Q3 #301): the attempt is the record
    assert len(_audit_rows(s)) == 2
    s.close()


def test_idempotent_arm_reachable_with_no_registry_row(env):
    """The half that keeps the gate honest about history: a revocation row with NO
    population row still reports ``already_revoked`` rather than 403.

    Refusing a repeat would turn a truthful no-op into an error, and would make
    idempotency depend on whether a boot had registered the credential.
    """
    client, SessionLocal = env
    s = SessionLocal()
    s.add(AdminCertRevocation(serial_number=UNKNOWN_SERIAL, reason="legacy", revoked_at=datetime.now(UTC)))
    s.commit()
    assert s.query(AdminCredential).filter_by(serial_number=UNKNOWN_SERIAL).count() == 0
    s.close()

    resp = _revoke(client, UNKNOWN_SERIAL)
    assert resp.status_code == 200, resp.text
    assert resp.json()["already_revoked"] is True


# --------------------------------------------------------------------------------------
# Half 4 — the operator's OWN live credential stays revocable (the naive-fix trap).
# --------------------------------------------------------------------------------------


def test_operator_bootstrap_credential_is_revocable_after_boot_ingest(env, tmp_path):
    """Boot ingest of the on-disk machine leaf is what makes the operator's credential
    revocable — the arm a bare "is this serial known?" check would strand.

    Drives the shipped ``ingest_admin_credential`` against a real certificate file, then
    revokes the serial that file's credential carries, through the same route.
    """
    from server.admin_registry import SOURCE_BOOT_DISK, ingest_admin_credential

    client, SessionLocal = env
    cert, _key = _mint_admin_credential(cn="venya-core-3")
    leaf = tmp_path / "admin.crt"
    leaf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    serial = canonical_serial(cert.serial_number)

    backend = SimpleNamespace(get_session=SessionLocal)
    facts = ingest_admin_credential(SimpleNamespace(), backend, cert_path=str(leaf))
    assert facts is not None, "a credential on disk must be registered by the boot"
    assert facts.serial_number == serial
    assert facts.common_name == "venya-core-3"

    s = SessionLocal()
    row = s.query(AdminCredential).filter_by(serial_number=serial).one()
    assert row.source == SOURCE_BOOT_DISK, row.source
    s.close()

    resp = _revoke(client, serial, reason="operator-own")
    assert resp.status_code == 200, f"the operator's own credential must stay revocable: {resp.text}"
    s = SessionLocal()
    assert len(_revocation_rows(s, serial)) == 1
    s.close()


def test_boot_ingest_is_idempotent_across_restarts(env, tmp_path):
    """A reboot registers once and does not duplicate the population row."""
    from server.admin_registry import ingest_admin_credential

    _client, SessionLocal = env
    cert, _key = _mint_admin_credential()
    leaf = tmp_path / "admin.crt"
    leaf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    backend = SimpleNamespace(get_session=SessionLocal)

    assert ingest_admin_credential(SimpleNamespace(), backend, cert_path=str(leaf)) is not None
    assert ingest_admin_credential(SimpleNamespace(), backend, cert_path=str(leaf)) is not None

    s = SessionLocal()
    assert s.query(AdminCredential).count() == 1, "two boots, one row — the upsert is keyed on the serial"
    s.close()


def test_boot_with_no_credential_warns_and_registers_nothing(env, tmp_path, caplog):
    """A missing file is a NAMED warning, not a silent pass, and it invents no row."""
    import logging

    from server.admin_registry import ingest_admin_credential

    _client, SessionLocal = env
    backend = SimpleNamespace(get_session=SessionLocal)
    with caplog.at_level(logging.WARNING, logger="venya.server"):
        facts = ingest_admin_credential(SimpleNamespace(), backend, cert_path=str(tmp_path / "absent.crt"))
    assert facts is None
    s = SessionLocal()
    assert s.query(AdminCredential).count() == 0
    s.close()
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "Admin credential registry NOT updated" in joined, joined
    assert "#684" in joined, "the warning must name the row it belongs to"


def test_unreadable_credential_is_a_named_warning(env, tmp_path, caplog):
    """PEM garbage is refused with the file named — never registered as a phantom member."""
    import logging

    from server.admin_registry import ingest_admin_credential

    _client, SessionLocal = env
    bad = tmp_path / "admin.crt"
    bad.write_bytes(b"not a certificate at all")
    backend = SimpleNamespace(get_session=SessionLocal)
    with caplog.at_level(logging.WARNING, logger="venya.server"):
        assert ingest_admin_credential(SimpleNamespace(), backend, cert_path=str(bad)) is None
    s = SessionLocal()
    assert s.query(AdminCredential).count() == 0
    s.close()


# --------------------------------------------------------------------------------------
# The register remedy the refusal sentence promises.
# --------------------------------------------------------------------------------------


def test_register_route_enrolls_from_the_certificate_then_allows_revoke(env):
    """AC2's remedy path: a pre-existing credential is enrolled by PRESENTING it, and only
    then becomes revocable. Facts come off the PEM, never from the request body."""
    client, _SessionLocal = env
    cert, _key = _mint_admin_credential(cn="workstation-admin")
    serial = canonical_serial(cert.serial_number)

    assert _revoke(client, serial).status_code == 403, "unknown before register"

    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    reg = client.post("/api/v1/admin/certs/register", json={"certificate_pem": pem})
    assert reg.status_code == 201, reg.text
    assert reg.json()["created"] is True and reg.json()["serial_number"] == serial

    # idempotent register
    reg2 = client.post("/api/v1/admin/certs/register", json={"certificate_pem": pem})
    assert reg2.status_code == 201 and reg2.json()["created"] is False

    assert _revoke(client, serial, reason="after-register").status_code == 200


def test_register_route_refuses_garbage_and_cannot_enroll_an_arbitrary_serial(env):
    """The paired negative: the verb reads the certificate, so a caller cannot ask for a
    serial. A body carrying one is refused (extra=forbid), and unreadable PEM is a 400."""
    client, SessionLocal = env
    bad = client.post("/api/v1/admin/certs/register", json={"certificate_pem": "-----BEGIN NOPE-----\nxx\n"})
    assert bad.status_code == 400, bad.text

    forged = client.post("/api/v1/admin/certs/register", json={"serial": UNKNOWN_SERIAL})
    assert forged.status_code == 422, forged.text

    s = SessionLocal()
    assert s.query(AdminCredential).count() == 0, "nothing was enrolled by either refusal"
    assert _audit_rows(s) == []
    s.close()


def test_register_emits_its_own_audit_event(env):
    """The register is a lifecycle fact too — ``admin_cert_registered``, value-free."""
    client, SessionLocal = env
    cert, _key = _mint_admin_credential()
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    assert client.post("/api/v1/admin/certs/register", json={"certificate_pem": pem}).status_code == 201

    s = SessionLocal()
    rows = s.query(AuditEvent).filter_by(event_type="admin_cert_registered").all()
    assert len(rows) == 1
    fields = rows[0].fields
    assert canonical_serial(cert.serial_number) in fields and "private" not in fields.lower()
    s.close()


# --------------------------------------------------------------------------------------
# The format gate is unchanged, and it still runs BEFORE membership.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("garbage", ["not-hex!", "", "z" * 10])
def test_malformed_serial_still_400_before_any_lookup(env, garbage):
    """400 (format) is a different answer from 403 (unknown), and the refusal order is
    asserted so a caller can tell them apart."""
    client, _SessionLocal = env
    resp = _revoke(client, garbage)
    assert resp.status_code == 400, f"{garbage!r} -> {resp.status_code}"


def test_membership_refusal_is_not_a_404(env):
    """Named on purpose: the relay route's reasoning is that a 404 reads like "nothing of
    that name exists anywhere", which is not the claim being made. This store does not
    VOUCH for it, so it refuses."""
    client, _SessionLocal = env
    resp = _revoke(client, UNKNOWN_SERIAL)
    assert resp.status_code == 403
    assert resp.status_code != 404


def test_population_serial_uses_the_one_canonical_write_form(env):
    """The registry stores canonical (lowercase, >=16 padded) — the same WRITE form as every
    other serial column (#481). A row stored in the compare key would be a second vocabulary,
    and the lookup would disagree with the write."""
    client, SessionLocal = env
    cert, _key = _mint_admin_credential(serial=0xABC)
    s = SessionLocal()
    _register(s, cert)
    row = s.query(AdminCredential).one()
    assert row.serial_number == canonical_serial(cert.serial_number) == "0000000000000abc", row.serial_number
    s.close()

    # and an operator typing the unpadded uppercase form matches the SAME row
    resp = _revoke(client, "ABC")
    assert resp.status_code == 200, resp.text


def test_migration_041_chains_and_builds_the_table():
    """The migration is mandatory (#684 AC1), so the chain and the table it creates are
    checked against the model, not asserted from the file's prose."""
    import importlib.util
    from pathlib import Path

    v = Path(__file__).resolve().parents[2] / "core" / "alembic" / "versions"
    path = v / "041_admin_credential_registry.py"
    assert path.is_file(), "the 041 admin-credential registry migration is missing"
    spec = importlib.util.spec_from_file_location("m041", str(path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == "041" and mod.down_revision == "040", (mod.revision, mod.down_revision)
    assert callable(mod.upgrade) and callable(mod.downgrade)

    src = path.read_text()
    model_cols = {c.name for c in AdminCredential.__table__.columns}
    for col in model_cols:
        assert f'"{col}"' in src, f"model column {col} is not created by migration 041"
    assert "uq_admin_credentials_serial_number" in src, "the unique serial is what makes the boot upsert safe"


def test_admin_cert_revocation_table_is_still_the_only_revocation_authority():
    """The one deliberate divergence from #597's shape, asserted rather than narrated: no
    second ``revoked_at`` on the population table, because ``AdminCertRevocation`` is what
    ``AdminCAManager.generate_crl`` reads. Two revocation columns would be two sources of
    truth for one fact."""
    assert "revoked_at" not in {c.name for c in AdminCredential.__table__.columns}
    assert "revoked_at" in {c.name for c in AdminCertRevocation.__table__.columns}


def test_audit_event_name_is_registered_in_the_lifecycle_vocabulary():
    """``audit_lifecycle`` REFUSES free strings, so a new event name must be in its known
    set — this cell fails loudly if someone adds the constant and forgets the set."""
    from server.audit_lifecycle import ADMIN_CERT_REGISTERED, audit_lifecycle

    s = MagicMock()
    audit_lifecycle(s, ADMIN_CERT_REGISTERED, "u", {"serial_number": "ab12", "created": True})
    assert s.add.call_count == 1


# --------------------------------------------------------------------------------------
# The fourth writer: the credential the admin-mTLS chain just VERIFIED is population too.
# --------------------------------------------------------------------------------------


def test_observed_admission_registers_a_verified_credential(env):
    """An admin credential that has just passed chain + plane + allowlist + revocation is,
    by definition, one this core vouches for — so the enforcement point records it.

    This is the writer that keeps the membership gate from stranding a core that never set
    ``VENYA_ADMIN_CERT`` and never ran a mint: the certificate the caller is already
    presenting IS the enrollment evidence. Asserted through the shipped helper with a real
    certificate and a real session, then confirmed by revoking that serial through the route.
    """
    from server.admin_registry import SOURCE_OBSERVED_ADMISSION
    from server.middleware.auth import _register_observed_admin_credential

    client, SessionLocal = env
    cert, _key = _mint_admin_credential(cn="venya-core-3")
    serial = canonical_serial(cert.serial_number)
    backend = SimpleNamespace(get_session=SessionLocal)

    _register_observed_admin_credential(backend, cert, serial)

    s = SessionLocal()
    row = s.query(AdminCredential).filter_by(serial_number=serial).one()
    assert row.source == SOURCE_OBSERVED_ADMISSION, row.source
    assert row.common_name == "venya-core-3"
    s.close()

    # and the whole point of the writer: that credential is now revocable
    assert _revoke(client, serial, reason="observed-then-revoked").status_code == 200


def test_observed_admission_is_idempotent(env):
    """Five admissions of the same certificate create ONE population row.

    Without this the population would grow a row per admin request and the gate would be
    measuring noise, not credentials.
    """
    from server.middleware.auth import _register_observed_admin_credential

    _client, SessionLocal = env
    cert, _key = _mint_admin_credential()
    serial = canonical_serial(cert.serial_number)
    backend = SimpleNamespace(get_session=SessionLocal)

    for _ in range(5):
        _register_observed_admin_credential(backend, cert, serial)

    s = SessionLocal()
    assert s.query(AdminCredential).count() == 1
    s.close()


def test_observed_admission_never_denies_on_a_registry_fault(caplog):
    """Bookkeeping must not turn an AUTHORIZED request into a refusal — and never silence.

    Both halves: the call returns normally with a broken session, and it logs a warning that
    names the serial and the register remedy.
    """
    import logging

    from server.middleware.auth import _register_observed_admin_credential

    cert, _key = _mint_admin_credential()
    serial = canonical_serial(cert.serial_number)
    boom = MagicMock()
    boom.get_session.side_effect = RuntimeError("db is down")

    with caplog.at_level(logging.WARNING, logger="venya.server"):
        _register_observed_admin_credential(boom, cert, serial)  # must NOT raise

    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "could not record the admitted credential" in joined, joined
    assert serial in joined, "the warning must name which credential is at risk"
    assert "admin/certs/register" in joined, "and the remedy that fixes it"


def test_boot_ingest_with_no_configured_path_registers_nothing(env, monkeypatch, caplog):
    """The server names NO leaf path, by the #565 site-1 destination seam. So with
    ``VENYA_ADMIN_CERT`` unset there is nothing to read, the boot says so BY NAME, and no
    population row is invented to fill the gap.
    """
    import logging

    from server.admin_registry import ADMIN_CERT_PATH_ENV, ingest_admin_credential

    _client, SessionLocal = env
    monkeypatch.delenv(ADMIN_CERT_PATH_ENV, raising=False)
    backend = SimpleNamespace(get_session=SessionLocal)

    with caplog.at_level(logging.WARNING, logger="venya.server"):
        assert ingest_admin_credential(SimpleNamespace(), backend) is None

    joined = " ".join(r.getMessage() for r in caplog.records)
    assert ADMIN_CERT_PATH_ENV in joined, f"the warning must name the variable: {joined}"
    s = SessionLocal()
    assert s.query(AdminCredential).count() == 0, "no path must never mean a guessed row"
    s.close()


def test_server_source_names_no_leaf_destination_in_the_new_module():
    """The #565 seam is a LAW, not a preference: no file under ``packages/server/src`` may
    name a delivered-leaf path. Re-checked here against THIS leg's own additions, so the
    rule cannot be broken by the very change that adds a boot reader.
    """
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "server"
    leaf_names = ("admin.key", "admin.crt", "venya-admin.key", "venya-admin.crt")
    offenders = []
    for p in sorted(src.rglob("*.py")):
        text = p.read_text(encoding="utf-8")
        if any(name in text for name in leaf_names):
            offenders.append(str(p.relative_to(src)))
    assert offenders == [], f"server source names a delivered-leaf destination: {offenders}"
