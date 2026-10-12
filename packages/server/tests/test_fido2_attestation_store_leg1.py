# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Attestation record capture — queue #2 leg 1 (store, not enforce).

Yubico RP guidance: "store the raw attestation object as part of the
credential" (WebAuthn Server Registration) / keep the verbatim response
"including the attestation statement" (WebAuthn Attestation). The server
used to parse the object and discard it. These cells pin the truth table:

- positive: a packed-format registration stores the VERBATIM bytes (exact
  match to what was sent) plus the parsed fmt and canonical AAGUID;
- open-default half: a none-format registration still enrolls, storing
  exactly what arrived (no new rejection modes for the shipped default);
- negative: a malformed attestation object refuses with the SAME error as
  before this change — recording adds no failure path;
- persistence: the DB row round-trips the bytes, and the startup load path
  propagates all three fields into the in-memory store.

Enforcement / chain verification / trust roots are LEG 2 — nothing here
refuses anything.
"""

import base64
import hashlib
import json
import struct

import pytest
from core.iam.models import Base, WebAuthnCredential
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor as fido2_cbor
from fido2.webauthn import ES256
from server.fido2.manager import Fido2Manager, WebAuthnError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.fido2_db import manager_with_db, peek_challenge_data

RP_ID = "venya-core-1"
RP_ID_HASH = hashlib.sha256(RP_ID.encode()).digest()
SYNTH_AAGUID = bytes(range(16))
SYNTH_AAGUID_CANONICAL = "00010203-0405-0607-0809-0a0b0c0d0e0f"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture()
def keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


@pytest.fixture()
def manager(tmp_path):
    mgr, _factory = manager_with_db(tmp_path, rp_id=RP_ID, rp_name="Venya")
    return mgr


def _build_attestation_object(
    cred_id: bytes,
    cose_key: dict,
    fmt: str = "none",
    att_stmt: dict | None = None,
    aaguid: bytes = SYNTH_AAGUID,
    counter: int = 1,
) -> bytes:
    """CBOR attestation object with attested credential data, given fmt/statement.

    fmt "none" carries the empty statement the spec requires; "packed"
    carries a synthetic statement — leg 1 RECORDS it and never validates it
    (that is leg 2), so the sig bytes here are placeholders on purpose.
    """
    if att_stmt is None:
        att_stmt = {} if fmt == "none" else {"alg": -7, "sig": b"leg1-placeholder-not-verified"}
    cred_data = aaguid + struct.pack(">H", len(cred_id)) + cred_id + fido2_cbor.encode(cose_key)
    flags = 0x01 | 0x04 | 0x40  # UP | UV | AT
    auth_data = RP_ID_HASH + bytes([flags]) + struct.pack(">I", counter) + cred_data
    return bytes(fido2_cbor.encode({"fmt": fmt, "authData": auth_data, "attStmt": att_stmt}))


def _finish(manager, cred_id: bytes, ao_bytes: bytes):
    """Run a full registration ceremony with the given raw attestation object."""
    challenge_id, _options = manager.start_registration(user_id="u1", username="u1")
    raw = peek_challenge_data(manager.store._sessions, challenge_id)["raw_challenge"]
    client_data = _b64url(
        json.dumps(
            {
                "type": "webauthn.create",
                "challenge": _b64url(raw),
                "origin": f"https://{RP_ID}",
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
    )
    response = {
        "id": _b64url(cred_id),
        "response": {
            "attestationObject": _b64url(ao_bytes),
            "clientDataJSON": client_data,
        },
    }
    return manager.finish_registration(challenge_id, response)


class TestRecordCapture:
    def test_packed_statement_stored_verbatim(self, manager, keypair):
        """Positive half: packed bytes round-trip EXACT, fmt + canonical AAGUID parsed."""
        _priv, public_key = keypair
        cred_id = b"leg1-packed-cred"
        ao_bytes = _build_attestation_object(cred_id, dict(ES256.from_cryptography_key(public_key)), fmt="packed")

        cred = _finish(manager, cred_id, ao_bytes)

        assert cred.attestation_object == ao_bytes, "stored bytes must be byte-identical to the object as sent"
        assert cred.attestation_fmt == "packed"
        assert cred.aaguid == SYNTH_AAGUID_CANONICAL
        # The pre-existing credential material is untouched by the capture.
        assert cred.credential_id == cred_id
        assert cred.user_id == "u1"

    def test_none_format_still_enrolls_and_records(self, manager, keypair):
        """Open-default half: none-format registers exactly as before, storing what arrived."""
        _priv, public_key = keypair
        cred_id = b"leg1-none-cred"
        ao_bytes = _build_attestation_object(cred_id, dict(ES256.from_cryptography_key(public_key)), fmt="none")

        cred = _finish(manager, cred_id, ao_bytes)

        assert cred.attestation_fmt == "none"
        assert cred.attestation_object == ao_bytes
        assert cred.aaguid == SYNTH_AAGUID_CANONICAL

    def test_malformed_attestation_object_refuses_as_before(self, manager):
        """Negative half: garbage bytes fail with the SAME error as before this
        change — recording introduces no new failure mode. The garbage is fed
        to the SERVER directly (a test-side parse would pre-empt the very
        branch under test)."""
        challenge_id, _options = manager.start_registration(user_id="u1", username="u1")
        response = {
            "id": _b64url(b"leg1-garbage"),
            "response": {"attestationObject": _b64url(b"this-is-not-cbor")},
        }
        with pytest.raises(WebAuthnError, match="Failed to parse attestation object"):
            manager.finish_registration(challenge_id, response)

    def test_missing_attestation_object_refuses_as_before(self, manager):
        """Second negative half: the missing-field path keeps its exact message."""
        challenge_id, _options = manager.start_registration(user_id="u2", username="u2")
        with pytest.raises(WebAuthnError, match="Missing attestationObject in response"):
            manager.finish_registration(challenge_id, {"id": _b64url(b"x"), "response": {}})


class TestPersistenceRoundTrip:
    def test_row_stores_and_reads_back_bytes(self, manager, keypair, tmp_path):
        """The three new columns persist the capture through a real DB write,
        mirroring the route constructor (the route's own tests exercise HTTP)."""
        _priv, public_key = keypair
        cred_id = b"leg1-row-cred"
        ao_bytes = _build_attestation_object(cred_id, dict(ES256.from_cryptography_key(public_key)), fmt="packed")
        cred = _finish(manager, cred_id, ao_bytes)

        engine = create_engine(f"sqlite:///{tmp_path}/cred.db")
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine)()
        session.add(
            WebAuthnCredential(
                user_id="u1",
                credential_id=cred.credential_id,
                public_key=cred.public_key,
                sign_count=cred.sign_count,
                label=None,
                is_active=True,
                attestation_fmt=cred.attestation_fmt,
                aaguid=cred.aaguid,
                attestation_object=cred.attestation_object,
            )
        )
        session.commit()

        row = session.query(WebAuthnCredential).filter_by(credential_id=cred_id).one()
        assert bytes(row.attestation_object) == ao_bytes
        assert row.attestation_fmt == "packed"
        assert row.aaguid == SYNTH_AAGUID_CANONICAL
        session.close()

    def test_startup_load_propagates_fields(self, keypair, tmp_path):
        """#441-style load path: an active row's capture reaches the in-memory
        StoredCredential (the fields the manager later hands to routes)."""
        _priv, public_key = keypair
        cred_id = b"leg1-load-cred"
        ao_bytes = _build_attestation_object(cred_id, dict(ES256.from_cryptography_key(public_key)), fmt="packed")

        engine = create_engine(f"sqlite:///{tmp_path}/load.db")
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine)()
        session.add(
            WebAuthnCredential(
                user_id="u1",
                credential_id=cred_id,
                public_key=b"pk",
                sign_count=3,
                is_active=True,
                attestation_fmt="packed",
                aaguid=SYNTH_AAGUID_CANONICAL,
                attestation_object=ao_bytes,
            )
        )
        session.add(
            WebAuthnCredential(  # a pre-038 legacy row: NULLs load cleanly
                user_id="u1",
                credential_id=b"leg1-legacy",
                public_key=b"pk2",
                sign_count=1,
                is_active=True,
            )
        )
        session.commit()
        session.close()

        factory = sessionmaker(bind=engine)

        class _Backend:
            def get_session(self):
                return factory()

        mgr = Fido2Manager(rp_id=RP_ID, rp_name="Venya", backend=_Backend())
        loaded = mgr.store.get_credential(cred_id)
        assert loaded is not None
        assert loaded.attestation_fmt == "packed"
        assert loaded.aaguid == SYNTH_AAGUID_CANONICAL
        assert loaded.attestation_object == ao_bytes
        legacy = mgr.store.get_credential(b"leg1-legacy")
        assert (legacy.attestation_fmt, legacy.aaguid, legacy.attestation_object) == (None, None, None)
