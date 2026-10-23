# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#573 — the DB-KEK plane carries the same passphrase length floor (N=15).

Owner sentence (s85 batch, item #554, verbatim): *"Deny whitespace-only passphrases **and
enforce a proper length passcode.**"* Clause 1 shipped as #554; the CA plane of clause 2
landed in `b50bc9e` (merged `37e414c`); these cells are the Argon2id half the ruling calls
"same number for BOTH KDFs" (decisions.md:282), enforced at the two doors this plane has:

- the **boot gate** — ``BackendConfig.__init__``, the seam the ticket names
  (`if passphrase is None and kek is None:` at filing time). Every product path that turns a
  configured passphrase into a KEK constructs it: ``server/dependencies.py`` ``init_db()``
  hands in a ``str``, ``core/engine/factory.py`` ``from_dict()`` hands in ``bytes``.
- the **derive door** — ``Backend.bootstrap_kek(passphrase)``, reached with an override by
  ``Backend.get_core(passphrase)`` (which is exactly what ``server/app.py`` does at startup),
  so a value that never passed the gate still cannot reach the KDF.

Ruled shape, and the two cells that pin it rather than assert it: 15 Unicode CODE POINTS,
INCLUSIVE (`len < 15` refuses, 15 passes), counted on the decoded value before any encode;
the 64 ceiling is STATED in the text and enforced nowhere — a 65-code-point passphrase is
ACCEPTED and used, and flipping ``MAX_PASSPHRASE_CODE_POINTS`` moves no door.

Truth table, paired negatives, each half failing independently:
  14 refuses · 15 passes · blank stays "not supplied" with #570's OWN sentence (the floor
  runs after that decision, never instead of it) · a legal passphrase whose spaces are
  content is delivered byte-for-byte and derives the key it always derived · 65 is ACCEPTED
  · 14 accented code points (28 UTF-8 bytes) refuses where 15 of them pass.
Door halves: the boot gate creates NOTHING (no object, no engine, no session, no salt row)
and the derive door loads NOTHING and re-wraps NOTHING (the persisted salt and every stored
envelope are byte-identical after a refusal).

The companion file ``test_db_kek_decrypt_voice_573.py`` pins the voice rule (#572/#574) that
a refusal on this plane carries none of the crypto binding's own sentences; the banned
strings asserted here were read off that same live probe.
"""

import sqlite3
from pathlib import Path

import pytest
from core.engine.backend import (
    MAX_PASSPHRASE_CODE_POINTS,
    MIN_PASSPHRASE_CODE_POINTS,
    Backend,
    BackendConfig,
    BackendConfigurationError,
    SentinelStatus,
    ensure_kek_sentinel,
    is_passphrase_below_floor,
    short_passphrase_refusal,
    verify_kek_sentinel,
)
from core.engine.encryption import derive_kek, encrypt_secret, unwrap_key
from core.iam.models import Base, KekSentinel, Secret
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

#: The binding's own sentences, transcribed from the same live probe recorded in
#: ``test_db_kek_decrypt_voice_573.py``'s docstring. Repeated here rather than imported so
#: these two changesets stay independent of each other's merge order.
_BINDING_VOICES = (
    "initializer for ctype",
    "must be a bytes or list or tuple",
    "Salt is too short",
    "HashingError",
    "InvalidTag",
    "mac check",
    "digest failed",
)

_DB_URL = "postgresql://test/test"
_ONE = "a"
_BELOW = _ONE * 14  # 14: refuses — a LITERAL length, so a constant flip goes red
_AT_FLOOR = _ONE * 15  # 15: passes INCLUSIVE (the shipped `test_passphrase` family is 15)
_AT_CEILING = _ONE * 64  # 64: passes
_OVER_CEILING = _ONE * 65  # 65: PASSES — the ceiling is stated, not enforced
_ACCENTED_14 = "é" * 14  # 14 code points = 28 UTF-8 bytes: over 15 BYTES, under the floor
_ACCENTED_15 = "é" * 15  # 15 code points = 30 UTF-8 bytes
_SPACED = " sword with spaces in it "  # legal length; the spaces are CONTENT
_BLANKS = [None, "", " ", "   ", "\t", b"", b" ", b"\t\n"]
# Dev-only synthetic values (the same family #570/#572/#574 cells record). Never real.
_LEGAL_BYTES = b"boot-gate-legal-573"
_SHORT_BYTES = b"short-573"  # 9 code points — refuses
_SHORT_STR = "short-573-str"  # 13 code points — refuses


#: The sentence the shipped #570 gate answers for a blank, read from the live code path
#: rather than retyped here (the same discipline as ``test_db_kek_blank_passphrase_570.py``).
def _not_supplied_message() -> str:
    with pytest.raises(BackendConfigurationError) as excinfo:
        BackendConfig(database_url=_DB_URL, passphrase=None)
    return str(excinfo.value)


def _current_kek(backend: Backend) -> bytes:
    """The KEK this backend already resolved, read through its scoped view."""
    with backend.kek_cache.view() as kek:
        return bytes(kek)


def _booted_sqlite_backend(tmp_path: Path, name: str, passphrase: bytes) -> Backend:
    """A real SQLite-backed Backend with a persisted salt and one stored secret."""
    url = f"sqlite:///{tmp_path / name}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    backend = Backend(BackendConfig(database_url=url, passphrase=passphrase))
    # Backend's pragma connect-listener is PostgreSQL-only; inject the plain engine so
    # the fixture speaks through the real Backend (the shape test_kek_sentinel.py uses).
    backend._engine = engine
    backend._session_factory = sessionmaker(bind=engine)
    backend.bootstrap_kek()
    session = backend.get_session()
    try:
        with backend.kek_cache.view() as view:
            kek = bytes(view)
            wrapped, nonce, ciphertext = encrypt_secret(kek, b"a-stored-secret")
        # The sentinel is normally minted by Core.encrypt at first crypto use; land it
        # here so the read cells have a stored envelope to prove they do not touch.
        ensure_kek_sentinel(session, kek)
        session.add(
            Secret(
                key="secret-573",
                encrypted_value=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped,
                key_version_id="v1",
                created_by="user1",
            )
        )
        session.commit()
    finally:
        session.close()
    return backend


def _db_file_rows(db_path: Path) -> int:
    """Count rows in ``venya_config`` without going through the product read path."""
    with sqlite3.connect(db_path) as conn:
        return conn.execute("SELECT count(*) FROM venya_config").fetchone()[0]


class TestFloorUnit:
    """The decision, at the one place that makes it."""

    def test_the_ruled_numbers_live_in_two_named_constants(self):
        assert MIN_PASSPHRASE_CODE_POINTS == 15
        assert MAX_PASSPHRASE_CODE_POINTS == 64

    @pytest.mark.parametrize(
        "value", [_SHORT_BYTES, _SHORT_STR, _BELOW, _ACCENTED_14], ids=["bytes-9", "str-13", "14", "14-accented"]
    )
    def test_below_the_floor_is_flagged(self, value):
        assert is_passphrase_below_floor(value) is True

    @pytest.mark.parametrize("value", [_AT_FLOOR, _LEGAL_BYTES, _AT_CEILING, _OVER_CEILING, _SPACED, _ACCENTED_15])
    def test_at_and_above_the_floor_is_not_flagged(self, value):
        assert is_passphrase_below_floor(value) is False

    def test_blank_is_not_supplied_never_too_short(self):
        """The shipped #570 answer keeps its own question. The floor must not pre-empt it."""
        for blank in _BLANKS:
            assert is_passphrase_below_floor(blank) is False, f"{blank!r} is 'not supplied', not 'too short'"

    def test_code_points_not_bytes(self):
        """15 accented characters pass where a byte-measuring floor would wave them by,
        and 14 of them (28 UTF-8 bytes) still refuse — both halves in one place."""
        assert len(_ACCENTED_14) == 14
        assert len(_ACCENTED_14.encode("utf-8")) == 28
        assert is_passphrase_below_floor(_ACCENTED_14) is True
        assert is_passphrase_below_floor(_ACCENTED_14.encode("utf-8")) is True
        assert is_passphrase_below_floor(_ACCENTED_15) is False
        assert is_passphrase_below_floor(_ACCENTED_15.encode("utf-8")) is False

    def test_the_sentence_carries_the_ruled_digits_and_no_library_voice(self):
        message = short_passphrase_refusal()
        assert f"at least {MIN_PASSPHRASE_CODE_POINTS} characters" in message
        # #675 AC3: the ceiling is a documented PERMIT (owner OPTION 1 / clause C2), so the
        # sentence must read as an allowance and not as a limit. The old cell asserted
        # "up to 64 characters", which is the wording the row calls inaccurate about its own
        # enforcement; this asserts the ruled replacement instead.
        assert f"longer than {MAX_PASSPHRASE_CODE_POINTS} characters are accepted too" in message
        assert "not a maximum it enforces" in message
        for voice in _BINDING_VOICES:
            assert voice not in message, f"the binding's own sentence reached the refusal: {voice!r}"

    def test_the_refusal_never_echoes_the_value_or_its_length(self):
        typed = "short-passphrase-that-i-typed"
        message = short_passphrase_refusal()
        assert typed not in message
        assert f"{len(typed)} characters" not in message

    def test_read_variant_is_the_blessed_block_minus_one_clause(self):
        write_text = short_passphrase_refusal()
        read_text = short_passphrase_refusal(read_path=True)
        assert " Nothing was written." in write_text
        assert "Nothing was written." not in read_text
        assert read_text == write_text.replace(
            " Nothing was written.", "", 1
        ), "exactly one clause moves between the doors — no other wording differs"

    def test_floor_flip_moves_the_stated_number(self, monkeypatch):
        """AC5 non-vacuity: the text reads the constant the door measures with."""
        import core.engine.backend as backend_mod

        monkeypatch.setattr(backend_mod, "MIN_PASSPHRASE_CODE_POINTS", 5)
        message = backend_mod.short_passphrase_refusal()
        assert "at least 5 characters" in message
        assert "at least 15 characters" not in message


class TestBootGateDoor:
    """The boot gate: refuse, and let nothing exist that could derive later."""

    def test_bytes_intake_below_floor_refuses_with_the_floor_text(self):
        with pytest.raises(BackendConfigurationError) as excinfo:
            BackendConfig(database_url=_DB_URL, passphrase=_SHORT_BYTES)
        assert str(excinfo.value) == short_passphrase_refusal()

    def test_str_intake_below_floor_refuses_the_same_way(self):
        """The real boot path hands a ``str`` (``server/dependencies.py`` ``init_db()``),
        so a gate that only caught bytes would fix the unit test and miss the boot."""
        with pytest.raises(BackendConfigurationError) as excinfo:
            BackendConfig(database_url=_DB_URL, passphrase=_SHORT_STR)
        assert str(excinfo.value) == short_passphrase_refusal()

    def test_blank_still_answers_with_the_570_sentence_byte_identical(self):
        """The paired negative that keeps the floor from replacing #570: blank is not
        supplied, and it says so in the shipped words, not the floor's."""
        expected = _not_supplied_message()
        for blank in ["", " ", "   ", "\t", b"", b" ", b"\t\n"]:
            with pytest.raises(BackendConfigurationError) as excinfo:
                BackendConfig(database_url=_DB_URL, passphrase=blank)
            assert str(excinfo.value) == expected, "blank must answer exactly as unset does"

    def test_legal_length_is_stored_byte_for_byte_and_derives_the_same_key(self):
        """DENY, never TRIM, on this plane: a legal passphrase whose spaces are content is
        stored as it arrived and still derives the key it always derived."""
        config = BackendConfig(database_url=_DB_URL, passphrase=_SPACED.encode("utf-8"))
        assert config.passphrase == _SPACED.encode("utf-8")
        salt = b"\x07" * 16
        assert derive_kek(config.passphrase, salt) == derive_kek(_SPACED.encode("utf-8"), salt)

    def test_sixty_five_is_accepted_at_the_gate(self):
        """OPTION 1, the negative half of the ceiling: nothing refuses above 64."""
        assert BackendConfig(database_url=_DB_URL, passphrase=_OVER_CEILING).passphrase == _OVER_CEILING

    def test_raw_kek_intake_is_not_a_passphrase_and_still_builds(self):
        """The boundary of the ruling: the intake slot is machine-written key material,
        and a blank or absent passphrase keeps its shipped meaning there."""
        assert BackendConfig(database_url=_DB_URL, kek=b"\xbb" * 32).kek == b"\xbb" * 32
        config = BackendConfig(database_url=_DB_URL, passphrase=b"   ", kek=b"\xbb" * 32)
        assert config.passphrase is None, "the blank is dropped before the floor asks"

    def test_refusal_creates_nothing(self, tmp_path):
        """Write-door half: a refused boot value leaves no database, no table, no salt row."""
        db_path = tmp_path / "never-created.db"
        with pytest.raises(BackendConfigurationError):
            BackendConfig(database_url=f"sqlite:///{db_path}", passphrase=_SHORT_BYTES)
        assert not db_path.exists(), "the gate touched the filesystem"

    def test_a_refused_config_cannot_be_built_into_a_backend(self):
        """Proved by assignment, like #570's N3b: if the constructor returned, `config`
        would be bound and a later ``bootstrap_kek`` could derive from the weak value."""
        config = None
        with pytest.raises(BackendConfigurationError):
            config = BackendConfig(database_url=_DB_URL, passphrase=_SHORT_BYTES)
        assert config is None


class TestDeriveDoor:
    """``bootstrap_kek`` is the only way a passphrase becomes a KEK. It asks too."""

    def test_override_below_floor_refuses_with_the_read_wording(self, tmp_path):
        backend = _booted_sqlite_backend(tmp_path, "derive.db", _LEGAL_BYTES)
        before = _db_file_rows(tmp_path / "derive.db")

        with pytest.raises(BackendConfigurationError) as excinfo:
            backend.bootstrap_kek(_SHORT_BYTES)
        assert str(excinfo.value) == short_passphrase_refusal(read_path=True)
        assert "Nothing was written." not in str(excinfo.value), "this door is not writing"

        assert _db_file_rows(tmp_path / "derive.db") == before, "the refusal changed stored state"

    def test_get_core_override_below_floor_refuses_too(self, tmp_path):
        """The shape ``server/app.py`` uses at boot — ``get_core(config.db.passphrase)``
        — so the boot path is floored even when the config gate was passed a raw KEK."""
        backend = _booted_sqlite_backend(tmp_path, "getcore.db", _LEGAL_BYTES)

        with pytest.raises(BackendConfigurationError):
            backend.get_core(passphrase=_SHORT_STR)

    def test_legal_override_still_derives_and_still_opens_the_stored_secret(self, tmp_path):
        """The paired positive, so no refusal above is green because derivation is dead:
        the key derived from a legal passphrase unwraps what it sealed."""
        backend = _booted_sqlite_backend(tmp_path, "roundtrip.db", _LEGAL_BYTES)
        session = backend.get_session()
        try:
            stored = session.query(Secret).one()
        finally:
            session.close()
        with backend.kek_cache.view() as kek:
            dek = unwrap_key(bytes(kek), stored.wrapped_dek)
        assert len(dek) == 32

    def test_ceilings_flip_moves_no_door(self, monkeypatch, tmp_path):
        """MAX 64→63 accepts the same values: the constant exists only to state the limit."""
        import core.engine.backend as backend_mod

        monkeypatch.setattr(backend_mod, "MAX_PASSPHRASE_CODE_POINTS", 63)
        for phrase in (_AT_CEILING, _OVER_CEILING):
            assert BackendConfig(database_url=_DB_URL, passphrase=phrase).passphrase == phrase

    def test_floor_flip_turns_the_at_floor_cell_red(self, monkeypatch):
        """Non-vacuity on the DOOR, not just the sentence: raise MIN and 15 refuses."""
        import core.engine.backend as backend_mod

        monkeypatch.setattr(backend_mod, "MIN_PASSPHRASE_CODE_POINTS", 16)
        with pytest.raises(BackendConfigurationError):
            BackendConfig(database_url=_DB_URL, passphrase=_AT_FLOOR)

    def test_no_derivation_and_no_binding_call_on_refusal(self, monkeypatch):
        """The mechanism, not the message: a refused value never reaches the KDF, so no
        Argon2 binding sentence can surface and no weak KEK is ever produced. The paired
        positive is in the same cell — a legal value DOES reach the KDF — so this cannot
        be green because derivation is dead.

        The session is the stand-in from ``tests/test_kek_salt.py`` (a persisted salt row,
        no database), because the assertion is about what the gate lets through, not about
        storage.
        """
        from unittest.mock import MagicMock

        calls: list[bytes] = []

        def _spy(passphrase, salt=None):
            calls.append(passphrase)
            return b"\x00" * 32, salt

        monkeypatch.setattr("core.engine.backend.derive_kek", _spy)
        with pytest.raises(BackendConfigurationError):
            BackendConfig(database_url=_DB_URL, passphrase=_SHORT_BYTES)
        assert calls == [], "a derivation ran with a below-floor passphrase"

        backend = Backend(BackendConfig(database_url=_DB_URL, kek=b"\xcc" * 32))
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = MagicMock(value=b"\x07" * 16)
        backend.get_session = lambda: mock_session
        backend.bootstrap_kek(_LEGAL_BYTES)
        assert calls == [_LEGAL_BYTES], "the legal value never reached the KDF"


class TestStoredStateIsUntouchedByARefusal:
    """AC-3 read half, on real rows: refusing loads nothing and re-wraps nothing."""

    def test_stored_envelope_and_sentinel_are_untouched_by_a_refusal(self, tmp_path):
        backend = _booted_sqlite_backend(tmp_path, "preserve.db", _LEGAL_BYTES)
        db_path = tmp_path / "preserve.db"

        session = backend.get_session()
        try:
            secret_before = session.query(Secret).one().wrapped_dek
            sentinel_before = session.query(KekSentinel).one().wrapped_sentinel
        finally:
            session.close()
        salt_bytes_before = db_path.read_bytes()

        with pytest.raises(BackendConfigurationError):
            backend.bootstrap_kek(_SHORT_BYTES)

        session = backend.get_session()
        try:
            assert session.query(Secret).one().wrapped_dek == secret_before
            assert session.query(KekSentinel).one().wrapped_sentinel == sentinel_before
        finally:
            session.close()
        assert db_path.read_bytes() == salt_bytes_before, "a refused derivation wrote to the database"

    def test_the_working_key_still_proves_the_sentinel_afterwards(self, tmp_path):
        """Anti-false-green: after the refusal above the plane is still alive — the real
        KEK unwraps the sentinel, so the refusals above were the gate, not a dead path."""
        backend = _booted_sqlite_backend(tmp_path, "alive.db", _LEGAL_BYTES)
        session = backend.get_session()
        try:
            row = session.query(KekSentinel).one()
        finally:
            session.close()
        with backend.kek_cache.view() as kek:
            assert unwrap_key(bytes(kek), row.wrapped_sentinel) == b"kek-sentinel-known-plaintext-v1!"

    def test_a_mismatched_legal_passphrase_keeps_the_304_verdict_not_this_one(self, tmp_path):
        """The neighbour arm keeps its own identity: a legal-but-wrong passphrase is the
        #304 sentinel-mismatch case, not a length refusal. This leg must not relabel it."""
        from core.iam.models import VenyaConfig

        backend = _booted_sqlite_backend(tmp_path, "mismatch.db", _LEGAL_BYTES)
        session = backend.get_session()
        try:
            salt = session.query(VenyaConfig).filter(VenyaConfig.key == "kek_salt").first().value
            check = verify_kek_sentinel(session, derive_kek(b"another-legal-passphrase-573", salt)[0])
            assert check.status is SentinelStatus.MISMATCH, "a wrong-but-legal key is the #304 arm"
            assert verify_kek_sentinel(session, _current_kek(backend)).status is SentinelStatus.MATCH
        finally:
            session.close()


def test_fixture_values_are_the_lengths_the_cells_claim():
    """Vacuity guard: the parametrised literals above are counted in code points, and the
    short ones are short BY MATERIAL, not by being blank — otherwise a refusal cell could
    pass on the #570 arm and the floor would be untested."""
    assert (
        len(_SHORT_BYTES.decode()) == 9
        and len(_SHORT_STR) == 13
        and len(_BELOW) == 14
        and len(_AT_FLOOR) == 15
        and len(_OVER_CEILING) == 65
    )
    for value in (_SHORT_BYTES, _SHORT_STR, _BELOW, _ACCENTED_14):
        assert value.strip() != (b"" if isinstance(value, bytes) else ""), "a 'short' fixture was blank"
