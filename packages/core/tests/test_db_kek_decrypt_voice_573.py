# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#573 core-plane companion — the DB-KEK failure arms speak in OUR words (voice row).

The #572/#574 class rule (R8-ADDENDUM, decisions.md commit dd1de4c, and #541's blanket
rule behind it) is that an operator-facing refusal must carry our sentence and NONE of the
crypto library's. Both landed rows proved it on the CA plane — the CLI loader (`572`) and
``server/ca.py`` ``_deserialize_key`` (`574`). Nobody proved it on this plane, so the
composition here was unproven: a defect could ship a raw library string through the DB-KEK
path and no cell would notice.

This file closes that gap with paired negatives, and every banned string was READ OFF A
LIVE PROBE at this base, not from memory (the same discipline #574's docstring states).
Measured at base `cd9bb72` with the pinned bindings (cryptography + argon2-cffi +
pycryptodome):

    cryptography.exceptions.InvalidTag            -> "" (empty message)
    ChaCha20Poly1305.decrypt(wrong key)          -> InvalidTag: ""
    AES-KW unwrap under a wrong KEK              -> DecryptionError: our sentence
    argon2 hash_secret_raw(secret=str)           -> TypeError: "initializer for ctype
                                                     'uint8_t[]' must be a bytes or list
                                                     or tuple, not str"
    argon2 hash_secret_raw(short salt)           -> HashingError: "Salt is too short"

The last two are the binding's own words. Where this plane composes a refusal, they must
not appear; where the plane lets one through by construction, that is recorded as a
finding below and NOT adopted as a posture.

Negative half of every cell: the correct key still unwraps and still decrypts, so a green
here means the guard works, not that the crypto path died.
"""

import pytest
from core.engine.backend import (
    SENTINEL_PLAINTEXT,
    SentinelStatus,
    verify_kek_sentinel,
)
from core.engine.encryption import (
    KEK_SIZE,
    DecryptionError,
    EncryptionError,
    KeyDerivationError,
    decrypt_secret,
    derive_kek,
    encrypt_secret,
    unwrap_key,
    wrap_key,
)

_SALT = b"\x11" * 16
_RIGHT = b"right-passphrase-for-voice-probe"
_WRONG = b"wrong-passphrase-for-voice-probe"

#: The binding's own sentences, transcribed from the probe above. None of these may
#: appear in anything this plane raises at an operator.
_BINDING_VOICES = (
    "initializer for ctype",
    "must be a bytes or list or tuple",
    "Salt is too short",
    "HashingError",
    "InvalidTag",
    "mac check",
    "digest failed",
)


def _assert_our_voice(message: str) -> None:
    """The ruled invariant, as an assertion: our words, and none of the binding's."""
    for voice in _BINDING_VOICES:
        assert voice not in message, f"the binding's own sentence reached the refusal: {voice!r}"


class TestUnwrapAndDecryptVoice:
    """The two crypto failure arms every DB secret funnels through."""

    def test_unwrap_under_wrong_kek_is_our_sentence(self):
        wrapped = wrap_key(derive_kek(_RIGHT, _SALT)[0], b"\x22" * 32)

        with pytest.raises(EncryptionError) as excinfo:
            unwrap_key(derive_kek(_WRONG, _SALT)[0], wrapped)

        assert isinstance(excinfo.value, DecryptionError), "the arm raises our type, not the binding's"
        assert str(excinfo.value) == "Unwrap failed: integrity check failed (wrong key)"
        _assert_our_voice(str(excinfo.value))

    def test_unwrap_under_wrong_kek_still_rejects_the_right_key_case(self):
        """The paired positive half: the guard did not kill the working path."""
        kek = derive_kek(_RIGHT, _SALT)[0]
        wrapped = wrap_key(kek, b"\x22" * 32)
        assert unwrap_key(kek, wrapped) == b"\x22" * 32

    def test_bad_sizes_are_our_sentence_not_the_bindings(self):
        """Length guards read OUR wording, including the count, so no ctype text lands."""
        with pytest.raises(KeyDerivationError) as short_kek:
            unwrap_key(b"\x00" * 8, b"\x00" * 40)
        assert str(short_kek.value) == f"KEK must be {KEK_SIZE} bytes, got 8"
        _assert_our_voice(str(short_kek.value))

        with pytest.raises(KeyDerivationError) as bad_env:
            unwrap_key(b"\x00" * KEK_SIZE, b"\x00" * 5)
        assert str(bad_env.value) == f"Wrapped key must be {KEK_SIZE + 8} bytes, got 5"
        _assert_our_voice(str(bad_env.value))

    def test_decrypt_secret_surfaces_our_type_never_invalidtag(self):
        """The AEAD arm: `InvalidTag` carries an EMPTY message, so a leak of the binding's
        type here would reach an operator as a colon with nothing after it. The plane
        converts it — that is what this cell pins."""
        kek = derive_kek(_RIGHT, _SALT)[0]
        wrapped_dek, nonce, ciphertext = encrypt_secret(kek, b"a-secret-value")

        with pytest.raises(DecryptionError) as excinfo:
            decrypt_secret(derive_kek(_WRONG, _SALT)[0], wrapped_dek, nonce, ciphertext)
        assert "Unwrap failed" in str(excinfo.value)
        _assert_our_voice(str(excinfo.value))

        # the binding's own exception type must not be what escapes the function
        with pytest.raises(DecryptionError):
            decrypt_secret(kek, wrapped_dek, nonce, b"corpus-crafted-bytes")

    def test_decrypt_secret_round_trip_still_works(self):
        """Paired positive: the conversion above did not break the honest path."""
        kek = derive_kek(_RIGHT, _SALT)[0]
        wrapped_dek, nonce, ciphertext = encrypt_secret(kek, b"a-secret-value")
        assert decrypt_secret(kek, wrapped_dek, nonce, ciphertext) == b"a-secret-value"


class TestSentinelStatusDoesNotRaiseTheBinding:
    """The boot proof (#304) reports a STATUS; it never lets a binding error escape."""

    def _session(self, wrapped_sentinel: bytes, secrets: list[bytes] | None = None):
        """A stand-in session carrying one sentinel row and optional DEK envelopes."""
        from core.iam.models import KekSentinel, Secret

        class _Query:
            def __init__(self, rows, columns):
                self._rows, self._columns = rows, columns

            def filter(self, *_a, **_k):
                return self

            def first(self):
                return self._rows[0] if self._rows else None

            def limit(self, _n):
                return self

            def all(self):
                return [tuple(r) for r in self._rows]

        class _Session:
            def __init__(self, sentinel_row, secret_rows):
                self._tables = {
                    KekSentinel: ([sentinel_row] if sentinel_row else [], "wrapped_sentinel"),
                    Secret: (secret_rows, "wrapped_dek"),
                }

            def query(self, model):
                # ``verify_kek_sentinel`` asks for the COLUMN (``Secret.wrapped_dek``) in the
                # legacy arm and for the MODEL (``KekSentinel``) in the sentinel arm, so both
                # spellings have to land on the same table.
                key = getattr(model, "parent", None)
                table = model if key is None else getattr(key, "class_", model)
                rows, columns = self._tables[table]
                return _Query(rows, columns)

        sentinel_row = KekSentinel(key="kek_sentinel", wrapped_sentinel=wrapped_sentinel) if wrapped_sentinel else None
        return _Session(sentinel_row, [(w,) for w in (secrets or [])])

    def test_mismatch_is_a_status_object_with_no_binding_text(self):
        right = derive_kek(_RIGHT, _SALT)[0]
        envelope = wrap_key(right, SENTINEL_PLAINTEXT)

        assert verify_kek_sentinel(self._session(envelope), derive_kek(_WRONG, _SALT)[0]).status is (
            SentinelStatus.MISMATCH
        )
        # and the matching half, so the arm above is not green because unwrap is dead
        assert verify_kek_sentinel(self._session(envelope), right).status is SentinelStatus.MATCH

    def test_legacy_all_fail_is_a_status_not_an_exception(self):
        right = derive_kek(_RIGHT, _SALT)[0]
        envelopes = [wrap_key(right, b"\x33" * KEK_SIZE) for _ in range(3)]
        session = self._session(None, envelopes)

        check = verify_kek_sentinel(session, derive_kek(_WRONG, _SALT)[0])
        assert check.status is SentinelStatus.LEGACY_MISMATCH
        assert check.failures == len(envelopes)
        # paired positive: the right KEK unwraps every sampled envelope
        assert verify_kek_sentinel(session, right).status is SentinelStatus.LEGACY_OK

    def test_fresh_empty_install_reports_nothing_to_verify(self):
        assert verify_kek_sentinel(self._session(None, []), b"\x00" * KEK_SIZE).status is SentinelStatus.FRESH_EMPTY


class TestLatentStrIntakeArm_isAFindingNotAPosture:
    """CHARACTERIZATION — a real gap on this plane, recorded so it is not mistaken for
    approved wording. The DB-KEK config intake accepts BOTH typing conventions
    (``server/dependencies.py`` ``init_db`` hands in a ``str``; ``factory.from_dict``
    encodes first), and the binding's raw ``TypeError`` is what surfaces if a ``str``
    ever reaches ``derive_kek`` — e.g. ``Backend(config_holding_a_str).bootstrap_kek()``
    with no argument, which ``Backend.get_core(None)`` takes for a passphrase-only
    config. That is binding voice, and under #572/#574's rule it is non-compliant.

    This cell pins today's behavior so a future guard has something to turn RED
    against; it does NOT bless the sentence. Filed to the lead as a follow-up row.
    """

    def test_str_reaching_the_binding_surfaces_its_own_words(self):
        with pytest.raises(TypeError) as excinfo:
            derive_kek("not-encoded-first", _SALT)  # type: ignore[arg-type]

        message = str(excinfo.value)
        assert "initializer for ctype" in message, (
            "the binding's sentence changed shape — re-read the probe in this file's docstring "
            "and repair the characterization, do not delete it"
        )
        # and the compliant arm beside it: encoded first, the same secret derives fine
        assert derive_kek(b"not-encoded-first", _SALT)[0] is not None
