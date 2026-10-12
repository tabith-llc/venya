# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#570 — the DB KEK boot gate answers "not supplied" for a whitespace passphrase.

The defect, in one sentence: a `VENYA_DB_PASSPHRASE` made only of spaces passed every
"was a passphrase supplied?" test in the tree, so it derived a LIVE key-encryption-key
from one space character and wrapped every DB secret under it. That is not a
confidentiality-only bug. ``KekPassphraseMismatchError`` in ``backend.py`` says the
consequence outright: a wrong passphrase derives a working KEK for NEW wrappings and can
NEVER unwrap existing ones — so the state is permanently unrecoverable, and the operator
learns about it only after the data is already wrapped (#304's sentinel).

The gate that decides the question is ``BackendConfig.__init__``, and as shipped it asked
it with an IDENTITY test:

    if passphrase is None and kek is None:

``b" "`` is not ``None``. One space sailed through. The fix asks the materiality question
the CA plane already asks (#554 ``server/ca.py`` ``_load_passphrase()``, #547 the CLI
predicate): a value with nothing but whitespace in it is *not supplied*, and it gets the
**same raise with the same message** — no new operator-facing sentence was authored, and
none is needed, because "no material" and "not set" are one answer to this command.

Deny, never trim (#554 again, and the load-bearing half of this file): the decision looks
at a stripped copy; the value itself is stored byte-for-byte, so a passphrase whose spaces
are CONTENT (`b" sword "`) still opens the database it sealed. A trim here would have
silently changed what a legitimate passphrase is and locked a real deployment out of its
own KEK — which is why the positive cells assert the stored bytes, not just the return
code.

Both halves of the truth table are paired in the same cell wherever they can be: the
blank refuses AND nothing derives.
"""

import inspect

import pytest
from core.engine.backend import Backend, BackendConfig, BackendConfigurationError

# Dev-only synthetic values (the same family #547/#554/#537 cells already record). Never
# real, never a live credential.
REAL_PASSPHRASE = b" test db passphrase 570 "
_DB_URL = "postgresql://test/test"

# The shipped sentence is read from the None case at run time (see _none_case_message),
# never retyped here, so an edit to the wording moves both halves of every comparison
# together instead of leaving a stale literal that pins the old text.


def _none_case_message() -> str:
    """The message the unset-passphrase case produces today."""
    try:
        BackendConfig(database_url=_DB_URL, passphrase=None)
    except BackendConfigurationError as exc:
        return str(exc)
    raise AssertionError("the None case stopped raising — the premise of every cell here")


class TestBlankIsUnsetAtTheGate:
    """N1 + N2 — the whitespace shapes, both typing conventions, one answer."""

    @pytest.mark.parametrize(
        "blank",
        [b" ", b"   ", b"\t", b"\n", b" \t \n ", b"\r\n"],
        ids=["space", "spaces3", "tab", "newline", "mixed", "crlf"],
    )
    def test_n1_bytes_blank_refuses_with_the_none_message(self, blank):
        """The refuse half — and the message is the UNSET message, asserted as equal."""
        expected = _none_case_message()
        with pytest.raises(BackendConfigurationError) as excinfo:
            BackendConfig(database_url=_DB_URL, passphrase=blank)
        assert str(excinfo.value) == expected, "blank must answer exactly as unset does"

    @pytest.mark.parametrize("blank", [" ", "   ", "\t"], ids=["space", "spaces3", "tab"])
    def test_n2_str_blank_refuses_the_same_way(self, blank):
        """The same shapes as ``str``, because that is what the real boot path hands in.

        Measured, not assumed: ``server/config.py`` types ``DatabaseConfig.passphrase`` as
        ``str | None`` and ``server/dependencies.py`` ``init_db()`` forwards
        ``db_config.passphrase`` into this constructor, so production arrives as ``str``
        while the annotation says ``bytes``. A gate that only caught bytes would fix the
        unit test and miss the boot.
        """
        expected = _none_case_message()
        with pytest.raises(BackendConfigurationError) as excinfo:
            BackendConfig(database_url=_DB_URL, passphrase=blank)
        assert str(excinfo.value) == expected

    def test_n3_nothing_derives_and_no_session_is_touched(self):
        """The paired negative on the mechanism, not on the message.

        Refusing is half the claim; "nothing derives" is the other half, and it is proved
        on the path that would actually derive. A blank passphrase alongside a raw KEK
        builds a backend, and taking the core from it must return the RAW key with no
        session opened — because the only way to derive from a passphrase is
        ``bootstrap_kek`` → ``ensure_kek_salt``, and that needs a database. So the session
        getter is the tripwire: any derivation attempt fails the cell, not just the log.

        At base this is the shape that wrapped real secrets: a blank value that survived
        the gate reached ``derive_kek`` and produced a live KEK from one space.
        """
        raw_kek = b"\xcc" * 32
        config = BackendConfig(database_url=_DB_URL, passphrase=b" ", kek=raw_kek)
        backend = Backend(config)
        # The blank must not survive as the stored secret either: at base it was kept, and
        # `get_core()` then treats "a passphrase is configured" as true.
        assert config.passphrase is None, "the blank was kept as a passphrase on the config"

        def _no_session():
            raise AssertionError("a derivation was attempted — the blank reached the salt read")

        backend.get_session = _no_session
        core = backend.get_core()
        assert core.kek is backend.kek_cache
        with core.kek.view() as buf:
            assert bytes(buf) == raw_kek, "the stored key is not the raw KEK it was given"

    def test_n3b_a_blank_alone_never_becomes_a_config(self):
        """The same law, from the other side: with no raw KEK there is nothing to fall back
        on, so the blank is refused and no object exists that could derive later. Proved
        by assignment — if the constructor returns, `config` is bound; it is not, so the
        caller never gets a BackendConfig to hand to `Backend` and no engine, cache, or
        session is ever created for it.
        """
        config = None
        with pytest.raises(BackendConfigurationError):
            config = BackendConfig(database_url=_DB_URL, passphrase=b" ")
        assert config is None, "the gate let a blank-passphrase config exist"

    def test_n4_blank_passphrase_alongside_a_raw_kek_still_refuses_to_be_used(self):
        """No half-measure: the blank is not stored, so nothing downstream can derive with it.

        A raw KEK is a legitimate way in, and the intake path must keep working — but the
        blank value must not be handed to ``bootstrap_kek`` as if it were a secret.
        """
        kek = b"\xaa" * 32
        config = BackendConfig(database_url=_DB_URL, passphrase=b"   ", kek=kek)
        assert config.passphrase is None, "a whitespace-only value was kept as a passphrase"
        assert config.kek == kek, "the raw-KEK intake path moved"
        backend = Backend(config)
        # get_core on a raw-KEK backend must not go looking for a passphrase to derive from.
        assert backend.config.passphrase is None

    def test_n5_the_gate_is_one_materiality_test_not_a_per_call_site_copy(self):
        """Shape pin: the decision reads the stored value's material, and nothing trims it.

        The #554 lesson in code form — a ``.strip()`` that reaches the stored value is a
        different (and wrong) program from a ``.strip()`` that only answers the question.
        """
        source = inspect.getsource(BackendConfig.__init__)
        assert "passphrase.strip()" in source, "the gate must ask the materiality question"
        assert "if passphrase is None and kek is None:" in source, "the shipped raise stayed"
        assert "self.passphrase = passphrase.strip()" not in source, "the stored value may not be trimmed"
        assert "passphrase = passphrase.strip()" not in source, "the value may not be trimmed anywhere"
        assert not source.count("strip()") > 2, "no new per-site copies of this decision"


class TestRealPassphrasesAreUntouched:
    """P1 + P2 + P3 — DENY, never TRIM, on both sides of the stored value."""

    def test_p1_spaces_that_are_content_survive_byte_for_byte(self):
        """The cell that keeps this a DENY and not a TRIM.

        ``b" test db passphrase 570 "`` has real material and leading/trailing spaces that
        are part of the secret. It must construct, and the value it stores must be the
        bytes it was handed — a strip here would derive a DIFFERENT KEK from a working
        deployment's own passphrase and orphan every envelope it already wrote.
        """
        config = BackendConfig(database_url=_DB_URL, passphrase=REAL_PASSPHRASE)
        assert config.passphrase == REAL_PASSPHRASE, "the gate trimmed the secret"

    def test_p2_the_padded_passphrase_derives_the_key_the_bytes_derive(self):
        """Second half of the same law, on the derivation the operator depends on.

        The key must come from the untrimmed bytes. If anything ever strips on the way in,
        this is the cell that notices — because the stripped form is a different secret and
        derives a different key, and the deployment's stored envelopes open with only one
        of the two.
        """
        from core.engine.encryption import derive_kek

        salt = b"\x01" * 16
        config = BackendConfig(database_url=_DB_URL, passphrase=REAL_PASSPHRASE)
        kek_untrimmed, _ = derive_kek(config.passphrase, salt)
        kek_as_handed, _ = derive_kek(REAL_PASSPHRASE, salt)
        kek_stripped, _ = derive_kek(REAL_PASSPHRASE.strip(), salt)
        assert kek_untrimmed == kek_as_handed
        assert kek_untrimmed != kek_stripped, "a stripped derivation would be a new KEK"

    def test_p3_plain_passphrase_and_raw_kek_paths_unchanged(self):
        """The paths that were never broken: real bytes pass, a raw KEK passes, no
        passphrase at all refuses with the shipped sentence.

        #573 data flip (R5(c)): the passphrase literal here was two characters and was
        lengthened to a legal one, because the floor now refuses the short value. The
        assertion is unchanged in kind — a supplied, material, legal-length passphrase is
        stored byte-for-byte — and no check in this file was deleted or skipped.
        """
        assert BackendConfig(database_url=_DB_URL, passphrase=b"pw-573-legal-passphrase").passphrase == (
            b"pw-573-legal-passphrase"
        )
        assert BackendConfig(database_url=_DB_URL, kek=b"\xbb" * 32).kek == b"\xbb" * 32
        with pytest.raises(BackendConfigurationError) as excinfo:
            BackendConfig(database_url=_DB_URL, passphrase=None)
        assert str(excinfo.value) == _none_case_message()

    def test_p4_empty_bytes_still_read_as_the_falsy_half_not_a_new_answer(self):
        """A consequence of the fix, stated rather than hidden: empty bytes now refuse here too.

        The ticket's paired-negative section says the empty-string half was already caught
        upstream — at ``server/dependencies.py`` ``init_db()``, which forwards
        `passphrase if passphrase else None`, and at ``app.py``'s `if not
        config.db.passphrase`. Neither of those is this gate, and at the base THIS
        constructor accepted empty bytes: empty is not `None`, so the identity test waved it
        through. One materiality answer covers both shapes; that is what "not supplied"
        means. No shipped cell depended on the old acceptance — core and server are both
        green with it refusing — and this cell is the RED-at-base record that the behavior
        moved, so the widening is disclosed, not slipped.
        """
        with pytest.raises(BackendConfigurationError) as excinfo:
            BackendConfig(database_url=_DB_URL, passphrase=b"")
        assert str(excinfo.value) == _none_case_message()

    def test_p5_a_whitespace_kek_is_not_a_blank_passphrase(self):
        """The boundary of the ruled change, stated cold.

        This leg denies a blank PASSPHRASE. A raw KEK is checked by LENGTH, and
        ``b" " * 32`` is 32 bytes of material — it is not in scope here and it is not
        refused by this gate. Recorded so nobody "fixes" it by extending the predicate
        without a ruling: the intake slot is machine-written key material, not a
        human-supplied secret.
        """
        padded_kek = b" " * 32
        config = BackendConfig(database_url=_DB_URL, kek=padded_kek)
        assert config.kek == padded_kek
