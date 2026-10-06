# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Unit cells for the ONE canonical certificate-serial representation (#481).

Ticket ``cert-serial-canonicalization-mismatch``: the same logical serial was
written zero-padded and presented unpadded, and every revocation lookup compared
the two by exact string equality — so ~1/16 of certificates (those whose serial
has a zero leading nibble) could be revoked with the revoke call reporting
success, and the revocation never took effect.

These cells pin the helper the writers and readers share (acceptance criterion
3f: ``canonical_serial`` is idempotent over padded/unpadded/upper/lower — the
four forms map to one key). The enforcement halves are in
``packages/server/tests/test_admin_mtls.py`` (admin mTLS, real SQLite) and
``packages/server/tests/test_executor_revocation_identity.py`` (executor
serial-form revocation).
"""

from core.utils.cert_serial import canonical_serial, parse_serial, serial_match_clause, serial_match_key, serials_equal

# A serial whose canonical hex has a zero leading nibble — the #481 slice.
PADDED = "0a1b2c3d4e5f6071"
UNPADDED = "a1b2c3d4e5f6071"
INT_VALUE = int(PADDED, 16)

# The four spellings legacy revocation rows hold (acceptance criterion 2).
LEGACY_FORMS = (PADDED, PADDED.upper(), UNPADDED, UNPADDED.upper())


class TestCanonicalSerial:
    def test_int_serial_renders_padded_lowercase(self):
        """The canonical form: 16-char lowercase zero-padded hex."""
        assert canonical_serial(INT_VALUE) == PADDED

    def test_every_legacy_spelling_canonicalizes_to_one_value(self):
        """3f idempotence, half one: all four stored spellings canonicalize the same."""
        for form in LEGACY_FORMS:
            assert canonical_serial(form) == PADDED, form

    def test_canonical_serial_is_idempotent(self):
        """3f idempotence, half two: re-rendering a canonical value changes nothing."""
        once = canonical_serial(INT_VALUE)
        assert canonical_serial(once) == once
        for form in LEGACY_FORMS:
            twice = canonical_serial(canonical_serial(form))
            assert twice == canonical_serial(form), form

    def test_match_key_collapses_all_four_forms(self):
        """The lookup key is what makes the mixed legacy rows matchable."""
        keys = {serial_match_key(form) for form in LEGACY_FORMS}
        assert keys == {serial_match_key(INT_VALUE)}
        assert serial_match_key(INT_VALUE) == UNPADDED.upper()

    def test_prefix_padding_counts_never_change_the_key(self):
        """Extra leading zeros (any count) key the same — the key is the integer."""
        for width in (1, 2, 5, 15):
            assert serial_match_key("0" * width + UNPADDED) == serial_match_key(INT_VALUE)

    def test_different_serials_never_share_a_key(self):
        """Truth table (negative half): padding tolerance must not become a
        prefix match — a leading-zero serial is not confused with its neighbor."""
        assert serial_match_key(PADDED) != serial_match_key("0999999999999999")
        assert serial_match_key(INT_VALUE) != serial_match_key(INT_VALUE + 1)
        assert not serials_equal(PADDED, "0999999999999999")

    def test_serials_equal_tolerates_spelling_across_types(self):
        """int-vs-string and case-vs-padding compare equal; different values do not."""
        assert serials_equal(INT_VALUE, PADDED)
        assert serials_equal(INT_VALUE, UNPADDED.upper())
        assert not serials_equal(INT_VALUE, INT_VALUE + 1)

    def test_width_is_a_minimum_not_a_mask(self):
        """A serial wider than 16 hex digits keeps every digit — no truncation."""
        wide = 0x1234567890ABCDEF1234567890ABCDEF
        assert canonical_serial(wide) == "1234567890abcdef1234567890abcdef"
        assert serial_match_key(wide) == "1234567890ABCDEF1234567890ABCDEF"

    def test_non_serial_text_keys_outside_the_serial_space(self):
        """A garbage value can never be hit by a real certificate serial, and
        never raises: enforcement paths compare it and simply find no match."""
        garbage = "cert-123"
        assert parse_serial(garbage) is None
        assert canonical_serial(garbage) == garbage
        assert serial_match_key(garbage) != serial_match_key(INT_VALUE)
        assert not serials_equal(garbage, INT_VALUE)
        # A garbage row still compares to itself (idempotent, no exception).
        assert serials_equal(garbage, garbage)

    def test_empty_and_negative_inputs_are_not_serials(self):
        """Never raises, never matches a real certificate serial."""
        for value in ("", "   ", -1, "0xzz"):
            assert parse_serial(value) is None, value
            assert serial_match_key(value) != serial_match_key(INT_VALUE), value

    def test_hex_prefix_input_is_accepted(self):
        """A 0x-prefixed spelling parses as the same serial (writers never emit
        it, but a hand-written legacy row or an operator paste must not crash)."""
        assert canonical_serial("0x" + PADDED) == PADDED
        assert serials_equal("0X" + UNPADDED, INT_VALUE)


class TestSerialMatchClause:
    def test_clause_compares_case_and_padding_insensitively_on_real_sqlite(self):
        """The SQL half of #481: ``ltrim(upper(col),'0')`` is evaluated by the
        database (SQLite here, PostgreSQL in deployment — the same two-argument
        ltrim), so mixed legacy spellings all match one certificate."""
        from core.iam.models import AdminCertRevocation, Base
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import sessionmaker

        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine, tables=[AdminCertRevocation.__table__])
        Session = sessionmaker(bind=engine)
        with Session() as s:
            for form in LEGACY_FORMS:
                s.add(AdminCertRevocation(serial_number=form, reason="row-per-spelling"))
            s.add(AdminCertRevocation(serial_number="0999999999999999", reason="different-serial"))
            s.add(AdminCertRevocation(serial_number="not-a-serial", reason="garbage-row"))
            s.commit()

            # One row per spelling is stored as given (no migration rewrites them)...
            assert s.query(AdminCertRevocation).count() == 6
            # ...and all four resolve to the SAME revocation through the clause.
            hits = (
                s.query(AdminCertRevocation)
                .filter(serial_match_clause(AdminCertRevocation.serial_number, INT_VALUE))
                .all()
            )
            assert {h.reason for h in hits} == {"row-per-spelling"}
            assert len(hits) == 4  # one per spelling — all four ARE this serial

            # Negative halves: a different serial and an empty value find nothing.
            assert (
                s.query(AdminCertRevocation)
                .filter(serial_match_clause(AdminCertRevocation.serial_number, "0999999999999998"))
                .all()
                == []
            )
            assert (
                s.query(AdminCertRevocation).filter(serial_match_clause(AdminCertRevocation.serial_number, "")).all()
                == []
            )
            # A non-serial value compares to the non-serial ROW (same text) and
            # never to a certificate serial — the SQL side normalizes case and
            # padding exactly the way serial_match_key does.
            garbage_hits = (
                s.query(AdminCertRevocation)
                .filter(serial_match_clause(AdminCertRevocation.serial_number, "not-a-serial"))
                .all()
            )
            assert [g.reason for g in garbage_hits] == ["garbage-row"]
            assert serials_equal("not-a-serial", "NOT-A-SERIAL") is True

            # The clause is a plain selectable expression too (no ORM surprises).
            rows = s.execute(
                select(AdminCertRevocation.serial_number).where(
                    serial_match_clause(AdminCertRevocation.serial_number, UNPADDED.upper())
                )
            ).all()
            assert sorted(r[0] for r in rows) == sorted(LEGACY_FORMS)
