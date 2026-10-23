# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""The ONE canonical representation of an X.509 certificate serial number.

Ticket ``cert-serial-canonicalization-mismatch`` (GitLab #481): the same logical
serial was WRITTEN zero-padded (``format(serial, "016x")``) and PRESENTED
unpadded (``format(serial, "x")``), and every revocation lookup compared the two
by exact string equality. A 64-bit random serial has a zero leading nibble in
1/16 of cases, so those certificates could be revoked — ``revoked=True``, an
audit row and a log line all asserting success — and the revocation never took
effect.

The ruled shape (ticket acceptance criteria 1-2):

* WRITE in one form: lowercase hex, zero-padded to a minimum of
  ``SERIAL_HEX_MIN_WIDTH`` digits (16 — the 8-byte serials ``secrets.token_bytes``
  mints). The width is a MINIMUM, not a mask: a serial that needs more digits
  keeps every digit. ``server.ca.CAManager.compute_serial_hex`` keeps its name
  and delegates here, so the padded precedent is this same definition.
* READ tolerantly: legacy rows exist in mixed spellings and no migration rewrites
  them, so enforcement compares ``serial_match_key`` values — the canonical form
  with leading zeros stripped and upper-cased. Stripping leading zeros of a hex
  rendering is the minimal spelling of the integer, so two keys are equal EXACTLY
  when the serials are: case and any padding count stop mattering.
* TOTAL, never an exception: a value that is not a hex serial (a hand-written or
  corrupt row) keys to its own upper-cased text, which carries a character no
  real serial key has — so garbage can neither crash an enforcement path nor be
  hit by accident, and a garbage revocation row can only match a garbage value.

Do not add a second ``format(..., "x")`` / ``format(..., "016x")`` site: import
``canonical_serial`` (write), ``serial_match_key`` / ``serial_match_clause``
(compare and lookup) and ``serials_equal`` (in-Python compare). ``venya-cli`` is
the deliberate exception — ``packages/cli/tests/test_capability_isolation.py``
bars that package from importing this one, and its serial writer (the value
printed for the operator to paste) already emits the canonical padded form.
"""

from typing import Any

SERIAL_HEX_MIN_WIDTH = 16

_ZERO = "0"


def parse_serial(value: Any) -> int | None:
    """Parse a serial of either type into its integer value.

    Args:
        value: An ``int`` serial (a certificate's ``serial_number``), or a hex
            string in any stored/provided spelling — case-insensitive, any
            padding, an optional ``0x``/``0X`` prefix and surrounding whitespace
            tolerated.

    Returns:
        The integer value, or ``None`` when the input is not a hex serial
        (negative, non-hex, empty). Never raises — see the module docstring.
    """
    if isinstance(value, int):
        return value if value >= 0 else None

    text = str(value).strip()
    if text[:2].lower() == "0x":
        text = text[2:]
    try:
        return int(text, 16)
    except ValueError:
        return None


def canonical_serial(value: Any) -> str:
    """Render a certificate serial in the ONE canonical form.

    Args:
        value: The serial as an ``int`` (preferred — from a certificate object)
            or as a hex string in any stored/provided spelling.

    Returns:
        Lowercase hex, zero-padded to at least ``SERIAL_HEX_MIN_WIDTH`` digits.
        A value that is not a hex serial comes back as its own casefolded text,
        which matches no canonicalized certificate serial.
    """
    parsed = parse_serial(value)
    if parsed is None:
        return str(value).strip().casefold() or _ZERO
    return format(parsed, f"0{SERIAL_HEX_MIN_WIDTH}x")


def serial_match_key(value: Any) -> str:
    """The case- and padding-insensitive key every spelling of a serial maps to.

    Args:
        value: A serial as an ``int`` or as a hex string.

    Returns:
        Uppercase hex with leading zeros stripped (a lone ``"0"`` for serial 0),
        so a row stored ``abcd1234``, ``ABCD1234`` or ``00000000abcd1234`` all
        key the same. A value that is not a hex serial keys to its own
        upper-cased text, which no certificate serial ever renders that way.
    """
    return (canonical_serial(value).lstrip(_ZERO) or _ZERO).upper()


def serials_equal(left: Any, right: Any) -> bool:
    """Case- and padding-insensitive equality of two serials of either type.

    Python-side comparisons (the incumbent-serial exemption, the F6
    replaced-serial check, the daemon's revocation-list membership test) use this
    instead of ``.casefold() ==`` so a legacy unpadded row does not read as a
    DIFFERENT credential than the certificate it names.

    Args:
        left: A serial as an ``int`` or hex string.
        right: A serial as an ``int`` or hex string.

    Returns:
        True when both name the same serial (or both are the same non-serial
        text), False otherwise.
    """
    return serial_match_key(left) == serial_match_key(right)


def serial_match_clause(column: Any, value: Any) -> Any:
    """SQLAlchemy equality predicate matching a serial column in ANY spelling.

    ``UPPER(TRIM(LEADING '0' FROM column))`` renders as ``ltrim(upper(col), '0')``
    in both engines this product runs on — SQLite in the unit suites, PostgreSQL
    in deployment — so one helper serves every enforcement lookup, and the
    database does the matching instead of a fetched-and-scanned row set.

    Applying a function to the column makes the predicate non-sargable: the same
    shape the admin-mTLS lookup already had (it compared ``func.upper(...)``), on
    tables that are CRL-capped and — since #685 (owner ruling 2026-10-20) — NOT
    retention-bounded any more: `ExecutorCertRevocation` is exempt from time-based purge, so
    the executor population grows for the life of the DB and this scan does not self-limit.
    That is the price of not aging revoked credentials out on a timer, and it was accepted on
    purpose; the operator consequence is `docs/revocation-table-operations-runbook.md` §2a.
    A lookup error here stays fail-closed at the call site, as before.

    Args:
        column: A ``serial_number`` column of a certificate/revocation model.
        value: The serial to match, as an ``int`` or hex string.

    Returns:
        A SQLA boolean expression for use in ``.filter(...)``.
    """
    from sqlalchemy import func

    return func.ltrim(func.upper(column), _ZERO) == serial_match_key(value)
