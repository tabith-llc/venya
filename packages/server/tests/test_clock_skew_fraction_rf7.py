# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-7 chunk 1 — clock-skew tolerance as a fraction of a 60-minute life.

RF-6 §5.3: the default ``cert_tolerance_seconds`` was 300 — free of
consequence against a 90-day cert, +8.3 % against the ruled 60-minute theft
window (§1.2 ruling 4a). The value is lowered to 60 s (1.7 %), and the
relationship is asserted rather than remembered: one cell reads the lifetime
constant and the tolerance default and goes red if tolerance > lifetime/20.

Constant-coupling is the point — a future lane raising one number without
the other trips this file, per §5.1: "a tolerance that is large relative to
the lifetime converts the theft window into a suggestion."
"""

import pytest
from pydantic import ValidationError
from server.ca import ADMIN_SHORT_CERT_LIFETIME_SECONDS
from server.config import ClockSkewConfig

# §5.3's bound: tolerance may be at most one twentieth of the lifetime.
_FRACTION_DIVISOR = 20


def _violates_fraction(tolerance_seconds: int, lifetime_seconds: int) -> bool:
    return tolerance_seconds > lifetime_seconds / _FRACTION_DIVISOR


class TestToleranceFractionInterlock:
    def test_default_pair_satisfies_the_fraction(self):
        """The live cell: default tolerance vs the ruled short-cert lifetime.
        Any lane that raises one number and not the other turns this red."""
        tolerance = ClockSkewConfig().cert_tolerance_seconds
        assert not _violates_fraction(tolerance, ADMIN_SHORT_CERT_LIFETIME_SECONDS), (
            f"cert_tolerance_seconds={tolerance} exceeds lifetime "
            f"({ADMIN_SHORT_CERT_LIFETIME_SECONDS})/{_FRACTION_DIVISOR} — RF-6 §5.1/§5.3"
        )

    def test_fraction_predicate_catches_the_old_default(self):
        """Negative half, in-suite and permanent: the pair BEFORE this change
        (300 s against a 60-minute life) is exactly what the interlock exists
        to reject. If this cell ever goes green-by-accident, the predicate —
        not the numbers — is broken."""
        assert _violates_fraction(300, ADMIN_SHORT_CERT_LIFETIME_SECONDS)
        # And the new default passes the same predicate (both halves, one cell).
        assert not _violates_fraction(60, ADMIN_SHORT_CERT_LIFETIME_SECONDS)

    def test_lifetime_constant_is_the_ruled_60_minutes(self):
        """Ruling 4a pins the number itself: 3600 s. A silent lifetime edit
        without re-running §5.3's arithmetic is caught here first."""
        assert ADMIN_SHORT_CERT_LIFETIME_SECONDS == 3600


class TestToleranceBoundsUnchanged:
    def test_default_is_60(self):
        """The dossier value (§5.3: ≤ 60 s), RF-7's owned choice, pinned."""
        assert ClockSkewConfig().cert_tolerance_seconds == 60

    def test_ge_zero_still_admitted_and_enforced(self):
        """§5.6 row: tolerance 0 is a legal strict window — and the ge=0 floor
        still refuses negative (the truth-table half)."""
        assert ClockSkewConfig(cert_tolerance_seconds=0).cert_tolerance_seconds == 0
        with pytest.raises(ValidationError):
            ClockSkewConfig(cert_tolerance_seconds=-1)

    def test_le_600_bound_kept(self):
        """The le= stays: it is a deployment-sizing ceiling (operators on slow
        hardware may dial UP, §5.3's direction-asymmetry note); only the
        DEFAULT moved. Negative half: above the ceiling refuses."""
        assert ClockSkewConfig(cert_tolerance_seconds=600).cert_tolerance_seconds == 600
        with pytest.raises(ValidationError):
            ClockSkewConfig(cert_tolerance_seconds=601)

    def test_token_knob_is_untouched(self):
        """§5.5's do-not-unify rule, asserted: the token tolerance keeps its
        own default — this change lowered the CERT knob only."""
        assert ClockSkewConfig().token_tolerance_seconds == 60
