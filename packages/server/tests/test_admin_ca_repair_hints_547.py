# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#547 follow-up — every path that tells an operator to run ``venya admin
init-admin-ca`` must name the variable that command now requires.

#547 (landed) made ``init-admin-ca`` REFUSE when ``VENYA_ADMIN_CA_KEY_PASSPHRASE``
is unset or empty. Two server-side repair hints named that command without naming
the requirement, so an operator following the hint walked straight into the refusal
— a dead end, the same class RF-8a/RF-8b closes on the CLI surface.

Both halves are checked, per the paired-negative rule: the shipped text names the
variable (positive), and the pre-#547 text does NOT (the verification seat is proven to bite
rather than passing on everything).

Mechanism of verification matters here, so nothing in this file re-types the
message it is checking:
  * the admin-CA 503 comes from calling the real route helper,
  * the startup hint comes from ``inspect.getsource`` of the real ``lifespan``,
  * the negative half runs the same predicate over the OLD strings on purpose.
"""

import inspect
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from server.app import lifespan
from server.routes.admin_certs import _get_admin_ca_manager

PASSPHRASE_ENV = "VENYA_ADMIN_CA_KEY_PASSPHRASE"
COMMAND = "venya admin init-admin-ca"

# The two hints BEFORE #547 named the command and nothing else. Kept here only as
# the negative half — see TestNegativeOldTextFails.
_OLD_APP_HINT = "admin_mtls.enabled but admin CA not found at admin-ca/. Run: venya admin init-admin-ca"
_OLD_ROUTE_HINT = (
    "Admin CA is not initialized — cannot sign. Repair: venya admin init-admin-ca "
    "(the core installer runs it during installation)."
)


def _names_the_requirement(text: str) -> bool:
    """True when a repair hint names BOTH the command and the variable it now needs.

    Order is part of the contract (#547 wording law): say what to set, then what to
    run — so the variable has to appear before the command it gates.
    """
    return PASSPHRASE_ENV in text and text.find(PASSPHRASE_ENV) < text.find(COMMAND)


class TestStartupHintNamesTheRequirement:
    """``lifespan`` raises when admin_mtls is enabled and the admin CA is missing."""

    def test_shipped_startup_hint_names_the_variable(self):
        src = inspect.getsource(lifespan)
        anchor = "admin_mtls.enabled but admin CA not found"
        window = " ".join(src[src.index(anchor) - 40 : src.index(anchor) + 400].split())
        assert PASSPHRASE_ENV in window, f"startup hint does not name {PASSPHRASE_ENV}: {window!r}"
        assert COMMAND in window, f"startup hint does not name the command: {window!r}"
        assert _names_the_requirement(window), f"hint must say what to set before what to run: {window!r}"

    def test_startup_hint_still_carries_its_own_subject(self):
        """The hint must remain recognizable as the admin_mtls/CA-missing abort."""
        assert "admin_mtls.enabled but admin CA not found" in inspect.getsource(lifespan)


class TestAdminCaMissing503NamesTheRequirement:
    """The signing route's 503 detail is the mid-session repair hint."""

    def _request_without_admin_ca(self) -> SimpleNamespace:
        state = SimpleNamespace()  # no admin_ca_manager attribute at all
        return SimpleNamespace(app=SimpleNamespace(state=state))

    def test_503_detail_names_the_variable(self):
        with pytest.raises(HTTPException) as excinfo:
            _get_admin_ca_manager(self._request_without_admin_ca())
        assert excinfo.value.status_code == 503
        detail = excinfo.value.detail
        assert PASSPHRASE_ENV in detail, f"503 repair hint does not name {PASSPHRASE_ENV}: {detail!r}"
        assert _names_the_requirement(detail), f"hint must say what to set before what to run: {detail!r}"

    def test_503_detail_still_names_the_command(self):
        with pytest.raises(HTTPException) as excinfo:
            _get_admin_ca_manager(self._request_without_admin_ca())
        assert COMMAND in excinfo.value.detail
        assert "Admin CA is not initialized" in excinfo.value.detail


class TestNegativeOldTextFails:
    """The predicate bites: the pre-#547 wording is rejected, so the two cells above
    are not passing on an always-true check."""

    @pytest.mark.parametrize("old_text", [_OLD_APP_HINT, _OLD_ROUTE_HINT], ids=["app-hint", "route-503"])
    def test_old_hint_without_the_requirement_is_rejected(self, old_text):
        assert old_text.count(COMMAND) == 1, "fixture drift: the old hints do name the command"
        assert not _names_the_requirement(old_text)
        assert PASSPHRASE_ENV not in old_text

    def test_hint_naming_the_variable_after_the_command_is_rejected(self):
        """Setting order is enforced: naming the var only AFTER the command is the
        same dead end (the operator runs first, refuses second)."""
        assert not _names_the_requirement(f"Run {COMMAND}; it needs {PASSPHRASE_ENV} set")
