# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#482 drift guard: CLI reads must stay inside their route's response model.

FastAPI serializes a handler return THROUGH the declared ``response_model``,
so a key the model does not declare never reaches the wire. Two commands
shipped reads of such phantom keys (``admin re-enroll`` reading ``status``,
``credential add`` reading ``label``) — the operator saw a blank or a
self-echoed field and the unit fixtures hid it by mocking the phantom.

This file pins the class, not just the two instances:

1. ``TestResponseKeyDriftGuard`` extracts every ``.get('<key>', ...)`` read
   from the live command source (``inspect.getsource`` — line numbers rot,
   the function body does not) and asserts each key is a field of that
   route's response model. The field set is derived from the model class
   (``model_fields`` / ``__annotations__``), never a hand-maintained list —
   a hand list would be a second copy that drifts. Subscript reads
   (``result["key"]``) are out of scope here; those wire pairs are pinned
   server-side (e.g. ``test_credentials.py`` asserting ``credential_label``).

2. ``test_serial_format_parity`` is the #481 carry-in cell: the naive
   ``format(cert.serial_number, "016x")`` and the shared
   ``core.utils.cert_serial.canonical_serial`` must agree on int serials.
   Importing ``core`` from a cli TEST is sanctioned (the capability-isolation
   scan covers ``venya_cli`` product source only — ruled in #481's close,
   note 3965893509).
"""

import inspect
import re
from types import SimpleNamespace
from typing import ClassVar

import pytest
from core.utils.cert_serial import canonical_serial
from server.routes.admin import AdminReEnrollResponse
from server.routes.credentials import CredentialAddCompleteResponse
from venya_cli import commands

# Matches .get('key' / .get("key" — the literal-key form used across
# commands.py response reads. getattr(...) and .get(k) variable lookups
# never match (no quote after the paren).
_GET_KEY_RE = re.compile(r"""\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""")

# (command function, response model its route declares) — the pairs in
# scope for #482. A new command needing this guard gets a row here; the
# assertion itself stays model-derived.
DRIFT_CASES = [
    pytest.param(commands.cmd_admin_re_enroll, AdminReEnrollResponse, id="admin_re_enroll"),
    pytest.param(commands.cmd_credential_add, CredentialAddCompleteResponse, id="credential_add"),
]


def _model_field_names(model) -> set:
    """Field names straight from the pydantic model class (no hand list)."""
    fields = getattr(model, "model_fields", None)
    if fields:
        return set(fields)
    return set(model.__annotations__)


def _response_get_keys(func) -> set:
    """Every literal key the command .get()s, read from live source."""
    source = inspect.getsource(func)
    return set(_GET_KEY_RE.findall(source))


class TestResponseKeyDriftGuard:
    @pytest.mark.parametrize("func, model", DRIFT_CASES)
    def test_every_get_key_is_a_model_field(self, func, model):
        reads = _response_get_keys(func)
        assert reads, f"{func.__name__} reads no .get() keys — guard lost its target"
        fields = _model_field_names(model)
        phantom = reads - fields
        assert not phantom, (
            f"{func.__name__} reads {sorted(phantom)} but "
            f"{model.__name__} declares {sorted(fields)} — FastAPI serializes "
            f"through the model, so the phantom key never reaches the wire."
        )

    @pytest.mark.parametrize("func, model", DRIFT_CASES)
    def test_guard_reads_the_expected_surface(self, func, model):
        """Teeth tripwire: the extraction must see the response reads at all.
        If someone renames the response variable or switches to subscripts
        wholesale, the parametrized guard above could pass vacuously —
        this pins that the known keys are still found by the extractor."""
        reads = _response_get_keys(func)
        if func is commands.cmd_admin_re_enroll:
            assert {"user_id", "status", "credentials_deactivated", "tokens_revoked"} <= reads
        else:
            assert {"credential_label"} <= reads


class TestSerialFormatParity481:
    """#481 carry-in cell: 016x format == canonical_serial on int serials."""

    # A small set spanning: zero, tiny, the classic 8-byte serial, a serial
    # wider than the 16-hex-digit minimum (padding is a MINIMUM, not a mask),
    # and the 2**64 boundary.
    SERIALS: ClassVar[list[int]] = [0, 1, 0xABCD1234, 0xDEADBEEFCAFE, 2**64 - 1, 2**64, 2**128 - 1]

    @pytest.mark.parametrize("serial", SERIALS)
    def test_format_016x_matches_canonical_serial(self, serial):
        cert = SimpleNamespace(serial_number=serial)
        assert format(cert.serial_number, "016x") == canonical_serial(cert.serial_number)
