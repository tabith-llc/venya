# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Parity guard for the two executor_id validation copies.

`validate_executor_id` exists in both `venya_cli.executor_id` (client-side
pre-send validation) and `server.utils.executor_id` (server-side trust
boundary). The copies are deliberate (server must not depend on the CLI
package; CLI must stay standalone) but they MUST NOT diverge: a loosened
server copy would accept IDs the client never sends, a tightened one would
reject valid enrollments. Any change to either module must be applied to
both — this test fails otherwise.

Ticket: executor-id-dual-copy-drift.
"""

import inspect

import pytest
from server.utils import executor_id as server_mod
from venya_cli import executor_id as cli_mod

# Shared case table: (value, expect_valid)
CASES = [
    ("ab", True),
    ("a-b", True),
    ("venya-exec-1", True),
    ("jump-1", True),
    ("a1", True),
    ("x" * 64, True),  # max length, all-alnum
    ("a" + "-b" * 31 + "c", True),  # exactly 64 chars with hyphens
    ("a", False),  # too short
    ("x" * 65, False),  # too long
    ("-ab", False),  # leading hyphen
    ("ab-", False),  # trailing hyphen
    ("Ab", False),  # uppercase
    ("a_b", False),  # underscore
    ("a.b", False),  # dot
    ("a b", False),  # space
    ("", False),  # empty
]


class TestExecutorIdParity:
    def test_constants_identical(self):
        assert cli_mod.EXECUTOR_ID_PATTERN == server_mod.EXECUTOR_ID_PATTERN
        assert cli_mod.EXECUTOR_ID_MIN_LENGTH == server_mod.EXECUTOR_ID_MIN_LENGTH
        assert cli_mod.EXECUTOR_ID_MAX_LENGTH == server_mod.EXECUTOR_ID_MAX_LENGTH

    def test_function_bytecode_identical(self):
        """Compiled code objects must match (docstrings may differ; code may not)."""
        c_cli = cli_mod.validate_executor_id.__code__
        c_srv = server_mod.validate_executor_id.__code__
        assert c_cli.co_code == c_srv.co_code
        assert c_cli.co_consts == c_srv.co_consts

    @pytest.mark.parametrize("value,valid", CASES)
    def test_shared_case_table(self, value, valid):
        for mod in (cli_mod, server_mod):
            if valid:
                assert mod.validate_executor_id(value) == value
            else:
                with pytest.raises(ValueError):
                    mod.validate_executor_id(value)

    @pytest.mark.parametrize("value,valid", CASES)
    def test_error_messages_identical(self, value, valid):
        """Both copies must raise byte-identical error messages."""
        if valid:
            return
        msgs = []
        for mod in (cli_mod, server_mod):
            try:
                mod.validate_executor_id(value)
                msgs.append(None)
            except ValueError as e:
                msgs.append(str(e))
            except TypeError:
                msgs.append("TypeError")
        assert msgs[0] == msgs[1], f"message drift for {value!r}: {msgs}"

    def test_non_string_rejected_identically(self):
        for mod in (cli_mod, server_mod):
            with pytest.raises(ValueError):
                mod.validate_executor_id(None)

    def test_sources_differ_only_in_docstring(self):
        """Tripwire for structural drift beyond the constants/bytecode checks."""

        def strip_doc(src: str) -> str:
            lines = [ln for ln in src.splitlines() if ln.strip() and not ln.strip().startswith("#")]
            out, in_doc = [], False
            for ln in lines:
                if not in_doc and ln.startswith(('"""', "'''")):
                    if ln.count('"""') >= 2 or ln.count("'''") >= 2:
                        continue
                    in_doc = True
                    continue
                if in_doc:
                    if '"""' in ln or "'''" in ln:
                        in_doc = False
                    continue
                out.append(ln)
            return "\n".join(out)

        assert strip_doc(inspect.getsource(cli_mod)) == strip_doc(inspect.getsource(server_mod))

    def test_inspect_signature_matches(self):
        assert inspect.signature(cli_mod.validate_executor_id) == inspect.signature(server_mod.validate_executor_id)
