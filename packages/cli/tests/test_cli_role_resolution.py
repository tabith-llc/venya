# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Role name resolution for the five role subcommands (ticket cli-role-name-and-comma-defects).

Help advertises "Role ID or name" on role get/delete/members/add-member/
remove-member; the handlers previously interpolated the raw arg into the
int-validated /api/v1/roles/{role_id} path, so every name died at 422.
Truth table: P1 name form resolves + forwards the id, N1 unresolvable name
is a clean error (no 422 dump), N2 int form unchanged (no lookup call),
A3 the help name-claim pins to the shared resolver's use in every handler.
"""

import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli import cli, commands

ROLE_HANDLERS = [
    "cmd_role_get",
    "cmd_role_delete",
    "cmd_role_members",
    "cmd_role_add_member",
    "cmd_role_remove_member",
]

ROLE_LIST = {
    "roles": [
        {"id": 7, "name": "compliance-auditor", "permissions": "read", "description": None, "member_count": 0},
        {"id": 2, "name": "user", "permissions": "read", "description": None, "member_count": 0},
    ]
}


def _args(role_id="Compliance-Auditor"):
    return SimpleNamespace(role_id=role_id, user_id="u1", json=False)


def _client_for(handler, role_id):
    """MagicMock client pre-loaded so the resolved (int-form) call succeeds."""
    client = MagicMock()
    if handler in ("cmd_role_get", "cmd_role_members"):
        detail = {"id": 7, "name": "compliance-auditor"} if handler == "cmd_role_get" else {"members": []}
        client.get.side_effect = ([ROLE_LIST] if not role_id.isdigit() else []) + [detail]
    elif not role_id.isdigit():
        client.get.return_value = ROLE_LIST
    if role_id.isdigit() and handler not in ("cmd_role_get", "cmd_role_members"):
        client.get.side_effect = AssertionError("int form must not list roles")
    return client


def _forwarded_target(client, handler, role_id):
    """URL of the action request (the one that is NOT the /api/v1/roles lookup)."""
    method = (
        client.get
        if handler in ("cmd_role_get", "cmd_role_members")
        else client.post if handler == "cmd_role_add_member" else client.delete
    )
    lookups = [c[0][0] for c in client.get.call_args_list if c[0][0] == "/api/v1/roles"]
    actions = [c[0][0] for c in method.call_args_list if c[0][0] != "/api/v1/roles"]
    assert len(actions) == 1, f"expected exactly one action call, got {actions}"
    return lookups, actions[0]


class TestP1NameResolves:
    """P1: each of the five handlers resolves a (case-folded) NAME to its id."""

    @pytest.mark.parametrize("handler", ROLE_HANDLERS)
    def test_name_form_forwards_resolved_id(self, handler, capsys):
        client = _client_for(handler, "Compliance-Auditor")
        rc = getattr(commands, handler)(client, _args())
        assert rc == 0, f"{handler} failed: {capsys.readouterr().err}"
        lookups, target = _forwarded_target(client, handler, "Compliance-Auditor")
        assert lookups == ["/api/v1/roles"], "name form must resolve via GET /api/v1/roles"
        assert "/roles/7" in target, f"{handler} must forward resolved id 7, got {target}"


class TestN1UnresolvableName:
    """N1: unknown name -> clean error naming the lookup, never a raw 422."""

    @pytest.mark.parametrize("handler", ROLE_HANDLERS)
    def test_unknown_name_clean_error(self, handler, capsys):
        client = MagicMock()
        client.get.return_value = ROLE_LIST
        rc = getattr(commands, handler)(client, _args(role_id="no-such-role"))
        err = capsys.readouterr().err
        assert rc == 1
        assert "no-such-role" in err, f"error must name the failed lookup: {err!r}"
        assert "422" not in err and "int_parsing" not in err, f"raw 422 dump: {err!r}"
        client.post.assert_not_called()
        if handler != "cmd_role_get":
            client.delete.assert_not_called()
        action_gets = [c for c in client.get.call_args_list if c[0][0] != "/api/v1/roles"]
        assert not action_gets


class TestN2IntFormRegression:
    """N2: int-id form is untouched — forwarded verbatim, NO roles-list lookup."""

    @pytest.mark.parametrize("handler", ROLE_HANDLERS)
    def test_int_form_no_lookup(self, handler, capsys):
        client = _client_for(handler, "7")
        rc = getattr(commands, handler)(client, _args(role_id="7"))
        assert rc == 0, f"{handler} failed: {capsys.readouterr().err}"
        lookups, target = _forwarded_target(client, handler, "7")
        assert lookups == [], f"int form must not trigger a name lookup: {lookups}"
        assert "/roles/7" in target


class TestA3HelpResolverPin:
    """A3: the 'Role ID or name' help claim lives ONLY if resolution exists."""

    def test_name_claim_requires_shared_resolver(self):
        assert "Role ID or name" in inspect.getsource(
            cli.create_parser
        ), "help no longer advertises names — update this pin with the help"
        for name in ROLE_HANDLERS:
            src = inspect.getsource(getattr(commands, name))
            assert "_resolve_role_id(" in src, f"{name} advertises 'Role ID or name' but never calls _resolve_role_id"
