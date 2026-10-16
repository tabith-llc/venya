# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#354 client half — secret-key and user_id path segments are URL-encoded.

quote(..., safe="") at every path site: crafted segments can no longer rewrite
the request path pre-normalization. Paired positive: ordinary keys/ids render
byte-identically (zero drift on the common path).
"""

from unittest.mock import MagicMock

from venya_cli import commands
from venya_cli.commands import (
    cmd_admin_configure,
    cmd_admin_issue_token,
    cmd_admin_list_tokens,
    cmd_admin_re_enroll,
    cmd_admin_remove,
    cmd_delete,
    cmd_get,
    cmd_role_remove_member,
    cmd_update_metadata,
)


def _args(**kw):
    return type("Args", (), kw)()


class TestPathEncoding354:
    def test_get_encodes_key(self):
        client = MagicMock()
        client.get.return_value = {"value": "x"}
        rc = cmd_get(client, _args(key="a/b", unmask=False))
        assert rc == 0
        assert client.get.call_args[0][0] == "/api/v1/secrets/a%2Fb"

    def test_delete_encodes_key(self):
        client = MagicMock()
        cmd_delete(client, _args(key="../x"))
        assert client.delete.call_args[0][0] == "/api/v1/secrets/..%2Fx"

    def test_patch_metadata_encodes_key_keeps_suffix(self):
        client = MagicMock()
        client.patch.return_value = {}
        cmd_update_metadata(client, _args(key="a/b", metadata=["purpose=t"], shape=None, usage=None))
        assert client.patch.call_args[0][0] == "/api/v1/secrets/a%2Fb/metadata"

    def test_admin_user_paths_encode_user_id(self, monkeypatch):
        client = MagicMock()
        client.get.return_value = {}
        client.post.return_value = {}
        client.delete.return_value = {}
        cmd_admin_remove(client, _args(user_id="a/b"))
        assert client.delete.call_args[0][0] == "/api/v1/admin/users/a%2Fb"
        # #625 leaves `configure-user` with no shipped setting, and an empty setting map refuses
        # LOCALLY — it never reaches the path builder this cell is about. One entry is injected
        # for the duration of this test so the PUT half of the #354 sweep stays covered.
        monkeypatch.setattr(commands, "_CONFIGURE_SETTINGS", (("display_name", "display_name"),))
        cmd_admin_configure(client, _args(user_id="x y", display_name="Ops", roles=None))
        assert client.put.call_args[0][0] == "/api/v1/admin/users/x%20y"
        cmd_admin_list_tokens(client, _args(user_id="a/b"))
        assert client.get.call_args[0][0] == "/api/v1/admin/users/a%2Fb/enrollment-tokens"
        cmd_admin_issue_token(client, _args(user_id="a/b"))
        assert client.post.call_args[0][0] == "/api/v1/admin/users/a%2Fb/enrollment-tokens"
        cmd_admin_re_enroll(client, _args(user_id="a/b"))
        assert client.post.call_args[0][0] == "/api/v1/admin/users/a%2Fb/re-enroll"

    def test_role_member_path_encodes_user_id(self):
        client = MagicMock()
        cmd_role_remove_member(client, _args(role_id="5", user_id="a/b"))
        assert client.delete.call_args[0][0] == "/api/v1/roles/5/members/a%2Fb"

    def test_normal_ids_byte_identical(self):
        # paired negative: the common path has ZERO drift
        client = MagicMock()
        client.get.return_value = {"value": "x"}
        cmd_get(client, _args(key="tier1_pw.venya-1", unmask=False))
        assert client.get.call_args[0][0] == "/api/v1/secrets/tier1_pw.venya-1"
