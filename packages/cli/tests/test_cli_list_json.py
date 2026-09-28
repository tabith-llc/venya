# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""`venya list --json` (ticket cli-list-json-output): byte-exact envelope
passthrough of the GET /api/v1/secrets response — parseable even when the
store is empty (branch BEFORE the empty check; the cmd_audit human-string
quirk is flagged in-ticket, not copied)."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.commands import cmd_list


def _args(**over):
    base = {"prefix": None, "executor": None, "purpose": None, "username": None, "json": False}
    base.update(over)
    return SimpleNamespace(**base)


def test_list_json_prints_exact_envelope(capsys):
    client = MagicMock()
    envelope = {"secrets": [{"key": "db/pass", "metadata": {"shape": "ssh-password"}}]}
    client.get.return_value = envelope
    rc = cmd_list(client, _args(json=True))
    assert rc == 0
    out = capsys.readouterr().out
    # Exact passthrough: parseable AND equal to the API envelope — the CLI
    # adds no field (and the list schema carries keys+metadata, never values).
    assert json.loads(out) == envelope


def test_list_json_empty_is_parseable(capsys):
    client = MagicMock()
    client.get.return_value = {"secrets": []}
    rc = cmd_list(client, _args(json=True))
    assert rc == 0
    out = capsys.readouterr().out
    # Paired negative vs the cmd_audit quirk: NOT the human string.
    assert json.loads(out) == {"secrets": []}
    assert "No secrets found." not in out


def test_list_without_json_flag_renders_human_table(capsys):
    client = MagicMock()
    client.get.return_value = {"secrets": [{"key": "k1", "metadata": {"shape": "askpass"}}]}
    rc = cmd_list(client, _args())
    assert rc == 0
    out = capsys.readouterr().out
    assert "k1" in out and "shape=askpass" in out
    # Paired negative: the human rendering is NOT JSON.
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)
