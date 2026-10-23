# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""`venya audit --json` (ticket audit-json-empty-case-unparseable):
byte-exact envelope passthrough of the GET /api/v1/audit response —
parseable even when the vault is empty (branch BEFORE the empty check;
same ordering as cmd_list, ticket cli-list-json-output)."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.commands import cmd_audit


def _args(**over):
    base = {
        "user": None,
        "key": None,
        "start_date": None,
        "end_date": None,
        "days": None,
        "hours": None,
        "limit": 100,
        "offset": 0,
        "json": False,
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_audit_json_empty_is_parseable(capsys):
    """T1: zero events with --json -> parseable envelope, events == []."""
    client = MagicMock()
    envelope = {"events": [], "total": 0, "limit": 100, "offset": 0}
    client.get.return_value = envelope
    rc = cmd_audit(client, _args(json=True))
    assert rc == 0
    out = capsys.readouterr().out
    # The contract of --json: parseable even when the vault is empty.
    # (RED on base: out is the human string "No audit events found."
    # and json.loads rejects it.)
    assert json.loads(out) == envelope
    assert json.loads(out)["events"] == []
    # Byte-exact passthrough — the CLI adds no field.
    assert out == json.dumps(envelope, indent=2) + "\n"


def test_audit_json_prints_exact_envelope(capsys):
    """T2: non-empty --json is byte-identical to the pre-fix passthrough."""
    client = MagicMock()
    envelope = {
        "events": [
            {
                "id": 1,
                "event_type": "secret_read",
                "user_id": "u1",
                "fields": None,
                "timestamp": "2026-10-01T00:00:00+00:00",
            }
        ],
        "total": 1,
        "limit": 100,
        "offset": 0,
    }
    client.get.return_value = envelope
    rc = cmd_audit(client, _args(json=True))
    assert rc == 0
    out = capsys.readouterr().out
    # Byte-identical to the pre-fix behavior: json.dumps(result, indent=2).
    assert out == json.dumps(envelope, indent=2) + "\n"


def test_audit_empty_without_json_prints_human_string(capsys):
    """T3-empty / N1 paired negative: empty WITHOUT --json prints exactly
    the pinned human string — the fix touches the JSON contract only,
    not the human text."""
    client = MagicMock()
    client.get.return_value = {"events": [], "total": 0, "limit": 100, "offset": 0}
    rc = cmd_audit(client, _args())
    assert rc == 0
    out = capsys.readouterr().out
    assert out == "No audit events found.\n"


def test_audit_without_json_renders_human_table(capsys):
    """T3-non-empty: human path unchanged (pinned line format)."""
    client = MagicMock()
    client.get.return_value = {
        "events": [
            {
                "id": 1,
                "event_type": "secret_read",
                "user_id": "u1",
                "fields": None,
                "timestamp": "2026-10-01T00:00:00+00:00",
            }
        ],
        "total": 1,
        "limit": 100,
        "offset": 0,
    }
    rc = cmd_audit(client, _args())
    assert rc == 0
    out = capsys.readouterr().out
    assert out == "  [2026-10-01T00:00:00+00:00] secret_read (user: u1)\n"
    # Paired negative: the human rendering is NOT JSON.
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)
