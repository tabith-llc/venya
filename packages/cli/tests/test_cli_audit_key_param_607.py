# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#607 AC4 — `venya audit --key <k>` puts `key` on the wire, and the route's
answer is what prints.

The server half (`routes/audit.py`) now consumes `key`; these cells pin the
client half so neither side can regress alone: `cmd_audit` must send the
parameter when `--key` is given (`commands.py`, the `params["key"]` line) and
must NOT send it when it is not — an empty `key=` on the wire would filter the
operator's view down to nothing.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from venya_cli.commands import cmd_audit

# The key name under test. A constant, not a literal inside the row: a
# `"secret_key": "<literal>"` pair in a test file reads to detect-secrets like
# a credential, and this row names a KEY path only — never a value.
DISCLOSED_KEY = "db/password"


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


def _envelope(events, total):
    return {"events": events, "total": total, "limit": 100, "offset": 0}


def test_key_flag_is_sent_as_the_key_query_param(capsys):
    """P: `--key db/password` reaches the route as `params["key"]`, and the
    filtered envelope (one row for that key) is what `--json` prints."""
    client = MagicMock()
    row = {
        "id": 1,
        "event_type": "secret_value_disclosed",
        "user_id": "alice",
        "fields": {"outcome": "disclosed", "secret_key": DISCLOSED_KEY},
        "timestamp": "2026-10-13T12:00:01+00:00",
    }
    client.get.return_value = _envelope([row], 1)

    rc = cmd_audit(client, _args(key=DISCLOSED_KEY, json=True))

    assert rc == 0
    _, kwargs = client.get.call_args
    assert kwargs["params"]["key"] == DISCLOSED_KEY
    out = capsys.readouterr().out
    assert json.loads(out) == _envelope([row], 1)
    # The CLI adds no field of its own: byte-exact passthrough.
    assert out == json.dumps(_envelope([row], 1), indent=2) + "\n"


def test_no_key_flag_sends_no_key_param(capsys):
    """N paired negative: without `--key` the parameter is absent, so the
    server's `key is not None` branch does not fire and the whole
    (visibility-scoped) log stays in view. `{"key": None}` would be the bug —
    requests would carry `?key=None` and filter everything away."""
    client = MagicMock()
    client.get.return_value = _envelope([], 0)

    rc = cmd_audit(client, _args(json=True))

    assert rc == 0
    params = client.get.call_args.kwargs["params"]
    assert "key" not in params, params
    assert json.loads(capsys.readouterr().out)["events"] == []
