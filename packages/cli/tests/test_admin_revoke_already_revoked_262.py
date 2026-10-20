# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""`admin revoke-admin-cert` must report which of the two things happened (leg 262).

The route is idempotent and answers a repeat call with `revoked=true` **and**
`already_revoked=true`, carrying the reason that is ON RECORD rather than the one typed into
this call. Before this row the CLI discarded the response body and printed
`Certificate <serial> revoked (reason: <typed reason>)` on both arms, so an operator could not
tell "this call did it" from "it was already done" — and on the repeat arm the printed reason was
the wrong one's provenance. Same class as the two sentences corrected for the executor plane at
`fcd1b34c`, and the same rule (#666): transport success is not semantic success.

**Paired negatives are the point.** The `already_revoked` cell alone could be satisfied by
suppressing every success message — which would be the same reporting failure in the other
direction — so the fresh-revocation arm and the missing-field arm are driven too. Exit status is
asserted UNCHANGED on every arm: this is a reporting fix, and the no-op-exits-zero question is a
separate row.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.commands import cmd_admin_revoke_admin_cert

SERIAL = "0a1b2c3d4e5f6789"  # pragma: allowlist secret — a test cert serial, not a credential
SERVER = "https://core.test:443"


def _client(post_result):
    """A client whose POST returns exactly `post_result` — the body the core sent back."""
    client = MagicMock()
    client.config.server_url = SERVER
    client.post.return_value = post_result
    return client


def _args(reason="key compromised"):
    return SimpleNamespace(serial=SERIAL, reason=reason, server_url=SERVER)


@pytest.fixture(autouse=True)
def _env_isolated(monkeypatch):
    """The handler reads VENYA_SERVER_URL when no --server-url is given; pin it off."""
    monkeypatch.delenv("VENYA_SERVER_URL", raising=False)


def test_already_revoked_arm_reports_no_change_and_not_a_new_revocation(capsys):
    """Negative half: an idempotent repeat must not read as though this call revoked anything."""
    client = _client({"serial": SERIAL, "revoked": True, "reason": "old reason on record", "already_revoked": True})

    assert cmd_admin_revoke_admin_cert(client, _args()) == 0, capsys.readouterr().err
    out = capsys.readouterr().out

    assert "was already revoked (no change)" in out, out
    assert f"revoked (reason: {SERIAL}" not in out, out
    # The sentence the defect printed. Asserting its ABSENCE is what makes this cell fail
    # against the old code, and keeps it failing if anyone reintroduces the unconditional form.
    assert "revoked (reason: key compromised)" not in out, out
    # The reason ON RECORD is not this call's reason, so it must not be passed off as such.
    assert "old reason on record" not in out, out


def test_fresh_revocation_still_reads_as_a_revocation(capsys):
    """Positive half of the pair: a confirmed new revocation keeps its success line.

    Without this cell the negative arm could be satisfied by muting every success message, which is
    the failure `flash5` explicitly guarded against on the sibling class.
    """
    client = _client({"serial": SERIAL, "revoked": True, "reason": "key compromised", "already_revoked": False})

    assert cmd_admin_revoke_admin_cert(client, _args()) == 0, capsys.readouterr().err
    out = capsys.readouterr().out

    assert f"Certificate {SERIAL} revoked (reason: key compromised)" in out, out
    assert "already revoked" not in out, out


def test_absent_field_is_read_as_a_fresh_revocation_not_a_crash(capsys):
    """The `already_revoked` field defaults to False on the route, and an older core may omit it.

    A missing key must land on the success arm, not raise — the guard `(result or {})` is what this
    cell exists to keep honest, alongside the empty-body case below.
    """
    client = _client({"serial": SERIAL, "revoked": True, "reason": "key compromised"})

    assert cmd_admin_revoke_admin_cert(client, _args()) == 0, capsys.readouterr().err
    out = capsys.readouterr().out
    assert "revoked (reason: key compromised)" in out, out
    assert "already revoked" not in out, out


def test_empty_body_is_read_as_a_fresh_revocation(capsys):
    """`APIClient._request` returns `{}` when the response carries no content (api_client.py:1016)."""
    client = _client({})

    assert cmd_admin_revoke_admin_cert(client, _args()) == 0, capsys.readouterr().err
    out = capsys.readouterr().out
    assert f"Certificate {SERIAL} revoked (reason: key compromised)" in out, out
    assert "already revoked" not in out, out


def test_repeat_call_still_posts_the_operators_serial_and_reason(capsys):
    """The fix is on the READ side only — the request the route validates is unchanged."""
    client = _client({"serial": SERIAL, "revoked": True, "already_revoked": True})

    cmd_admin_revoke_admin_cert(client, _args())
    client.post.assert_called_once()
    url, kwargs = client.post.call_args[0][0], client.post.call_args[1]
    assert url.endswith("/api/v1/admin/certs/revoke"), url
    assert kwargs["json"] == {"serial": SERIAL, "reason": "key compromised"}, kwargs["json"]
