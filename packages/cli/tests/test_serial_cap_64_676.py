# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#676 — the CLI's serial cap is the STORE width (64), not 16, at all three doors.

The defect this pair of files closes: the CA mints 20-byte leaf serials, which render as
**40 hex characters**. `register` accepted such a credential, `list` PRINTED its serial, and
`revoke` then refused the exact string `list` had displayed — locally, at the CLI, before any
request left the machine. Net effect: no installer-minted relay credential was revocable by any
shipped verb. Unit fixtures minted short serials and could not see it, which is why the fixtures
are re-paired here rather than left alone.

Owner ruling s150c option 2 raised the cap to 64 — the width the ``serial_number`` columns
actually are (`String(64)` at `core/iam/models.py:372/:385/:619/:696`) — because
`canonical_serial` is int-based and #481 made 16 a write MINIMUM, never a ceiling.

Truth-table law (AGENTS.md): every gate gets its rejection half. The positive cells below are the
40-hex shape from the field, the 17-char value that used to be the negative case, and the exact
64-char width; the negatives are 65 (one past the store), non-hex, empty, whitespace-only and the
bare ``0x``. Each refusal is asserted to carry the NEW number in its message — a corrected gate
that still advertises "up to 16 chars" is a wrong fix twice over.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from venya_cli.commands import cmd_admin_core_relay_cert, cmd_admin_revoke_admin_cert, executor_cert_revoke

# The measured shape from the field: a prior lane's installer-minted leaf began 5803696f and ended f69d0b.
SERIAL_40 = "5803696f1234567890abcdef1234567890f69d0b"  # pragma: allowlist secret
SERIAL_64 = "f" * 64
TOO_LONG = "a" * 65


def _client() -> MagicMock:
    client = MagicMock()
    client.config.server_url = "https://core.test:443"
    client.post.return_value = {"already_revoked": False, "serial_number": SERIAL_40, "revoked": True}
    client.get.return_value = []
    return client


# --------------------------------------------------------------------------- positive halves


@pytest.mark.parametrize(
    "serial", [SERIAL_40, "0" * 17, "a" * 40, SERIAL_64], ids=["40-hex", "17-hex", "40-a", "64-hex"]
)
def test_admin_revoke_admin_cert_accepts_serials_at_the_raised_cap(serial, capsys, monkeypatch):
    """A 40-hex serial reaches the POST instead of dying in the local gate. That IS #676."""
    monkeypatch.delenv("VENYA_SERVER_URL", raising=False)
    client = _client()
    args = SimpleNamespace(serial=serial, reason="test", server_url="https://core.test:443")

    assert cmd_admin_revoke_admin_cert(client, args) == 0, capsys.readouterr().err
    client.post.assert_called_once()
    url, kwargs = client.post.call_args[0][0], client.post.call_args[1]
    assert url.endswith("/api/v1/admin/certs/revoke")
    assert kwargs["json"]["serial"] == serial, "the accepted serial must reach the server unchanged"


@pytest.mark.parametrize("serial", [SERIAL_40, "0" * 17, SERIAL_64], ids=["40-hex", "17-hex", "64-hex"])
def test_core_relay_cert_revoke_accepts_serials_at_the_raised_cap(serial, capsys):
    """The relay door is the one the field hit: `list` prints a 40-hex serial, `revoke` must take it back."""
    client = _client()
    args = SimpleNamespace(
        core_relay_cert_command="revoke",
        serial=serial,
        cert_file=None,
        reason="test",
        server_url="https://core.test:443",
        json=False,
    )

    assert cmd_admin_core_relay_cert(client, args) == 0, capsys.readouterr().err
    client.post.assert_called_once()
    assert client.post.call_args[1]["json"]["serial"] == serial


@pytest.mark.parametrize("serial", [SERIAL_40, "0" * 17, SERIAL_64], ids=["40-hex", "17-hex", "64-hex"])
def test_executor_cert_revoke_accepts_serials_at_the_raised_cap(serial):
    """The third CLI door (`revoke-executor --serial`), twin of the admin server route."""
    client = _client()
    args = SimpleNamespace(executor_id="exec-1", cert_path="/nonexistent/executor.crt", serial=serial, reason="test")

    assert executor_cert_revoke(args, client=client) == 0
    assert client.post.call_args[1]["json"]["serial"] == serial.casefold()


# --------------------------------------------------------------------------- negative halves

BAD = [
    pytest.param(TOO_LONG, id="65-hex"),
    pytest.param("a" * 200, id="200-hex"),
    pytest.param("nothex", id="non-hex"),
    pytest.param("zz", id="not-hex-at-all"),
    pytest.param("", id="empty"),
    pytest.param("   ", id="whitespace-only"),
    pytest.param("0x", id="bare-0x-prefix"),
]


@pytest.mark.parametrize("serial", BAD)
def test_admin_revoke_admin_cert_still_refuses_bad_serials(serial, capsys):
    client = _client()
    args = SimpleNamespace(serial=serial, reason="test", server_url="https://core.test:443")
    assert cmd_admin_revoke_admin_cert(client, args) == 1
    err = capsys.readouterr().err
    assert "64" in err, f"refused with the OLD cap in the message: {err!r}"
    client.post.assert_not_called()


@pytest.mark.parametrize("serial", BAD)
def test_core_relay_cert_revoke_still_refuses_bad_serials(serial, capsys):
    """Empty is refused by the "not provided" door, not the format door — both refuse, and neither POSTs.

    Asserted separately because the two messages are different and both are correct: an empty
    ``--serial`` means the operator gave neither ``--serial`` nor ``--cert-file``, which is a missing
    argument, not a malformed one.
    """
    client = _client()
    args = SimpleNamespace(
        core_relay_cert_command="revoke",
        serial=serial,
        cert_file=None,
        reason="test",
        server_url="https://core.test:443",
        json=False,
    )
    assert cmd_admin_core_relay_cert(client, args) == 1
    err = capsys.readouterr().err
    if serial == "":
        assert "--serial or --cert-file" in err, err
    else:
        assert "64" in err, f"refused with the OLD cap in the message: {err!r}"
    client.post.assert_not_called()


@pytest.mark.parametrize("serial", BAD)
def test_executor_cert_revoke_still_refuses_bad_serials(serial, capsys):
    client = _client()
    args = SimpleNamespace(executor_id="exec-1", cert_path="/nonexistent/executor.crt", serial=serial, reason="test")
    assert executor_cert_revoke(args, client=client) == 1
    err = capsys.readouterr().err
    assert "64" in err, f"refused with the OLD cap in the message: {err!r}"
    client.post.assert_not_called()


# --------------------------------------------------------------------------- the message law


def test_no_cli_string_still_advertises_the_old_cap():
    """A gate that was widened while its help still says 16 documents a rule it does not enforce.

    Read off the shipped files, not off this test's memory of them: the two `--help` strings and
    every CLI error message must carry 64 and must not carry the 16-char phrasing.
    """
    import pathlib
    import re

    pkg = pathlib.Path(__file__).resolve().parents[1] / "src" / "venya_cli"
    offenders = []
    for name in ("cli.py", "commands.py"):
        text = (pkg / name).read_text(encoding="utf-8")
        for pat in (r"up to 16 char", r"1-16 char", r"> 16\b"):
            for m in re.finditer(pat, text):
                line_no = text[: m.start()].count("\n") + 1
                line_text = text.split("\n")[line_no - 1]
                # `> 16` alone is not a serial cap — PKCS7 padding blocks carry the same digits at
                # commands.py:4223. Only a line about a serial may not say 16.
                if "serial" not in line_text.lower():
                    continue
                offenders.append(f"{name}:{line_no} still says {m.group(0)!r}: {line_text.strip()[:70]}")
    assert not offenders, "; ".join(offenders)
