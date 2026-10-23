# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#625 — ``venya admin configure-user --timeout`` is gone, and the hollow command says so.

Ruled shape (a) DELETE: the **write path** dies, the ``users.session_timeout`` **column stays**
(it is ``NOT NULL`` with ``server_default="900"`` in ``001_initial_schema.py``, so "unset" is
unrepresentable and dropping it is an Alembic migration spent on dead text in a beta window).
The column half of that ruling is pinned server-side in
``packages/server/tests/test_admin_session_timeout_dead_write_625.py``.

``commands.py`` keeps the settings a ``configure-user`` call may send in one map,
``_CONFIGURE_SETTINGS``, and states three checks a setting must clear before it joins:

  (a) ``cli.py`` ships the option            — ``--timeout`` does NOT: it is a usage error;
  (b) the server request model declares it   — it does NOT (cross-package import below, the
      same precedent ``test_cli_response_key_drift_482.py`` uses);
  (c) some shipped path READS it and acts    — it does NOT, and the pair may never rejoin.

Two of those three are searched from THIS file because they are the CLI's own face; (c) is the
absence of the pair. A setting that clears (a) and (b) but not (c) is exactly the defect this
row recorded, so the map is the door and these cells are the door's negative half.

Plus part 3 of the ruling: with nothing on offer, ``cmd_admin_configure`` refuses LOCALLY — no
PUT, no ``configured: true``, no exit 0 — and the paired negative below proves that refusal is
about an empty setting map, not about a disabled command.
"""

import argparse
import io
from contextlib import redirect_stderr
from unittest.mock import MagicMock

import pytest
from venya_cli import commands
from venya_cli.cli import create_parser


def _parse(argv: list[str]) -> argparse.Namespace:
    return create_parser().parse_args(argv)


def _parser_at(path: list[str]):
    """The live sub-parser for a command path, walked out of create_parser()."""
    parser = create_parser()
    for name in path:
        choices = {}
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                choices = action.choices
                break
        assert name in choices, f"no subcommand {name!r} under {parser.prog}"
        parser = choices[name]
    return parser


def _configure_dests() -> set[str]:
    return {a.dest for a in _parser_at(["admin", "configure-user"])._actions if a.dest != "help"}


class TestTimeoutOptionIsGone:
    """Check (a): the option must die loudly, never as an accepted no-op."""

    def test_timeout_is_a_usage_error(self):
        with pytest.raises(SystemExit) as exc:
            _parse(["admin", "configure-user", "jsmith", "--timeout", "60"])
        assert exc.value.code == 2, "a removed knob must fail as an argparse usage error"

    def test_timeout_absent_from_help(self):
        """The generated reference renders this help — a hidden row would be a doc lie."""
        assert "--timeout" not in _parser_at(["admin", "configure-user"]).format_help()

    def test_bare_invocation_carries_no_timeout_attribute(self):
        ns = _parse(["admin", "configure-user", "jsmith"])
        assert ns.user_id == "jsmith"
        assert not hasattr(ns, "timeout")


class TestSettingsMapDiscipline:
    """The map is the only source of keys; these cells keep it honest in both directions."""

    def test_no_session_timeout_pair_in_the_map(self):
        """Check (c) as a standing rule: the dead field stays out even if a flag returns."""
        assert all(field != "session_timeout" for _dest, field in commands._CONFIGURE_SETTINGS)

    def test_every_mapped_dest_is_a_shipped_option(self):
        """A map entry naming a removed flag would be check (a) rotting silently.

        VACUOUS while the map is empty — it becomes a real gate the moment a setting joins,
        which is why the paired positive below injects a temporary entry rather than waiting.
        """
        dests = _configure_dests()
        for dest, _field in commands._CONFIGURE_SETTINGS:
            assert dest in dests, f"_CONFIGURE_SETTINGS names {dest!r}, which cli.py does not ship"

    def test_server_request_model_declares_no_session_timeout(self):
        """Check (b), read across the package boundary at test time.

        If a future server field reappears without a reader, the (c) rule above is what stops
        it from being wired to a CLI flag.
        """
        from server.routes.admin import AdminConfigureUserRequest

        assert "session_timeout" not in AdminConfigureUserRequest.model_fields
        assert "display_name" in AdminConfigureUserRequest.model_fields


class TestHollowCommandRefuses:
    """Part 3: an empty setting map must never reach the wire as ``PUT {}``."""

    def _args(self, **values) -> argparse.Namespace:
        return argparse.Namespace(user_id="jsmith", **values)

    def test_bare_configure_user_refuses_before_any_request(self):
        client = MagicMock()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = commands.cmd_admin_configure(client, self._args())

        assert rc == 1, "refusal must be non-zero, never the shipped exit 0"
        client.put.assert_not_called()
        client.get.assert_not_called()
        text = stderr.getvalue()
        assert "Configure refused" in text
        assert "625" in text, "the refusal must name itself, not just fail"
        assert "Nothing was sent" in text

    def test_a_stale_timeout_attribute_cannot_resurrect_the_write(self):
        """argparse no longer sets it; a hand-built Namespace must not either.

        The shipped command read ``args.timeout`` directly, so any value there became a PUT
        body. The map lookup replaces that open door, so the attribute is now inert.
        """
        client = MagicMock()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = commands.cmd_admin_configure(client, self._args(timeout=1800))

        assert rc == 1
        client.put.assert_not_called()

    def test_a_mapped_setting_still_puts_and_reports_success(self, monkeypatch):
        """PAIRED NEGATIVE: the refusal answers emptiness, not a disabled command.

        No setting ships today, so the map entry is injected for the duration of this cell —
        the point is that the ONE gate is ``config == {}``, not a hard stop on the command.
        """
        monkeypatch.setattr(commands, "_CONFIGURE_SETTINGS", (("display_name", "display_name"),))
        client = MagicMock()
        client.put.return_value = {"configured": True}
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            rc = commands.cmd_admin_configure(client, self._args(display_name="Ops"))

        assert rc == 0, stderr.getvalue()
        client.put.assert_called_once_with("/api/v1/admin/users/jsmith", json={"display_name": "Ops"})

    def test_payload_builder_keeps_a_zero_value(self, monkeypatch):
        """The falsy-drop the row recorded: ``if args.timeout:`` silently ate ``--timeout 0``.

        The builder tests ``is not None``, so a legitimate zero for a future setting is sent,
        not dropped in silence. Positive control for that clause: ``None`` contributes nothing.
        """
        assert commands._configure_payload(self._args(display_name=None, quota=0)) == {}
        monkeypatch.setattr(commands, "_CONFIGURE_SETTINGS", (("quota", "quota"),))
        assert commands._configure_payload(self._args(quota=0)) == {"quota": 0}
        assert commands._configure_payload(self._args(quota=None)) == {}
