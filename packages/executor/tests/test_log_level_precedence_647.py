# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#647 — the executor's ``--log-level`` default no longer outranks the config file.

The row: ``main()`` registered ``--log-level`` with ``default="info"``, then ran
``config.log_level = args.log_level`` UNCONDITIONALLY, and configured the logger from
``args.log_level`` rather than from the resolved config. An argparse default is a built-in
value nobody passed, so on every start it discarded whatever ``ExecutorConfig.from_file`` had
just resolved — an operator who set ``log_level`` in ``/etc/venya/executor.toml`` got ``info``
anyway, and the only way to get any other verbosity was the flag itself. The ruled order is
**flag > file > env > default**, which means the flag layer applies only when the flag was
actually given. Same precedence family as #598 (``file > env > default``, re-pinned here at
this plane so this fix cannot quietly invert it), opposite direction: there the file beat the
environment; here a default beat the file.

Every cell drives ``main()`` — the defect is the wiring between the parser, the loader and
``logging.basicConfig``, and nothing in the suite reached it. #598's cells assert through
``ExecutorConfig.from_file``, and its two ``main()`` cells are labelled source-shape pins
(``inspect.getsource``), which is exactly why that family stayed green while the served path
was broken.

The truth table, both halves (AC2 of the row):

| flag | file | env | expected |
|------|------|-----|----------|
| absent | set | absent | **file** value runs — today it loses to the default; this is the defect |
| given | set | absent | **flag** value runs — the order must not invert |
| absent | absent | set | **env** value runs — the #598 direction, at this plane |
| absent | set | set | **file** runs, note stands alone, UNQUALIFIED |
| given | set | set | **flag** runs AND the #598 note is qualified, because it names a value the daemon discards |
| absent | absent | absent | the built-in default runs, nothing announced |

## The trap in this file, stated because it decides the design

``logging.basicConfig()`` **does nothing when the root logger already has handlers**, and
pytest attaches its own capture handlers to root for the whole call phase. So:

* a cell that called ``main()`` and read ``logging.getLogger().level`` read pytest's 30 and
  failed while the shipped code was right — and worse, the same 30 could be read as proof the
  fix did nothing; and
* clearing root's handlers in a fixture SETUP does not help, because pytest installs them
  again for the call phase, after setup.

``_boot`` is the answer, and it is the only observation surface in this file: it detaches
root's handlers *immediately before* ``main()`` runs (the state a real ``venya-executor``
start is genuinely in), captures records on the daemon's OWN logger rather than on root —
propagation still happens, but a child handler leaves ``len(root.handlers) == 0``, which is
what ``basicConfig`` tests — reads the level that actually landed, and restores everything in
a ``finally``. It is not a convenience: a leaked handler or a root left at DEBUG would
silently change every cell after it, in this file and in the rest of the suite. Because the
capture is ours and not ``caplog``'s, no cell here reads ``caplog``; if you are adding one,
use ``result.records``.
"""

import inspect
import logging
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from executor.config import ExecutorConfig
from executor.daemon import LOG_LEVEL_DEFAULT, main, resolve_log_level

#: The one key this row is about, in its env carrier's spelling.
TOP_ENV = "VENYA_EXECUTOR_LOG_LEVEL"

#: The daemon logger these cells capture on. Named here because getting it wrong captures
#: nothing at all and the cells would still pass on the level assertion alone.
DAEMON_LOGGER = "venya.executor.daemon"

#: Cleared before every cell: an environment nobody meant to set is not noise in a
#: which-carrier-wins row, it is a fourth row that answers the cell for the wrong reason.
ALL_EXECUTOR_ENV = (
    "VENYA_EXECUTOR_LOG_LEVEL",
    "VENYA_EXECUTOR_SERVER_URL",
    "VENYA_EXECUTOR_EXECUTOR_ID",
    "VENYA_EXECUTOR_DNS_RESOLVER",
    "VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ALL_EXECUTOR_ENV:
        monkeypatch.delenv(name, raising=False)


@dataclass
class Boot:
    """What one ``main()`` start actually did."""

    config: ExecutorConfig
    level: int
    records: list[logging.LogRecord]

    def lines(self, needle: str) -> list[str]:
        return [r.getMessage() for r in self.records if needle in r.getMessage()]


def _boot(argv) -> Boot:
    """Run ``main()`` the way a process start runs it, and report what took effect.

    Returns the config object the daemon was built with, the root level that actually landed,
    and every record the daemon emitted. ``ExecutorDaemon`` is a MagicMock because the thing
    under test is the parser/loader/logger wiring; booting a real one would dial a core, and
    a cell that cannot say what it is observing is not evidence. See the module docstring for
    why root must be emptied here rather than in a fixture.
    """
    root = logging.getLogger()
    daemon_logger = logging.getLogger(DAEMON_LOGGER)
    saved_root_handlers = list(root.handlers)
    saved_root_level = root.level
    saved_propagate = daemon_logger.propagate
    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    sink = _Capture()
    sink.setLevel(logging.DEBUG)
    for handler in saved_root_handlers:
        root.removeHandler(handler)
    daemon_logger.addHandler(sink)
    daemon_logger.propagate = True
    root.setLevel(logging.NOTSET)
    try:
        daemon = MagicMock()
        with patch("executor.daemon.ExecutorDaemon", return_value=daemon) as daemon_cls:
            with patch("sys.argv", argv):
                main()
        return Boot(
            config=daemon_cls.call_args[0][0],
            level=root.level,
            records=captured,
        )
    finally:
        daemon_logger.removeHandler(sink)
        sink.close()
        for handler in list(root.handlers):
            if handler is not sink:
                root.removeHandler(handler)
        for handler in saved_root_handlers:
            root.addHandler(handler)
        root.setLevel(saved_root_level)
        daemon_logger.propagate = saved_propagate


def _write(tmp_path, text):
    path = tmp_path / "executor.toml"
    path.write_text(text)
    return str(path)


def _serve(tmp_path, text, extra=()):
    """Boot with the shipped unit's own argv shape (``--config`` only) plus ``extra``."""
    return _boot(["venya-executor", "--config", _write(tmp_path, text), *extra])


# ---------------------------------------------------------------------------
# Row 1 — flag absent, file set: the file runs. This is the defect.
# ---------------------------------------------------------------------------


class TestRowFileWinsWhenTheFlagWasNotPassed:
    """AC1, both halves: the logger runs at the file's value, and so does the daemon."""

    def test_the_config_file_level_is_the_level_that_runs(self, tmp_path):
        result = _serve(tmp_path, 'log_level = "debug"\nserver_url = "https://core:8080"\n')
        assert result.level == logging.DEBUG, (
            "root must run at the file's DEBUG; a 30 here means the built-in default still "
            "outranked the file, i.e. #647 is not fixed"
        )

    def test_the_daemon_is_handed_the_same_value_the_logger_runs(self, tmp_path):
        """AC1's second half. ``ExecutorDaemon`` receives this config object, so a fix that
        set root to DEBUG while leaving ``config.log_level`` at the default would give the two
        carriers different answers and still pass a logger-only cell."""
        result = _serve(tmp_path, 'log_level = "debug"\nserver_url = "https://core:8080"\n')
        assert result.config.log_level == "debug"
        assert result.level == logging.DEBUG

    def test_a_non_default_file_value_on_the_other_end_of_the_set_also_lands(self, tmp_path):
        """NEGATIVE half against a fix hard-coded to ``debug``: the shape is "the file's own
        value", not "debug". ERROR is the far end of the shipped set."""
        result = _serve(tmp_path, 'log_level = "error"\nserver_url = "https://core:8080"\n')
        assert (result.config.log_level, result.level) == ("error", logging.ERROR)

    def test_no_precedence_line_is_invented_for_a_file_that_simply_won(self, tmp_path):
        """NEGATIVE half: one carrier, no contest, no line. #598's agreement rule still holds
        after this change, and a boot warning on every start is how a real one stops being
        read."""
        result = _serve(tmp_path, 'log_level = "debug"\nserver_url = "https://core:8080"\n')
        assert result.lines("Config precedence") == []


# ---------------------------------------------------------------------------
# Row 2 — flag given, file set: the flag runs. The order must not invert.
# ---------------------------------------------------------------------------


class TestRowFlagWinsWhenItWasPassed:
    """AC2 — the paired negative. "Only apply the flag when passed" must not become "never
    apply the flag"."""

    def test_an_explicit_flag_outranks_the_file(self, tmp_path):
        result = _serve(
            tmp_path,
            'log_level = "warning"\nserver_url = "https://core:8080"\n',
            extra=["--log-level", "debug"],
        )
        assert result.level == logging.DEBUG, "a fix that lets the file always win is a new defect"
        assert result.config.log_level == "debug"

    def test_a_flag_agreeing_with_the_file_lands_without_a_fuss(self, tmp_path):
        """Agreement is not a conflict. The operator passed ``--log-level info`` over a file
        that already said ``info``: the value runs and nothing is announced — #598's agreement
        rule, carried up to this plane."""
        result = _serve(
            tmp_path,
            'log_level = "info"\nserver_url = "https://core:8080"\n',
            extra=["--log-level", "info"],
        )
        assert result.level == logging.INFO
        assert result.config.log_level == "info"
        assert result.lines("Config precedence") == []

    def test_the_flag_still_refuses_a_name_it_never_accepted(self, tmp_path, capsys):
        """NEGATIVE half for the gate itself: ``choices`` is untouched, so a bogus value on
        the command line still exits 2. Making the default honest must not have widened the
        flag — that would trade a loud refusal for a silent fallback."""
        cfg = _write(tmp_path, 'log_level = "debug"\nserver_url = "https://core:8080"\n')
        with patch("sys.argv", ["venya-executor", "--config", cfg, "--log-level", "TRACE"]):
            with patch("executor.daemon.ExecutorDaemon"):
                with pytest.raises(SystemExit) as exc:
                    main()
        assert exc.value.code == 2
        assert "invalid choice" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Row 3 — the environment, at this plane. AC4: the #598 direction must survive.
# ---------------------------------------------------------------------------


class TestRowEnvStillBeatsDefaultAndFileStillBeatsEnv:
    def test_the_environment_lands_when_the_file_does_not_carry_the_key(self, tmp_path, monkeypatch):
        """The value reaches the logger through the RESOLVED config. A fix that read the file
        directly instead of ``config.log_level`` would pass Row 1 and fail here."""
        monkeypatch.setenv(TOP_ENV, "debug")
        result = _serve(tmp_path, 'server_url = "https://core:8080"\n')
        assert result.level == logging.DEBUG
        assert result.config.log_level == "debug"

    def test_the_file_beats_the_environment_at_this_plane_too(self, tmp_path, monkeypatch):
        """#598's ruled winner, re-asserted through ``main()`` rather than only through the
        loader — which is the level this row broke it at."""
        monkeypatch.setenv(TOP_ENV, "debug")
        result = _serve(tmp_path, 'log_level = "warning"\nserver_url = "https://core:8080"\n')
        assert result.level == logging.WARNING, "file > env > default must hold at the logger as well"
        assert result.config.log_level == "warning"


# ---------------------------------------------------------------------------
# Row 4 — nothing set: the built-in default runs.
# ---------------------------------------------------------------------------


class TestRowNeitherSourceRunsTheDefault:
    def test_no_carrier_at_all_runs_the_built_in_default(self, tmp_path):
        result = _serve(tmp_path, 'server_url = "https://core:8080"\n')
        assert result.level == logging.INFO
        assert result.config.log_level == LOG_LEVEL_DEFAULT
        assert result.lines("Config precedence") == []

    def test_the_default_the_daemon_falls_back_to_is_the_default_the_model_declares(self):
        """One meaning for "the built-in default". No boot needed: if ``config.py``'s field
        default ever moves, these lines go red together instead of the fallback quietly
        disagreeing with the schema."""
        field_default = ExecutorConfig.model_fields["log_level"].default
        assert LOG_LEVEL_DEFAULT == field_default
        assert resolve_log_level(field_default) == logging.INFO

    def test_the_served_unit_shape_is_config_only_so_the_default_was_the_whole_story(self, tmp_path):
        """The unit-mask clause, checked at the file the fleet actually runs rather than
        remembered: ``ExecStart`` passes ``--config`` and NO ``--log-level``. That is why this
        defect was live rather than masked on an installer-served executor — the absent flag is
        the ordinary case, not an edge one."""
        from pathlib import Path

        unit = Path(__file__).resolve().parents[3] / "systemd" / "venya-executor.service"
        exec_start = [ln for ln in unit.read_text().splitlines() if ln.startswith("ExecStart=")]
        assert len(exec_start) == 1, f"expected one ExecStart, read {exec_start}"
        assert "--log-level" not in exec_start[0], (
            "the unit now passes the flag, so an operator's file value is legitimately "
            "outranked on a served install — re-read this row's masked-versus-live claim"
        )
        assert "--config" in exec_start[0]


# ---------------------------------------------------------------------------
# The guard #647 creates: an unusable name can now REACH the logger at all.
# ---------------------------------------------------------------------------


class TestUnusableNameFromAFileOrTheEnvironment:
    """Before this row the file value was discarded unread, so an unusable name was
    unreachable and ``choices`` was the only door. Once the file is honoured, a typo must be
    refused LOUDLY — and must not park an executor in systemd failed state, because the unit
    carries ``Restart=always``. Both halves are the point: refuse, and do not crash."""

    def test_an_unusable_file_name_falls_back_to_the_default_and_says_so(self, tmp_path):
        result = _serve(tmp_path, 'log_level = "chatty"\nserver_url = "https://core:8080"\n')
        assert result.level == logging.INFO, "an unusable name must neither crash nor raise"
        assert result.config.log_level == LOG_LEVEL_DEFAULT, (
            "the config the daemon carries must agree with the logger, or the next reader "
            "acts on a verbosity that is not running"
        )
        refused = result.lines("is not a level this daemon can use")
        assert refused, "falling back without a line is the same silence #598 was opened for"
        assert "'chatty'" in refused[0]
        assert "debug, info, warning, error" in refused[0], "a refusal the operator cannot act on"

    def test_an_unusable_name_emits_exactly_one_line(self, tmp_path):
        """NEGATIVE half: one bad value, one line. Two WARNINGs for one typo is how a real
        one stops being read."""
        result = _serve(tmp_path, 'log_level = "chatty"\nserver_url = "https://core:8080"\n')
        assert len(result.lines("is not a level this daemon can use")) == 1
        assert result.lines("Config precedence") == []

    def test_uppercase_is_not_folded_in_one_carrier_only(self, tmp_path):
        """``--log-level DEBUG`` has always been refused by ``choices``. A file that accepted
        it would make one plane more permissive than another, which is how a written value
        stops working the moment somebody moves it."""
        result = _serve(tmp_path, 'log_level = "DEBUG"\nserver_url = "https://core:8080"\n')
        assert result.level == logging.INFO
        assert result.config.log_level == LOG_LEVEL_DEFAULT

    def test_an_unusable_ENVIRONMENT_name_is_refused_the_same_way(self, tmp_path, monkeypatch):
        """The third carrier, so the guard is not a file-only courtesy."""
        monkeypatch.setenv(TOP_ENV, "chatty")
        result = _serve(tmp_path, 'server_url = "https://core:8080"\n')
        assert result.level == logging.INFO
        assert len(result.lines("is not a level this daemon can use")) == 1

    def test_a_usable_name_announces_nothing_about_being_unusable(self, tmp_path):
        """The positive half of the guard's own truth table, and the pair that stops it
        turning into a boot-time nag."""
        result = _serve(tmp_path, 'log_level = "debug"\nserver_url = "https://core:8080"\n')
        assert result.lines("is not a level this daemon can use") == []


# ---------------------------------------------------------------------------
# AC3 — the boot note may not name a winner the daemon discarded.
# ---------------------------------------------------------------------------


class TestTheFiveNineEightNoteIsQualifiedWhenTheFlagWon:
    """``precedence_conflicts`` is computed inside ``from_file``, where the command line does
    not exist. With the flag given, its "the file value is in use" sentence describes a value
    this daemon does not run — the same false operator-facing statement #598 exists to end,
    one plane up. ``main()`` qualifies it where the flag is known, instead of rewriting that
    template in ``config.py`` and the cells that pin it (outside this leg's fence)."""

    def test_the_note_and_the_qualifier_are_both_present_when_the_flag_won(self, tmp_path, monkeypatch):
        monkeypatch.setenv(TOP_ENV, "warning")
        result = _serve(
            tmp_path,
            'log_level = "error"\nserver_url = "https://core:8080"\n',
            extra=["--log-level", "debug"],
        )
        assert result.level == logging.DEBUG
        note = result.lines("Config precedence: log_level: set in the executor config file")
        qualifier = result.lines("also given on the command line")
        assert len(note) == 1, "the #598 note must still be emitted — this is a correction, not a gag"
        assert len(qualifier) == 1, "with the flag given, the note names a value that is not running"
        assert "flag > file > env > default" in qualifier[0]
        positions = [r.getMessage() for r in result.records]
        assert positions.index(note[0]) < positions.index(qualifier[0]), (
            "the qualifier must follow the line it qualifies; a correction read first is " "read as the claim"
        )

    def test_no_qualifier_when_the_flag_was_not_passed_and_the_note_was_right(self, tmp_path, monkeypatch):
        """NEGATIVE half, and the whole point of the gate. With no flag the file genuinely is
        in use, so the note stands alone. A correction that fires whether or not the flag was
        passed is a second statement about a contest that never happened."""
        monkeypatch.setenv(TOP_ENV, "debug")
        result = _serve(tmp_path, 'log_level = "warning"\nserver_url = "https://core:8080"\n')
        assert result.level == logging.WARNING, "the #598 winner must still run at this plane"
        assert len(result.lines("Config precedence: log_level: set in the executor config file")) == 1
        assert result.lines("also given on the command line") == []

    def test_the_note_and_the_qualifier_are_both_visible_only_because_the_run_is_not_quiet(self, tmp_path, monkeypatch):
        """A consequence of honouring the file, pinned so nobody later 'fixes' it by promoting
        the notes to ERROR: the #598 announcement is a WARNING, so an operator who sets
        ``log_level = "error"" and gets it honoured also stops seeing the announcement. That is
        the knob working, not a defect — but it is invisible in a cell that only asserts the
        level, and a lane that found it un-pinned could easily conclude the emitter broke. The
        pair here is the same argv with ``error`` instead of ``warning``: level honoured, note
        suppressed by that very level."""
        monkeypatch.setenv(TOP_ENV, "debug")
        loud = _serve(tmp_path, 'log_level = "warning"\nserver_url = "https://core:8080"\n')
        assert loud.level == logging.WARNING
        assert loud.lines("Config precedence") != [], "the WARNING must be visible at WARNING"

        quiet = _serve(tmp_path, 'log_level = "error"\nserver_url = "https://core:8080"\n')
        assert quiet.level == logging.ERROR, "the file's ERROR must be honoured regardless"
        assert quiet.lines("Config precedence") == [], (
            "a WARNING is below ERROR: the note is suppressed BY the level this row just "
            "started honouring, which is the knob doing what the operator asked"
        )

    def test_no_qualifier_when_the_flag_was_given_but_there_was_no_note_to_correct(self, tmp_path):
        """Third row of that gate: flag given, no file-versus-environment contest at all.
        Nothing above claimed a winner for this key, so nothing needs correcting."""
        result = _serve(
            tmp_path,
            'log_level = "warning"\nserver_url = "https://core:8080"\n',
            extra=["--log-level", "debug"],
        )
        assert result.level == logging.DEBUG
        assert result.lines("Config precedence") == []


# ---------------------------------------------------------------------------
# Source-shape pins. LABELLED AS SUCH: they cannot prove behaviour — the rows above do.
# ---------------------------------------------------------------------------


class TestShapePins:
    """Here because the specific regressions this row is exposed to are someone re-adding the
    unguarded assignment, or reading the namespace at the logger again. Both are invisible to
    every other cell in the suite."""

    def test_the_override_is_guarded_and_the_logger_reads_the_resolved_config(self):
        body = inspect.getsource(main)
        assert (
            "config.log_level = args.log_level" not in body
        ), "the unguarded assignment IS #647; if it is back, the file loses again"
        assert (
            "if cli_log_level is not None:" in body
        ), "the flag layer must be applied only when the flag was actually given"
        assert "level=log_level," in body, "the logger must be configured from the RESOLVED value"
        assert body.count("args.log_level") == 1, (
            "the namespace may be read exactly once — to name the flag layer. Reading it at "
            "the logger, or assigning it unguarded, is the defect re-opening"
        )

    def test_the_announcements_still_run_after_basicconfig_and_in_order(self):
        """#598's ordering contract, re-pinned so this leg cannot quietly reorder it: the
        notes must arrive through the journal's own formatter, and the new qualifier rides
        after the line it qualifies."""
        body = inspect.getsource(main)
        assert body.index("logging.basicConfig") < body.index("_log_precedence_conflicts(config)")
        assert body.index("_log_precedence_conflicts(config)") < body.index("_log_cli_level_override(config)")

    def test_the_flag_and_the_carriers_advertise_one_set_of_names(self):
        """One surface, so a name cannot be accepted by the parser and refused by the logger,
        or the reverse."""
        from executor import daemon as daemon_module

        assert list(daemon_module._LOG_LEVELS) == ["debug", "info", "warning", "error"]
        assert [resolve_log_level(n) for n in daemon_module._LOG_LEVELS] == [
            logging.DEBUG,
            logging.INFO,
            logging.WARNING,
            logging.ERROR,
        ]
        assert resolve_log_level("chatty") is None
        assert resolve_log_level("DEBUG") is None
