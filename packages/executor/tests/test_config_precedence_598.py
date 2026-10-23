# Copyright (c) 2026 Tabith LLC.
# Use of this code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#598 — the executor config precedence is a stated contract with a loud conflict.

The row: ``ExecutorConfig.from_file`` returns ``cls(**data)``, so every key the
``executor.toml`` carries arrives as an explicit init argument and outranks the
``VENYA_EXECUTOR_*`` environment spelling the shipped docs tell an operator to set.
The direction is now ruled (lead, 2026-10-13): **file > env > default**. What was
defective was the SILENCE — no error, no log line, no effect.

These cells are the truth table AC2 asks for, all four rows, and they run through the
shipped loader (AC5) rather than a direct constructor call: a constructor-only cell
tests pydantic, not the product path that reads the file.

| env | file | expected |
|-----|------|----------|
| set | absent | env value lands, nothing announced |
| absent | set | file value lands, nothing announced |
| set | set | **file** value lands **and** the conflict is announced |
| absent | absent | the field default lands, nothing announced |

The third row is the negative half this repo's measure law demands, and it is tested
for two key classes on purpose — a plain top-level key and the RF-3 ``[executor]``
section — because those two are resolved by different pydantic-settings machinery and
a detector wired for only one of them would be the same silence in new clothes.
"""

import logging

import pytest

from executor.config import (
    PRECEDENCE_RULE,
    ExecutorConfig,
    precedence_conflicts,
)
from executor.daemon import _log_precedence_conflicts

#: The two spellings of one key, per key class (both measured before this file existed).
TOP_ENV = "VENYA_EXECUTOR_LOG_LEVEL"
SECTION_ENV = "VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS"
FILE_ONLY_ENV = "VENYA_EXECUTOR_DNS_RESOLVER"

ALL_EXECUTOR_ENV = (
    "VENYA_EXECUTOR_LOG_LEVEL",
    "VENYA_EXECUTOR__MAX_CONCURRENT_COMMANDS",
    "VENYA_EXECUTOR_DNS_RESOLVER",
    "VENYA_EXECUTOR_SERVER_URL",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """No inherited VENYA_EXECUTOR_* from the developer's or CI's shell: the whole point of
    this row is that an environment nobody meant to set changes what the daemon runs."""
    for name in ALL_EXECUTOR_ENV:
        monkeypatch.delenv(name, raising=False)


def _write(tmp_path, text):
    path = tmp_path / "executor.toml"
    path.write_text(text)
    return path


def _notes(cfg):
    return cfg.precedence_conflict_notes()


# ---------------------------------------------------------------------------
# Row 1 — env set, file absent: the environment value lands, and it is NOT announced.
# ---------------------------------------------------------------------------


class TestRowEnvOnly:
    def test_env_lands_top_level(self, monkeypatch):
        monkeypatch.setenv(TOP_ENV, "debug")
        assert ExecutorConfig().log_level == "debug"

    def test_env_lands_section_key(self, monkeypatch):
        monkeypatch.setenv(SECTION_ENV, "7")
        assert ExecutorConfig().executor.max_concurrent_commands == 7

    def test_env_only_loads_no_conflict(self, tmp_path, monkeypatch):
        """The file does not carry the key, so there is nothing to announce — a
        precedence log on every boot would train the operator to ignore it."""
        monkeypatch.setenv(TOP_ENV, "debug")
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'server_url = "https://core:8080"\n'))
        assert cfg.log_level == "debug"
        assert _notes(cfg) == []


# ---------------------------------------------------------------------------
# Row 2 — file set, env absent: the file value lands, and nothing is announced.
# ---------------------------------------------------------------------------


class TestRowFileOnly:
    def test_file_lands_top_level(self, tmp_path):
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'log_level = "warning"\n'))
        assert cfg.log_level == "warning"

    def test_file_lands_section_key(self, tmp_path):
        cfg = ExecutorConfig.from_file(_write(tmp_path, "[executor]\nmax_concurrent_commands = 3\n"))
        assert cfg.executor.max_concurrent_commands == 3

    def test_file_only_loads_no_conflict(self, tmp_path):
        cfg = ExecutorConfig.from_file(
            _write(tmp_path, 'log_level = "warning"\n[executor]\nmax_concurrent_commands = 3\n')
        )
        assert _notes(cfg) == []


# ---------------------------------------------------------------------------
# Row 3 — the defect. Both spellings carry the same key: the FILE lands AND the
# conflict is loud. Pinned for both key classes, through the shipped loader.
# ---------------------------------------------------------------------------


class TestRowBothSources:
    def test_top_level_file_wins_and_is_announced(self, tmp_path, monkeypatch):
        monkeypatch.setenv(TOP_ENV, "debug")
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'log_level = "warning"\n'))
        assert cfg.log_level == "warning", "the ruled winner must actually run"
        notes = _notes(cfg)
        assert len(notes) == 1, f"exactly one conflict expected, got {notes}"
        assert "log_level" in notes[0]
        assert PRECEDENCE_RULE in notes[0]
        assert "ignored" in notes[0].lower()

    def test_section_key_file_wins_and_is_announced(self, tmp_path, monkeypatch):
        """RF-3's knob, the case a prior worker lane measured: the [executor] section and the
        VENYA_EXECUTOR__ spelling resolve through the alias pair, so the detector has
        to see this class too — not just plain top-level keys."""
        monkeypatch.setenv(SECTION_ENV, "8")
        cfg = ExecutorConfig.from_file(_write(tmp_path, "[executor]\nmax_concurrent_commands = 2\n"))
        assert cfg.executor.max_concurrent_commands == 2, "the ruled winner must actually run"
        notes = _notes(cfg)
        assert len(notes) == 1, f"exactly one conflict expected, got {notes}"
        assert "executor.max_concurrent_commands" in notes[0]

    def test_both_classes_at_once_announce_both(self, tmp_path, monkeypatch):
        monkeypatch.setenv(TOP_ENV, "debug")
        monkeypatch.setenv(SECTION_ENV, "8")
        cfg = ExecutorConfig.from_file(
            _write(tmp_path, 'log_level = "warning"\n[executor]\nmax_concurrent_commands = 2\n')
        )
        keys = {n.split(":", 1)[0] for n in _notes(cfg)}
        assert keys == {"log_level", "executor.max_concurrent_commands"}

    def test_both_spellings_asking_for_the_same_value_stay_quiet(self, tmp_path, monkeypatch):
        """NEGATIVE half of AC2's third row as written: the loud case is both-set AND
        different. Two spellings agreeing defeat nothing, and a warning on every boot is
        the fast way to make the real one unread."""
        monkeypatch.setenv(TOP_ENV, "warning")
        monkeypatch.setenv(SECTION_ENV, "2")
        cfg = ExecutorConfig.from_file(
            _write(tmp_path, 'log_level = "warning"\n[executor]\nmax_concurrent_commands = 2\n')
        )
        assert cfg.log_level == "warning" and cfg.executor.max_concurrent_commands == 2
        assert _notes(cfg) == []

    def test_boolean_and_int_spellings_compare_across_types(self, tmp_path, monkeypatch):
        """The environment only ever carries a string, so ``daemonize = false`` in the file
        and ``VENYA_EXECUTOR_DAEMONIZE=true`` in the environment really are different
        values, and must not be waved through by a naive equality check."""
        monkeypatch.setenv("VENYA_EXECUTOR_DAEMONIZE", "true")
        cfg = ExecutorConfig.from_file(_write(tmp_path, "daemonize = false\n"))
        assert cfg.daemonize is False
        assert len(_notes(cfg)) == 1 and "daemonize" in _notes(cfg)[0]
        monkeypatch.setenv("VENYA_EXECUTOR_DAEMONIZE", "false")
        assert _notes(ExecutorConfig.from_file(_write(tmp_path, "daemonize = false\n"))) == []

    def test_announcement_names_key_sources_and_winner_not_values(self, tmp_path, monkeypatch):
        """AC2's three required parts, and the deliberate omission: a boot-time line
        is not where a credential path belongs, and the redacting formatter is not yet
        attached at the point the file is read."""
        monkeypatch.setenv(FILE_ONLY_ENV, "198.51.100.53")
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'dns_resolver = "192.0.2.53"\n'))
        (note,) = _notes(cfg)
        assert "dns_resolver" in note
        assert "config file" in note and "environment" in note
        assert PRECEDENCE_RULE in note
        for value in ("198.51.100.53", "192.0.2.53"):
            assert value not in note, f"the line must not print values, saw {value!r}"

    def test_conflict_line_reaches_the_daemon_log(self, tmp_path, monkeypatch, caplog):
        """The note existing is not the fix; the operator has to SEE it. This pins the
        emitter the served boot path uses (``venya-executor --config ...`` → main → this
        call), which is where the journal line comes from."""
        monkeypatch.setenv(TOP_ENV, "debug")
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'log_level = "warning"\n'))
        (note,) = _notes(cfg)
        with caplog.at_level(logging.WARNING, logger="venya.executor.daemon"):
            _log_precedence_conflicts(cfg)
        matched = [
            r for r in caplog.records if r.name == "venya.executor.daemon" and "Config precedence" in r.getMessage()
        ]
        assert (
            len(matched) == 1
        ), f"exactly one precedence line expected, got {[r.getMessage() for r in caplog.records]}"
        assert note in matched[0].getMessage()
        assert "log_level" in matched[0].getMessage()

    def test_a_load_with_no_conflict_logs_nothing(self, tmp_path, caplog):
        """NEGATIVE half of the emitter: silence is correct when there is nothing to
        report, and a boot that always warns is a boot nobody reads."""
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'log_level = "warning"\n'))
        with caplog.at_level(logging.WARNING, logger="venya.executor.daemon"):
            _log_precedence_conflicts(cfg)
        assert not [r for r in caplog.records if "Config precedence" in r.getMessage()]


# ---------------------------------------------------------------------------
# Row 4 — neither spelling: the field default lands, nothing is announced.
# ---------------------------------------------------------------------------


class TestRowNeitherSource:
    def test_defaults_land_and_nothing_is_announced(self, tmp_path):
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'server_url = "https://core:8080"\n'))
        assert cfg.log_level == "info"
        assert cfg.executor.max_concurrent_commands == 1
        assert _notes(cfg) == []


# ---------------------------------------------------------------------------
# Detector-level halves: the pure function, its no-value contract, and the two
# false-announcement shapes the row's own history warns about.
# ---------------------------------------------------------------------------


class TestDetectorItsOwnTruthTable:
    def test_agreeing_values_are_not_announced(self):
        """Same key, same value in both places: the operator gets what they asked for
        either way, and a warning nobody can act on is noise that trains the next
        operator to ignore the real ones."""
        notes = precedence_conflicts(file_data={"log_level": "debug"}, env_data={"log_level": "debug"})
        assert notes == []

    def test_a_key_the_environment_carries_but_the_file_does_not_is_not_announced(self):
        notes = precedence_conflicts(file_data={}, env_data={"log_level": "debug"})
        assert notes == []

    def test_a_key_the_file_carries_but_the_environment_does_not_is_not_announced(self):
        notes = precedence_conflicts(file_data={"log_level": "debug"}, env_data={})
        assert notes == []

    def test_section_header_alone_is_not_a_key(self):
        """A bare ``[audit]`` table is not a setting. Announcing it would be the
        false-positive class: the log would name a conflict the operator cannot find."""
        notes = precedence_conflicts(file_data={"audit": {}}, env_data={"audit": {}})
        assert notes == []

    def test_nested_key_matches_only_its_own_path(self):
        notes = precedence_conflicts(
            file_data={"mtls": {"cert": "/a"}},
            env_data={"mtls": {"key": "/b"}},
        )
        assert notes == []
        notes = precedence_conflicts(
            file_data={"mtls": {"cert": "/a"}},
            env_data={"mtls": {"cert": "/c"}},
        )
        assert len(notes) == 1 and "mtls.cert" in notes[0]

    def test_notes_are_stable_and_sorted(self):
        notes = precedence_conflicts(
            file_data={"log_level": "a", "dns_resolver": "b"},
            env_data={"log_level": "c", "dns_resolver": "d"},
        )
        assert [n.split(":")[0] for n in notes] == ["dns_resolver", "log_level"]


class TestNoThirdSpellingIsInvented:
    """The env source the detector reads is pydantic's own, so a spelling pydantic does
    not honour must not produce a note either — a prior worker lane's #589 cells show how many shapes
    a name can take; only the ones the model reads are live."""

    @pytest.mark.parametrize(
        "name", ["VENYA_EXECUTOR_MAX_CONCURRENT_COMMANDS", "VENYA_EXECUTOR_EXECUTOR__MAX_CONCURRENT_COMMANDS"]
    )
    def test_unhonoured_spelling_neither_lands_nor_announces(self, tmp_path, monkeypatch, name):
        monkeypatch.setenv(name, "9")
        cfg = ExecutorConfig.from_file(_write(tmp_path, "[executor]\nmax_concurrent_commands = 2\n"))
        assert cfg.executor.max_concurrent_commands == 2
        assert _notes(cfg) == [], "a note for a spelling the model never read would be a lie"


class TestContractIsStatedWhereItIsDecided:
    """AC1's code half: the rule lives at the resolution site and in one constant, not in
    scattered prose. Source-shape check, labelled as such — it cannot prove behaviour,
    which is what the rows above are for."""

    def test_one_constant_names_the_order(self):
        assert PRECEDENCE_RULE == "file > env > default"

    def test_the_served_boot_path_calls_the_emitter(self):
        """Wiring pin, labelled as the source-shape check it is. This repo's own
        ``ctx is not defined`` history is the evidence that a correct, tested function
        nobody calls is still a dead path — and ``main()`` is the only thing the systemd
        unit runs (``ExecStart=/opt/venya/.venv/bin/venya-executor --config
        /etc/venya/executor.toml``)."""
        import inspect

        from executor import daemon as daemon_module

        body = inspect.getsource(daemon_module.main)
        assert "_log_precedence_conflicts(config)" in body
        assert body.index("logging.basicConfig") < body.index("_log_precedence_conflicts(config)"), (
            "the announcement must come AFTER logging is configured, or it escapes the "
            "journal formatter the boot lines are read through"
        )

    def test_the_resolution_site_states_the_order_it_enforces(self):
        import inspect

        body = inspect.getsource(ExecutorConfig.from_file)
        assert "cls(**data)" in body, "the site that decides precedence must be this call"
        assert PRECEDENCE_RULE in body or "file > env > default" in body


class TestConflictNotesDoNotBecomeConfig:
    """The loud list is a report, not a setting. If it leaked into the model's fields,
    ``save_file`` would write it back and the next install would read a key nobody set."""

    def test_not_a_model_field(self):
        assert "_precedence_conflicts" not in ExecutorConfig.model_fields
        assert "precedence_conflicts" not in ExecutorConfig.model_fields

    def test_save_round_trip_does_not_write_the_notes(self, tmp_path, monkeypatch):
        """The notes must never become a config key. Reloading the written file DOES
        legitimately report the conflict again — the environment variable is still set — so
        the thing under test is the file's bytes, not the note count."""
        monkeypatch.setenv(TOP_ENV, "debug")
        cfg = ExecutorConfig.from_file(_write(tmp_path, 'log_level = "warning"\n'))
        assert _notes(cfg), "the cell needs a live conflict to mean anything"
        out = tmp_path / "again.toml"
        cfg.save_file(out)
        text = out.read_text()
        assert "precedence" not in text.lower()
        assert "conflict" not in text.lower()
        assert "_precedence_conflicts" not in text
        # and the reloaded value is still the file's own, not the note's
        assert ExecutorConfig.from_file(out).log_level == "warning"
