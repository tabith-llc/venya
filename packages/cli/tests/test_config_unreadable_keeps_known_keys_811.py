# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#811 — a session file this tool cannot read is never quietly replaced by an empty one.

The shape that was measured (leg 1586, the half that needs no ruling): ``Config._load`` caught the
parse failure and set ``_data = {}``, so the file stayed ``read=False`` with ``source_error`` unset
on the default path, and the next ``save()`` — which is what ``venya login`` does when its ceremony
finishes — published that empty snapshot. ``server_url survived? False``: the core the operator had
named with ``venya config set-server`` was gone from the file, the following command dialled
``http://localhost:8000``, and nothing anywhere said so. The MCP reader, on the same bytes, raises at
construction; two tools, one damaged file, and the quiet one is the one that destroys.

Cells, in the order the fix states them:

* every damaged shape is driven through the **writer**, not the reader: truncated JSON, a zero-byte
  file, a top-level list, a top-level string;
* the bytes are **kept** — a rename to ``<file>.corrupt``, so the operator's own text is still there
  to read, and no second copy of a token-bearing file is created;
* the tell reaches the operator **on the default path**, where ``VENYA_CONFIG`` named nothing, and it
  names paths and the act, never a value;
* the write still lands: a preservation that fails is reported, not turned into a refusal, because the
  verbs that repair this file (``venya login``, ``venya setup``) must keep working;
* the flag is consumed, so two saves in one process tell once and never move the good file aside.

Paired negatives, which are the half that keeps this honest: **a healthy config round-trips
unchanged** — same keys, same mode, no ``.corrupt`` sibling, nothing on stderr; and a machine with no
config file at all still gets its first one written in silence. A fix that makes every good read shout
is the worse bug.
"""

import json
import os
from pathlib import Path

import pytest
from venya_cli import api_client
from venya_cli.api_client import DEFAULT_SERVER_URL, Config

CORE_URL = "https://core.example.test"
HEALTHY_DOC = {"server_url": CORE_URL, "access_token": "tok-a", "operator_key": "keep-me"}
NEW_TOKEN = "tok-B"

#: bytes that do not yield a config object, and the reason each one is its own shape
DAMAGED = {
    "truncated": '{"server_url": "https://core.example.test", "acc',
    "zero_byte": "",
    "top_level_list": '["a", "b"]',
    "top_level_string": '"just a string"',
}


def _config_at(tmp_path: Path, body: str | None) -> Config:
    """A fixture-planted session file in a fresh directory — never a real user config."""
    path = tmp_path / "config.json"
    if body is not None:
        path.write_text(body)
    return Config(config_file=path)


@pytest.mark.parametrize("body", sorted(DAMAGED.values()), ids=sorted(DAMAGED))
def test_a_damaged_file_is_kept_when_the_writer_next_saves(tmp_path: Path, body: str, capsys) -> None:
    """The save writes its own keys AND leaves the unreadable bytes where a person can read them."""
    config = _config_at(tmp_path, body)
    assert config.read is False
    assert config.damaged_bytes is True  # the read knew, even when it said nothing

    config.access_token = NEW_TOKEN  # what `venya login` does at the end of a ceremony

    kept = tmp_path / "config.json.corrupt"
    assert kept.exists(), "the bytes this tool could not parse were not preserved"
    assert kept.read_text() == body, "the preserved copy must be the operator's own text, unchanged"
    assert json.loads((tmp_path / "config.json").read_text()) == {
        "access_token": NEW_TOKEN
    }, "the new file holds exactly what this process knows"

    err = capsys.readouterr().err
    assert "could not be read as a config" in err
    assert str(tmp_path / "config.json") in err, "the tell names the path the operator has to act on"
    assert "config.json.corrupt" in err
    assert "venya config set-server" in err, "the tell carries the verb that puts the core back"


@pytest.mark.parametrize("body", sorted(DAMAGED.values()), ids=sorted(DAMAGED))
def test_the_tell_never_prints_a_value(tmp_path: Path, body: str, capsys) -> None:
    """The session file is where a bearer token lives; the report about it stays on the path."""
    config = _config_at(tmp_path, body)
    config.access_token = NEW_TOKEN

    err = capsys.readouterr().err
    assert NEW_TOKEN not in err, "the value this command wrote is not printed in the tell"
    assert "tok-a" not in err and CORE_URL not in err, "nor is anything read back out of the file"


def test_a_non_object_document_no_longer_crashes_the_reader(tmp_path: Path) -> None:
    """Before: ``read=True`` and ``AttributeError`` out of every property. Now it is a failed read.

    This is the shape the finding did not name and the measurement turned up: ``json.loads`` succeeds
    on a top-level list, so the old code trusted it, and the first ``.get`` raised. The key read now
    answers the documented built-in default, which `config show` marks as a default and never as
    configuration.
    """
    config = _config_at(tmp_path, DAMAGED["top_level_list"])

    assert config.read is False
    assert config.server_url == DEFAULT_SERVER_URL
    assert config.access_token is None


def test_two_saves_in_one_process_tell_once_and_move_nothing_twice(tmp_path: Path, capsys) -> None:
    """The flag is consumed by the preservation, so a healthy file is never renamed away."""
    config = _config_at(tmp_path, DAMAGED["truncated"])
    config.access_token = NEW_TOKEN
    config.server_url = CORE_URL  # a second write, now on a file this process just made

    err = capsys.readouterr().err
    assert err.count("could not be read as a config") == 1
    assert json.loads((tmp_path / "config.json").read_text()) == {
        "access_token": NEW_TOKEN,
        "server_url": CORE_URL,
    }
    assert sorted(q.name for q in tmp_path.iterdir()) == ["config.json", "config.json.corrupt"]


def test_a_failed_preservation_is_reported_and_still_writes(tmp_path: Path, monkeypatch, capsys) -> None:
    """Losing the bytes is bad; blocking the repair is worse, so the write goes on and says so.

    The rename is made to fail on the ``.corrupt`` destination only, so the atomic write underneath it
    still runs — the same distinction the product draws everywhere else between a warning and a stop.
    """
    real_replace = os.replace

    def replace_unless_keeping(src, dst):
        if str(dst).endswith(".corrupt"):
            raise OSError(18, "cross-device link")
        return real_replace(src, dst)

    monkeypatch.setattr(api_client.os, "replace", replace_unless_keeping)
    config = _config_at(tmp_path, DAMAGED["zero_byte"])

    config.access_token = NEW_TOKEN

    err = capsys.readouterr().err
    assert "could not be kept" in err, "the tell says the bytes were lost, not that they were saved"
    assert json.loads((tmp_path / "config.json").read_text()) == {"access_token": NEW_TOKEN}
    assert not (tmp_path / "config.json.corrupt").exists()


# --- the paired negatives: nothing about a good config changes -------------------------------


def test_a_healthy_config_round_trips_unchanged_and_silent(tmp_path: Path, capsys) -> None:
    """Same keys, same mode, no sibling file, not one word on stderr.

    This is the cell that keeps the fix honest: a louder failure that blocks the repair is the worse
    outcome, and a warning printed on every good save is how an operator learns to ignore warnings.
    """
    path = tmp_path / "config.json"
    path.write_text(json.dumps(HEALTHY_DOC))
    config = Config(config_file=path)
    assert config.read is True

    config.access_token = NEW_TOKEN

    after = json.loads(path.read_text())
    assert after == {**HEALTHY_DOC, "access_token": NEW_TOKEN}, "the operator's keys are untouched"
    assert path.stat().st_mode & 0o777 == 0o600, "and the owner-only write is the one it already was"
    assert [q.name for q in tmp_path.iterdir()] == ["config.json"], "no .corrupt on a good read"
    assert capsys.readouterr().err == "", "and a healthy session is silent"


def test_a_machine_with_no_config_yet_is_still_written_in_silence(tmp_path: Path, capsys) -> None:
    """The fresh-home shape: absence is not damage, and the first save is the normal case."""
    config = _config_at(tmp_path, None)
    assert config.read is False
    assert config.source_error is None  # a path the PROGRAM supplied is never an operator error (#247)

    config.access_token = NEW_TOKEN

    assert json.loads((tmp_path / "config.json").read_text()) == {"access_token": NEW_TOKEN}
    assert [q.name for q in tmp_path.iterdir()] == ["config.json"]
    assert capsys.readouterr().err == ""
