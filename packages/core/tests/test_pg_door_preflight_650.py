# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#650 — the PostgreSQL test door fails loud with its cause, or it does not fail at all.

The door variable (read it in ``scripts/pg_door_preflight.py``) is an opt-in. Set, it means "run the
PostgreSQL cells"; unset, it means "skip them", and that skip is the honest 'not run'. Between those
two there was a third state the tree never named: the door was ASKED FOR and the host could not give it. On 2026-10-16 the shared tmpfs
hit zero bytes, the scratch fixture on it self-shut on ``ENOSPC``, and the suites answered with
``psycopg2.OperationalError: … Is the server running on that host…`` — a RED PRODUCT CELL, for five
hours, twice, in two lanes. The lead's own summary: those door-ON reds were host state, not tree
state.

These cells are the row's acceptance, and the load-bearing half of them is the pair: a door that is
healthy must NOT be aborted. An abort that fires on a good host is a new way to lose the door, so
the positive controls are run against a real fixture, not asserted.

What is proven where:

* ``read_door`` state classification — pure function, real sockets, no server needed.
* The three distinct causes #650 AC3 requires be told apart: never started / died mid-run / refused.
* ``abort_unusable_door`` fires on a gated item and leaves a non-gated item alone.
* Redaction: a URL that carries a password never reaches the message, the target, or a report.
* The gate-signature contract: every gated file in the tree names the env var in its skip reason,
  because the pre-flight identifies door cells by that string. A file that invented its own wording
  would silently escape the abort, and that is the failure this row is about.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "pg_door_preflight.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the module declares a @dataclass, and that resolves its owning module
    # through sys.modules at class-creation time. Omitting this line is an ImportError, not a warning.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pdp = _load("pg_door_preflight", _SCRIPT)

# Read from the module under test rather than spelled out here, twice over for one reason: the
# #614/#630 interlock treats any file carrying that literal as a file of gated CELLS and demands a
# ``*Postgresql`` class plus the shared ``_PG_DEADLINE`` inside it. This file holds no gated cell —
# it tests the thing that decides whether they may run — and a dead class added to satisfy the
# scanner would be a check that passes on nothing. The scanner's own claims are untouched.
DOOR_ENV = pdp.DOOR_ENV


@pytest.fixture(autouse=True)
def _fresh_state_cache():
    pdp.reset_door_state_cache()
    yield
    pdp.reset_door_state_cache()


def _unix_url(sock_dir: Path, port: int, *, db: str = "nodb", user: str = "agent") -> str:
    return f"postgresql+psycopg2://{user}@/{db}?host={sock_dir}&port={port}"


def _make_stale_socket(sock_dir: Path, port: int) -> Path:
    """A socket FILE with no listener behind it — the shape a self-shut cluster leaves on disk."""
    sock_dir.mkdir(parents=True, exist_ok=True)
    path = sock_dir / f".s.PGSQL.{port}"
    if path.exists():
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
    finally:
        listener.close()  # closed on purpose: the file stays, nobody answers it
    return path


class TestDoorStateIsRead:
    """The classification, on real filesystem and socket state."""

    def test_unrequested_door_is_not_a_failure(self):
        """Door OFF: requested=False, cause=None. Cells skip and that is the honest answer.

        The negative half of the whole row — a pre-flight that complained about a lane that never
        asked for the door would be worse than the silence it replaced.
        """
        state = pdp.read_door(None) if not os.environ.get(DOOR_ENV) else pdp.read_door("")
        assert state.requested is False
        assert state.cause is None
        assert state.unusable is False
        assert pdp.abort_message(state) == ""

    def test_missing_socket_directory_reads_as_never_started(self, tmp_path):
        state = pdp.read_door(_unix_url(tmp_path / "no-such-dir", 55901))
        assert state.requested is True
        assert state.kind == "unix"
        assert state.cause == pdp.CAUSE_NEVER_STARTED
        assert "never started" in pdp.abort_message(state)

    def test_stale_socket_file_reads_as_died_mid_run(self, tmp_path):
        """AC3's whole point, as a string an operator can act on.

        Connection-refused and never-started used to be the same psycopg error. Here they are two
        named causes, and the died-mid-run one says the thing that matters: read the fixture's log
        before filing anything.
        """
        stale_dir = tmp_path / "sock"
        path = _make_stale_socket(stale_dir, 55902)
        assert path.exists(), "fixture: the socket file must survive the closed listener"
        state = pdp.read_door(_unix_url(stale_dir, 55902))
        assert state.kind == "unix"
        assert state.reachable is False
        assert state.cause == pdp.CAUSE_DIED_MID_RUN
        message = pdp.abort_message(state)
        assert "STOPPED" in message and "log" in message
        assert state.cause != pdp.CAUSE_NEVER_STARTED, "the two causes collapsed into one"

    @pytest.mark.parametrize(
        ("maker", "want"),
        [
            (lambda tp: _unix_url(tp / "absent", 55913), pdp.CAUSE_NEVER_STARTED),
            (
                lambda tp: (_make_stale_socket(tp / "sock", 55914), _unix_url(tp / "sock", 55914))[1],
                pdp.CAUSE_DIED_MID_RUN,
            ),
            (lambda tp: "postgresql+psycopg2://agent@127.0.0.1:59995/db", pdp.CAUSE_REFUSED),
        ],
    )
    def test_an_unreachable_door_on_a_healthy_disk_names_the_reach_not_the_disk(self, tmp_path, maker, want):
        """Condition 3 of the lead's ruling, stated as a refusal to blame the tmpfs.

        The three states must not collapse into one "PG door unavailable": a lane that is told the
        disk is short when 4.8 GiB is free goes and frees a disk that was never the problem, which is
        a false-green wearing a louder font. So the space words appear ONLY in the space cause.
        """
        state = pdp.read_door(maker(tmp_path))
        assert state.cause == want
        message = pdp.abort_message(state)
        assert (
            "floor" not in message and "space low" not in message
        ), f"cause {want!r} was reported with disk language: {message}"
        assert f"{state.free_mib} MiB free" in message, "the number still belongs in the line"
        assert state.free_bytes > pdp.MIN_FREE_BYTES, "precondition: this disk really is healthy"

    def test_tcp_door_with_no_listener_reads_as_refused(self):
        state = pdp.read_door("postgresql+psycopg2://agent@127.0.0.1:59997/venya_test")
        assert state.kind == "tcp"
        assert state.cause == pdp.CAUSE_REFUSED

    def test_the_port_of_a_unix_url_is_read_from_the_query_not_the_netloc(self, tmp_path):
        """The bug this cell was written to keep: the socket file is named by the QUERY port.

        ``parsed.port`` is None for a ``…?host=/sock&port=N`` URL, and a pre-flight that defaulted
        to 5432 looked for the wrong file and called a dead--but-present fixture 'never started'.
        """
        sock_dir = tmp_path / "sock"
        _make_stale_socket(sock_dir, 55903)
        state = pdp.read_door(_unix_url(sock_dir, 55903))
        assert state.cause == pdp.CAUSE_DIED_MID_RUN, (
            f"the port was mis-read and the cause became {state.cause!r} — the message would have "
            "sent a lane to start a fixture that is already sitting there stopped"
        )

    def test_a_live_socket_answers_as_reachable_and_nothing_is_aborted(self, tmp_path):
        """THE PAIRED NEGATIVE, run against a real listener: a healthy door is not aborted."""
        sock_dir = tmp_path / "sock"
        sock_dir.mkdir()
        path = sock_dir / ".s.PGSQL.55904"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        try:
            state = pdp.read_door(_unix_url(sock_dir, 55904))
            assert state.reachable is True
            assert state.cause is None
            assert state.unusable is False
            assert pdp.abort_message(state) == ""
        finally:
            listener.close()
            path.unlink(missing_ok=True)

    def test_an_unparseable_url_is_a_named_cause_not_a_traceback(self):
        """A pre-flight that raises is a new outage. It reports, whatever it is given."""
        for junk in ["", "not-a-url", "mysql://agent@localhost/db", "postgresql://"]:
            state = pdp.read_door(junk) if junk else pdp.read_door("")
            assert isinstance(state.cause, str) or not state.requested
            assert not state.reachable


class TestBothParsersAgree:
    """The door URL is read two ways — SQLAlchemy when it answers, plain text when it does not.

    This is not decoration: the first cut's text fallback read ``…@/nodb`` as a HOST and never looked
    for a port in the query, so a unix door became a bogus TCP probe of "/nodb" on 5432 and the
    stopped-but-present fixture was reported as "never started". A fallback nobody runs is a fallback
    nobody tests, and the bug is exactly the mislabelled-cause failure #650 exists to stop.
    """

    _UNIX = "postgresql+psycopg2://agent@/venya_test_x?host=/tmp/tabichat/pg/sock&port=55902"
    _TCP = "postgresql+psycopg2://agent@127.0.0.1:55903/venya_test_x"

    @pytest.mark.parametrize(
        ("url", "want"),
        [
            (_UNIX, {"host": None, "port": 55902, "socket_dir": "/tmp/tabichat/pg/sock", "database": "venya_test_x"}),
            (_TCP, {"host": "127.0.0.1", "port": 55903, "socket_dir": None, "database": "venya_test_x"}),
        ],
    )
    def test_the_plain_text_path_reads_the_same_parts(self, url, want):
        got = pdp._parse_plain(url)
        assert got == want, f"plain path read {got}, wanted {want}"

    def test_both_parsers_classify_one_door_identically(self, tmp_path):
        """Force the fallback by breaking the import, and require the same answer either way."""
        sock_dir = tmp_path / "sock"
        _make_stale_socket(sock_dir, 55904)
        url = _unix_url(sock_dir, 55904)
        via_sqlalchemy = pdp.read_door(url)

        import builtins

        real_import = builtins.__import__

        def _no_sqlalchemy(name, *args, **kwargs):
            if name.startswith("sqlalchemy"):
                raise ImportError("simulated: the door must still be readable without it")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = _no_sqlalchemy
        try:
            via_plain = pdp.read_door(url)
        finally:
            builtins.__import__ = real_import

        assert (
            via_plain.cause == via_sqlalchemy.cause == pdp.CAUSE_DIED_MID_RUN
        ), f"sqlalchemy said {via_sqlalchemy.cause!r}, the text path said {via_plain.cause!r}"
        assert via_plain.kind == via_sqlalchemy.kind == "unix"


class TestSpaceIsPartOfTheDoor:
    """The half that would have caught 2026-10-16 while it was still only a disk."""

    def test_free_space_is_reported_on_the_door_s_own_volume(self, tmp_path):
        state = pdp.read_door(_unix_url(tmp_path / "absent", 55905))
        assert state.free_bytes >= 0, "statvfs answered, so the number is real and not a guess"
        assert Path(state.filesystem).exists() or state.filesystem == tmp_path.as_posix()
        assert state.free_mib > 0

    def test_a_door_on_a_volume_below_the_floor_is_aborted_for_space_first(self, tmp_path, monkeypatch):
        """Reachable OR not, low space wins the naming.

        Ordering is the finding: on 2026-10-16 every later symptom — the self-shut, the refused
        socket, the red cells — sat behind one number that nobody printed.
        """
        sock_dir = tmp_path / "sock"
        _make_stale_socket(sock_dir, 55906)
        monkeypatch.setattr(pdp, "MIN_FREE_BYTES", 10**15)  # a floor no tmpfs on this box clears
        state = pdp.read_door(_unix_url(sock_dir, 55906))
        assert state.cause == pdp.CAUSE_SPACE_LOW
        message = pdp.abort_message(state)
        assert "floor" in message and "MiB free" in message, message

    def test_a_space_reading_that_fails_is_not_reported_as_a_full_disk(self, monkeypatch):
        """An unreadable volume answers -1 free and must NOT trip the floor.

        "Cannot statvfs" and "no space left" are different facts, and calling the first one the
        second would file a phantom defect — the same class of mislabel this row was born from.
        """

        def _boom(_path):
            return ("/nonexistent-volume", -1)

        monkeypatch.setattr(pdp, "_free_bytes", _boom)
        state = pdp.read_door(_unix_url(Path("/nonexistent-volume/sock"), 55907))
        assert state.free_bytes == -1
        assert state.cause != pdp.CAUSE_SPACE_LOW

    def test_the_floor_is_a_stated_number_not_a_mystery(self):
        """#650 AC4: capacity is a named input. 64 MiB, and the module says it is a guard band."""
        assert pdp.MIN_FREE_BYTES == 64 * 1024 * 1024
        source = _SCRIPT.read_text(encoding="utf-8")
        assert "GUARD BAND" in source, "the floor must be labelled as what it is, not a measurement"


class TestTheHookFailsTheRightCells:
    """``abort_unusable_door`` — one gated cell aborted, one ordinary cell untouched."""

    class _Marker:
        """A stand-in for one collected ``skipif`` mark: ``gate_reasons`` reads args/kwargs and
        nothing else, so the hook is exercised without touching pytest's private marker class."""

        def __init__(self, args=(), kwargs=None):
            self.args = tuple(args)
            self.kwargs = kwargs or {}

    class _Item:
        def __init__(self, reasons):
            self._reasons = reasons

        def iter_markers(self, name=None):
            assert name == "skipif"
            return [TestTheHookFailsTheRightCells._Marker(kwargs={"reason": r}) for r in self._reasons]

    def test_gated_cell_is_failed_with_the_cause_and_the_number(self, tmp_path, monkeypatch):
        monkeypatch.setenv(DOOR_ENV, _unix_url(tmp_path / "absent", 55908))
        pdp.reset_door_state_cache()
        item = self._Item([f"real-concurrency cell needs a scratch PostgreSQL in {DOOR_ENV}"])
        with pytest.raises(pytest.fail.Exception) as got:
            pdp.abort_unusable_door(item)
        text = str(got.value)
        assert "PG DOOR ABORTED BY PRE-FLIGHT" in text
        assert "never started" in text
        assert "MiB free" in text, "the number belongs in the line; a cause without it is a guess"

    def test_non_gated_cell_is_left_alone(self, tmp_path, monkeypatch):
        """The other half of the pair: a dead door must not take the package down with it."""
        monkeypatch.setenv(DOOR_ENV, _unix_url(tmp_path / "absent", 55909))
        pdp.reset_door_state_cache()
        pdp.abort_unusable_door(self._Item(["needs a network"]))

    def test_reason_with_the_gate_string_in_a_positional_form_is_still_detected(self, tmp_path, monkeypatch):
        """Some files write ``skipif(cond, "reason")`` positionally. Both shapes must match."""
        monkeypatch.setenv(DOOR_ENV, _unix_url(tmp_path / "absent", 55910))
        pdp.reset_door_state_cache()
        item = self._Item([])
        item.iter_markers = lambda name=None: [  # type: ignore[method-assign]
            self._Marker(args=(True, f"needs {DOOR_ENV} scratch"))
        ]
        with pytest.raises(pytest.fail.Exception):
            pdp.abort_unusable_door(item)

    def test_a_healthy_door_does_not_abort_anything(self, tmp_path, monkeypatch):
        """THE ROW'S PAIRED NEGATIVE at the hook level: healthy /tmp, live listener, no abort."""
        sock_dir = tmp_path / "sock"
        sock_dir.mkdir()
        path = sock_dir / ".s.PGSQL.55911"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        try:
            monkeypatch.setenv(DOOR_ENV, _unix_url(sock_dir, 55911))
            pdp.reset_door_state_cache()
            gated = self._Item([f"needs a scratch PostgreSQL in {DOOR_ENV}"])
            pdp.abort_unusable_door(gated)  # must not raise
        finally:
            listener.close()
            path.unlink(missing_ok=True)

    def test_the_state_is_probed_once_per_run_not_once_per_cell(self, tmp_path, monkeypatch):
        """A pre-flight that can stall is its own outage: one read per process, cached."""
        monkeypatch.setenv(DOOR_ENV, _unix_url(tmp_path / "absent", 55912))
        pdp.reset_door_state_cache()
        calls: list[str] = []
        real = pdp.read_door

        def counting(url=None):
            calls.append(str(url))
            return real(url)

        monkeypatch.setattr(pdp, "read_door", counting)
        for _ in range(25):
            pdp.door_state()
        assert len(calls) == 1, f"the door was probed {len(calls)} times for 25 cells"


class TestCredentialsNeverReachTheLine:
    """The URL may hold the dev DB password. Masker law: structure never content."""

    #: Not a credential and never was one — a sentinel whose only job is to be absent from the
    #: printed line. Named without the word "secret" so the repo's own detect-secrets hook does not
    #: have to be suppressed for it: a pragma here would be a suppression of a finding that should
    #: never have existed, and the baseline is not a place to park test fiction.
    _SENTINEL_VALUE = "must-not-appear-in-any-printed-line"

    def test_a_password_in_the_url_never_reaches_the_target_or_the_message(self):
        url = f"postgresql+psycopg2://venya_test:{self._SENTINEL_VALUE}@127.0.0.1:59996/venya_test"
        state = pdp.read_door(url)
        assert self._SENTINEL_VALUE not in state.target
        assert self._SENTINEL_VALUE not in pdp.abort_message(state)
        assert self._SENTINEL_VALUE not in pdp.describe_for_report(state)
        assert "venya_test@127.0.0.1" in state.target, "the account is host state and stays readable"

    def test_a_url_with_no_credential_is_left_whole(self):
        url = "postgresql+psycopg2://agent@/venya_test?host=/tmp/tabichat/sock&port=55443"
        assert pdp.redact_url(url) == url


class TestGateSignatureContractIsTrueOfTheTree:
    """The hook identifies door cells by the env var naming in their skip reason.

    That is only safe while it is TRUE of the tree, so it is checked against the tree rather than
    assumed: every file that reads the door must carry the string in a reason the hook can see. A
    file that invented its own wording would keep dying quietly, which is the defect class this row
    exists to close — and the guard is a cell, not a paragraph in a doc.
    """

    @staticmethod
    def _gated_files() -> list[Path]:
        roots = [_REPO_ROOT / "packages" / p / "tests" for p in ("core", "server")]
        return sorted(
            path for root in roots for path in root.glob("*.py") if DOOR_ENV in path.read_text(encoding="utf-8")
        )

    def test_the_scan_finds_the_gated_files_and_is_not_empty(self):
        files = self._gated_files()
        assert len(files) >= 11, f"only {len(files)} files name the door — the scan went blind"
        assert _SCRIPT.name not in [f.name for f in files]

    def test_every_gated_class_names_the_door_in_its_skip_reason(self):
        """The contract, per file: a ``*Postgresql`` class whose skipif reason carries the string."""
        import ast

        offenders: list[str] = []
        for path in self._gated_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.ClassDef) and node.name.endswith("Postgresql")):
                    continue
                reasons: list[str] = []
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and "skipif" in ast.dump(decorator.func):
                        for arg in list(decorator.args) + [kw.value for kw in decorator.keywords]:
                            if isinstance(arg, ast.JoinedStr):
                                reasons.append(ast.unparse(arg))
                            elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                reasons.append(arg.value)
                blob = " ".join(reasons)
                if DOOR_ENV not in blob and "_PG_URL_ENV" not in blob and "PG_URL_ENV" not in blob:
                    offenders.append(f"{path.name}::{node.name}")
        assert not offenders, (
            "these gated classes do not name the door in a skipif reason, so the pre-flight cannot "
            f"see them: {offenders}"
        )

    @pytest.mark.parametrize("package", ["core", "server"])
    def test_each_package_wires_the_shared_script_in_its_tests_dir(self, package):
        """One rulebook, two thin wirings, both in ``packages/<pkg>/tests/conftest.py``.

        Asserted as text, so a third copy of the rule cannot appear quietly in a conftest and a
        wiring that was deleted cannot pass as coverage. The location is the lead's ruling
        (``wren-650-conftest-ruling-flash1-s134``), and the file must stay a wiring: if a cause table
        or an ENOSPC string ever appears in it, someone grew a second implementation.
        """
        conftest = _REPO_ROOT / "packages" / package / "tests" / "conftest.py"
        assert conftest.is_file(), f"{package} lost its door wiring: {conftest} is not there"
        source = conftest.read_text(encoding="utf-8")
        assert "pg_door_preflight" in source, f"{package}'s conftest stopped loading the shared script"
        assert "abort_unusable_door" in source, f"{package}'s conftest stopped calling the hook"
        assert "pytest_report_header" in source, f"{package}'s conftest stopped stating the finding"
        assert (
            "CAUSE_" not in source and "ENOSPC" not in source
        ), f"{package}'s conftest grew its own copy of the cause table"

    def test_the_script_is_the_only_copy_of_the_rule(self):
        """No second implementation of the door's causes in a conftest or a test."""
        hits = []
        for path in _REPO_ROOT.glob("packages/*/tests/conftest.py"):
            source = path.read_text(encoding="utf-8")
            if "CAUSE_DIED_MID_RUN" in source or "ENOSPC" in source:
                hits.append(str(path))
        assert not hits, f"a second copy of the cause table lives here: {hits}"
