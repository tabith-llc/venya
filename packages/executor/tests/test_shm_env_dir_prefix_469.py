# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Ticket #469 — the ``env_*`` tmpfs fallback dir is now reaped by somebody.

``SbxStrategy._write_env_file`` creates a fallback directory when no
``prepare()`` session dir exists:
``tempfile.mkdtemp(prefix="env_", dir=SECRET_TMPFS_BASE)`` under
``/dev/shm/venya-secrets``. Nothing removed ``env_*``: the daemon reaper skipped
every name that was not ``session_*``, and ``sweep_workspace_base`` walks a
DIFFERENT base (``~/.venya-workspaces``) matching ``ws_*`` only. So the fallback
branch left its directory for the host's uptime, and an abort between the
``os.open`` and the ``finally`` destroy left a 0600 plaintext-secret ``venya-env``
file in a directory whose name carries no session id.

Two owners, two halves of the fix (mechanism stated per site, AC1):

* **AC4 — the writer takes back what it made.** ``_write_env_file`` records the
  fallback dir in ``self._fallback_env_dir``; ``execute_command``'s ``finally``
  calls ``_release_fallback_dir()``, which ``os.rmdir``-s that dir once the env
  file is gone. ``rmdir`` (not ``rmtree``) is the collateral guard: a non-empty
  dir refuses the remove and is left for the reaper.
* **AC1 — the reaper now matches the prefix.** ``ReaperLoop._check_orphaned``
  accepts ``env_*`` beside ``session_*``.

The §3 mis-parse check is why the prefix half needed a guard, and it is the
reason the *rename* alternative was not chosen: ``mkdtemp``'s random charset is
``[a-z0-9_]``, so an ``env_`` name can contain underscores — ``env_a1b_2c``
splits into three parts. The reaper's left-pick (``parts[1]``) would read a
random token as an execution-session id and POST a revoke for it; the server
skips non-numeric ids for the DELETE but STILL writes a ``credential_revoked``
audit row per id it is handed (routes/secrets.py, "audit writes unchanged").
So the parse is gated on the ``session_`` prefix: an ``env_*`` dir is deleted,
never attributed.

All cells are unit-only against a tmp_path base (the autouse ``_setup_tmpfs``
fixture repoints ``SECRET_TMPFS_BASE``); the real /dev/shm is never touched. The
physical step (a killed daemon, a real /dev/shm, a sweep cycle) is the DO-NOT-RUN
cell in the leg report.
"""

import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from executor.config import ExecutorConfig, ReaperConfig
from executor.daemon import DaemonState, ReaperLoop
from executor.strategies.sbx_strategy import ENV_DIR_PREFIX, SESSION_DIR_PREFIX, SbxStrategy

SESSION_ID = "11111111-2222-3333-4444-555555555555"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _reaper(base: Path, ttl_seconds: int = 1) -> ReaperLoop:
    config = ExecutorConfig(
        server_url="https://example.com",
        executor_id="test-executor",
        reaper=ReaperConfig(check_interval=0.1, secret_ttl_seconds=ttl_seconds),
    )
    client = MagicMock()
    return ReaperLoop(config, DaemonState(), tmpfs_dir=str(base), http_client=client)


def _age(path: Path, seconds: float = 10.0) -> None:
    old = time.time() - seconds
    os.utime(path, (old, old))


def _fallback_strategy(base: Path) -> SbxStrategy:
    """A strategy on the fallback branch: no prepare() ran, so _session_dir is None.

    SECRET_TMPFS_BASE is the autouse tmp_path base (conftest ``_setup_tmpfs``),
    which is what the fallback mkdtemp writes into.
    """
    strategy = SbxStrategy()
    strategy._sandbox_name = "venya-test469"
    assert strategy._session_dir is None
    assert base.is_dir()
    return strategy


def _run_exec(strategy: SbxStrategy, env: dict | None = None) -> None:
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
        strategy.execute_command("cmd", env_override=env if env is not None else {"A": "1"})


# ---------------------------------------------------------------------------
# AC4 — the writer removes the directory it created
# ---------------------------------------------------------------------------


class TestFallbackDirIsOwnedAndRemoved:
    def test_T1_success_path_leaves_no_dir(self, tmp_path):
        """T1: the fallback branch creates env_*; after the exec, file AND dir are gone."""
        base = tmp_path / "shm"
        base.mkdir(exist_ok=True)
        strategy = _fallback_strategy(base)

        _run_exec(strategy, {"A": "1"})

        assert base.exists()
        assert list(base.iterdir()) == [], "fallback env dir survived the success path"
        assert strategy._session_dir is None
        assert strategy._fallback_env_dir is None

    def test_T1b_created_dir_carries_the_env_prefix(self, tmp_path):
        """The dir really is an ``env_*`` name while the exec is in flight.

        Pinned here so a future prefix change cannot silently move the dir out
        from under the reaper that now matches it.
        """
        base = tmp_path / "shm"
        base.mkdir(exist_ok=True)
        strategy = _fallback_strategy(base)
        seen: list[str] = []

        def _spy(*args, **kwargs):
            seen[:] = sorted(p.name for p in base.iterdir())
            return MagicMock(returncode=0, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=_spy):
            strategy.execute_command("cmd", env_override={"A": "1"})

        assert seen and all(name.startswith(ENV_DIR_PREFIX) for name in seen), seen
        assert strategy._fallback_env_dir is None  # taken back after the exec

    def test_T4_rejected_env_name_leaves_no_dir(self, tmp_path):
        """A rejection happens before any file exists — the empty dir is taken back.

        The raise itself is unchanged (paired negative on the error contract).
        """
        base = tmp_path / "shm"
        base.mkdir(exist_ok=True)
        strategy = _fallback_strategy(base)

        with pytest.raises(ValueError, match="invalid env var name"):
            strategy.execute_command("cmd", env_override={"BAD NAME": "1"})

        assert list(base.iterdir()) == []
        assert strategy._session_dir is None

    def test_T5_abort_between_open_and_destroy_is_swept(self, tmp_path):
        """T5: kill mid-exec — the dir with its plaintext file is NOT left to fester.

        Simulated the way a kill leaves it: the env file still inside the
        ``env_*`` dir, no ``finally`` ever ran. ``_release_fallback_dir`` refuses
        the non-empty dir (rmdir, not rmtree), then the reaper collects it.
        """
        base = tmp_path / "shm"
        base.mkdir(exist_ok=True)
        strategy = _fallback_strategy(base)

        env_path = strategy._write_env_file({"SECRET": "plaintext-value"})
        assert Path(env_path).read_text() == "SECRET=plaintext-value\n"
        # The destroy never ran (a kill in that window): file + dir both present.
        env_dir = Path(env_path).parent
        _age(env_dir)

        reaper = _reaper(base)
        reaper._check_orphaned()

        assert not env_dir.exists(), "aborted env dir survived the sweep"
        assert not Path(env_path).exists()
        assert list(base.iterdir()) == []
        # No session id in the name, so no revoke was ever attempted.
        reaper.http_client.post.assert_not_called()

    def test_T4b_nonempty_dir_is_never_rmtree_ed_by_the_writer(self, tmp_path):
        """Paired negative for the rmdir choice: a dir holding anything survives.

        The writer's cleanup must never become a recursive delete — collateral
        material inside the dir is the reaper's question, not this one's.
        """
        base = tmp_path / "shm"
        base.mkdir(exist_ok=True)
        strategy = _fallback_strategy(base)

        env_path = strategy._write_env_file({"A": "1"})
        env_dir = Path(env_path).parent
        strategy._release_fallback_dir()  # file still inside -> rmdir refuses

        assert env_dir.exists()
        assert Path(env_path).exists()
        assert strategy._fallback_env_dir == str(env_dir)  # ownership not released


# ---------------------------------------------------------------------------
# AC1 — the reaper matches the prefix now
# ---------------------------------------------------------------------------


class TestReaperCollectsEnvPrefix:
    def test_T1_env_dir_swept_aged(self, tmp_path):
        base = tmp_path / "shm"
        d = base / f"{ENV_DIR_PREFIX}a1b2c3d4"
        d.mkdir(parents=True)
        (d / "venya-env").write_text("A=plaintext\n")
        _age(d)

        _reaper(base)._check_orphaned()

        assert not d.exists()
        assert list(base.iterdir()) == []

    def test_fresh_env_dir_is_not_swept(self, tmp_path):
        """Paired negative: the TTL still rules — a live run's dir is untouched."""
        base = tmp_path / "shm"
        d = base / f"{ENV_DIR_PREFIX}fresh1"
        d.mkdir(parents=True)
        (d / "venya-env").write_text("A=1\n")

        _reaper(base, ttl_seconds=300)._check_orphaned()

        assert d.exists()

    def test_env_suffix_that_looks_like_a_session_is_still_swept(self, tmp_path):
        """A name that merely CONTAINS 'session_' is env-classified by its prefix."""
        base = tmp_path / "shm"
        d = base / f"{ENV_DIR_PREFIX}session_9"
        d.mkdir(parents=True)
        _age(d)

        reaper = _reaper(base)
        reaper._check_orphaned()

        assert not d.exists()
        reaper.http_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# §3 — the mis-parse check: an env_* name must never reach the session parser
# ---------------------------------------------------------------------------


class TestEnvNameCannotBeMisParsed:
    def test_T6_underscore_in_env_rand_is_not_read_as_a_session_id(self, tmp_path):
        """THE cell. ``mkdtemp``'s charset is [a-z0-9_], so env_* CAN split to
        three parts: ``env_a1b_2c`` -> ['env','a1b','2c']. Under the ungated
        left-pick the reaper would POST a revoke for session id 'a1b' — a
        phantom session — and the server would write a credential_revoked audit
        row for every name in the dir. Gated on the prefix, it deletes and
        attributes nothing."""
        base = tmp_path / "shm"
        d = base / f"{ENV_DIR_PREFIX}a1b_2c"  # 3 parts if split naively
        d.mkdir(parents=True)
        (d / "venya-env").write_text("A=plaintext\n")
        _age(d)

        reaper = _reaper(base)
        reaper._check_orphaned()

        assert not d.exists()
        reaper.http_client.post.assert_not_called()

    def test_T6b_underscore_only_env_names_never_revoke(self, tmp_path):
        """Sweep of shapes: every underscore count, zero revoke calls."""
        base = tmp_path / "shm"
        names = [
            f"{ENV_DIR_PREFIX}plain",
            f"{ENV_DIR_PREFIX}one_two",
            f"{ENV_DIR_PREFIX}two_three_four",
            f"{ENV_DIR_PREFIX}_lead_trail_",
        ]
        for n in names:
            d = base / n
            d.mkdir(parents=True)
            (d / "venya-env").write_text("A=1\n")
            _age(d)

        reaper = _reaper(base)
        reaper._check_orphaned()

        assert list(base.iterdir()) == [], "an env dir survived the sweep"
        reaper.http_client.post.assert_not_called()

    def test_T6c_session_parse_still_attributes_after_the_gate(self, tmp_path):
        """Paired negative for the gate itself: gating the PARSE on the prefix
        must not cost the session_* half its attribution."""
        base = tmp_path / "shm"
        d = base / f"{SESSION_DIR_PREFIX}{SESSION_ID}_abcd1234"
        d.mkdir(parents=True)
        (d / "7").write_bytes(b"x")
        (d / "3").write_bytes(b"x")
        _age(d)

        reaper = _reaper(base)
        reaper._check_orphaned()

        assert not d.exists()
        args, kwargs = reaper.http_client.post.call_args
        assert args[0] == f"/api/v1/sessions/{SESSION_ID}/secrets/revoke"
        assert kwargs["json"] == {"secret_ids": ["3", "7"]}


# ---------------------------------------------------------------------------
# AC3 — paired negative: session_* reaping unchanged, no collateral deletion
# ---------------------------------------------------------------------------


class TestSessionReapingUnchangedAndNoCollateral:
    def test_T2_aged_session_dir_deleted_and_revoked(self, tmp_path):
        base = tmp_path / "shm"
        d = base / f"{SESSION_DIR_PREFIX}{SESSION_ID}_abcd1234"
        d.mkdir(parents=True)
        (d / "9").write_bytes(b"x")
        _age(d)

        reaper = _reaper(base)
        reaper._check_orphaned()

        assert not d.exists()
        reaper.http_client.post.assert_called_once()

    def test_T2b_unparseable_session_name_still_deleted_without_revoke(self, tmp_path):
        """The pre-existing 'two parts -> no id' behavior survives the change."""
        base = tmp_path / "shm"
        d = base / f"{SESSION_DIR_PREFIX}x"  # splits to 2 parts
        d.mkdir(parents=True)
        (d / "5").write_bytes(b"x")
        _age(d)

        reaper = _reaper(base)
        reaper._check_orphaned()

        assert not d.exists()
        reaper.http_client.post.assert_not_called()

    def test_T3_matching_neither_prefix_is_untouched(self, tmp_path):
        """T3: the reaper must not be widened into a general tmpfs delete."""
        base = tmp_path / "shm"
        strangers = {
            "ws_leftover": "dir",
            "not-a-session": "dir",
            "venya_1_x.secret": "file",  # pragma: allowlist secret — a legacy FILE name, not a credential
            "session": "dir",  # exact word, no separator
            "envx_trailing": "dir",  # looks close, is not the prefix
            "env": "dir",  # the prefix without its separator
        }
        for name, kind in strangers.items():
            p = base / name
            if kind == "dir":
                p.mkdir(parents=True)
            else:
                p.write_bytes(b"x")
            _age(p)

        reaper = _reaper(base)
        reaper._check_orphaned()

        surviving = sorted(p.name for p in base.iterdir())
        assert surviving == sorted(strangers), "collateral deletion: the sweep took a stranger"
        reaper.http_client.post.assert_not_called()

    def test_T3b_session_prefix_is_not_matched_as_env(self, tmp_path):
        """The reverse half: a session dir is classified session, not env —
        proven by its revoke still being attempted."""
        base = tmp_path / "shm"
        d = base / f"{SESSION_DIR_PREFIX}{SESSION_ID}_env_1"
        d.mkdir(parents=True)
        (d / "42").write_bytes(b"x")
        _age(d)

        reaper = _reaper(base)
        reaper._check_orphaned()

        args, _ = reaper.http_client.post.call_args
        assert args[0] == f"/api/v1/sessions/{SESSION_ID}/secrets/revoke"

    def test_T2c_prepare_session_dir_is_never_the_writers_to_remove(self, tmp_path):
        """AC4 ownership: _release_fallback_dir must not reach prepare()'s dir.

        The normal path (prepare() ran, so _session_dir is a session_* dir and
        _fallback_env_dir was never set) executes, destroys the env file, and
        leaves the session dir for the InjectionResult cleanup that owns it.
        """
        base = tmp_path / "shm"
        base.mkdir(exist_ok=True)
        strategy = SbxStrategy()
        strategy._sandbox_name = "venya-test469"
        bundles = []
        strategy.prepare(bundles, SESSION_ID)
        session_dir = strategy._session_dir
        assert session_dir is not None and Path(session_dir).name.startswith(SESSION_DIR_PREFIX)
        assert strategy._fallback_env_dir is None

        _run_exec(strategy, {"A": "1"})

        assert Path(session_dir).exists(), "the writer deleted a dir it did not create"
        assert not (Path(session_dir) / "venya-env").exists()
        assert strategy._session_dir == session_dir


# ---------------------------------------------------------------------------
# naming: the two prefixes stay distinct and are used by exactly their owners
# ---------------------------------------------------------------------------


def test_prefixes_are_distinct_and_shared_with_the_writer():
    """The daemon and the strategy import the SAME two constants — the pairing
    that broke when env_* was created but never named anywhere else."""
    import executor.daemon as daemon_mod

    assert daemon_mod.SESSION_DIR_PREFIX == SESSION_DIR_PREFIX
    assert daemon_mod.ENV_DIR_PREFIX == ENV_DIR_PREFIX
    assert SESSION_DIR_PREFIX != ENV_DIR_PREFIX
    assert not SESSION_DIR_PREFIX.startswith(ENV_DIR_PREFIX)
