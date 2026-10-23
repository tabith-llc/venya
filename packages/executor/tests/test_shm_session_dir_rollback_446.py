# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Ticket #446 — the tmpfs session dir must not survive a mid-stage write failure.

SbxStrategy.prepare() creates the session directory before it writes any
secret file, so anything that throws in between (tmpfs full, permission
error, a failing copy helper) used to leave an unreferenced ``session_*``
directory — possibly holding staged secret material — behind: the cleanup
callable that owns it was appended only after ALL writes succeeded.

Every failure cell here asserts the EMPTINESS of the tmpfs base (no
``session_*`` entry survives), not just "the dir is gone" (AC3). The base is
always a tmp_path directory under this test's control — the real
/dev/shm on this host is never touched (unit cells only; the physical
fleet cell is AC5, lead-scheduled).
"""

import os

import pytest

import executor.strategies.sbx_strategy as sbx_module
from executor.bundles import SecretBundle
from executor.strategies.sbx_strategy import SbxStrategy

SESSION_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def base(tmp_path, monkeypatch):
    """Hermetic tmpfs base under tmp_path — monkeypatched module constant.

    Deliberately NOT pre-created: failure paths that abort before
    os.makedirs must leave it absent, and the success path creates it.
    """
    shm = tmp_path / "shm446"
    monkeypatch.setattr(sbx_module, "SECRET_TMPFS_BASE", str(shm))
    return shm


def _bundles(n: int = 2) -> list[SecretBundle]:
    return [SecretBundle(secret_id=f"secret-{i}", value=f"value-{i}".encode(), wrapped_value=b"") for i in range(n)]


def _leftover_names(base_dir) -> list[str]:
    """Contents of the tmpfs base — empty means the session dir died with it."""
    if not os.path.exists(base_dir):
        return []
    return sorted(p.name for p in base_dir.iterdir())


class ExplodingBundle:
    """A bundle whose .value access raises — the spec's sanctioned way to
    blow up the write step without patching global os.write."""

    def __init__(self, secret_id: str) -> None:
        self.secret_id = secret_id
        self.wrapped_value = b""

    @property
    def value(self) -> bytes:
        raise OSError(28, "No space left on device")


class TestWriteStepFailureRollsBack:
    def test_secret_write_failure_leaves_base_empty(self, base):
        """Failure at the write step (os.write of the second bundle blows
        up) -> prepare() raises AND the base holds NO leftover session_* entry."""
        strategy = SbxStrategy()
        bundles = [_bundles(1)[0], ExplodingBundle("secret-1")]

        with pytest.raises(OSError, match="No space left on device"):
            strategy.prepare(bundles, SESSION_ID)

        assert _leftover_names(base) == []  # AC3: base emptiness, not dir-absence alone

    def test_session_dir_attr_not_left_dangling_after_write_failure(self, base):
        """self._session_dir must not point at the deleted path after the
        rollback — it is reset to None (the constructor default), so later
        readers such as _write_env_file fall back to creating their own dir."""
        strategy = SbxStrategy()
        bundles = [_bundles(1)[0], ExplodingBundle("secret-1")]

        with pytest.raises(OSError):
            strategy.prepare(bundles, SESSION_ID)

        assert strategy._session_dir is None


class TestDirChmodFailureRollsBack:
    def test_chmod_on_session_dir_failure_leaves_base_empty(self, base, monkeypatch):
        """Failure in the os.chmod(self._session_dir, 0o700) right after
        mkdtemp -> same guarantee: raises AND the base is empty."""
        real_chmod = os.chmod

        def boom_chmod(path, mode, *args, **kwargs):
            if str(path).startswith(str(base)) and mode == 0o700:
                raise PermissionError(1, "Operation not permitted")
            return real_chmod(path, mode, *args, **kwargs)

        monkeypatch.setattr(sbx_module.os, "chmod", boom_chmod)
        strategy = SbxStrategy()

        with pytest.raises(PermissionError):
            strategy.prepare(_bundles(2), SESSION_ID)

        assert _leftover_names(base) == []
        assert strategy._session_dir is None


class TestMountConstructionFailureRollsBack:
    def test_secret_mount_construction_failure_leaves_base_empty(self, base, monkeypatch):
        """Failure in the SecretMount construction (per-secret loop) ->
        same: raises AND the base is empty — even though secret files were
        already written inside the session dir."""

        def boom_mount(*args, **kwargs):
            raise RuntimeError("mount construction failed")

        monkeypatch.setattr(sbx_module, "SecretMount", boom_mount)
        strategy = SbxStrategy()

        with pytest.raises(RuntimeError, match="mount construction failed"):
            strategy.prepare(_bundles(2), SESSION_ID)

        assert _leftover_names(base) == []
        assert strategy._session_dir is None


class TestBoundaryPropertyKept:
    def test_malformed_secret_id_aborts_with_nothing_created(self, base):
        """Paired negative for the pre-existing boundary property: a
        malformed id aborts BEFORE any filesystem write — the base itself
        is never created, no session dir, no partial mounts."""
        strategy = SbxStrategy()
        bundles = [SecretBundle(secret_id="../../escape", value=b"x", wrapped_value=b"")]

        with pytest.raises(ValueError, match="unsafe secret_id"):
            strategy.prepare(bundles, SESSION_ID)

        assert not base.exists()  # nothing created at all
        assert strategy._session_dir is None


class TestSuccessPathUnchanged:
    def test_two_secret_prepare_positive(self, base):
        """Paired positive — zero behavior change on success: dir exists
        under the base, both files at mode 0o400, dir at 0o700, the result
        carries >=1 cleanup func, and cleanup() removes the whole dir."""
        strategy = SbxStrategy()
        result = strategy.prepare(_bundles(2), SESSION_ID)

        entries = _leftover_names(base)
        assert len(entries) == 1
        assert entries[0].startswith(f"session_{SESSION_ID}_")

        session_dir = base / entries[0]
        assert str(session_dir) == strategy._session_dir
        assert os.stat(session_dir).st_mode & 0o777 == 0o700
        for bundle in _bundles(2):
            secret_path = session_dir / bundle.secret_id
            assert secret_path.exists()
            assert os.stat(secret_path).st_mode & 0o777 == 0o400

        assert len(result.cleanup_funcs) >= 1
        assert len(result.secret_mounts) == 2

        result.cleanup()
        assert _leftover_names(base) == []
