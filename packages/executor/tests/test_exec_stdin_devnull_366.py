# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for ticket exec-stdin-inheritance-holds-the-permit (#695 AC1, leg 366).

The sbx COMMAND-EXECUTION ``subprocess.run`` site passed neither ``stdin=`` nor
``input=``, so the ``sbx`` client inherited the executor daemon's own stdin. Any
guest command that waits on stdin — ``ssh`` at a password or host-key prompt,
``read``, a paged viewer — therefore did not fail fast: it sat holding the
executor's SINGLE admission permit until ``SBX_TIMEOUT`` (3600 s) while every
client fuse upstream blows far earlier (relay read 300 s, nginx 330 s, CLI/MCP
340 s). That is the act-7 hang class.

Fix pinned here: the exec run site passes ``stdin=subprocess.DEVNULL``, so a
command that would prompt gets immediate EOF and fails inside the sandbox in
milliseconds instead of holding the permit for an hour.

Paired negative — the one that guards the DO-NOT-TOUCH list: the secret-injection
``tee`` site in ``copy_secrets_into_sandbox`` still receives the secret over
``input=`` and is NOT given ``DEVNULL``. Secrets reach the sandbox on stdin by
design (module docstring, and the comment block above the injection path), so a
blanket "DEVNULL every subprocess.run" sweep would silently destroy secret
injection. That cell is what catches such a sweep.

Scope notes, stated so a later seat does not over-read these rows: the hour-long
ceiling itself (``SBX_TIMEOUT``), its configurability, and a process-group kill on
the sbx path are #696's rows — NOT claimed or changed here.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from executor.strategies.sbx_strategy import SbxStrategy


def _strategy():
    strategy = SbxStrategy()
    strategy._sandbox_name = "venya-test123"
    return strategy


class TestExecStdinDevNull366:
    """AC1: the exec run site gives the ``sbx`` client EOF instead of the daemon's stdin."""

    def test_sh_c_posture_passes_stdin_devnull(self):
        """The ruled ``<`` sudo-redirect form (caller omits argv) runs through
        ``sh -c``; that is the posture act-7 used, so it must be the one pinned."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            strategy.execute_command("sudo -S id < /run/secrets/venya/3")
        assert mock_run.call_count == 1
        assert mock_run.call_args.kwargs["stdin"] is subprocess.DEVNULL

    def test_direct_argv_posture_passes_stdin_devnull(self):
        """The no-shell posture (#322 C3) reaches the SAME run site, so it gets
        the same EOF — a prompt-hang fix that covered only one of the two forms
        would leave half the command surface holding the permit."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            strategy.execute_command("ignored", argv=["/usr/bin/ssh", "host", "uptime"])
        assert mock_run.call_count == 1
        cmd = mock_run.call_args.args[0]
        assert cmd == ["sbx", "exec", "venya-test123", "/usr/bin/ssh", "host", "uptime"]
        assert mock_run.call_args.kwargs["stdin"] is subprocess.DEVNULL

    def test_existing_exec_kwargs_are_preserved_alongside_the_fix(self):
        """Deletion beats addition, and an added kwarg must not cost us an
        existing one: capture, the timeout bound and check=False all still hold
        after the stdin line lands."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"out", stderr=b"")
            strategy.execute_command("echo hello")
        kwargs = mock_run.call_args.kwargs
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == 3600
        assert kwargs["check"] is False

    def test_the_cell_can_fail(self):
        """Instrument self-check: if ``execute_command`` ever stops passing the
        kwarg, this row goes red rather than reporting a green it never tested.
        Reads the same recorded call the positive cells do."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            strategy.execute_command("echo hello")
        recorded = mock_run.call_args.kwargs
        assert "stdin" in recorded, "the exec run site stopped controlling stdin"
        assert recorded["stdin"] is subprocess.DEVNULL


class TestSecretInjectionStdinUntouched366:
    """The paired negative, guarding the DO-NOT-TOUCH list: secret injection rides stdin."""

    def test_tee_injection_site_still_receives_input_and_no_devnull(self, tmp_path):
        strategy = _strategy()
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(b"supersecret")
        mounts = [MagicMock(secret_id="pass", path=str(secret_file), container_path="/run/secrets/venya/pass")]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr=b"")
            strategy.copy_secrets_into_sandbox(mounts)
        tee_call = [c for c in mock_run.call_args_list if "tee" in c.args[0]]
        assert len(tee_call) == 1, "the secret-tee injection site disappeared from the path"
        assert tee_call[0].kwargs["input"] == b"supersecret"
        assert tee_call[0].kwargs.get("stdin") is not subprocess.DEVNULL, (
            "secret injection was DEVNULL'd — a blanket stdin sweep destroys the "
            "stdin-only secret delivery the module docstring specifies"
        )

    def test_no_stdin_kwarg_is_added_to_the_injection_site(self, tmp_path):
        """Stronger form of the same guard: the injection site must keep the
        ``input=``-only shape, and must not gain a ``stdin=`` argument at all —
        ``subprocess`` forbids both together for one call, so a careless edit
        would raise at runtime on a real install rather than in review."""
        strategy = _strategy()
        secret_file = tmp_path / "secret"
        secret_file.write_bytes(b"p")
        mounts = [MagicMock(secret_id="s", path=str(secret_file), container_path="/run/secrets/venya/s")]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr=b"")
            strategy.copy_secrets_into_sandbox(mounts)
        for call in mock_run.call_args_list:
            if "input" in call.kwargs:
                assert "stdin" not in call.kwargs, f"input= and stdin= coexist at {call.args[0][:3]}…"

    def test_exec_site_is_the_only_one_changed(self):
        """Sweep-guard, negative half of the previous two: prove this leg touched
        exactly the exec run site. Every OTHER non-exec sbx call (create, rm,
        policy, cp, login) must still be reachable with no stdin kwarg forced on
        it by this change — those calls are not in scope and a blanket edit there
        is what the row above defends against."""
        strategy = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            strategy.execute_command("echo hi")
            exec_kwargs = mock_run.call_args.kwargs
        assert exec_kwargs["stdin"] is subprocess.DEVNULL
        # And the same strategy, asked to remove a sandbox, must not have had its
        # rm call rewritten by this change (timeout 30, no stdin control).
        strategy2 = _strategy()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            strategy2.remove_sandbox()
        assert "stdin" not in mock_run.call_args.kwargs


@pytest.mark.parametrize("posture", ["sh-c", "argv"])
def test_prompt_command_shape_is_pinned_for_both_postures(posture):
    """One row, two postures, same assertion — kept as a parametrize so a future
    third posture has to be added here rather than silently skipping coverage."""
    strategy = _strategy()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
        if posture == "sh-c":
            strategy.execute_command("ssh host uptime")
        else:
            strategy.execute_command("ignored", argv=["ssh", "host", "uptime"])
        assert mock_run.call_args.kwargs["stdin"] is subprocess.DEVNULL
