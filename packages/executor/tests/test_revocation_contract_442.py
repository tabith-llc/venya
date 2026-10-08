# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#442 site 4 — the revocation poll distinguishes "live" from "we could not ask".

The contract was ``check_revocation() -> bool``: False meant "not revoked" AND
"I could not reach the server to ask". The caller reset its consecutive-failure
counter on False, so an outage WIPED the very evidence the threshold exists to
collect — the bounded fail-closed the ticket amendment credited it with never
engaged on the transport-fault path (lead ruling R0 confirms the measurement:
transport fault → ``counter=0``, only a ``future.result()`` timeout incremented).

Ruled fix (R3, shape 1): ``RevocationStatus`` — NOT_REVOKED / REVOKED /
UNREACHABLE. The caller now resets only on NOT_REVOKED and counts UNREACHABLE
toward the existing threshold. ``cert_rotation.max_revocation_failures`` and the
"treating certificate as revoked" log line are UNCHANGED — what feeds them is
what got fixed.

Truth table, both halves, plus the end-to-end consequence:

  rejected — transport fault → UNREACHABLE (not an assertion of liveness), logged
             above debug, and counted by the caller;
  rejected — a run of UNREACHABLE answers still trips the threshold at exactly
             max_revocation_failures and flips state.revoked;
  accepted — server answered "live" → NOT_REVOKED, counter reset, daemon keeps
             running, log stays quiet;
  accepted — server answered "revoked" → REVOKED, terminal, unchanged.
"""

import logging
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from executor.config import CertificateRotationConfig, ExecutorConfig
from executor.daemon import CertificateManager, ExecutorDaemon, RevocationStatus

CERT_DIR = "certs"


@pytest.fixture()
def cert_manager(tmp_path):
    """CertificateManager over a config with a real rotation section (threshold)."""
    config = ExecutorConfig(
        server_url="https://core.invalid",
        executor_id="exec-442",
        cert_rotation=CertificateRotationConfig(rotate_before_days=1, max_revocation_failures=4),
    )
    mgr = CertificateManager(config)
    mgr.serial = "0000000000000001"
    mgr.client = MagicMock(spec=httpx2.Client)
    return mgr


def _answered(mgr, revoked_serials=(), revoked_identities=(), status_code=200, etag='"e1"'):
    """Patch the client to ANSWER with a revocation list."""
    resp = MagicMock(spec=httpx2.Response)
    resp.status_code = status_code
    resp.headers = {"etag": etag}
    resp.json.return_value = {
        "revoked_serials": list(revoked_serials),
        "revoked_identities": list(revoked_identities),
    }
    resp.raise_for_status.return_value = None
    return patch.object(mgr.client, "get", return_value=resp)


def _unreachable(mgr):
    """Patch the client to fail at the transport layer."""
    return patch.object(mgr.client, "get", side_effect=httpx2.RequestError("Connection refused", request=MagicMock()))


class TestContractDistinguishesTheAnswers:
    """The naming half: three answers, three names."""

    def test_unreachable_is_not_reported_as_live(self, cert_manager):
        """AC3 core: a fault is UNREACHABLE, never the old False."""
        with _unreachable(cert_manager):
            assert cert_manager.check_revocation() is RevocationStatus.UNREACHABLE

    def test_unreachable_logs_above_debug(self, cert_manager, caplog):
        """AC3: the unreachable case moved off debug, so an outage is visible in a
        default-INFO journal without being a warning-level false alarm either."""
        with caplog.at_level(logging.DEBUG, logger="venya.executor"):
            with _unreachable(cert_manager):
                cert_manager.check_revocation()

        matching = [r for r in caplog.records if "Revocation status UNKNOWN" in r.getMessage()]
        assert matching, caplog.text
        assert all(r.levelno > logging.DEBUG for r in matching), [r.levelno for r in matching]
        # Names the identity so an operator can tell WHICH executor is blind.
        assert "exec-442" in matching[0].getMessage()

    def test_server_answered_live_is_not_revoked(self, cert_manager):
        with _answered(cert_manager, revoked_serials=["00000000000000ff"]):
            assert cert_manager.check_revocation() is RevocationStatus.NOT_REVOKED

    def test_server_answered_revoked_is_revoked(self, cert_manager):
        with _answered(cert_manager, revoked_serials=["0000000000000001"]):
            assert cert_manager.check_revocation() is RevocationStatus.REVOKED

    def test_identity_revocation_still_terminal(self, cert_manager):
        """Unchanged verdict, new name: own executor_id in revoked_identities."""
        with _answered(cert_manager, revoked_identities=["exec-442"]):
            assert cert_manager.check_revocation() is RevocationStatus.REVOKED

    def test_not_modified_answer_is_an_answer(self, cert_manager):
        """A 304 is the server saying the list is unchanged — that is NOT_REVOKED,
        not uncertainty: it must keep resetting the failure counter."""
        cert_manager._last_revocation_etag = '"e1"'
        with _answered(cert_manager, status_code=304):
            assert cert_manager.check_revocation() is RevocationStatus.NOT_REVOKED

    def test_no_credential_loaded_is_not_revoked(self, cert_manager):
        """Pre-registration state keeps its old verdict (the name changed, the
        behavior did not — no request is even attempted)."""
        cert_manager.serial = None
        with patch.object(cert_manager.client, "get") as mock_get:
            assert cert_manager.check_revocation() is RevocationStatus.NOT_REVOKED
        mock_get.assert_not_called()

    def test_three_answers_are_mutually_distinct(self):
        """The point of the enum in one check: nothing is equal to nothing else,
        so no caller can confuse an outage with a clean bill of health."""
        assert len({RevocationStatus.NOT_REVOKED, RevocationStatus.REVOKED, RevocationStatus.UNREACHABLE}) == 3
        assert RevocationStatus.UNREACHABLE is not RevocationStatus.NOT_REVOKED
        # And no member is the bool its predecessor returned.
        assert RevocationStatus.NOT_REVOKED is not False
        assert RevocationStatus.REVOKED is not True


@pytest.fixture()
def daemon_config():
    return ExecutorConfig(
        server_url="https://core.invalid",
        executor_id="exec-442-daemon",
        cert_rotation=CertificateRotationConfig(rotate_before_days=1, max_revocation_failures=3),
    )


def _drive_loop(daemon, answers, stop_after):
    """Run _main_loop for `stop_after` iterations, feeding it `answers` in order.

    The loop breaks on a REVOKED verdict, so the caller's own
    `_shutdown_event.wait` is used as the iteration clock: the loop stops when
    `wait` reports running=False, exactly as a real shutdown would.
    """
    seen = []

    def _wait(_timeout):
        seen.append(True)
        if len(seen) >= stop_after:
            daemon.state.running = False
        return False

    def _check():
        # Consume the scripted answer list, repeating the last entry if exhausted.
        idx = min(len(seen), len(answers) - 1)
        return answers[idx]

    with patch.object(daemon.cert_manager, "needs_rotation", return_value=False):
        with patch.object(daemon.cert_manager, "check_revocation", side_effect=_check):
            with patch.object(daemon, "_submit_heartbeat"):
                with patch.object(daemon._shutdown_event, "wait", side_effect=_wait):
                    daemon._main_loop()
    return seen


class TestCallerCountsWhatItUsedToWipe:
    """The R0 half: an outage now advances the counter instead of resetting it."""

    def test_outage_increments_the_counter(self, daemon_config):
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True

        seen = _drive_loop(daemon, [RevocationStatus.UNREACHABLE], stop_after=2)
        assert len(seen) == 2
        # Two unreachable answers → count is 2, not the 0 the bool contract produced.
        assert daemon.state._consecutive_revocation_failures == 2
        assert daemon.state.revoked is False

    def test_a_clean_answer_between_outages_still_resets(self, daemon_config):
        """Ruled shape: reset ONLY on NOT_REVOKED. A server that answers resets —
        the counter is a CONSECUTIVE-failure count, not a lifetime one."""
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True

        answers = [
            RevocationStatus.UNREACHABLE,
            RevocationStatus.UNREACHABLE,
            RevocationStatus.NOT_REVOKED,
            RevocationStatus.UNREACHABLE,
        ]
        _drive_loop(daemon, answers, stop_after=4)
        assert daemon.state._consecutive_revocation_failures == 1

    def test_threshold_still_flips_revoked_at_exactly_max(self, daemon_config):
        """Threshold UNCHANGED (R3): 3 consecutive unreachable answers against
        max_revocation_failures=3 trips state.revoked, and two do not."""
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True
        _drive_loop(daemon, [RevocationStatus.UNREACHABLE], stop_after=3)
        assert daemon.state.revoked is True

        daemon2 = ExecutorDaemon(daemon_config)
        daemon2.client = MagicMock(spec=httpx2.Client)
        daemon2.state.running = True
        _drive_loop(daemon2, [RevocationStatus.UNREACHABLE], stop_after=2)
        assert daemon2.state.revoked is False
        assert daemon2.state._consecutive_revocation_failures == 2

    def test_threshold_warning_text_is_unchanged(self, daemon_config, caplog):
        """R3 keeps the "treating certificate as revoked" line verbatim."""
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True
        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            _drive_loop(daemon, [RevocationStatus.UNREACHABLE], stop_after=3)
        assert any("treating certificate as revoked" in r.getMessage() for r in caplog.records), caplog.text

    def test_answered_live_keeps_the_daemon_running_quietly(self, daemon_config, caplog):
        """Positive half of the pair: a server that answers "live" never advances
        the counter and never warns about UNKNOWN."""
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True
        with caplog.at_level(logging.WARNING, logger="venya.executor"):
            _drive_loop(daemon, [RevocationStatus.NOT_REVOKED], stop_after=3)
        assert daemon.state._consecutive_revocation_failures == 0
        assert daemon.state.revoked is False
        assert not [r for r in caplog.records if "Revocation status UNKNOWN" in r.getMessage()]

    def test_revoked_answer_is_terminal_immediately(self, daemon_config):
        """Unchanged: REVOKED stops the loop on the first answer, threshold or not."""
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True
        seen = _drive_loop(daemon, [RevocationStatus.REVOKED], stop_after=99)
        assert daemon.state.revoked is True
        assert len(seen) == 0  # broke before ever waiting

    def test_real_check_revocation_fault_feeds_the_counter(self, daemon_config):
        """End-to-end, nothing patched but the socket: a REAL transport fault (the
        R0 path) advances the count. Before this change the same scenario produced
        counter=0 — that was the fail-open.

        Two iterations against max_revocation_failures=3, so this cell proves the
        counting without also tripping the threshold (that half is the cell above)."""
        daemon = ExecutorDaemon(daemon_config)
        daemon.client = MagicMock(spec=httpx2.Client)
        daemon.cert_manager.serial = "0000000000000001"
        daemon.cert_manager.client = MagicMock(spec=httpx2.Client)
        daemon.state.running = True

        ticks = []

        def _wait(_timeout):
            ticks.append(True)
            if len(ticks) >= 2:
                daemon.state.running = False
            return False

        with patch.object(daemon.cert_manager, "needs_rotation", return_value=False):
            with _unreachable(daemon.cert_manager):
                with patch.object(daemon, "_submit_heartbeat"):
                    with patch.object(daemon._shutdown_event, "wait", side_effect=_wait):
                        daemon._main_loop()

        assert len(ticks) == 2
        assert (
            daemon.state._consecutive_revocation_failures == 2
        ), "a real transport fault must count; the bool contract reset it to 0"
        assert daemon.state.revoked is False
