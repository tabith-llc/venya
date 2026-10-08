# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#442 site 2 — a failing first-registration probe picks the STRICTER limiter.

The defect (``server/rate_limit.py``, ``rate_limit_registration``): the probe
that decides whether this executor has a cert before it looked like this::

    is_first = False
    try:
        ...cert lookup...
        is_first = cert is None
    except Exception:  # nosec B110 — best-effort DB query, None falls through
        pass

Any fault — a dead DB, an ImportError, a missing backend — landed in the
``pass`` and left ``is_first`` at its loose default, so the operator's tight
``registration_first_attempt_per_minute`` (3/min) was silently traded for the
roomy per-IP cap. This file's own comment records that the same swallow had
already masked an ``ImportError`` for the whole alpha series (M-63), which is
why the fault case is the one that matters here.

The ruled fix: ``is_first`` starts ``True`` and only a probe that COMPLETES may
loosen it, the blanket swallow narrows to named classes, and every caught fault
logs a WARNING naming the reason.

Truth table, both halves:

  rejected — probe faults (missing backend, DB error, unexpected attribute) →
             the FIRST-ATTEMPT limiter holds the ``reg_ip:`` key, the per-IP
             limiter never sees it, and a WARNING is logged;
  accepted — a genuine returning executor (probe completes, cert found) → the
             per-IP limiter holds the key exactly as before this change;
  accepted — a genuine first attempt (probe completes, no cert) → first-attempt
             limiter, unchanged.

Also pinned: an exception class outside the named set PROPAGATES instead of
falling open — the request is refused, never accepted under the loose limit.
"""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from server import rate_limit as rl
from server.rate_limit import rate_limit_registration
from sqlalchemy.exc import OperationalError

IP_CAP = 1000
FIRST_ATTEMPT_CAP = 3
EXEC_CAP = 2
HOST = "203.0.113.77"


@pytest.fixture()
def fresh_limiters():
    """Isolate the module-level limiter cache for one cell."""
    saved = dict(rl._LIMITERS)
    rl._LIMITERS.clear()
    yield
    rl._LIMITERS.clear()
    rl._LIMITERS.update(saved)


def _config(**overrides):
    base = {
        "enabled": True,
        "registration_ip_per_minute": IP_CAP,
        "registration_attempts_per_minute": EXEC_CAP,
        "token_generation_per_minute": 10,
        "registration_global_per_minute": 500,
        "registration_first_attempt_per_minute": FIRST_ATTEMPT_CAP,
    }
    base.update(overrides)
    return SimpleNamespace(executor_enrollment=SimpleNamespace(**base))


def _request(config, executor_id="execA", host=HOST, backend="present", probe_error=None):
    """Request whose probe answers, or faults in one of the ruled ways.

    backend="present"  → a MagicMock whose cert lookup FINDS a cert, i.e. a
                          genuine returning executor (the loose reading, earned)
    backend="absent"   → app.state.backend is None → get_backend raises
                          HTTPException(503) — the missing-backend fault
    probe_error=exc    → the cert query raises that exception instead
    """
    req = SimpleNamespace()
    if backend == "absent":
        req.app = SimpleNamespace(state=SimpleNamespace(config=config, backend=None))
    else:
        backend_mock = MagicMock()
        first = backend_mock.get_session.return_value.query.return_value.filter.return_value.first
        if probe_error is not None:
            first.side_effect = probe_error
        else:
            first.return_value = MagicMock()  # cert EXISTS → returning executor
        req.app = SimpleNamespace(state=SimpleNamespace(config=config, backend=backend_mock))
    req.client = SimpleNamespace(host=host)
    req.state = SimpleNamespace()

    async def _json():
        return {"executor_id": executor_id}

    req.json = _json
    return req


def _first_request(config, executor_id="execA", host=HOST):
    """A genuine FIRST attempt: the probe completes and finds no cert."""
    req = _request(config, executor_id=executor_id, host=host)
    req.app.state.backend.get_session.return_value.query.return_value.filter.return_value.first.return_value = None
    return req


def _slots_by_limiter():
    """Consumed slots per limiter: {limiter cache key: {rate-limit key: count}}.

    Counts, not just key presence — the denial cells need to see the cap is what
    is FULL, and a set of key names cannot show that.
    """
    out = {}
    for name, limiter in rl._LIMITERS.items():
        out[name] = {key: len(ts) for key, ts in limiter._requests.items() if ts}
    return out


def _keys_by_limiter():
    """Which limiter holds which rate-limit key."""
    return {name: set(slots.keys()) for name, slots in _slots_by_limiter().items()}


class TestProbeFaultSelectsStrictLimiter:
    """Negative half: every fault path lands on the tighter limiter."""

    @pytest.mark.parametrize(
        ("label", "fault"),
        [
            ("missing-backend", {"backend": "absent"}),
            ("db-error", {"probe_error": OperationalError("no connection to server", None, None)}),
            ("unexpected-attribute", {"probe_error": AttributeError("'NoneType' has no attribute 'query'")}),
            ("type-error", {"probe_error": TypeError("unhashable executor_id")}),
        ],
        ids=["missing-backend", "db-error", "unexpected-attribute", "type-error"],
    )
    async def test_fault_holds_the_first_attempt_limiter(self, fresh_limiters, label, fault):
        cfg = _config()
        await rate_limit_registration(_request(cfg, **fault))

        keys = _keys_by_limiter()
        ip_key = f"reg_ip:{HOST}"
        strict = keys.get("limiter_registration_first_attempt_per_minute", set())
        loose = keys.get("limiter_registration_ip_per_minute", set())
        assert ip_key in strict, f"{label}: fault must consume the STRICT first-attempt key, got {keys}"
        assert ip_key not in loose, f"{label}: the loose per-IP limiter must never see a faulted request"

    async def test_fault_denies_at_the_first_attempt_cap(self, fresh_limiters):
        """Behavioral half of the same rule: with the DB down, a burst from one
        IP is cut off at 3/min — the cap the operator configured — not at 1000.

        Distinct executor_ids per request so the denial can only come from the
        IP-side limiter under test, never from the 2/min per-executor cap."""
        cfg = _config()
        for i in range(FIRST_ATTEMPT_CAP):
            await rate_limit_registration(_request(cfg, executor_id=f"burst-{i}", backend="absent"))

        with pytest.raises(HTTPException) as exc:
            await rate_limit_registration(_request(cfg, executor_id="burst-over", backend="absent"))
        assert exc.value.status_code == 429
        assert exc.value.detail == "Too many registration attempts"
        # Named the binder: the strict limiter is the one that is full, and the
        # denied request consumed nothing beyond the cap.
        slots = _slots_by_limiter()
        assert slots["limiter_registration_first_attempt_per_minute"][f"reg_ip:{HOST}"] == FIRST_ATTEMPT_CAP
        assert not slots.get("limiter_registration_ip_per_minute", {})

    async def test_fault_logs_warning_naming_the_reason(self, fresh_limiters, caplog):
        cfg = _config()
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            await rate_limit_registration(_request(cfg, backend="absent"))

        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("stricter first-attempt limiter" in m for m in warnings), warnings
        # The reason must be identifiable: class and message, not a bare "failed".
        assert any("HTTPException" in m and "Backend not initialized" in m for m in warnings), warnings

    async def test_db_error_names_the_sqlalchemy_class(self, fresh_limiters, caplog):
        cfg = _config()
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            await rate_limit_registration(_request(cfg, probe_error=OperationalError("connection refused", None, None)))
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("OperationalError" in m for m in warnings), warnings

    async def test_unanticipated_class_propagates_not_falls_open(self, fresh_limiters):
        """The ruled backstop: a class outside the named set must NOT reach the
        loose limit. It propagates (the request is refused), so the looser reading
        can never be earned by an unforeseen fault."""
        cfg = _config()
        with pytest.raises(RuntimeError):
            await rate_limit_registration(_request(cfg, probe_error=RuntimeError("unexpected")))

        keys = _keys_by_limiter()
        assert f"reg_ip:{HOST}" not in keys.get("limiter_registration_ip_per_minute", set())


class TestNormalCasesUnchanged:
    """Positive half: the readings that used to work still work, identically."""

    async def test_returning_executor_still_uses_the_per_ip_limiter(self, fresh_limiters):
        cfg = _config()
        await rate_limit_registration(_request(cfg))

        keys = _keys_by_limiter()
        assert f"reg_ip:{HOST}" in keys.get("limiter_registration_ip_per_minute", set())
        assert f"reg_ip:{HOST}" not in keys.get("limiter_registration_first_attempt_per_minute", set())

    async def test_returning_executor_burst_beyond_first_attempt_cap_passes(self, fresh_limiters):
        """Paired negative of the denial cell above: the SAME burst with a
        working probe is accepted, because the returning-executor reading is
        the per-IP cap. Guards that site 2 did not tighten the normal case.

        Distinct executor_ids so the 2/min per-executor cap cannot be what
        makes this pass or fail."""
        cfg = _config()
        for i in range(FIRST_ATTEMPT_CAP + 5):
            await rate_limit_registration(_request(cfg, executor_id=f"ok-{i}"))

    async def test_genuine_first_attempt_uses_the_first_attempt_limiter(self, fresh_limiters):
        cfg = _config()
        await rate_limit_registration(_first_request(cfg))

        keys = _keys_by_limiter()
        assert f"reg_ip:{HOST}" in keys.get("limiter_registration_first_attempt_per_minute", set())

    async def test_genuine_first_attempt_denies_at_its_own_cap(self, fresh_limiters):
        cfg = _config()
        for i in range(FIRST_ATTEMPT_CAP):
            await rate_limit_registration(_first_request(cfg, executor_id=f"fa-{i}"))
        with pytest.raises(HTTPException) as exc:
            await rate_limit_registration(_first_request(cfg, executor_id="fa-over"))
        assert exc.value.status_code == 429
        # Same binder as the fault case — which is the point: the fault now
        # behaves exactly like a genuine first attempt.
        slots = _slots_by_limiter()
        assert slots["limiter_registration_first_attempt_per_minute"][f"reg_ip:{HOST}"] == FIRST_ATTEMPT_CAP
        assert not slots.get("limiter_registration_ip_per_minute", {})

    async def test_executor_key_still_consumed_alongside_the_ip_key(self, fresh_limiters):
        """Both keys are still checked (dual-key AND) under the fault reading —
        tightening the IP side must not drop the per-executor key."""
        cfg = _config()
        await rate_limit_registration(_request(cfg, executor_id="execZ", backend="absent"))
        keys = _keys_by_limiter()
        assert "reg_exec:execZ" in keys.get("limiter_registration_attempts_per_minute", set())

    async def test_no_executor_id_path_keeps_the_per_ip_limiter(self, fresh_limiters):
        """Boundary of the fix: a request whose body carries no executor_id had no
        probe to fail, so it is NOT a fault case and must keep today's per-IP
        reading (it reaches the same 400 the route gives it, through the limiter
        the per-IP cap guards)."""
        cfg = _config()
        req = _request(cfg, executor_id="execA")

        async def _json():
            return {}

        req.json = _json
        await rate_limit_registration(req)

        keys = _keys_by_limiter()
        assert f"reg_ip:{HOST}" in keys.get("limiter_registration_ip_per_minute", set())
        assert f"reg_ip:{HOST}" not in keys.get("limiter_registration_first_attempt_per_minute", set())

    async def test_probe_success_does_not_warn(self, fresh_limiters, caplog):
        cfg = _config()
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            await rate_limit_registration(_request(cfg))
        assert not [r for r in caplog.records if r.levelno == logging.WARNING and "first-attempt" in r.getMessage()]
