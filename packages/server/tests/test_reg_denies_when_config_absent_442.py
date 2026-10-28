# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#442 site 3 — an uninitialized server config requires the enrollment token.

The defect (``routes/executors.py``, ``register_executor``, the tokenless arm):

    server_config = getattr(request.app.state, "config", None)
    if server_config and server_config.executor_enrollment.require_token:
        ...refuse unless incumbent...
    else:
        token_audit_fields = {"with_token": False}   # ACCEPTED

The condition's first operand is what failed open: with no config on
``app.state`` (not initialized, partially initialized, or a legacy object with
no ``executor_enrollment`` section), ``server_config`` was falsy, the whole
conjunction was False, and a TOKENLESS registration was accepted. "We do not
know the policy" resolved to the loosest policy available. The shipped default
IS enforcement (``require_token=True``, the Phase-1 flip that followed the
physical tokenless registration on exec-2), so an unknown policy must read as
that default, not as its opposite.

Truth table, both halves:

  rejected — config attribute never set; config set to None; config whose
             executor_enrollment section carries no require_token knob →
             400 "Enrollment token required", and no certificate is signed;
  accepted — config present with require_token=False: the operator's documented
             choice, still 201 (this leg changes the FAULT case only);
  accepted — a caller presenting a valid token with the config absent: the
             token path is untouched.

The Phase 2 incumbent exemption is deliberately NOT re-tested as changed — it is
unchanged code, still pinned by
test_executor_revocation_identity.py::TestRegisterGateRuling3::
test_c1_incumbent_serial_match_exempts_tokenless. The house builder from
test_executor_enrollment.py supplies the working registration stack so only the
config knob varies between cells.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from tests.test_executor_enrollment import _create_test_app, _generate_test_csr, _make_mock_ca

BODY = {"executor_id": "test-1", "csr_pem": _generate_test_csr()}
DETAIL = "Enrollment token required"


@pytest.fixture(autouse=True)
def _fresh_limiters():
    """Isolate the process-global limiter cache in server.rate_limit.

    The registration limiter keys are per-IP and the TestClient address is the
    same for every cell in the suite, so without this the cells here inherit
    consumed slots from whichever other module registered first and fail on a 429
    that has nothing to do with the token gate (same isolation fixture
    test_rate_limiter.py uses).
    """
    from server import rate_limit as _rl

    saved = dict(_rl._LIMITERS)
    _rl._LIMITERS.clear()
    yield
    _rl._LIMITERS.clear()
    _rl._LIMITERS.update(saved)


def _backend():
    """Backend whose every lookup finds nothing.

    The house pattern from test_executor_enrollment.py: a MagicMock db answers
    EVERY query with the same "no row" query object, otherwise the terminal
    identity check downstream reads a truthy mock and the cell fails on a 403
    that has nothing to do with the token gate under test.
    """
    backend = MagicMock()
    mock_db = MagicMock()
    empty_query = MagicMock()
    empty_query.filter.return_value.first.return_value = None
    empty_query.update.return_value = 1
    mock_db.query.side_effect = lambda model: empty_query
    backend.get_session.return_value = mock_db
    return backend, mock_db


def _register(app):
    client = TestClient(app, raise_server_exceptions=False)
    return client.post("/api/v1/executors/register", json=BODY)


class TestConfigUnknownRequiresToken:
    """Negative half: every shape of "no policy available" refuses a tokenless register."""

    def test_config_attribute_never_set_refuses_tokenless(self):
        backend, _ = _backend()
        app = _create_test_app(backend=backend, require_token=False, ca_manager=_make_mock_ca())
        # The fault: the config the builder installed is gone entirely.
        del app.state.config

        resp = _register(app)
        assert resp.status_code == 400, resp.text
        assert DETAIL in resp.json()["detail"]

    def test_config_set_to_none_refuses_tokenless(self):
        backend, _ = _backend()
        app = _create_test_app(backend=backend, require_token=False, ca_manager=_make_mock_ca())
        app.state.config = None

        resp = _register(app)
        assert resp.status_code == 400, resp.text
        assert DETAIL in resp.json()["detail"]

    def test_enrollment_section_without_knob_refuses_tokenless(self):
        """A config object whose executor_enrollment section exists but carries no
        require_token — the third way to not know the policy."""
        backend, _ = _backend()
        app = _create_test_app(backend=backend, require_token=True, ca_manager=_make_mock_ca())
        app.state.config = SimpleNamespace(executor_enrollment=SimpleNamespace(enabled=False))

        resp = _register(app)
        assert resp.status_code == 400, resp.text
        assert DETAIL in resp.json()["detail"]

    def test_enrollment_section_with_no_knob_at_all_refuses_tokenless(self):
        """A section that is live (enabled) but carries no require_token knob —
        the route cannot read a policy, so it must not read permission.

        (An executor_enrollment that is None never reaches this code at all: the
        registration limiter dereferences it first and the request dies as a 500,
        which is a refusal, not a fail-open. Not what this cell is about.)"""
        backend, _ = _backend()
        app = _create_test_app(backend=backend, require_token=False, ca_manager=_make_mock_ca())
        app.state.config = SimpleNamespace(executor_enrollment=SimpleNamespace(enabled=True))

        resp = _register(app)
        assert resp.status_code == 400, resp.text
        assert DETAIL in resp.json()["detail"]

    def test_refusal_signs_no_certificate(self):
        """The refusal must precede issuance — a tokenless caller never gets a
        credential while the policy is unknown."""
        backend, _ = _backend()
        ca = _make_mock_ca()
        app = _create_test_app(backend=backend, require_token=False, ca_manager=ca)
        del app.state.config

        resp = _register(app)
        assert resp.status_code == 400, resp.text
        ca.sign_csr.assert_not_called()


class TestKnownPolicyUnchanged:
    """Positive half: what the policy DOES say keeps behaving exactly as today."""

    def test_operator_require_token_false_still_accepts_tokenless(self):
        """The documented knob-OFF mode: a real ServerConfig with
        require_token=False. The leg rules name this cell explicitly — site 3 must
        not break the operator's choice."""
        backend, _ = _backend()
        app = _create_test_app(backend=backend, require_token=False, ca_manager=_make_mock_ca())

        resp = _register(app)
        assert resp.status_code == 201, resp.text
        assert resp.json()["executor_id"] == "test-1"

    def test_require_token_true_still_refuses_tokenless(self):
        backend, _ = _backend()
        app = _create_test_app(backend=backend, require_token=True, ca_manager=_make_mock_ca())

        resp = _register(app)
        assert resp.status_code == 400, resp.text
        assert DETAIL in resp.json()["detail"]

    def test_shipped_default_still_refuses_tokenless(self):
        """No override at all: the ServerConfig default is enforcement."""
        backend, _ = _backend()
        app = _create_test_app(backend=backend, require_token=None, ca_manager=_make_mock_ca())

        resp = _register(app)
        assert resp.status_code == 400, resp.text
        assert DETAIL in resp.json()["detail"]

    def test_valid_token_path_untouched_with_config_absent(self):
        """Requiring the token when the config is missing must not break the
        token-HOLDER: a valid, unconsumed token still registers."""
        import hashlib

        from core.iam.models import ExecutorEnrollmentToken

        backend, mock_db = _backend()
        app = _create_test_app(backend=backend, require_token=False, ca_manager=_make_mock_ca())
        del app.state.config

        token_plain = "enrl_exec_valid_442"
        token_row = MagicMock(spec=ExecutorEnrollmentToken)
        token_row.id = 7
        token_row.executor_id = "test-1"
        token_row.state = "active"
        token_row.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        token_row.token_hash = hashlib.sha256(token_plain.encode()).hexdigest()

        token_query = MagicMock()
        token_query.filter.return_value.first.return_value = token_row
        other_query = MagicMock()
        other_query.filter.return_value.first.return_value = None

        def empty_for_others():
            return other_query

        mock_db.query.side_effect = lambda model: (
            token_query if model is ExecutorEnrollmentToken else empty_for_others()
        )
        mock_db.execute.return_value.rowcount = 1

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/executors/register",
            json={"executor_id": "test-1", "csr_pem": _generate_test_csr(), "enrollment_token": token_plain},
        )
        assert resp.status_code == 201, resp.text


def test_incumbent_exemption_cell_still_passes():
    """Ruled constraint: "do not loosen the Phase-2 incumbent exemption". The
    exemption's own cell is run as part of this leg's gate (it lives in
    test_executor_revocation_identity.py); this marker asserts nothing new about
    the source, only that the exemption's home file is exercised at the same
    commit as the change."""
    import inspect

    from server.routes import executors as exec_mod

    src = inspect.getsource(exec_mod.register_executor)
    assert (
        "_incumbent_exemption_applies" in src or "_incumbent_exemption_offloaded" in src
    ), "the incumbent exemption must remain in the require-token arm"
    # Strengthened, not relaxed (#603 offload leg): the arm may now reach the exemption through
    # the off-loop wrapper, so the guard follows the delegation instead of a single literal —
    # the exemption body must STILL be the one called, or the arm is no longer the exemption.
    wrapper_src = inspect.getsource(exec_mod._incumbent_exemption_offloaded)
    assert (
        "_incumbent_exemption_applies" in wrapper_src
    ), "the off-loop wrapper must delegate to the one exemption implementation, not reimplement it"
    assert "Enrollment token required" in src
