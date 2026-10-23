# Copyright (c) 2026 Tabith LLC. All rights reserved.
"""#673 guard — the revoked executor's 200 ``{revoked: true}`` beat is a ruled channel.

Owner ruling **B1 (2026-09-20)** makes the heartbeat's ``reject_revoked=False`` the fast
cooperative-stop signal: a revoked-but-verified executor gets **HTTP 200 with
``revoked: true``** and writes nothing. The enforcing control lives elsewhere (the dial-gate
refusal, ruling 4). So a future seat reading "revoked executor gets 200" as a bug and
"hardening" it — ``reject_revoked=True``, or a 401/403 in the route — does not fix a
vulnerability, it KILLS a channel the owner ruled, and the executor loses its stop signal.

The pins that already exist each cover ONE tier, and that is the gap:

* ``test_session_middleware.py::test_heartbeat_revoked_identity_passes_through_for_advisory``
  drives the real middleware, but its app mounts a **stub** heartbeat that echoes
  ``auth_user`` — it never exercises the route's response shape.
* ``test_executor_server.py::TestHeartbeat::test_heartbeat_revoked_executor`` drives the
  real route, but INJECTS the auth state, so it never exercises the middleware.

Neither reddens if the OTHER half is changed. This cell crosses both: real
``SessionMiddleware`` + the real ``POST /api/v1/heartbeat``, revoked CRL row, mTLS headers.

Named in the ``dependencies.py`` ``require_role`` comment it guards, and non-vacuity is
proven in the report by planting both regressions.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace


def _rows(revoked_at):
    """Rows shaped for BOTH tiers, which is why this cell does not reuse the harness's.

    ``test_session_middleware._rows`` carries only what the middleware reads (``id``,
    ``serial_number``), because its heartbeat is an echo stub. The real route also reads
    ``ExecutorCert.not_after`` for the rotation hint, so a cross-tier cell needs a cert
    row with that field or it dies in an AttributeError before the ruled shape is ever
    observed. ``revoked_at`` on the EXECUTOR row is the identity-revocation flag; the CRL
    row is what the middleware reads for the presented serial.
    """
    executor_row = SimpleNamespace(id="venya-exec-1", revoked_at=revoked_at)
    cert_row = SimpleNamespace(
        serial_number="0000000000000001",
        not_after=datetime.now(UTC) + timedelta(days=365),
    )
    crl_row = SimpleNamespace(serial_number="0000000000000001", revoked_at=revoked_at)
    return executor_row, cert_row, crl_row


def _revoked_beat_app(harness, tmp_path, backend):
    """Real middleware + the REAL heartbeat route, wired the shipped way.

    Reuses the shipped executor-mTLS harness for the certificate material and the
    model-dispatching mock backend, and mounts ``executors_routes.router`` instead of
    that harness's echo stub. ``inner_mtls`` is enabled because the middleware's
    executor path requires the inner-mTLS posture to be configured.
    """
    from fastapi import FastAPI
    from server.config import InnerTLSConfig, ServerConfig
    from server.middleware.auth import SessionMiddleware
    from server.routes import executors as executors_routes

    certfiles = tmp_path / "certfiles"
    certfiles.mkdir(exist_ok=True)

    app = FastAPI()
    app.add_middleware(SessionMiddleware)
    app.state.config = ServerConfig(
        recovery_code_pepper="test-pepper",
        admin_mtls={"enabled": False},
        inner_mtls=InnerTLSConfig(
            enabled=True,
            cert_file="/test/inner.crt",
            key_file="/test/inner.key",
            client_ca_file="/test/inner-ca.crt",
        ),
    )
    app.state.ca_manager = harness._root_ca(tmp_path)[0]
    app.state.backend = backend
    app.include_router(executors_routes.router, prefix="/api/v1")
    return app


class TestHeartbeatCooperativeStopChannelB1:
    """Ruling B1: revoked executor → 200 {revoked: true}, and NO write."""

    def test_heartbeat_revoked_still_200_cooperative_channel_b1(self, tmp_path):
        from starlette.testclient import TestClient

        from .test_session_middleware import TestExecutorSessionPathAuth

        harness = TestExecutorSessionPathAuth()
        executor_row, cert_row, crl_row = _rows(datetime.now(UTC))
        backend, db = harness._make_executor_backend(executor_row=executor_row, cert_row=cert_row, crl_row=crl_row)
        app = _revoked_beat_app(harness, tmp_path, backend)
        cert = harness._exec_cert(tmp_path, serial=1)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
            headers=harness._fwd(tmp_path, cert),
        )

        # The ruled shape: NOT 403, NOT 401 — a 200 that carries the stop signal.
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["revoked"] is True
        # And the write guard that rides the same ruling: the beat REFUSES to stamp
        # liveness for a revoked identity. commit() on the mock backend is the only
        # way this route records a write.
        db.commit.assert_not_called()

    def test_heartbeat_unrevoked_still_200_and_writes(self, tmp_path):
        """Paired negative: the 200 is not an artifact of the revoked branch only.

        Same harness, NO revocation row → still 200, ``revoked`` false, and the liveness
        write DOES happen. So the previous cell's ``commit.assert_not_called()`` cannot
        pass because the route never writes at all, and the 200 cannot pass because every
        beat is refused.
        """
        from starlette.testclient import TestClient

        from .test_session_middleware import TestExecutorSessionPathAuth

        harness = TestExecutorSessionPathAuth()
        executor_row, cert_row, _crl = _rows(revoked_at=None)
        backend, db = harness._make_executor_backend(executor_row=executor_row, cert_row=cert_row)
        app = _revoked_beat_app(harness, tmp_path, backend)
        cert = harness._exec_cert(tmp_path, serial=1)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/heartbeat",
            json={"executor_id": "venya-exec-1", "cert_fingerprint": "abc"},
            headers=harness._fwd(tmp_path, cert),
        )

        assert resp.status_code == 200, resp.text
        assert resp.json()["revoked"] is False
        db.commit.assert_called_once()
