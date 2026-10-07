# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#518 enroll-label-width-500-after-ceremony — browser-enroll label bound.

``BrowserEnrollCompleteRequest.label`` had no width bound while
``WebAuthnCredential.label`` is ``String(64)`` (core/iam/models.py:515): an
over-width label reached the DB write that runs AFTER the server completes the
WebAuthn ceremony — the worst place for a late failure (psycopg 500 class,
#334 posture). The sibling credential-add route already declares the ruled
shape (credentials.py: ``max_length=64, min_length=1`` + strict-UTF-8
validator); this route now mirrors it exactly, so pydantic rejects at request
PARSE — before the handler calls ``finish_registration`` — and a refused
request never burns the ceremony or writes a row.

Truth table (paired-negative law), on a REAL SQLite app so the rejects show
the DB untouched:
  65 chars      -> 422, field named, ceremony NOT consumed, no row.  RED at HEAD.
  empty string  -> 422 (min_length, sibling parity), no row.
  lone surrogate-> 422 (strict-UTF-8, sibling parity), no row.
  64 chars      -> 200, row written with the exact label (paired positive).
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from core.iam.enrollment_manager import EnrollmentManager
from core.iam.models import Base, User, WebAuthnCredential
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from server.app import _validation_error_handler
from server.routes import enroll
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.testclient import TestClient

LABEL_WIDTH = 64  # WebAuthnCredential.label — models.py:515


def _build_app(tmp_path: Path):
    """Real SQLite app with the browser-enroll router wired to production's
    sanitized 422 handler. Returns (client, SessionLocal, fido2 mock)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'enroll518.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    s = SessionLocal()
    s.add(
        User(
            user_id="newuser",
            status="pending_enrollment",
            auth_mode="security-key",
            display_name="New User",
        )
    )
    s.commit()

    # Real token lifecycle on the real DB: created -> in_progress, the exact
    # state the complete endpoint demands.
    em = EnrollmentManager(s, None)
    _token, plaintext = em.create_enrollment_token("newuser")
    em.mark_token_in_progress(plaintext)
    s.commit()
    s.close()

    app = FastAPI()
    app.include_router(enroll.router, prefix="/api/v1")
    app.add_exception_handler(RequestValidationError, _validation_error_handler)

    fido2 = MagicMock()
    fido2.finish_registration.return_value = SimpleNamespace(
        user_id="newuser",
        credential_id=b"cred-123",
        public_key=b"pub-key",
        sign_count=0,
    )
    app.state.fido2_manager = fido2
    app.state.config = SimpleNamespace(
        session=SimpleNamespace(session_timeout=900, access_token_ttl=900, max_session_duration=3600),
        fido2=SimpleNamespace(enrollment_token_ttl=15),
        recovery_code_pepper="",
    )

    def _db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    from server.dependencies import get_db

    app.dependency_overrides[get_db] = _db
    return TestClient(app, raise_server_exceptions=False), SessionLocal, fido2, plaintext


def _post_complete(client, plaintext_token: str, label):
    return client.post(
        "/api/v1/enroll/browser/complete",
        json={
            "enrollment_token": plaintext_token,
            "challenge_id": "challenge-123",
            "response": {"id": "dGVzdA==", "response": {}},
            "label": label,
        },
    )


class TestEnrollLabelWidth518:
    def test_over_width_label_422_ceremony_not_consumed_no_row(self, tmp_path):
        """AC1 (RED at HEAD): 65-char label -> 422 naming the field, and NO
        WebAuthn registration side-effect: finish_registration never runs
        (the hardware/challenge step is untouched), the credential table stays
        empty, the token is still 'in_progress', and the user is still
        'pending_enrollment' — the whole request is refused at parse."""
        client, SessionLocal, fido2, plaintext = _build_app(tmp_path)
        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            resp = _post_complete(client, plaintext, "x" * (LABEL_WIDTH + 1))
        assert resp.status_code == 422, resp.text
        assert "label" in resp.text
        fido2.finish_registration.assert_not_called()
        with SessionLocal() as s:
            assert s.query(WebAuthnCredential).count() == 0
            assert s.query(User).filter_by(user_id="newuser").one().status == "pending_enrollment"

    def test_empty_label_422_sibling_min_length_parity(self, tmp_path):
        """Sibling parity (AC2): credentials.py carries min_length=1 — so does
        this model now; an empty label is refused pre-ceremony."""
        client, SessionLocal, fido2, plaintext = _build_app(tmp_path)
        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            resp = _post_complete(client, plaintext, "")
        assert resp.status_code == 422, resp.text
        fido2.finish_registration.assert_not_called()
        with SessionLocal() as s:
            assert s.query(WebAuthnCredential).count() == 0

    def test_lone_surrogate_label_422_sibling_utf8_parity(self, tmp_path):
        """Sibling parity (AC2): the credential-add route also rejects lone
        surrogates pre-DB (the #334 posture) — the width bound alone would
        pass a 1-char surrogate that then dies inside the psycopg write."""
        client, SessionLocal, fido2, plaintext = _build_app(tmp_path)
        # Raw JSON with the escaped surrogate: what a real client sends over
        # the wire (test_admin_string_validation.py technique).
        body = (
            b'{"enrollment_token": "' + plaintext.encode() + b'", '
            b'"challenge_id": "challenge-123", "response": {"id": "dGVzdA==", "response": {}}, '
            b'"label": "ok\\ud800tail"}'
        )
        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            resp = client.post(
                "/api/v1/enroll/browser/complete", content=body, headers={"Content-Type": "application/json"}
            )
        assert resp.status_code == 422, resp.text
        fido2.finish_registration.assert_not_called()
        with SessionLocal() as s:
            assert s.query(WebAuthnCredential).count() == 0

    def test_at_limit_label_enrolls_normally(self, tmp_path):
        """AC3 paired positive: exactly 64 chars completes — row written with
        the exact label, ceremony consumed, user activated."""
        client, SessionLocal, fido2, plaintext = _build_app(tmp_path)
        label = "n" * LABEL_WIDTH
        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            resp = _post_complete(client, plaintext, label)
        assert resp.status_code == 200, resp.text
        fido2.finish_registration.assert_called_once()
        with SessionLocal() as s:
            cred = s.query(WebAuthnCredential).one()
            assert cred.label == label
            assert s.query(User).filter_by(user_id="newuser").one().status == "active"

    def test_normal_label_still_enrolls(self, tmp_path):
        """AC3 (existing behavior retained): the everyday 'Primary key' label
        still completes end-to-end on the real DB."""
        client, SessionLocal, _fido2, plaintext = _build_app(tmp_path)
        with patch("server.routes.enroll.verify_binding_hash", return_value=True):
            resp = _post_complete(client, plaintext, "Primary key")
        assert resp.status_code == 200, resp.text
        with SessionLocal() as s:
            assert s.query(WebAuthnCredential).one().label == "Primary key"

    def test_model_level_shape_matches_sibling(self):
        """AC2 direct pin: both routes agree on the label bound. Compare the
        pydantic constraint metadata (MaxLen/MinLen) rather than FieldInfo
        attributes, which pydantic 2.13 does not expose for these, and prove
        behavior by construction. A refactor that drops any of these here
        fails even if the route cells get rewritten."""
        from server.routes.credentials import CredentialAddCompleteRequest

        def _bounds(field) -> tuple:
            max_len = min_len = None
            for c in field.metadata:
                max_len = getattr(c, "max_length", max_len)
                min_len = getattr(c, "min_length", min_len)
            return (max_len, min_len)

        label_bounds = _bounds(enroll.BrowserEnrollCompleteRequest.model_fields["label"])
        sib_bounds = _bounds(CredentialAddCompleteRequest.model_fields["label"])
        assert label_bounds == (LABEL_WIDTH, 1), label_bounds
        assert label_bounds == sib_bounds, f"routes disagree: {label_bounds} vs {sib_bounds}"
        with pytest.raises(ValidationError):
            enroll.BrowserEnrollCompleteRequest(
                enrollment_token="t", challenge_id="c", response={}, label="x" * (LABEL_WIDTH + 1)
            )
        with pytest.raises(ValidationError):
            enroll.BrowserEnrollCompleteRequest(enrollment_token="t", challenge_id="c", response={}, label="")
        with pytest.raises(ValidationError):
            enroll.BrowserEnrollCompleteRequest(
                enrollment_token="t", challenge_id="c", response={}, label="ok\ud800tail"
            )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
