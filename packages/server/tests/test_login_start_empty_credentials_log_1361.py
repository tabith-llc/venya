"""Leg 1361 item 1A — login/start with an unknown user id: the server records the truth.

The shipped behaviour at `fc6b8abe`: `start_authentication` omits `allowCredentials`
when the targeted id matched no credentials (manager.py, the `if allow_credentials:`
attach), the browser then volunteers any resident credential for the rp id, and the
next call answers 401 `Credential not found` — accusing the key for a cause that sat
in THIS call. The fix adds a server-side WARN with the id and no secret material.

The posture that does NOT change, and its paired negative (spec §1A): what the route
returns is untouched. A non-existent id must stay indistinguishable to a network
observer — same status, same body shape, same absence of `allowCredentials`. If a
future seat finds the only way to log this case is to alter the response, the
response loses, not the log.

Liveness note for a cold seat: the `fido2_manager` is a MagicMock — these cells drive
the ROUTE, which is where the user id is in scope, not the manager.
"""

import logging
from unittest.mock import MagicMock

from starlette.testclient import TestClient

from .test_auth import _create_test_app  # same builder, same seams


def _options_without_allow():
    """What the manager returns for an id that matched nothing (field absent)."""
    return {"challenge": "q3V4d2x1c9n0b8m7k5j3h1", "rpId": "venya.test", "userVerification": "required"}


def _options_with_allow():
    return {**_options_without_allow(), "allowCredentials": [{"type": "public-key", "id": "cred1"}]}


class TestEmptyCredentialsCaseIsLogged:
    def test_unknown_id_warns_with_the_id_and_nothing_else_sensitive(self, caplog):
        fido2 = MagicMock()
        fido2.start_authentication.return_value = ("auth-cid-1", _options_without_allow())
        app = _create_test_app(fido2_manager=fido2)
        client = TestClient(app, raise_server_exceptions=False)
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            resp = client.post("/api/v1/auth/login/start", json={"user_id": "dust-admin"})
        assert resp.status_code == 200
        warns = [r for r in caplog.records if r.levelno == logging.WARNING and "login/start" in r.getMessage()]
        assert warns, "the empty-credentials case must be recorded server-side"
        msg = warns[0].getMessage()
        assert "dust-admin" in msg, msg
        # no secret material: the challenge bytes and the credential list are never logged
        assert "q3V4d2x1c9n0b8m7k5j3h1" not in msg
        assert "cred1" not in msg

    def test_paired_negative_response_shape_is_untouched(self):
        """The anti-enumeration door: status, keys, and the absent field stay EXACTLY
        as shipped. The log is the only addition this route may make."""
        fido2 = MagicMock()
        fido2.start_authentication.return_value = ("auth-cid-2", _options_without_allow())
        app = _create_test_app(fido2_manager=fido2)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/v1/auth/login/start", json={"user_id": "dust-admin"})
        assert resp.status_code == 200, "an unknown id must not become a distinguishable status"
        body = resp.json()
        assert set(body) == {"challenge_id", "options"}, body
        assert "allowCredentials" not in body["options"]
        assert body["challenge_id"] == "auth-cid-2"

    def test_known_id_with_credentials_does_not_warn(self, caplog):
        fido2 = MagicMock()
        fido2.start_authentication.return_value = ("auth-cid-3", _options_with_allow())
        app = _create_test_app(fido2_manager=fido2)
        client = TestClient(app, raise_server_exceptions=False)
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            resp = client.post("/api/v1/auth/login/start", json={"user_id": "dusty-admin"})
        assert resp.status_code == 200
        assert "allowCredentials" in resp.json()["options"]
        assert not [
            r for r in caplog.records if r.levelno == logging.WARNING and "login/start" in r.getMessage()
        ], "a targeted id that matched credentials is not the empty case"

    def test_no_user_id_is_not_the_empty_case(self, caplog):
        """An untargeted start omits the field by design (discoverable-by-choice path,
        no id given); it must not be logged as a mistyped name."""
        fido2 = MagicMock()
        fido2.start_authentication.return_value = ("auth-cid-4", _options_without_allow())
        app = _create_test_app(fido2_manager=fido2)
        client = TestClient(app, raise_server_exceptions=False)
        with caplog.at_level(logging.WARNING, logger="venya.server"):
            resp = client.post("/api/v1/auth/login/start", json={})
        assert resp.status_code == 200
        assert not [r for r in caplog.records if r.levelno == logging.WARNING and "login/start" in r.getMessage()]
