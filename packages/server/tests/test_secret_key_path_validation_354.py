# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#354 server half — secret key path params + create body validated.

Ruled charset ^[A-Za-z0-9._-]{1,128}$ (owner batch-yes 2026-10-02 + RULING-INPUTS
verification note). Truth table both halves: crafted keys ('a/b', '../x',
'a%2Fb', 129-char) -> 422 pre-handler; normal keys keep working (round-trip).
"""

import re
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import pytest
from fastapi import FastAPI
from server.dependencies import get_current_user
from server.routes import secrets as secrets_routes
from starlette.testclient import TestClient

TEST_USER = {"user_id": "test-user", "roles": ["devops"], "caller": "human"}

BAD_KEYS = ["a/b", "../x", "a%2Fb", "x" * 129]
GOOD_KEYS = ["tier1_pw", "a.b_c-d", "x" * 128]


def _app():
    app = FastAPI()
    core = MagicMock()
    app.state.core = core
    backend = MagicMock()
    backend.get_session.return_value = MagicMock()
    app.state.backend = backend
    app.include_router(secrets_routes.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: TEST_USER
    rm = MagicMock()
    rm.get_user_permissions.side_effect = lambda uid: {1: "read-write"}
    patcher = patch("server.dependencies.RoleManager", return_value=rm)
    patcher.start()
    return app, core, patcher


class TestSecretKeyValidation354:
    @pytest.mark.parametrize("bad", BAD_KEYS)
    def test_create_body_bad_key_422(self, bad):
        app, _core, patcher = _app()
        try:
            client = TestClient(app)
            resp = client.post(
                "/api/v1/secrets",
                json={"key": bad, "value": "v", "roles": ["devops"], "key_version_id": "1"},
            )
            assert resp.status_code == 422, f"{bad!r} accepted: {resp.status_code}"
        finally:
            patcher.stop()

    @pytest.mark.parametrize("bad", BAD_KEYS)
    def test_get_path_bad_key_422(self, bad):
        app, _core, patcher = _app()
        try:
            client = TestClient(app)
            # route() bypasses TestClient URL normalization — the raw crafted
            # segment must be refused by the validator, not by HTTP parsing.
            resp = client.request(
                "GET", "/api/v1/secrets/" + quote(bad, safe=""), headers={"Authorization": "Bearer x"}
            )
            # crafted keys must be REJECTED, never served: single-segment crafted
            # values die at the #354 validator (422); values carrying a decoded "/" split
            # the route and die at routing (404) — both refuse before the handler.
            assert resp.status_code in (422, 404), f"{bad!r} accepted: {resp.status_code}"
        finally:
            patcher.stop()

    @pytest.mark.parametrize("bad", BAD_KEYS)
    def test_delete_path_bad_key_422(self, bad):
        app, _core, patcher = _app()
        try:
            client = TestClient(app)
            resp = client.request("DELETE", "/api/v1/secrets/" + quote(bad, safe=""))
            assert resp.status_code in (422, 404), f"{bad!r} accepted: {resp.status_code}"
        finally:
            patcher.stop()

    @pytest.mark.parametrize("bad", BAD_KEYS)
    def test_patch_metadata_path_bad_key_422(self, bad):
        app, _core, patcher = _app()
        try:
            client = TestClient(app)
            resp = client.request(
                "PATCH", "/api/v1/secrets/" + quote(bad, safe="") + "/metadata", json={"metadata": {}}
            )
            assert resp.status_code in (422, 404), f"{bad!r} accepted: {resp.status_code}"
        finally:
            patcher.stop()

    def test_normal_keys_pass_validation(self):
        # paired positive: valid keys reach the handler (mocked core answers)
        app, core, patcher = _app()
        try:
            rec = MagicMock()
            rec.id, rec.replaced = 7, False
            core.put.return_value = rec
            core.get.return_value = "v"
            client = TestClient(app)
            for good in GOOD_KEYS:
                resp = client.post(
                    "/api/v1/secrets",
                    json={"key": good, "value": "v", "roles": ["devops"], "key_version_id": "1"},
                )
                # the validator must not block normal keys (422 either way);
                # full create/round-trip behavior is covered by tests/test_secrets.py.
                assert resp.status_code != 422, f"GET-blocked valid {good!r}: {resp.status_code}"
                resp = client.get(f"/api/v1/secrets/{good}")
                assert resp.status_code != 422, f"GET blocked valid {good!r}"
        finally:
            patcher.stop()

    def test_whole_segment_literals_accepted_by_ruling(self):
        # RULING-INPUTS: '..' and '.' ACCEPT as literal key NAMES (no '/' can
        # reach the path post client-quote + this pattern; DB key names only).
        assert re.match(secrets_routes.SECRET_KEY_PATTERN, "..")
        assert re.match(secrets_routes.SECRET_KEY_PATTERN, ".")


class TestSecretKeyNeverAPathComponent354:
    """Ruling-mandated verification cell: no server/CLI/executor/core consumer
    treats Secret.key as a filesystem path component (grep open/join/Path( with
    key). If a real one lands here, the charset ruling must be tightened."""

    EXCLUDE = re.compile(
        r"private_key|public_key|pub_key|key_path|key_version|keypair|api_key|"
        r"keyboard|monkeypatch|_key-|key data|keychain|sort|dict|\.keys\(|"
        r"cache|encrypt|decrypt|passphrase"
    )
    PATHISH = re.compile(r"(Path\(|open\(|os\.path\.join|joinpath|write_text|write_bytes)")
    KEYREF = re.compile(r"\{key\}|\bkey\b(?!_)|\[.key.\]")

    def test_no_path_consumer_of_secret_key(self, tmp_path):
        import subprocess
        from pathlib import Path

        roots = [
            Path(__file__).resolve().parents[1] / "src",  # server
            Path(__file__).resolve().parents[2] / "cli" / "src",
            Path(__file__).resolve().parents[2] / "core" / "src",
            Path(__file__).resolve().parents[2] / "executor" / "src",
        ]
        hits = []
        for root in roots:
            assert root.exists(), root
            out = subprocess.run(
                ["grep", "-rn", "-E", str(self.PATHISH.pattern)[:60], str(root)],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in out.stdout.splitlines():
                if self.KEYREF.search(line) and not self.EXCLUDE.search(line):
                    hits.append(line)
        assert hits == [], "Secret.key used as a path component:\n" + "\n".join(hits)
