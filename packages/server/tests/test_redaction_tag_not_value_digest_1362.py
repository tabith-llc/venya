"""Leg 1362 — the `[REDACTED:<8 hex>]` tag must stop being an unkeyed digest of the VALUE.

Finding (the estate-run report 342 §2, re-proved at this tip before any edit): the stage-2
filter route writes `hash_hex[:8]` where `hash_hex = sha256(plaintext)`, so a captured
masked line is an OFFLINE VERIFIER for low-entropy secrets — nothing in venya rate-
limits an attacker's own laptop — and identical values in different sessions print the
SAME tag, leaking an equality the mask exists to remove.

Both historical reproductions held at `fc6b8abe`:
  sha256("dogfood-value-not-real-341")[:8]        == 369df037   (reports/342)
  sha256("leg1069-marker-not-a-secret")[:8]       == 191a5d27   (reports/253)

Cells, per the spec's bars:
- TestOracle: plant a low-entropy value, harvest the printed tag, brute-force a small
  candidate set OFFLINE. RED at base (the recovery finds the planted value), green once
  the tag carries no value relation.
- TestEqualityLeak: the same value across two sessions must print DIFFERENT tags;
  within ONE response the same value keeps ONE tag (a stable marker per response is the
  verification affordance at routes/filter.py's "did the mask fire" oracle, kept intact).
- Paired negatives: the mask itself stays — marker present in output, masked_count
  unchanged, and NO server-side lookup keys off the tag (the tag is an answer, not an
  index). Bar: the fix must never weaken the mask or the screen.
"""

import base64
import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from .test_filter_endpoint import _create_test_app, _db_stub, _exec_session, _secret_row

CANDIDATES = [b"pw-42", b"hunter2", b"passw0rd", b"letmein", b"swordfish", b"admin123"]
PLANTED = b"pw-42"


def _app_with_secret(session_id: str, secret_value: bytes):
    backend = MagicMock()
    backend.get_session.return_value = _db_stub(
        exec_session=_exec_session(session_id),
        bindings=[SimpleNamespace(secret_id=1)],
        secrets=[_secret_row(1, "low-entropy-key")],
    )
    from core.engine.secure_memory import KekCache  # same import the base harness uses

    backend.kek_cache = KekCache.from_bytes(b"A" * 32, mlock=False)
    app = _create_test_app(backend=backend)
    return backend, app


def _run_filter(app, session_id: str, output: bytes):
    client = TestClient(app, raise_server_exceptions=False)
    with patch("core.engine.encryption.decrypt_secret") as mock_decrypt:
        mock_decrypt.return_value = PLANTED
        resp = client.post(
            f"/api/v1/sessions/{session_id}/filter",
            json={
                "stdout": base64.b64encode(output).decode(),
                "stderr": base64.b64encode(b"clean").decode(),
            },
        )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestOracle:
    def test_planted_low_entropy_value_is_not_recoverable_from_the_tag(self):
        _, app = _app_with_secret("sess-oracle", PLANTED)
        data = _run_filter(app, "sess-oracle", b"token=" + PLANTED)
        # the mask fired — that property must NOT be weakened by the fix
        assert data["masked_count"] >= 1
        body = base64.b64decode(data["stdout"])
        assert PLANTED not in body, "the mask itself stays; only the tag's value-relation moves"
        assert b"[REDACTED:" in body
        tags = data["masked_hashes"]
        assert tags, "the mask-fire oracle keeps a marker per response"
        recovered = [c for c in CANDIDATES if hashlib.sha256(c).hexdigest()[:8] in tags]
        assert not recovered, (
            f"offline brute force over {len(CANDIDATES)} candidates recovered the value "
            f"from the printed tag: {recovered} — the tag must carry no value relation"
        )


class TestEqualityLeak:
    def test_same_value_two_sessions_print_different_tags(self):
        _, app_a = _app_with_secret("sess-eq-1", PLANTED)
        _, app_b = _app_with_secret("sess-eq-2", PLANTED)
        tags_a = set(_run_filter(app_a, "sess-eq-1", b"x " + PLANTED)["masked_hashes"])
        tags_b = set(_run_filter(app_b, "sess-eq-2", b"x " + PLANTED)["masked_hashes"])
        assert tags_a and tags_b
        assert not (tags_a & tags_b), (
            "identical values share a tag across sessions — the equality the mask removes " "is handed back by the tag"
        )

    def test_one_value_one_response_keeps_one_stable_tag(self):
        """Paired negative: per-RESPONSE stability is the verification affordance
        (routes/filter.py: masked_count/masked_hashes answer 'did the mask fire')."""
        _, app = _app_with_secret("sess-stable", PLANTED)
        data = _run_filter(app, "sess-stable", PLANTED + b" and again " + PLANTED)
        tags = data["masked_hashes"]
        assert len(set(tags)) == 1, f"same value in one response must not fork tags: {tags}"

    def test_tag_is_short_hex_like_the_shipped_surface(self):
        """Form must not silently widen or narrow the printed surface."""
        _, app = _app_with_secret("sess-shape", PLANTED)
        data = _run_filter(app, "sess-shape", b"v=" + PLANTED)
        for t in data["masked_hashes"]:
            assert len(t) == 8, t
            int(t, 16)  # hex, as shipped
