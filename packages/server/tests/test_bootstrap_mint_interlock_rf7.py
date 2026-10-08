# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""RF-7 chunk 1 — the bootstrap-mint caller interlock (RF-6 §6.3 item 3).

The design does not trust "nobody calls the key-exporting mint": it asserts
it. Two in-repo precedent shapes, copied deliberately:

* attribute-shape, from test_ca_key_accessor_retired_539.py — the retired
  half paired with the surviving half, so the cell cannot pass on a diff that
  deleted the wrong thing;
* source-scan, from test_header_trust_interlock.py — walk shipped source and
  fail the moment a forbidden call reappears.

The allowed caller is exactly one: the installer's bootstrap block in
install-venya-core.sh (dossier flag F-1 — the reason this chunk forbids a
delete commit). Nothing under packages/server/src/ may call the mint; a route
that ever reaches it is a red suite, not a review finding.
"""

import re
from pathlib import Path

import pytest
from cryptography import x509
from server.ca import AdminCAManager

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "server"
INSTALLER = Path(__file__).resolve().parents[3] / "install-venya-core.sh"

# A call site, not the def: match "<receiver>.sign_admin_cert(" — the def line
# ("def sign_admin_cert(self...") is excluded by the required dot receiver.
_CALL_RE = re.compile(r"[\w\)\]]\.sign_admin_cert\s*\(")
# The mint that returns a keypair; the CSR signer is the sanctioned sibling.
_CSR_SIGNER_RE = re.compile(r"[\w\)\]]\.sign_admin_csr\s*\(")


def _iter_source():
    for path in sorted(SRC_ROOT.rglob("*.py")):
        yield path, path.read_text(encoding="utf-8")


class TestCallerInterlockAttributeShape:
    def test_both_mints_exist_with_their_shapes(self):
        """Positive half: the replacement signer AND the narrowed bootstrap
        mint both exist (a delete here would precede RF-10's installer commit
        — forbidden in this chunk). The negative half: the CSR signer exists
        under its ruled name, so a rename is not a silent retirement."""
        assert hasattr(
            AdminCAManager, "sign_admin_cert"
        ), "bootstrap/machine-plane mint stays until RF-10's installer commit (RF-6 §6.3, flag F-1)"
        assert hasattr(AdminCAManager, "sign_admin_csr"), "the §2.5b human-plane signer must exist"
        # And nothing on the class hands back a private key except the
        # bootstrap path: the CSR signer's signature is cert-only.
        import inspect

        sig = inspect.signature(AdminCAManager.sign_admin_csr)
        assert sig.return_annotation is x509.Certificate
        # Bootstrap keeps its 3-tuple contract for the installer unpack.
        boot = inspect.signature(AdminCAManager.sign_admin_cert)
        assert boot.return_annotation == tuple[x509.Certificate, bytes, bytes], (
            "sign_admin_cert arity changed — install-venya-core.sh:420 unpacks "
            "(cert, key_pem, cert_pem); this chunk stays byte-compatible (F-1)"
        )


class TestCallerInterlockSourceScan:
    def test_no_shipped_server_source_calls_the_bootstrap_mint(self):
        """Every file under packages/server/src/: zero call sites of the
        key-exporting mint. The only allowed caller lives in the installer,
        asserted next."""
        offenders = [str(path.relative_to(SRC_ROOT)) for path, content in _iter_source() if _CALL_RE.search(content)]
        assert offenders == [], (
            f"sign_admin_cert reached from shipped source: {offenders} — it is the "
            "bootstrap/machine-plane mint only (RF-6 §6.3); human issuance goes "
            "through sign_admin_csr."
        )

    def test_installer_bootstrap_call_site_is_the_single_allowed_caller(self):
        """The dossier's F-1 pin, checked rather than remembered: the installer
        calls the mint exactly once, in the bootstrap block, unpacking the
        3-tuple. If RF-10 rewrites this line for a new return shape, this cell
        is updated in the SAME changeset as the installer — never before."""
        assert INSTALLER.exists(), f"installer not found at {INSTALLER}"
        content = INSTALLER.read_text(encoding="utf-8")
        calls = _CALL_RE.findall(content)
        assert len(calls) == 1, f"expected exactly one bootstrap call site, found {len(calls)}"
        assert re.search(r"cert,\s*key_pem,\s*cert_pem\s*=\s*\w+\.sign_admin_cert\(", content), (
            "the installer's unpack shape (cert, key_pem, cert_pem) is the arity this "
            "chunk must stay byte-compatible with"
        )

    @pytest.mark.parametrize(
        ("filename", "has_call"),
        [(str(p.relative_to(SRC_ROOT)), bool(_CSR_SIGNER_RE.search(c))) for p, c in _iter_source()],
    )
    def test_csr_signer_wired_to_exactly_the_issuance_route(self, filename, has_call):
        """Chunk-2 boundary, re-scoped as this cell always said it would be.

        Chunk 1 pinned "no route calls ``sign_admin_csr`` yet" so the chunk
        boundary was visible. Chunk 2 ships the issuance endpoint, so the
        interlock is now a two-sided statement over the SAME route-layer
        population chunk 1 walked: inside ``routes/``, a file calls the
        human-plane signer IF AND ONLY IF it is ``routes/admin_certs.py``.
        A second route reaching the mint is a red suite, not a review finding
        (RF-6 §6.3 item 3, §2.5b). Non-route files stay outside the assertion,
        exactly as in chunk 1 — the population walked does not change size.
        """
        if not filename.startswith("routes/"):
            return
        if filename == "routes/admin_certs.py":
            assert has_call, (
                "routes/admin_certs.py no longer calls sign_admin_csr — the issuance "
                "endpoint is the human-plane mint's only caller (RF-6 §2.5b); if the "
                "endpoint moved, the caller interlock moved with it, never ahead."
            )
        else:
            assert not has_call, (
                f"{filename}: a route calls sign_admin_csr — the human-plane mint has "
                "exactly one caller (RF-6 §2.5b). Route issuance through "
                "POST /api/v1/admin/certs/issue instead."
            )

    def test_the_issuance_route_is_the_one_caller(self):
        """Positive half of the chunk-2 pair: the issuance route exists AND is
        the single signer caller. A branch that deleted the endpoint while
        relaxing the negative above would pass vacuously — this cell is what
        keeps the pair honest (both halves required, RF-6 §6.3 item 3)."""
        caller_files = [
            filename
            for filename, has_call in [
                (str(p.relative_to(SRC_ROOT)), bool(_CSR_SIGNER_RE.search(c))) for p, c in _iter_source()
            ]
            if has_call
        ]
        assert caller_files == ["routes/admin_certs.py"], (
            f"sign_admin_csr callers changed shape: {caller_files} — the human-plane "
            "mint must be reached only through the issuance endpoint (RF-6 §2.5b)."
        )
