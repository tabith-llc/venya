# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Zero-header-reads interlock (end-to-end-mtls-header-trust-removal #314).

Ruled acceptance posture (Q3): the X-Client-Verified / X-Client-Subject /
X-Client-Serial header chain is RETIRED across both identity planes in one
changeset — no request header is identity anywhere in the server package.
This interlock fails the build the moment a read of a retired header (or a
re-introduced read helper) appears in shipped source, in EITHER spelling;
prose mentions (docstrings/comments) are allowed only when the name is NOT
followed by a read-call. The one surviving identity-adjacent header is the
nginx-written forwarded-cert-file PATH (config default
``x-client-cert-file``), which carries no asserted identity — the app
re-verifies the certificate itself.
"""

import re
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "server"

RETIRED_HEADERS = ("x-client-verified", "x-client-subject", "x-client-serial")

_READ_RE = re.compile(r"(?:headers|scope)\s*(?:\.get\(|\[)\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_HELPER_RE = re.compile(r"_extract_identity_from_subject|_verify_cert_against_ca")


def _iter_source():
    for path in sorted(SRC_ROOT.rglob("*.py")):
        yield path, path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("filename", "content"),
    [(str(p.relative_to(SRC_ROOT)), c) for p, c in _iter_source()],
    ids=lambda v: v if isinstance(v, str) and not v.startswith("<") else "",
)
def test_no_retired_header_reads_in_shipped_source(filename, content):
    for match in _READ_RE.finditer(content):
        header = match.group(1).lower()
        assert header not in RETIRED_HEADERS, (
            f"{filename}: retired identity header {header!r} is read again — "
            "#314 removed header-based identity; verify the forwarded certificate instead."
        )


def test_retired_identity_helpers_stay_deleted():
    """The header-era helpers must not creep back (they parsed STRINGS an
    attacker used to control; the crypto path uses the cert object)."""
    for filename, content in _iter_source():
        assert not _HELPER_RE.search(content), f"{filename}: retired helper resurrected"


def test_cert_pem_header_default_is_the_only_client_header_surface():
    """config default pins the single forwarded header name; the middleware
    reads it ONLY through the config value (no hardcoded magic string)."""
    from server.config import InnerTLSConfig

    assert InnerTLSConfig().cert_pem_header == "x-client-cert-pem"
    auth_src = (SRC_ROOT / "middleware" / "auth.py").read_text(encoding="utf-8")
    assert 'headers.get("x-client-cert-pem")' not in auth_src
    assert "headers.get(inner.cert_pem_header)" in auth_src


def test_no_cert_path_extfile_residue():
    """Fleet-HALT-3 regression pin: the #314 extfile transport named an nginx
    variable that never existed in stock nginx (nginx -t: unknown variable —
    dead front-end on every fresh core). The path transport and its header are
    DELETED: neither identifier may appear in the installer scripts or the
    server source, in any spelling of the retired header."""
    repo = Path(__file__).resolve().parents[3]
    surfaces = [
        repo / "install-venya-core.sh",
        repo / "install-venya-executor.sh",
        repo / "venya-common.sh",
    ]
    surfaces += sorted((repo / "packages" / "server" / "src").rglob("*.py"))
    forbidden = ("ssl_client_certificate_path", "x-client-cert-file", "X-Client-Cert-File")
    for path in surfaces:
        content = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in content, f"{path}: retired cert-path surface {needle!r} resurrected"
