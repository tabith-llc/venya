# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#353 ruling R2 — forgery-charset gate on admin identity before CA signing.

CN/SAN interpolate the identity verbatim; RDN/SAN STRUCTURAL characters
(comma, quote, backslash, equals, control chars incl. CR/LF) are REJECTED
loudly with zero mint (reject, don't escape). Everything else passes —
plain hostnames AND the shipped email-form identities stay untouched.
"""

import pytest
from venya_cli.commands import cmd_admin_generate_admin_cert, cmd_admin_init_admin_ca


def _args(identity, ca_dir, output_dir):
    return type("Args", (), {"identity": identity, "ca_dir": ca_dir, "output_dir": str(output_dir)})()


@pytest.fixture
def ca_dir(tmp_path, monkeypatch):
    d = tmp_path / "admin-ca"
    d.mkdir()
    monkeypatch.setenv("VENYA_ADMIN_CA_KEY_PASSPHRASE", "test_passphrase")
    assert cmd_admin_init_admin_ca(type("Args", (), {"output_dir": str(d)})()) == 0
    return str(d)


FORGERY = [
    "a\nOU=evil",  # ticket verbatim: LF + RDN fragment
    "a,b=C",  # ticket verbatim: comma/equals structure forgery
    'a"x',  # quote
    "a\\b",  # backslash
    "a\rX",  # CR
    "a\x00b",  # control chars
    "a\x09b",
]


class TestIdentityForgeryGate353:

    @pytest.mark.parametrize("bad", FORGERY)
    def test_forgery_rejected_zero_mint(self, ca_dir, tmp_path, bad):
        out = tmp_path / f"out-{abs(hash(bad))}"
        rc = cmd_admin_generate_admin_cert(_args(bad, ca_dir, out))
        assert rc == 1, f"{bad!r} minted"
        assert not (out / "admin.crt").exists()
        assert not (out / "admin.key").exists()

    @pytest.mark.parametrize(
        "good",
        [
            "admin-laptop",
            "admin-laptop.corp.example",
            "admin@example.com",  # shipped identity form (green cells)
            "operator@venya.internal",
        ],
    )
    def test_allowed_identities_still_mint(self, ca_dir, tmp_path, good):
        out = tmp_path / f"out-{good}"
        rc = cmd_admin_generate_admin_cert(_args(good, ca_dir, out))
        assert rc == 0, f"{good!r} blocked: {rc}"
        assert (out / "admin.crt").exists()

    def test_empty_identity_rejected(self, ca_dir, tmp_path):
        assert cmd_admin_generate_admin_cert(_args("", ca_dir, tmp_path / "out-e")) == 1
