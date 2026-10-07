# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""#539 ca-get-ca-key-pem-unreferenced-plaintext-claim — the key accessor is gone.

``CAManager.get_ca_key_pem`` read ``ca.key`` straight off disk and handed the
bytes to whoever called it. It had no caller anywhere in the tree (production or
test), and its docstring described a job the product does differently: backup and
export is a command, not a library call that hands key material to a caller —
``venya admin export-ca-key`` re-wraps with an operator-supplied passphrase,
refuses an empty one, writes ``0600`` under ``0700``, and cannot emit plaintext.

The retirement is now checked rather than remembered. The paired positive half —
the certificate accessors still exist — is what stops this cell from passing on
a diff that deleted the wrong thing.

Confirmed adjacent facts (checked, not changed):
* ``AdminCAManager`` never had a key accessor; its public surface is
  ``get_admin_ca_cert_pem()`` (certificate only).
* ``CAManager.get_ca_cert_pem`` / ``compute_fingerprint`` / ``compute_serial_hex``
  are referenced and stay.
"""

from server.ca import AdminCAManager, CAManager


class TestKeyAccessorRetired539:
    """The CA classes expose certificate material, never key material."""

    def test_ca_key_accessor_absent_and_cert_accessors_remain(self):
        """Negative half: no key accessor on either CA class.

        Positive half: the certificate accessors are still there, so an absent
        key method means a retirement, not a rename or a mistaken deletion.
        """
        assert not hasattr(CAManager, "get_ca_key_pem"), "CAManager must not offer a private-key accessor (refs 539)"
        assert hasattr(
            CAManager, "get_ca_cert_pem"
        ), "the certificate accessor is referenced product surface and must remain"
        assert hasattr(CAManager, "load_ca"), "the signing path keeps loading the key through load_ca()"

        # AdminCA never carried an equivalent accessor; asserted here so a future
        # copy of the retired method onto the admin class fails the same check.
        assert not hasattr(AdminCAManager, "get_ca_key_pem")
        assert not hasattr(AdminCAManager, "get_admin_ca_key_pem")
        assert hasattr(AdminCAManager, "get_admin_ca_cert_pem")
