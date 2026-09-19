# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Regression for ticket cli-ca-dir-default-mismatch.

_resolve_ca_dir defaulted to /etc/venya/ca — a path that exists nowhere in a
deployment (CA lives at /var/lib/venya/ca; /etc/venya is read-only for the
core service) and that contradicted the --ca-dir help text in cli.py. All
four admin CA commands route through this one function.
"""

from types import SimpleNamespace

from venya_cli.commands import _resolve_ca_dir


class TestResolveCaDir:
    def test_default_matches_deployed_ca_dir(self):
        """No --ca-dir: resolve to the server's ca_dir default (/var/lib/venya/ca)."""
        assert _resolve_ca_dir(SimpleNamespace(ca_dir=None)) == "/var/lib/venya/ca"

    def test_missing_attr_defaults_same(self):
        assert _resolve_ca_dir(SimpleNamespace()) == "/var/lib/venya/ca"

    def test_explicit_ca_dir_wins(self):
        """Negative half: an explicit --ca-dir must override the default."""
        assert _resolve_ca_dir(SimpleNamespace(ca_dir="/custom/ca")) == "/custom/ca"

    def test_parser_help_agrees_with_default(self):
        """The --ca-dir help text and the resolved default must not disagree again."""
        from venya_cli.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["admin", "export-ca-cert"])
        assert _resolve_ca_dir(args) == "/var/lib/venya/ca"
