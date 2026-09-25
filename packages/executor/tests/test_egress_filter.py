# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Tests for EgressFilter — allowlist reader for sbx sandbox network policies."""

from pathlib import Path

import pytest

from executor.egress_filter import EgressFilter


class TestReadAllowlist:
    """Tests for EgressFilter.read_allowlist()."""

    def test_read_allowlist_parses_entries(self, tmp_path: Path):
        """File with 3 entries returns 3 hosts."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("198.51.100.50\n198.51.100.100\nweb-server-3\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.read_allowlist()

        assert result == ["198.51.100.50", "198.51.100.100", "web-server-3"]

    def test_read_allowlist_ignores_comments(self, tmp_path: Path):
        """Lines starting with # are skipped."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("# This is a comment\n198.51.100.50\n# Another comment\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.read_allowlist()

        assert result == ["198.51.100.50"]

    def test_read_allowlist_ignores_blanks(self, tmp_path: Path):
        """Empty lines are skipped."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("\n198.51.100.50\n\n\n198.51.100.100\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.read_allowlist()

        assert result == ["198.51.100.50", "198.51.100.100"]

    def test_read_allowlist_strips_whitespace(self, tmp_path: Path):
        """Leading/trailing whitespace is removed."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("  198.51.100.50  \n\t198.51.100.100\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.read_allowlist()

        assert result == ["198.51.100.50", "198.51.100.100"]

    def test_missing_file_returns_empty(self, tmp_path: Path):
        """No file returns empty list (fail-closed)."""
        allowlist = tmp_path / "nonexistent.txt"

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.read_allowlist()

        assert result == []

    def test_empty_file_returns_empty(self, tmp_path: Path):
        """Empty file returns empty list (fail-closed)."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.read_allowlist()

        assert result == []


class TestGetAllowedHosts:
    """Tests for EgressFilter.get_allowed_hosts()."""

    def test_get_allowed_hosts_includes_dns(self, tmp_path: Path):
        """DNS resolver is always in result."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("198.51.100.50\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.get_allowed_hosts()

        assert "198.51.100.50" in result
        assert "192.0.2.53" in result

    def test_get_allowed_hosts_no_duplicates(self, tmp_path: Path):
        """DNS resolver not duplicated if already in file."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("192.0.2.53\n198.51.100.50\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.get_allowed_hosts()

        assert result.count("192.0.2.53") == 1

    def test_get_allowed_hosts_empty_file(self, tmp_path: Path):
        """Empty file returns only DNS resolver."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.get_allowed_hosts()

        assert result == ["192.0.2.53"]

    def test_get_allowed_hosts_custom_dns(self, tmp_path: Path):
        """Custom DNS resolver is used when specified."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("198.51.100.50\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="8.8.8.8")
        result = egress.get_allowed_hosts()

        assert "8.8.8.8" in result
        assert "192.0.2.53" not in result

    def test_get_allowed_hosts_cidr(self, tmp_path: Path):
        """CIDR entries are passed through."""
        allowlist = tmp_path / "egress-allowlist.txt"
        allowlist.write_text("198.51.100.0/24\n")

        egress = EgressFilter(allowlist_path=allowlist, dns_resolver="192.0.2.53")
        result = egress.get_allowed_hosts()

        assert "198.51.100.0/24" in result
        assert "192.0.2.53" in result


class TestRequiresResolver:
    """Ticket private-infra-product-defaults-and-fixtures (stage 2, ruling D1
    option (a)): the resolver is explicit config — Venya never guesses the
    operator's network, so construction without one is rejected."""

    def test_egress_filter_requires_resolver(self, tmp_path: Path):
        """Omitting dns_resolver is a TypeError — no default is supplied."""
        with pytest.raises(TypeError):
            EgressFilter(allowlist_path=tmp_path / "egress-allowlist.txt")
