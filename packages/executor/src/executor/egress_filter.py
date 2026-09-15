# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Egress allowlist reader for sbx sandbox network policies.

Reads /etc/venya/egress-allowlist.txt at sandbox creation time.
Returns a list of hosts (IPs, CIDRs, hostnames) to allow via sbx policy.

Fail-closed: missing or empty file -> only DNS resolver is allowed.
"""

import logging
from pathlib import Path

logger = logging.getLogger("venya.executor.egress")

DEFAULT_ALLOWLIST_PATH = Path("/etc/venya/egress-allowlist.txt")
DEFAULT_DNS_RESOLVER = "10.27.28.1"


class EgressFilter:
    """Reads egress allowlist and returns hosts to allow in sbx sandbox.

    The allowlist is a static file read once at sandbox creation.
    No hot-reload, no per-command updates.

    Format: one entry per line. Entries can be:
      - IP addresses: 10.27.28.5
      - CIDRs: 10.27.28.0/24
      - Hostnames: web-server-3
    Lines starting with # are comments. Blank lines are ignored.
    """

    def __init__(
        self,
        allowlist_path: Path | None = None,
        dns_resolver: str = DEFAULT_DNS_RESOLVER,
    ):
        self.allowlist_path = allowlist_path or DEFAULT_ALLOWLIST_PATH
        self.dns_resolver = dns_resolver

    def read_allowlist(self) -> list[str]:
        """Parse the allowlist file. Returns list of hosts to allow.

        Missing or empty file -> returns empty list (fail-closed).
        DNS resolver is always added by get_allowed_hosts(), not here.
        """
        if not self.allowlist_path.exists():
            logger.warning(
                "Egress allowlist not found at %s -- fail-closed (only DNS allowed)",
                self.allowlist_path,
            )
            return []

        entries = []
        for line in self.allowlist_path.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            entries.append(stripped)

        if not entries:
            logger.warning(
                "Egress allowlist is empty at %s -- fail-closed (only DNS allowed)",
                self.allowlist_path,
            )

        return entries

    def get_allowed_hosts(self) -> list[str]:
        """Return all hosts to allow in the sandbox, including DNS resolver.

        DNS resolver is always included -- without it, hostname-based
        allowlist entries cannot resolve inside the sandbox.
        """
        hosts = self.read_allowlist()
        if self.dns_resolver not in hosts:
            hosts.append(self.dns_resolver)
        return hosts
