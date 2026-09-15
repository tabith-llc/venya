# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""Command whitelist and dangerous pattern blocking.

Enforces an allowlist of permitted commands on the jump host.
Policy is configurable at initialization and changeable by an admin.
"""

import os
import shlex
import shutil
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CommandPolicy:
    """Immutable command execution policy."""

    preset: str  # strict | balanced | permissive
    allowed_commands: frozenset[str]  # explicit allowlist (strict mode)
    trusted_paths: frozenset[str]  # trusted directories (balanced mode)
    dangerous_patterns: frozenset[str]  # blocked patterns (all modes)
    match_word_boundaries: bool = True  # use \b regex matching for dangerous patterns
    allowed_hosts: list[dict[str, Any]] = field(default_factory=list)  # network allow rules (sbx)


# Default dangerous patterns (all presets block these)
DEFAULT_DANGEROUS_PATTERNS: tuple[str, ...] = (
    # Destructive
    "rm -rf",
    "rm -rf ",
    "dd ",
    "dd if=",
    "mkfs",
    "fdisk",
    "shred",
    # Network exfiltration
    " nc ",
    " ncat ",
    "scp ",
    "rsync ",
    # Privilege escalation
    "sudo ",
    "sudo",
    "su ",
    "su:",
    "chmod 4755",
    "setuid",
    # Device access
    "mount",
    "insmod",
    "modprobe",
    # Shell chaining
)

# Trusted paths for balanced mode
DEFAULT_TRUSTED_PATHS: tuple[str, ...] = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
)

# Strict mode allowlist (empty by default — admin must populate)
STRICT_DEFAULT_COMMANDS: tuple[str, ...] = ()

# SSH options that consume the next token as their value.
SSH_OPTS_WITH_VALUE: frozenset[str] = frozenset(
    {
        "-B",
        "-b",
        "-c",
        "-D",
        "-E",
        "-F",
        "-I",
        "-i",
        "-J",
        "-L",
        "-l",
        "-m",
        "-O",
        "-o",
        "-P",
        "-p",
        "-R",
        "-S",
        "-W",
        "-e",
        "-s",
    }
)


def _load_default_policy() -> CommandPolicy:
    """Load the default command policy (balanced preset)."""
    return CommandPolicy(
        preset="balanced",
        allowed_commands=frozenset(STRICT_DEFAULT_COMMANDS),
        trusted_paths=frozenset(DEFAULT_TRUSTED_PATHS),
        dangerous_patterns=frozenset(DEFAULT_DANGEROUS_PATTERNS),
        match_word_boundaries=True,
    )


@dataclass
class CommandValidator:
    """Validates commands against the current policy."""

    policy: CommandPolicy = field(default_factory=_load_default_policy)
    custom_patterns: frozenset[str] = frozenset()

    def validate(self, command: str) -> tuple[bool, str]:
        """Validate a command against the current policy.

        Args:
            command: The command string to validate.

        Returns:
            (is_valid, reason) — reason is empty if valid.
        """
        if not command or not command.strip():
            return False, "Empty command"

        # Strip --no-network flag from command for validation
        command = self._strip_flag(command, "--no-network")

        # Host-scoped validation: for ssh/sshpass remote-exec commands,
        # only the local (jump-host) portion is scanned for dangerous patterns.
        split = self._split_local_remote(command)
        local_part = split[0] if split else command

        # Check dangerous patterns first (applies to all presets)
        matched, reason = self._matches_dangerous_pattern(local_part)
        if matched:
            return False, reason

        # Check custom patterns
        matched, reason = self._matches_custom_pattern(local_part)
        if matched:
            return False, reason

        # Preset-specific checks
        if self.policy.preset == "strict":
            return self._validate_strict(command)
        elif self.policy.preset == "balanced":
            return self._validate_balanced(command)
        elif self.policy.preset == "permissive":
            return True, ""
        else:
            return False, f"Unknown preset: {self.policy.preset!r}"

    def _strip_flag(self, command: str, flag: str) -> str:
        """Remove a flag from the command string.

        Args:
            command: The full command string.
            flag: The flag to remove (e.g., '--no-network').

        Returns:
            Command string with the flag removed.
        """
        import re

        # Remove the flag and any trailing whitespace
        pattern = rf"\s*{re.escape(flag)}\s*"
        return re.sub(pattern, " ", command).strip()

    def _split_local_remote(self, command: str) -> tuple[str, str] | None:
        """Split an ssh/sshpass command into (local_part, remote_part).

        Returns None if the command is not an ssh/sshpass remote-exec command.
        The local part contains everything that runs on the jump host.
        The remote part contains the command that runs on the target host.

        D3: local_part is a token-rejoin, not an original string slice.
        Equivalent under word-boundary matching (production default).
        """
        try:
            tokens = shlex.split(command)
        except ValueError:
            return None  # D2: fail-closed, flat matcher applies

        if not tokens:
            return None

        first = os.path.basename(tokens[0])
        if first == "ssh":
            ssh_idx: int = 0
        elif first == "sshpass":
            found: int | None = None
            for i in range(1, len(tokens)):
                if os.path.basename(tokens[i]) == "ssh":
                    found = i
                    break
            if found is None:
                return None
            ssh_idx = found
        else:
            return None  # D1: gate on first token

        # Find destination (first non-option arg to ssh)
        dest_idx = None
        i = ssh_idx + 1
        while i < len(tokens):
            token = tokens[i]
            if token in SSH_OPTS_WITH_VALUE:
                i += 2  # skip flag + value
            elif token.startswith("-"):
                i += 1  # boolean flag, --, or concatenated form
            else:
                dest_idx = i
                break

        if dest_idx is None:
            return None

        local_part = " ".join(tokens[: dest_idx + 1])
        remote_part = " ".join(tokens[dest_idx + 1 :])
        return local_part, remote_part

    def _parse_allow_hosts(self, command: str) -> list[dict[str, Any]]:
        """Parse --allow-host flags from the command string.

        Args:
            command: The command string (may contain --allow-host flags).

        Returns:
            List of {host, port} dicts parsed from --allow-host flags.
        """
        import re

        allowed_hosts: list[dict[str, Any]] = []
        pattern = r"--allow-host\s+(\S+)"

        for match in re.finditer(pattern, command):
            host_port = match.group(1)
            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                try:
                    port = int(port_str)
                    allowed_hosts.append({"host": host, "port": port})
                except ValueError:
                    pass  # Invalid port, skip
            else:
                # No port specified, default to all ports
                allowed_hosts.append({"host": host_port, "port": 0})

        return allowed_hosts

    def _matches_dangerous_pattern(self, command: str) -> tuple[bool, str]:
        """Check if command matches any dangerous pattern.

        Args:
            command: The command string to check.

        Returns:
            (is_match, reason) — reason is empty if no match.
        """
        import re

        for pattern in self.policy.dangerous_patterns:
            stripped = pattern.strip()
            if self.policy.match_word_boundaries:
                regex = r"\b" + re.escape(stripped) + r"\b"
                if re.search(regex, command):
                    return True, f"Dangerous pattern blocked: {pattern!r}"
            else:
                if stripped in command:
                    return True, f"Dangerous pattern blocked: {pattern!r}"
        return False, ""

    def _matches_custom_pattern(self, command: str) -> tuple[bool, str]:
        """Check if command matches any custom pattern.

        Args:
            command: The command string to check.

        Returns:
            (is_match, reason) — reason is empty if no match.
        """
        import re

        for pattern in self.custom_patterns:
            if self.policy.match_word_boundaries:
                regex = r"\b" + re.escape(pattern) + r"\b"
                if re.search(regex, command):
                    return True, f"Custom pattern blocked: {pattern!r}"
            else:
                if pattern in command:
                    return True, f"Custom pattern blocked: {pattern!r}"
        return False, ""

    def _validate_strict(self, command: str) -> tuple[bool, str]:
        """Strict mode: only explicitly allowed commands."""
        cmd_path = self._extract_command_path(command)
        if not cmd_path:
            return False, "Cannot extract command path"
        if cmd_path not in self.policy.allowed_commands:
            return False, f"Command not in allowlist: {cmd_path!r}"
        return True, ""

    def _validate_balanced(self, command: str) -> tuple[bool, str]:
        """Balanced mode: trusted paths + dangerous pattern blocking."""
        cmd_path = self._extract_command_path(command)
        if not cmd_path:
            return False, "Cannot extract command path"
        for trusted_path in self.policy.trusted_paths:
            if cmd_path.startswith(trusted_path):
                return True, ""
        return False, f"Command not in trusted paths: {cmd_path!r}"

    def _extract_command_path(self, command: str) -> str:
        """Extract the base command path from a command string."""
        # Strip leading sudo/su if present
        cmd = command.strip()
        for prefix in ("sudo ", "su "):
            cmd = cmd.removeprefix(prefix)

        # Get the first word (command)
        first_word = cmd.split()[0] if cmd.split() else cmd

        # If it's an absolute path, normalize (handles ".": "/usr/bin/./ls" -> "/usr/bin/ls")
        if first_word.startswith("/"):
            return os.path.normpath(first_word)

        # Otherwise, resolve via PATH (e.g., "ls" -> "/usr/bin/ls")
        resolved = shutil.which(first_word)
        return resolved if resolved else first_word

    def update_policy(self, policy: CommandPolicy) -> None:
        """Update the current command policy.

        Args:
            policy: New command policy.
        """
        self.policy = policy

    def add_custom_pattern(self, pattern: str) -> None:
        """Add a custom dangerous pattern.

        Args:
            pattern: Pattern to block.
        """
        self.custom_patterns = frozenset(self.custom_patterns) | {pattern}

    def remove_custom_pattern(self, pattern: str) -> None:
        """Remove a custom dangerous pattern.

        Args:
            pattern: Pattern to unblock.
        """
        self.custom_patterns = frozenset(self.custom_patterns - {pattern})


def make_strict_policy(allowed_commands: list[str] | None = None) -> CommandPolicy:
    """Create a strict mode policy.

    Args:
        allowed_commands: Explicit allowlist of command paths.

    Returns:
        CommandPolicy in strict mode.
    """
    return CommandPolicy(
        preset="strict",
        allowed_commands=frozenset(allowed_commands or STRICT_DEFAULT_COMMANDS),
        trusted_paths=frozenset(),
        dangerous_patterns=frozenset(DEFAULT_DANGEROUS_PATTERNS),
        match_word_boundaries=True,
    )


def make_balanced_policy() -> CommandPolicy:
    """Create a balanced mode policy.

    Returns:
        CommandPolicy in balanced mode.
    """
    return CommandPolicy(
        preset="balanced",
        allowed_commands=frozenset(),
        trusted_paths=frozenset(DEFAULT_TRUSTED_PATHS),
        dangerous_patterns=frozenset(DEFAULT_DANGEROUS_PATTERNS),
        match_word_boundaries=True,
    )


def make_permissive_policy() -> CommandPolicy:
    """Create a permissive mode policy.

    Returns:
        CommandPolicy in permissive mode.
    """
    return CommandPolicy(
        preset="permissive",
        allowed_commands=frozenset(),
        trusted_paths=frozenset(),
        dangerous_patterns=frozenset(DEFAULT_DANGEROUS_PATTERNS),
        match_word_boundaries=True,
    )
