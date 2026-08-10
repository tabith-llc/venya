"""Command whitelist and dangerous pattern blocking.

Enforces an allowlist of permitted commands on the jump host.
Policy is configurable at initialization and changeable by an admin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CommandPolicy:
    """Immutable command execution policy."""

    preset: str  # strict | balanced | permissive
    allowed_commands: frozenset[str]  # explicit allowlist (strict mode)
    trusted_paths: frozenset[str]  # trusted directories (balanced mode)
    dangerous_patterns: frozenset[str]  # blocked patterns (all modes)
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


def _load_default_policy() -> CommandPolicy:
    """Load the default command policy (balanced preset)."""
    return CommandPolicy(
        preset="balanced",
        allowed_commands=frozenset(STRICT_DEFAULT_COMMANDS),
        trusted_paths=frozenset(DEFAULT_TRUSTED_PATHS),
        dangerous_patterns=frozenset(DEFAULT_DANGEROUS_PATTERNS),
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

        # Extract and validate --allow-host flags
        allowed_hosts = self._parse_allow_hosts(command)

        # Check dangerous patterns first (applies to all presets)
        for pattern in self.policy.dangerous_patterns:
            if pattern in command:
                return False, f"Dangerous pattern blocked: {pattern!r}"

        # Check custom patterns
        for pattern in self.custom_patterns:
            if pattern in command:
                return False, f"Custom pattern blocked: {pattern!r}"

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
        pattern = rf'\s*{re.escape(flag)}\s*'
        return re.sub(pattern, ' ', command).strip()

    def _parse_allow_hosts(self, command: str) -> list[dict[str, Any]]:
        """Parse --allow-host flags from the command string.

        Args:
            command: The command string (may contain --allow-host flags).

        Returns:
            List of {host, port} dicts parsed from --allow-host flags.
        """
        import re

        allowed_hosts: list[dict[str, Any]] = []
        pattern = r'--allow-host\s+(\S+)'

        for match in re.finditer(pattern, command):
            host_port = match.group(1)
            if ':' in host_port:
                host, port_str = host_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                    allowed_hosts.append({"host": host, "port": port})
                except ValueError:
                    pass  # Invalid port, skip
            else:
                # No port specified, default to all ports
                allowed_hosts.append({"host": host_port, "port": 0})

        return allowed_hosts

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

        # If it's an absolute path, return it
        if first_word.startswith("/"):
            return first_word

        # Otherwise, try to resolve via PATH-like logic
        # For now, just return the command name
        return first_word

    def update_policy(self, policy: CommandPolicy) -> None:
        """Update the current command policy.

        Args:
            policy: New command policy.
        """
        object.__setattr__(self, "policy", policy)

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
    )
