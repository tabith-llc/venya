"""Command whitelist and dangerous pattern blocking.

Enforces an allowlist of permitted commands on the jump host.
Policy is configurable at initialization and changeable by an admin.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CommandPolicy:
    """Immutable command execution policy."""

    preset: str  # strict | balanced | permissive
    allowed_commands: frozenset[str]  # explicit allowlist (strict mode)
    trusted_paths: frozenset[str]  # trusted directories (balanced mode)
    dangerous_patterns: frozenset[str]  # blocked patterns (all modes)


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
            if cmd.startswith(prefix):
                cmd = cmd[len(prefix):]

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
