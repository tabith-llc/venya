"""Tests for the Stage 1 filter Python wrapper layer.

Tests build_filter_entries, filter_output, and filter_and_redact
functions that wrap the Rust venya_filter extension.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

try:
    from venya_filter import compute_detection_hashes as _compute_detection_hashes  # type: ignore
    from venya_filter import filter_output as _filter_output  # type: ignore
except ImportError:
    pytest.skip("venya_filter Rust extension not available", allow_module_level=True)

from executor.filter import build_filter_entries, filter_and_redact, filter_output


def _make_entries(secret_id: str, value: bytes) -> list[dict[str, Any]]:
    """Helper to create filter entries using the Rust extension."""
    hashes = _compute_detection_hashes(value)
    return [{"secret_id": secret_id, "hashes": hashes, "secret_value": value}]


# ---------------------------------------------------------------------------
# build_filter_entries
# ---------------------------------------------------------------------------


class TestBuildFilterEntries:
    """Tests for build_filter_entries()."""

    def test_build_entries_auto_computes_hashes(self):
        """Entries without pre-computed hashes get hashes from Rust extension."""
        secrets = [{"secret_id": "s1", "value": b"test-secret-value"}]
        entries = build_filter_entries(secrets)

        assert len(entries) == 1
        assert entries[0]["secret_id"] == "s1"
        assert "hashes" in entries[0]
        assert len(entries[0]["hashes"]) == 3  # raw, b64, hex (no whitespace)
        assert entries[0]["secret_value"] == b"test-secret-value"

    def test_build_entries_uses_pre_computed_hashes(self):
        """Entries with pre-computed hashes use them directly."""
        hashes = ["abc123", "def456", "ghi789"]
        secrets = [{"secret_id": "s1", "value": b"data", "hashes": hashes}]
        entries = build_filter_entries(secrets)

        assert entries[0]["hashes"] == hashes

    def test_build_entries_multiple_secrets(self):
        """Handles multiple secrets correctly."""
        secrets = [
            {"secret_id": "s1", "value": b"secret-one"},
            {"secret_id": "s2", "value": b"secret-two"},
            {"secret_id": "s3", "value": b"secret-three"},
        ]
        entries = build_filter_entries(secrets)

        assert len(entries) == 3
        assert entries[0]["secret_id"] == "s1"
        assert entries[1]["secret_id"] == "s2"
        assert entries[2]["secret_id"] == "s3"

    def test_build_entries_empty_list(self):
        """Empty input returns empty output."""
        entries = build_filter_entries([])
        assert entries == []

    def test_build_entries_with_whitespace_value(self):
        """Values with whitespace get 4 hashes (trimmed variant included)."""
        secrets = [{"secret_id": "s1", "value": b"  padded  "}]
        entries = build_filter_entries(secrets)

        assert len(entries[0]["hashes"]) == 4

    def test_build_entries_preserves_order(self):
        """Entry order matches input order."""
        secrets = [
            {"secret_id": "first", "value": b"1"},
            {"secret_id": "second", "value": b"2"},
            {"secret_id": "third", "value": b"3"},
        ]
        entries = build_filter_entries(secrets)
        assert [e["secret_id"] for e in entries] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# filter_output (Python wrapper)
# ---------------------------------------------------------------------------


class TestFilterOutput:
    """Tests for filter_output() Python wrapper."""

    def test_empty_entries_passthrough(self):
        """Empty entries returns data unchanged."""
        data = b"no secrets here"
        masked, masked_ids = filter_output(data, [])
        assert masked == data
        assert masked_ids == []

    def test_wraps_rust_filter_output(self):
        """Properly delegates to Rust extension."""
        secret = b"wrapper-test-secret"
        entries = _make_entries("wrapped", secret)
        data = f"Output with {secret.decode()} in it".encode()

        masked, masked_ids = filter_output(data, entries)

        assert secret not in masked
        assert "wrapped" in masked_ids

    def test_empty_data(self):
        """Empty data returns empty."""
        masked, masked_ids = filter_output(b"", [])
        assert masked == b""
        assert masked_ids == []

    def test_window_size_parameter_passthrough(self):
        """Window size parameter is accepted (even if unused)."""
        data = b"clean output"
        masked, _ = filter_output(data, [], _window_size=30)
        assert masked == data

    def test_min_match_length_parameter_passthrough(self):
        """Min match length parameter is accepted (even if unused)."""
        data = b"clean output"
        masked, _ = filter_output(data, [], _min_match_length=16)
        assert masked == data


# ---------------------------------------------------------------------------
# filter_and_redact
# ---------------------------------------------------------------------------


class TestFilterAndRedact:
    """Tests for filter_and_redact()."""

    def test_filters_both_stdout_and_stderr(self):
        """Both stdout and stderr are filtered."""
        stdout_secret = b"stdout-secret"
        stderr_secret = b"stderr-secret"
        secrets = [
            {"secret_id": "s1", "value": stdout_secret},
            {"secret_id": "s2", "value": stderr_secret},
        ]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"stdout with " + stdout_secret,
            b"stderr with " + stderr_secret,
            secrets,
        )

        assert stdout_secret not in masked_stdout
        assert stderr_secret not in masked_stderr
        assert "s1" in stdout_ids
        assert "s2" in stderr_ids

    def test_clean_output_passthrough(self):
        """Clean output passes through unchanged."""
        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"clean stdout",
            b"clean stderr",
            [{"secret_id": "s1", "value": b"not-in-output"}],
        )

        assert masked_stdout == b"clean stdout"
        assert masked_stderr == b"clean stderr"
        assert stdout_ids == []
        assert stderr_ids == []

    def test_empty_both_streams(self):
        """Empty streams return empty."""
        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"", b"", []
        )

        assert masked_stdout == b""
        assert masked_stderr == b""
        assert stdout_ids == []
        assert stderr_ids == []

    def test_only_stdout_has_secret(self):
        """Only stdout is masked when secret only appears there."""
        secret = b"only-in-stdout"
        secrets = [{"secret_id": "s1", "value": secret}]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"output " + secret,
            b"clean stderr",
            secrets,
        )

        assert secret not in masked_stdout
        assert masked_stderr == b"clean stderr"
        assert "s1" in stdout_ids
        assert stderr_ids == []

    def test_only_stderr_has_secret(self):
        """Only stderr is masked when secret only appears there."""
        secret = b"only-in-stderr"
        secrets = [{"secret_id": "s1", "value": secret}]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"clean stdout",
            b"error " + secret,
            secrets,
        )

        assert masked_stdout == b"clean stdout"
        assert secret not in masked_stderr
        assert stdout_ids == []
        assert "s1" in stderr_ids

    def test_shared_secret_both_streams(self):
        """Same secret in both streams is masked in both."""
        secret = b"shared-secret"
        secrets = [{"secret_id": "shared", "value": secret}]

        masked_stdout, masked_stderr, stdout_ids, stderr_ids = filter_and_redact(
            b"stdout " + secret,
            b"stderr " + secret,
            secrets,
        )

        assert secret not in masked_stdout
        assert secret not in masked_stderr
        assert "shared" in stdout_ids
        assert "shared" in stderr_ids

    def test_pre_computed_hashes_used(self):
        """Uses pre-computed hashes from secret dicts."""
        secret = b"precomputed-test"
        hashes = _compute_detection_hashes(secret)
        secrets = [{"secret_id": "s1", "value": secret, "hashes": hashes}]

        masked_stdout, _, stdout_ids, _ = filter_and_redact(
            b"output " + secret,
            b"",
            secrets,
        )

        assert secret not in masked_stdout
        assert "s1" in stdout_ids
