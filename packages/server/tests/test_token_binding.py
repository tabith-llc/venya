"""Tests for token binding utility."""

import hashlib
import hmac as hmac_module

import pytest

from server.utils.token_binding import (
    compute_binding_hash,
    derive_binding_key,
    verify_binding_hash,
)


class TestDeriveBindingKey:
    """Tests for HKDF key derivation."""

    def test_derive_returns_32_bytes(self):
        """Derived key is 32 bytes (256 bits)."""
        key = derive_binding_key("test-secret")
        assert len(key) == 32

    def test_derive_deterministic(self):
        """Same secret produces same key."""
        key1 = derive_binding_key("my-secret")
        key2 = derive_binding_key("my-secret")
        assert key1 == key2

    def test_derive_different_secrets(self):
        """Different secrets produce different keys."""
        key1 = derive_binding_key("secret-one")
        key2 = derive_binding_key("secret-two")
        assert key1 != key2

    def test_derive_different_info(self):
        """Derived key is domain-separated (different from raw pepper hash)."""
        key = derive_binding_key("test-secret")
        # The derived key should NOT be a simple hash of the secret
        assert key != hashlib.sha256(b"test-secret").digest()


class TestComputeBindingHash:
    """Tests for HMAC binding hash computation."""

    def test_deterministic(self):
        """Same inputs produce same hash."""
        h1 = compute_binding_hash("exec-1", "token-abc", "secret")
        h2 = compute_binding_hash("exec-1", "token-abc", "secret")
        assert h1 == h2
        assert len(h1) == 64

    def test_differs_for_different_entity_ids(self):
        """Changing entity_id changes the binding hash."""
        h1 = compute_binding_hash("exec-1", "token-abc", "secret")
        h2 = compute_binding_hash("exec-2", "token-abc", "secret")
        assert h1 != h2

    def test_differs_for_different_tokens(self):
        """Changing plaintext_token changes the binding hash."""
        h1 = compute_binding_hash("exec-1", "token-abc", "secret")
        h2 = compute_binding_hash("exec-1", "token-def", "secret")
        assert h1 != h2

    def test_differs_for_different_secrets(self):
        """Changing server_secret changes the binding hash."""
        h1 = compute_binding_hash("exec-1", "token-abc", "secret-a")
        h2 = compute_binding_hash("exec-1", "token-abc", "secret-b")
        assert h1 != h2

    def test_returns_hex_string(self):
        """Binding hash is a 64-char hex string."""
        h = compute_binding_hash("exec-1", "token-abc", "secret")
        assert len(h) == 64
        int(h, 16)  # Should not raise — valid hex


class TestVerifyBindingHash:
    """Tests for binding hash verification."""

    def test_verify_matches(self):
        """Correct binding returns True."""
        binding = compute_binding_hash("exec-1", "token-abc", "secret")
        assert verify_binding_hash("exec-1", "token-abc", "secret", binding) is True

    def test_verify_mismatch_entity_id(self):
        """Wrong entity_id returns False."""
        binding = compute_binding_hash("exec-1", "token-abc", "secret")
        assert verify_binding_hash("exec-2", "token-abc", "secret", binding) is False

    def test_verify_mismatch_token(self):
        """Wrong plaintext_token returns False."""
        binding = compute_binding_hash("exec-1", "token-abc", "secret")
        assert verify_binding_hash("exec-1", "token-def", "secret", binding) is False

    def test_verify_mismatch_secret(self):
        """Wrong server_secret returns False."""
        binding = compute_binding_hash("exec-1", "token-abc", "secret-a")
        assert verify_binding_hash("exec-1", "token-abc", "secret-b", binding) is False

    def test_verify_none_stored_returns_false(self):
        """None stored_binding_hash returns False (no legacy fallback)."""
        assert verify_binding_hash("exec-1", "token-abc", "secret", None) is False

    def test_verify_empty_stored_returns_false(self):
        """Empty string stored_binding_hash returns False (no legacy fallback)."""
        assert verify_binding_hash("exec-1", "token-abc", "secret", "") is False

    def test_constant_time_comparison_used(self):
        """verify_binding_hash uses hmac.compare_digest for constant-time comparison."""
        import server.utils.token_binding as module

        with pytest.MonkeyPatch.context() as mp:
            called = []

            def mock_compare_digest(a, b):
                called.append((a, b))
                return a == b

            mp.setattr(hmac_module, "compare_digest", mock_compare_digest)

            # Re-import to get patched version
            import importlib
            importlib.reload(module)

            binding = module.compute_binding_hash("exec-1", "token-abc", "secret")
            module.verify_binding_hash("exec-1", "token-abc", "secret", binding)

            assert len(called) == 1
