# Copyright (c) 2026 Tabith LLC.
# Use of this source code is governed by the Business Source License 1.1
# included in the LICENSE file at the root of this repository. As of the
# Change Date listed there, the work is available under MPL 2.0.
# SPDX-License-Identifier: BUSL-1.1

"""CoreFactory: builder pattern for creating Core instances."""

from .backend import Backend, BackendConfig
from .core import Core
from .encryption import KEK_SIZE
from .rate_limiter import RateLimiter


class CoreFactoryError(Exception):
    """Factory error."""


class CoreFactory:
    """Factory for creating configured Core instances.

    Usage:
        core = CoreFactory.from_config(config).build()
    """

    def __init__(self, config: BackendConfig) -> None:
        self._config = config
        self._rate_limiter: RateLimiter | None = None

    @classmethod
    def from_config(cls, config: BackendConfig) -> CoreFactory:
        """Create a factory from a BackendConfig.

        Args:
            config: Backend configuration.

        Returns:
            Configured CoreFactory instance.
        """
        return cls(config)

    @classmethod
    def from_dict(cls, config_dict: dict) -> CoreFactory:
        """Create a factory from a dictionary configuration.

        Args:
            config_dict: Configuration dict with keys:
                - database_url: PostgreSQL connection URL
                - passphrase: Master passphrase (bytes or string)
                - wal_mode: Enable WAL mode (default True)

        Returns:
            Configured CoreFactory instance.
        """
        database_url = config_dict.get("database_url")
        if database_url is None:
            raise CoreFactoryError("config_dict missing required key: 'database_url'")
        passphrase = config_dict.get("passphrase")
        if isinstance(passphrase, str):
            passphrase = passphrase.encode("utf-8")

        config = BackendConfig(
            database_url=database_url,
            passphrase=passphrase,
            wal_mode=config_dict.get("wal_mode", True),
        )
        return cls(config)

    def with_rate_limiter(self, max_attempts: int = 5, window_seconds: int = 300) -> CoreFactory:
        """Set rate limiter parameters.

        Args:
            max_attempts: Maximum failed attempts before lockout.
            window_seconds: Time window for counting failures.

        Returns:
            self for chaining.
        """
        self._rate_limiter = RateLimiter(
            max_attempts=max_attempts,
            window_seconds=window_seconds,
        )
        return self

    def with_kek(self, kek: bytes) -> CoreFactory:
        """Set the KEK explicitly, through the config intake slot.

        The bytes go into ``BackendConfig.kek`` and are copied into the
        backend's KEK cache when ``build()`` constructs it; the factory keeps
        no key material of its own (#472).

        Args:
            kek: 32-byte Key Encryption Key.

        Returns:
            self for chaining.

        Raises:
            CoreFactoryError: If the KEK is not the required size.
        """
        if len(kek) != KEK_SIZE:
            raise CoreFactoryError(f"KEK must be {KEK_SIZE} bytes, got {len(kek)}")
        self._config.kek = kek
        return self

    def build(self) -> Core:
        """Build the Core instance.

        Returns:
            Configured Core instance.

        Raises:
            CoreFactoryError: If KEK is not available.
        """
        backend = Backend(self._config)
        # Backend() has already moved any raw intake into the cache and cleared
        # the intake slot. Resolve from the passphrase only when the cache is
        # still empty: bootstrap_kek() reads/creates the persisted salt (C-11)
        # and fills that one cache — it is the only derivation point.
        if not backend.kek_cache.is_populated:
            if self._config.passphrase is not None:
                backend.bootstrap_kek()
            else:
                raise CoreFactoryError(
                    "KEK not available: provide either a passphrase or call " "with_kek() before build()"
                )

        rate_limiter = self._rate_limiter or RateLimiter()

        return Core(
            backend=backend,
            rate_limiter=rate_limiter,
            kek=backend.kek_cache,
        )
