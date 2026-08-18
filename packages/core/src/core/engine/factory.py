"""CoreFactory: builder pattern for creating Core instances."""


from pathlib import Path

from .backend import Backend, BackendConfig
from .rate_limiter import RateLimiter
from .core import Core


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
        self._kek: bytes | None = None

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
        database_url = config_dict["database_url"]
        passphrase = config_dict.get("passphrase")
        if isinstance(passphrase, str):
            passphrase = passphrase.encode("utf-8")

        config = BackendConfig(
            database_url=database_url,
            passphrase=passphrase,
            wal_mode=config_dict.get("wal_mode", True),
        )
        return cls(config)

    def with_rate_limiter(
        self, max_attempts: int = 5, window_seconds: float = 300.0
    ) -> CoreFactory:
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
        """Set the KEK explicitly.

        Args:
            kek: 32-byte Key Encryption Key.

        Returns:
            self for chaining.
        """
        self._kek = kek
        return self

    def build(self) -> Core:
        """Build the Core instance.

        Returns:
            Configured Core instance.

        Raises:
            CoreFactoryError: If KEK is not available.
        """
        if self._kek is None:
            # Try to derive from config passphrase
            if self._config.passphrase is not None:
                from .encryption import derive_kek

                self._kek, _ = derive_kek(self._config.passphrase)
            else:
                raise CoreFactoryError(
                    "KEK not available: provide either a passphrase or call "
                    "with_kek() before build()"
                )

        backend = Backend(self._config)
        rate_limiter = self._rate_limiter or RateLimiter()

        return Core(
            backend=backend,
            rate_limiter=rate_limiter,
            kek=self._kek,
        )
