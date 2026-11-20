class VaultError(Exception):
    """Base class for secret-storage failures."""


class VaultPassphrasePolicyError(VaultError):
    """Raised when a new passphrase violates its length policy.

    ``reason`` is either ``"too-short"`` or ``"too-large"``. Policy errors
    never retain or display the submitted passphrase.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        minimum_length: int | None = None,
        maximum_bytes: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.minimum_length = minimum_length
        self.maximum_bytes = maximum_bytes


class VaultLockedError(VaultError):
    """Raised when a locked file vault is used."""


class SecretNotFoundError(VaultError):
    """Optional convenience error for missing secrets."""


class SecretStoreUnavailableError(VaultError):
    """Raised when a secret backend cannot be used securely."""


class VaultFormatError(VaultError):
    """Raised when a vault file is malformed or unsupported."""


class VaultUnlockError(VaultError):
    """Raised when a file vault cannot be authenticated or unlocked."""


class VaultPermissionError(VaultError):
    """Raised when vault filesystem permissions are unsafe."""


class VaultConflictError(VaultError):
    """Raised when a concurrent vault update would overwrite another change."""


class SecretExistsError(VaultError):
    """Raised when a create-only operation targets an existing secret."""
