class VaultError(Exception):
    """Base class for secret-storage failures."""


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
