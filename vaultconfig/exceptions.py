"""Custom exceptions for vaultconfig."""

from __future__ import annotations


class VaultConfigError(Exception):
    """Base exception for all vaultconfig errors."""


class EncryptionError(VaultConfigError):
    """Raised when encryption fails."""


class DecryptionError(VaultConfigError):
    """Raised when decryption fails."""


class InvalidPasswordError(DecryptionError):
    """Raised when password is incorrect for decryption."""


class FormatError(VaultConfigError):
    """Raised when config format is invalid or unsupported."""


class SchemaValidationError(VaultConfigError):
    """Raised when config data fails schema validation."""


class ConfigNotFoundError(VaultConfigError):
    """Raised when requested config does not exist."""


class ConfigExistsError(VaultConfigError):
    """Raised when trying to create a config that already exists."""
