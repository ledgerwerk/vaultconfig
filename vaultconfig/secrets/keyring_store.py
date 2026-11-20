from __future__ import annotations

import importlib
from types import ModuleType

from .api import SecretBackendInfo
from .envelope import MAX_SECRET_NAME_LENGTH
from .errors import SecretStoreUnavailableError, VaultError, VaultFormatError

_ACCEPTABLE_BACKEND_MODULES = frozenset(
    {
        "keyring.backends.SecretService",
        "keyring.backends.kwallet",
        "keyring.backends.macOS",
        "keyring.backends.Windows",
    }
)


_BACKEND_NAMES = {
    "keyring.backends.SecretService": "SecretService",
    "keyring.backends.kwallet": "KWallet",
    "keyring.backends.macOS": "macOS",
    "keyring.backends.Windows": "Windows Vault",
}


class _KeyringUnavailable(SecretStoreUnavailableError):
    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class KeyringVault:
    """Store opaque string secrets in an explicitly accepted OS keyring."""

    __slots__ = ("service",)

    def __init__(self, service: str) -> None:
        if not isinstance(service, str) or not service.strip():
            raise VaultError("keyring service must be non-empty text")
        self.service = service

    def __repr__(self) -> str:
        return "KeyringVault(service=<configured>)"

    def backend_info(self) -> dict[str, str]:
        _, backend = self._checked_backend()
        backend_type = type(backend)
        return {
            "type": "keyring",
            "backend": f"{backend_type.__module__}.{backend_type.__qualname__}",
        }

    def probe(self) -> SecretBackendInfo:
        try:
            _, backend = self._checked_backend()
        except _KeyringUnavailable as error:
            return SecretBackendInfo(
                kind="keyring",
                available=False,
                reason=error.reason,
            )
        except SecretStoreUnavailableError:
            return SecretBackendInfo(
                kind="keyring",
                available=False,
                reason="backend-error",
            )

        return SecretBackendInfo(
            kind="keyring",
            available=True,
            backend=_BACKEND_NAMES[type(backend).__module__],
        )

    def get_secret(self, name: str) -> str | None:
        self._validate_name(name)
        keyring, _ = self._checked_backend()
        try:
            value = keyring.get_password(self.service, name)
        except Exception:  # noqa: BLE001
            raise SecretStoreUnavailableError(
                "OS keyring could not retrieve a secret"
            ) from None
        if value is None:
            return None
        if not isinstance(value, str):
            raise SecretStoreUnavailableError("OS keyring returned an invalid secret")
        return value

    def set_secret(self, name: str, value: str) -> None:
        self._validate_name(name)
        if not isinstance(value, str):
            raise VaultFormatError("secret values must be strings")
        keyring, _ = self._checked_backend()
        try:
            keyring.set_password(self.service, name, value)
        except Exception:  # noqa: BLE001
            raise SecretStoreUnavailableError(
                "OS keyring could not store a secret"
            ) from None

    def delete_secret(self, name: str) -> bool:
        self._validate_name(name)
        keyring, _ = self._checked_backend()
        try:
            keyring.delete_password(self.service, name)
        except Exception as error:  # noqa: BLE001
            error_type = type(error)
            if (
                error_type.__module__ == "keyring.errors"
                and error_type.__name__ == "PasswordDeleteError"
            ):
                return False
            raise SecretStoreUnavailableError(
                "OS keyring could not delete a secret"
            ) from None
        return True

    @staticmethod
    def _validate_name(name: str) -> None:
        if not isinstance(name, str) or not name or len(name) > MAX_SECRET_NAME_LENGTH:
            raise VaultFormatError("invalid secret name")

    @staticmethod
    def _load_keyring() -> ModuleType:
        try:
            return importlib.import_module("keyring")
        except ImportError:
            raise _KeyringUnavailable(
                "optional keyring support is not installed",
                "not-installed",
            ) from None
        except Exception:  # noqa: BLE001
            raise _KeyringUnavailable(
                "keyring support could not be initialized",
                "backend-error",
            ) from None

    def _checked_backend(self) -> tuple[ModuleType, object]:
        keyring = self._load_keyring()
        try:
            backend = keyring.get_keyring()
            if backend is None:
                raise _KeyringUnavailable(
                    "OS keyring backend is unavailable",
                    "no-backend",
                )
            priority = backend.priority
        except _KeyringUnavailable:
            raise
        except Exception:  # noqa: BLE001
            raise _KeyringUnavailable(
                "OS keyring backend is unavailable",
                "backend-locked",
            ) from None

        if isinstance(priority, (int, float)) and priority <= 0:
            reason = (
                "backend-locked"
                if type(backend).__module__ in _ACCEPTABLE_BACKEND_MODULES
                else "no-backend"
            )
            raise _KeyringUnavailable(
                "configured keyring backend is not an accepted OS keyring",
                reason,
            )
        is_supported_backend = type(backend).__module__ in _ACCEPTABLE_BACKEND_MODULES
        if not is_supported_backend or not isinstance(priority, (int, float)):
            raise _KeyringUnavailable(
                "configured keyring backend is not an accepted OS keyring",
                "backend-rejected",
            )
        return keyring, backend
