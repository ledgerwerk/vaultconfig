from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from .api import SecretStore
from .crypto import decrypt_v2, encode_passphrase, encrypt_v2
from .envelope import MAX_SECRET_NAME_LENGTH
from .errors import (
    VaultConflictError,
    VaultFormatError,
    VaultLockedError,
    VaultUnlockError,
)
from .fileio import (
    read_vault_file,
    vault_file_exists,
    vault_lock,
    vault_path,
    write_vault_file,
)


class FileVault:
    def __init__(self, path: str | Path) -> None:
        self.path = vault_path(path)

    def __repr__(self) -> str:
        return f"FileVault(path={str(self.path)!r})"

    def initialize(self, passphrase: str) -> None:
        password_bytes = encode_passphrase(passphrase, require_strength=True)
        with vault_lock(self.path):
            if vault_file_exists(self.path):
                raise VaultConflictError("vault file already exists")
            data = encrypt_v2({}, password_bytes)
            write_vault_file(self.path, data, overwrite=False)

    @contextmanager
    def open(self, passphrase: str) -> Iterator[SecretStore]:
        password_bytes = encode_passphrase(passphrase, require_strength=False)
        if not password_bytes:
            raise VaultUnlockError("vault could not be unlocked")
        try:
            data = read_vault_file(self.path)
        except FileNotFoundError:
            raise VaultFormatError("vault file does not exist") from None
        secrets = decrypt_v2(data, password_bytes)
        store = _UnlockedFileVault(
            path=self.path,
            passphrase=password_bytes,
            secrets=secrets,
            revision=hashlib.sha256(data).digest(),
        )
        try:
            yield store
        finally:
            store.close()

    def change_passphrase(self, old_passphrase: str, new_passphrase: str) -> None:
        new_password = encode_passphrase(new_passphrase, require_strength=True)
        with self.open(old_passphrase) as store:
            cast(_UnlockedFileVault, store)._change_passphrase(new_password)


class _UnlockedFileVault:
    __slots__ = ("_closed", "_passphrase", "_path", "_revision", "_secrets")

    def __init__(
        self,
        *,
        path: Path,
        passphrase: bytes,
        secrets: dict[str, str],
        revision: bytes,
    ) -> None:
        self._path = path
        self._passphrase: bytes | None = passphrase
        self._secrets: dict[str, str] | None = secrets
        self._revision = revision
        self._closed = False

    def __repr__(self) -> str:
        return "<UnlockedFileVault>"

    def get_secret(self, name: str) -> str | None:
        self._ensure_open()
        self._validate_name(name)
        assert self._secrets is not None
        return self._secrets.get(name)

    def set_secret(self, name: str, value: str) -> None:
        self._ensure_open()
        self._validate_name(name)
        if not isinstance(value, str):
            raise VaultFormatError("secret values must be strings")
        assert self._secrets is not None
        updated = dict(self._secrets)
        updated[name] = value
        self._commit(updated)

    def delete_secret(self, name: str) -> bool:
        self._ensure_open()
        self._validate_name(name)
        assert self._secrets is not None
        if name not in self._secrets:
            return False
        updated = dict(self._secrets)
        del updated[name]
        self._commit(updated)
        return True

    def close(self) -> None:
        if self._secrets is not None:
            self._secrets.clear()
        self._secrets = None
        self._passphrase = None
        self._revision = b""
        self._closed = True

    def _change_passphrase(self, new_passphrase: bytes) -> None:
        self._ensure_open()
        assert self._secrets is not None
        self._commit(dict(self._secrets), passphrase=new_passphrase)

    def _commit(
        self,
        secrets: dict[str, str],
        *,
        passphrase: bytes | None = None,
    ) -> None:
        self._ensure_open()
        assert self._passphrase is not None
        next_passphrase = self._passphrase if passphrase is None else passphrase
        with vault_lock(self._path):
            current = read_vault_file(self._path)
            if hashlib.sha256(current).digest() != self._revision:
                raise VaultConflictError("vault changed during this unlocked session")
            data = encrypt_v2(secrets, next_passphrase)
            write_vault_file(self._path, data, overwrite=True)
        self._secrets = secrets
        self._revision = hashlib.sha256(data).digest()
        self._passphrase = next_passphrase

    def _ensure_open(self) -> None:
        if self._closed or self._secrets is None or self._passphrase is None:
            raise VaultLockedError("file vault session is closed")

    @staticmethod
    def _validate_name(name: str) -> None:
        if not isinstance(name, str) or not name or len(name) > MAX_SECRET_NAME_LENGTH:
            raise VaultFormatError("invalid secret name")
