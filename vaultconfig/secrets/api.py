from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class SecretBackendInfo:
    kind: str
    available: bool
    backend: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class FileVaultInfo:
    format: str
    entry_count: int
    kdf_name: str
    opslimit: int
    memlimit_bytes: int


@runtime_checkable
class SecretStore(Protocol):
    def get_secret(self, name: str) -> str | None: ...

    def set_secret(self, name: str, value: str) -> None: ...

    def delete_secret(self, name: str) -> bool: ...


@runtime_checkable
class CreateOnlySecretStore(SecretStore, Protocol):
    def create_secret(self, name: str, value: str) -> None: ...
