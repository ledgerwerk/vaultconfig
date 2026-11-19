from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretStore(Protocol):
    def get_secret(self, name: str) -> str | None: ...

    def set_secret(self, name: str, value: str) -> None: ...

    def delete_secret(self, name: str) -> bool: ...
