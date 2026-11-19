from __future__ import annotations

import importlib
from types import ModuleType, SimpleNamespace

import pytest

from vaultconfig.secrets import (
    KeyringVault,
    SecretStore,
    SecretStoreUnavailableError,
    VaultError,
    VaultFormatError,
    keyring_store,
)


class FakeBackend:
    priority = 1


FakeBackend.__module__ = "keyring.backends.SecretService"


class FakeKeyring:
    def __init__(self, backend: object | None = None) -> None:
        self.backend = FakeBackend() if backend is None else backend
        self.values: dict[tuple[str, str], str] = {}
        self.get_error: Exception | None = None
        self.set_error: Exception | None = None
        self.delete_error: Exception | None = None
        self.calls: list[tuple[str, str]] = []

    def get_keyring(self) -> object:
        return self.backend

    def get_password(self, service: str, name: str) -> str | None:
        self.calls.append(("get", service))
        if self.get_error is not None:
            raise self.get_error
        return self.values.get((service, name))

    def set_password(self, service: str, name: str, value: str) -> None:
        self.calls.append(("set", service))
        if self.set_error is not None:
            raise self.set_error
        self.values[(service, name)] = value

    def delete_password(self, service: str, name: str) -> None:
        self.calls.append(("delete", service))
        if self.delete_error is not None:
            raise self.delete_error
        del self.values[(service, name)]


def install_keyring(monkeypatch: pytest.MonkeyPatch, fake: FakeKeyring) -> None:
    module = SimpleNamespace(
        get_keyring=fake.get_keyring,
        get_password=fake.get_password,
        set_password=fake.set_password,
        delete_password=fake.delete_password,
    )
    monkeypatch.setattr(
        keyring_store.KeyringVault,
        "_load_keyring",
        staticmethod(lambda: module),
    )


def test_keyring_missing_get_set_delete_and_service_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeKeyring()
    install_keyring(monkeypatch, fake)
    first = KeyringVault("imapledger:mail.example.net:993")
    second = KeyringVault("imapledger:other.example.net:993")
    assert isinstance(first, SecretStore)

    assert first.get_secret("alice") is None
    assert first.delete_secret("alice") is False
    first.set_secret("alice", "first-secret")
    assert first.get_secret("alice") == "first-secret"
    assert second.get_secret("alice") is None
    assert first.backend_info() == {
        "type": "keyring",
        "backend": "keyring.backends.SecretService.FakeBackend",
    }
    assert "first-secret" not in repr(first)

    assert first.delete_secret("alice") is True
    assert first.get_secret("alice") is None


def test_keyring_rejects_unacceptable_and_unavailable_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FileBackend:
        priority = 1

    FileBackend.__module__ = "keyrings.alt.file"
    fake = FakeKeyring(FileBackend())
    install_keyring(monkeypatch, fake)

    with pytest.raises(SecretStoreUnavailableError, match="not an accepted"):
        KeyringVault("service").set_secret("alice", "secret")
    assert fake.calls == []

    class DisabledBackend:
        priority = 0

    DisabledBackend.__module__ = "keyring.backends.SecretService"
    fake.backend = DisabledBackend()
    with pytest.raises(SecretStoreUnavailableError, match="not an accepted"):
        KeyringVault("service").get_secret("alice")
    assert fake.calls == []


def test_keyring_backend_failures_are_typed_and_do_not_expose_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeKeyring()
    install_keyring(monkeypatch, fake)
    fake.set_error = RuntimeError("secret value leaked by backend")

    with pytest.raises(SecretStoreUnavailableError) as error:
        KeyringVault("service").set_secret("alice", "secret value")

    assert "secret value" not in str(error.value)
    assert error.value.__cause__ is None


def test_missing_optional_keyring_dependency_is_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import_module = importlib.import_module

    def import_without_keyring(name: str, package: str | None = None) -> ModuleType:
        if name == "keyring":
            raise ImportError("simulated missing optional dependency")
        return original_import_module(name, package)

    monkeypatch.setattr(
        keyring_store.importlib,
        "import_module",
        import_without_keyring,
    )
    with pytest.raises(SecretStoreUnavailableError, match="not installed"):
        KeyringVault("service").get_secret("alice")


def test_keyring_validates_service_name_and_secret_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(VaultError, match="service"):
        KeyringVault(" ")

    fake = FakeKeyring()
    install_keyring(monkeypatch, fake)
    store = KeyringVault("service")
    with pytest.raises(VaultFormatError, match="secret name"):
        store.get_secret("")
    with pytest.raises(VaultFormatError, match="secret values"):
        store.set_secret("alice", 1)  # type: ignore[arg-type]
