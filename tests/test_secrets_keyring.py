from __future__ import annotations

import importlib
from types import ModuleType, SimpleNamespace

import pytest

from vaultconfig.secrets import (
    KeyringVault,
    SecretBackendInfo,
    SecretStore,
    SecretStoreUnavailableError,
    VaultError,
    VaultFormatError,
    keyring_store,
)


class FakeBackend:
    priority = 1


FakeBackend.__module__ = "keyring.backends.SecretService"


class PasswordDeleteError(Exception):
    pass


PasswordDeleteError.__module__ = "keyring.errors"


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
        try:
            del self.values[(service, name)]
        except KeyError:
            raise PasswordDeleteError("secret not found") from None


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
    before = len(fake.calls)
    assert first.delete_secret("alice") is False
    assert fake.calls[before:] == [("delete", first.service)]
    first.set_secret("alice", "first-secret")
    assert first.get_secret("alice") == "first-secret"
    assert second.get_secret("alice") is None
    assert first.backend_info() == {
        "type": "keyring",
        "backend": "keyring.backends.SecretService.FakeBackend",
    }
    assert "first-secret" not in repr(first)

    before = len(fake.calls)
    assert first.delete_secret("alice") is True
    assert fake.calls[before:] == [("delete", first.service)]
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

    fake.get_error = RuntimeError("secret value leaked by backend")
    with pytest.raises(SecretStoreUnavailableError) as retrieval_error:
        KeyringVault("service").get_secret("alice")
    assert "secret value leaked by backend" not in str(retrieval_error.value)


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
    info = KeyringVault("service").probe()
    assert info.available is False
    assert info.reason == "not-installed"
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


@pytest.mark.parametrize(
    ("module", "backend_name"),
    [
        ("keyring.backends.SecretService", "SecretService"),
        ("keyring.backends.kwallet", "KWallet"),
        ("keyring.backends.macOS", "macOS"),
        ("keyring.backends.Windows", "Windows Vault"),
    ],
)
def test_probe_accepts_supported_os_backend_families(
    monkeypatch: pytest.MonkeyPatch,
    module: str,
    backend_name: str,
) -> None:
    class Backend:
        priority = 1

    Backend.__module__ = module
    fake = FakeKeyring(Backend())
    install_keyring(monkeypatch, fake)

    info = KeyringVault("service").probe()

    assert info == SecretBackendInfo(
        kind="keyring",
        available=True,
        backend=backend_name,
        reason=None,
    )
    assert fake.calls == []


@pytest.mark.parametrize(
    ("module", "priority", "reason"),
    [
        ("keyring.backends.fail", 0, "no-backend"),
        ("keyrings.alt.file", 1, "backend-rejected"),
        ("keyring.backends.chainer", 1, "backend-rejected"),
    ],
)
def test_probe_reports_no_backend_and_rejected_backends(
    monkeypatch: pytest.MonkeyPatch,
    module: str,
    priority: int,
    reason: str,
) -> None:
    class Backend:
        pass

    Backend.__module__ = module
    Backend.priority = priority
    fake = FakeKeyring(Backend())
    install_keyring(monkeypatch, fake)

    info = KeyringVault("service").probe()

    assert info.available is False
    assert info.backend is None
    assert info.reason == reason
    assert fake.calls == []


def test_probe_sanitizes_locked_backend_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class LockedBackend:
        @property
        def priority(self) -> int:
            raise RuntimeError("private backend failure")

    LockedBackend.__module__ = "keyring.backends.SecretService"
    fake = FakeKeyring(LockedBackend())
    install_keyring(monkeypatch, fake)

    info = KeyringVault("service").probe()

    assert info.available is False
    assert info.reason == "backend-locked"
    assert "private backend failure" not in repr(info)
    assert fake.calls == []


def test_probe_sanitizes_backend_initialization_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_loading() -> ModuleType:
        raise SecretStoreUnavailableError("private backend failure")

    monkeypatch.setattr(KeyringVault, "_load_keyring", staticmethod(fail_loading))

    info = KeyringVault("service").probe()

    assert info.available is False
    assert info.reason == "backend-error"
    assert "private backend failure" not in repr(info)


def test_keyring_delete_backend_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeKeyring()
    install_keyring(monkeypatch, fake)
    fake.delete_error = RuntimeError("private backend failure")

    with pytest.raises(SecretStoreUnavailableError) as error:
        KeyringVault("service").delete_secret("alice")

    assert "private backend failure" not in str(error.value)
    assert fake.calls == [("delete", "service")]
