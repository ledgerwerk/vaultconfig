"""VaultConfig configuration management and secret storage.

Legacy configuration exports are loaded on first access so importing the
secret-storage API does not import CLI or schema dependencies.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from vaultconfig._version import __version__

_EXPORTS: dict[str, tuple[str, str | None]] = {
    "ConfigEntry": (".config", "ConfigEntry"),
    "ConfigManager": (".config", "ConfigManager"),
    "ConfigSchema": (".schema", "ConfigSchema"),
    "FieldDef": (".schema", "FieldDef"),
    "Obscurer": (".obscure", "Obscurer"),
    "create_obscurer_from_hex": (".obscure", "create_obscurer_from_hex"),
    "create_obscurer_from_passphrase": (".obscure", "create_obscurer_from_passphrase"),
    "create_obscurer_from_bytes": (".obscure", "create_obscurer_from_bytes"),
    "create_simple_schema": (".schema", "create_simple_schema"),
    "crypt": (".crypt", None),
    "obscure": (".obscure", None),
    "VaultConfigError": (".exceptions", "VaultConfigError"),
    "EncryptionError": (".exceptions", "EncryptionError"),
    "DecryptionError": (".exceptions", "DecryptionError"),
    "InvalidPasswordError": (".exceptions", "InvalidPasswordError"),
    "FormatError": (".exceptions", "FormatError"),
    "SchemaValidationError": (".exceptions", "SchemaValidationError"),
    "ConfigNotFoundError": (".exceptions", "ConfigNotFoundError"),
    "ConfigExistsError": (".exceptions", "ConfigExistsError"),
}

__all__ = [
    "ConfigEntry",
    "ConfigExistsError",
    "ConfigManager",
    "ConfigNotFoundError",
    "ConfigSchema",
    "DecryptionError",
    "EncryptionError",
    "FieldDef",
    "FormatError",
    "InvalidPasswordError",
    "Obscurer",
    "SchemaValidationError",
    "VaultConfigError",
    "__version__",
    "create_obscurer_from_bytes",
    "create_obscurer_from_hex",
    "create_obscurer_from_passphrase",
    "create_simple_schema",
    "crypt",
    "obscure",
]


def __getattr__(name: str) -> Any:
    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    module = import_module(module_name, __name__)
    value = module if attribute is None else getattr(module, attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
