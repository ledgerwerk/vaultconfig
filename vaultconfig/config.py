"""Configuration management for vaultconfig."""

from __future__ import annotations

import copy
import logging
import os
import tempfile
from pathlib import Path, PurePath
from typing import Any

from vaultconfig import crypt, obscure
from vaultconfig.exceptions import (
    ConfigExistsError,
    ConfigNotFoundError,
    EncryptionError,
    FormatError,
    VaultConfigError,
)
from vaultconfig.formats import get_format_handler, supported_formats
from vaultconfig.schema import ConfigSchema

logger = logging.getLogger(__name__)
_MISSING = object()


def _matches_sensitive_field(key: str, sensitive_fields: set[str]) -> bool:
    key_parts = key.split(".")
    return any(
        len(field_parts := field.split(".")) == len(key_parts)
        and all(
            expected == "*" or expected == actual
            for expected, actual in zip(field_parts, key_parts, strict=True)
        )
        for field in sensitive_fields
    )


def _obscure_nested_value(
    data: dict[str, Any], field: str, obscurer: obscure.Obscurer
) -> None:
    """Obscure a value at a potentially nested (dotted) key path."""

    def obscure_value(value: Any, keys: list[str]) -> Any:
        if not keys:
            if isinstance(value, str) and not obscurer.is_obscured(value):
                return obscurer.obscure(value)
            return value

        key = keys[0]
        if key == "*":
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    value[child_key] = obscure_value(child_value, keys[1:])
            elif isinstance(value, list):
                for index, child_value in enumerate(value):
                    value[index] = obscure_value(child_value, keys[1:])
        elif isinstance(value, dict) and key in value:
            value[key] = obscure_value(value[key], keys[1:])
        elif isinstance(value, list) and key.isdecimal():
            index = int(key)
            if index < len(value):
                value[index] = obscure_value(value[index], keys[1:])
        return value

    obscure_value(data, field.split("."))


def _validate_config_name(name: str) -> str:
    """Validate and normalize a config name."""
    if not isinstance(name, str):
        raise FormatError("Config name must be a string")

    normalized = name.strip()
    if not normalized:
        raise FormatError("Config name cannot be empty")

    path = PurePath(normalized)
    if path.is_absolute() or len(path.parts) != 1 or ".." in path.parts:
        raise FormatError(f"Invalid config name: {name!r}")

    # Normalize behavior across platforms: reject all path separators.
    if "/" in normalized or "\\" in normalized:
        raise FormatError(f"Invalid config name: {name!r}")

    return normalized


def _write_temporary_file(path: Path, data: bytes) -> Path:
    """Write data to a private temporary file beside its target."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            if os.name != "nt":
                os.fchmod(temporary_file.fileno(), 0o600)
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        return temporary_path
    except OSError:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        raise


def _secure_write_file(path: Path, data: bytes) -> None:
    """Write a file atomically with secure permissions."""
    temporary_path: Path | None = None
    try:
        temporary_path = _write_temporary_file(path, data)
        os.replace(temporary_path, path)
    except OSError as e:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        raise OSError(f"Failed to write file {path}: {e}") from e


class ConfigEntry:
    """Configuration entry with metadata."""

    def __init__(
        self,
        name: str,
        data: dict[str, Any],
        sensitive_fields: set[str] | None = None,
        obscurer: obscure.Obscurer | None = None,
    ) -> None:
        """Initialize config entry.

        Args:
            name: Configuration name
            data: Configuration mapping
            sensitive_fields: Dotted sensitive paths to obscure
            obscurer: Optional obscurer used to reveal sensitive values
        """
        self.name = name
        self._data = data
        self._sensitive_fields = sensitive_fields or set()
        self._obscurer = obscurer if obscurer is not None else obscure.Obscurer()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value, revealing obscured passwords if needed."""
        keys = key.split(".")
        value: Any = self._data

        for path_part in keys:
            if isinstance(value, dict):
                value = value.get(path_part, _MISSING)
            elif isinstance(value, list) and path_part.isdecimal():
                index = int(path_part)
                value = value[index] if index < len(value) else _MISSING
            else:
                return default
            if value is _MISSING:
                return default

        if isinstance(value, str) and _matches_sensitive_field(
            key, self._sensitive_fields
        ):
            try:
                return self._obscurer.reveal(value)
            except ValueError:
                return value
        return value

    def get_all(self, reveal_secrets: bool = True) -> dict[str, Any]:
        """Get all configuration values, optionally revealing obscured secrets."""
        if not reveal_secrets:
            return copy.deepcopy(self._data)
        return {
            key: self._reveal_nested(value, key) for key, value in self._data.items()
        }

    def _reveal_nested(self, value: Any, prefix: str) -> Any:
        if isinstance(value, dict):
            return {
                key: self._reveal_nested(child, f"{prefix}.{key}")
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [
                self._reveal_nested(child, f"{prefix}.{index}")
                for index, child in enumerate(value)
            ]
        if isinstance(value, str) and (
            _matches_sensitive_field(prefix, self._sensitive_fields)
            or self._obscurer.is_obscured(value)
        ):
            try:
                return self._obscurer.reveal(value)
            except ValueError:
                return value
        return value


class ConfigManager:
    """Manager for configuration files with encryption and format support."""

    def __init__(
        self,
        config_dir: Path | str,
        format: str = "toml",
        schema: ConfigSchema | None = None,
        password: str | None = None,
        obscurer: obscure.Obscurer | None = None,
        auto_load: bool = True,
    ) -> None:
        """Initialize configuration manager.

        Args:
            config_dir: Directory for config files
            format: Config file format (toml, ini, or yaml)
            schema: Optional configuration schema
            password: Optional directory-level encryption password
            obscurer: Optional obscurer for sensitive values
            auto_load: Load existing configs during initialization

        Raises:
            FormatError: If format is not supported
        """
        self.config_dir = Path(config_dir).expanduser()
        self.schema = schema
        self._password = password  # Directory-level default password
        self._config_passwords: dict[str, str] = {}  # Per-config passwords
        self._obscurer = obscurer if obscurer is not None else obscure.Obscurer()
        self._configs: dict[str, ConfigEntry] = {}

        try:
            self._format_handler = get_format_handler(format)
        except ValueError as exc:
            raise FormatError(
                f"Unsupported format: {format}. "
                f"Supported formats: {', '.join(supported_formats())}"
            ) from exc
        self.format = format
        # Load existing configs (unless disabled)
        if auto_load:
            self._load_all()

    def _get_config_file(self, name: str) -> Path:
        """Get path to config file.

        Args:
            name: Config name

        Returns:
            Path to config file
        """
        safe_name = _validate_config_name(name)
        matches = [
            self.config_dir / f"{safe_name}{extension}"
            for extension in self._format_handler.get_extensions()
            if (self.config_dir / f"{safe_name}{extension}").is_file()
        ]
        if len(matches) > 1:
            raise FormatError(
                f"Multiple {self.format} files found for config '{safe_name}'"
            )
        if matches:
            return matches[0]
        return self.config_dir / f"{safe_name}{self._format_handler.get_extension()}"

    def _list_config_files(self) -> list[Path]:
        files = sorted(
            path
            for extension in self._format_handler.get_extensions()
            for path in self.config_dir.glob(f"*{extension}")
        )
        names: set[str] = set()
        for path in files:
            if path.stem in names:
                raise FormatError(
                    f"Multiple {self.format} files found for config '{path.stem}'"
                )
            names.add(path.stem)
        return files

    def _load_all(self) -> None:
        """Load all configuration files from directory."""
        if not self.config_dir.exists():
            logger.debug(f"Config directory not found: {self.config_dir}")
            return

        for config_file in self._list_config_files():
            name = config_file.stem
            try:
                self._load_config(name)
            except (OSError, ValueError, VaultConfigError) as e:
                logger.error(f"Failed to load config '{name}': {e}")

    def _load_config(self, name: str) -> None:
        """Load a single config file.

        Args:
            name: Config name

        Raises:
            ConfigNotFoundError: If config file doesn't exist
            DecryptionError: If decryption fails
            FormatError: If parsing fails
        """
        config_file = self._get_config_file(name)

        if not config_file.exists():
            raise ConfigNotFoundError(f"Config '{name}' not found")

        # Read file
        with open(config_file, "rb") as f:
            data = f.read()

        # Decrypt if encrypted
        if crypt.is_encrypted(data):
            # Try to get password in priority order:
            # 1. Per-config password (already in memory)
            # 2. Environment variable VAULTCONFIG_PASSWORD_<CONFIGNAME>
            # 3. Directory-level password
            # 4. Prompt user
            password = self._config_passwords.get(name)

            if password is None:
                # Try environment variable for this specific config
                env_var = f"VAULTCONFIG_PASSWORD_{name.upper()}"
                password = os.environ.get(env_var)
                if password:
                    self._config_passwords[name] = password

            if password is None:
                # Try directory-level password
                password = self._password

            if password is None:
                # Prompt user with config-specific message
                password = crypt.get_password(f"Password for config '{name}': ")
                # Store for this session
                self._config_passwords[name] = password

            data = crypt.decrypt(data, password)

        # Parse config
        config_str = data.decode("utf-8")
        config_data = self._format_handler.load(config_str)

        # Validate schema if provided
        if self.schema:
            config_data = self.schema.validate(config_data)

        # Get sensitive fields
        sensitive_fields = set()
        if self.schema:
            sensitive_fields = self.schema.get_sensitive_fields()

        self._configs[name] = ConfigEntry(
            name, config_data, sensitive_fields, self._obscurer
        )
        logger.debug(f"Loaded config '{name}' from {config_file}")

    def _serialize_config(self, name: str, password: str | None) -> bytes:
        if name not in self._configs:
            raise ConfigNotFoundError(f"Config '{name}' not found")

        config_entry = self._configs[name]
        config_str = self._format_handler.dump(config_entry._data)
        data = config_str.encode("utf-8")
        if password is not None:
            data = crypt.encrypt(data, password)
        return data

    def _write_configs_transactionally(self, serialized: dict[str, bytes]) -> None:
        staged: dict[Path, Path] = {}
        backups: dict[Path, Path] = {}
        replaced: list[Path] = []
        preserved_backups: set[Path] = set()
        try:
            for name, data in serialized.items():
                target = self._get_config_file(name)
                staged[target] = _write_temporary_file(target, data)

            for target in staged:
                backups[target] = _write_temporary_file(target, target.read_bytes())

            for target, temporary_path in staged.items():
                os.replace(temporary_path, target)
                replaced.append(target)
        except OSError as exc:
            rollback_failed = False
            for target in reversed(replaced):
                backup = backups.pop(target)
                try:
                    os.replace(backup, target)
                except OSError:
                    rollback_failed = True
                    preserved_backups.add(backup)
                    logger.exception(
                        "Could not restore config file %s; backup retained at %s",
                        target,
                        backup,
                    )
            if rollback_failed:
                raise EncryptionError(
                    "Failed to roll back a multi-config update; "
                    "private backups were retained"
                ) from exc
            raise
        finally:
            for temporary_path in (*staged.values(), *backups.values()):
                if temporary_path in preserved_backups:
                    continue
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    logger.warning(
                        "Could not remove temporary config file %s: %s",
                        temporary_path,
                        cleanup_error,
                    )

    def _save_config(self, name: str) -> None:
        """Serialize and save a single config file."""
        password = self._config_passwords.get(name, self._password)
        data = self._serialize_config(name, password)
        config_file = self._get_config_file(name)
        _secure_write_file(config_file, data)
        logger.debug(f"Saved config '{name}' to {config_file}")

    def list_configs(self) -> list[str]:
        """List all configured names (only loaded configs).

        Returns:
            List of config names that have been successfully loaded
        """
        return list(self._configs.keys())

    def list_config_files(self) -> list[str]:
        """List all config file names without loading them.

        Returns:
            List of all config file names found in the directory
        """
        if not self.config_dir.exists():
            return []

        return [path.stem for path in self._list_config_files()]

    def get_config(self, name: str) -> ConfigEntry | None:
        """Get a configuration by name, loading it if it exists on disk."""
        safe_name = _validate_config_name(name)
        if safe_name not in self._configs:
            if not self._get_config_file(safe_name).is_file():
                return None
            self._load_config(safe_name)
        return self._configs[safe_name]

    def has_config(self, name: str) -> bool:
        """Check whether a configuration file exists on disk."""
        return self._get_config_file(name).is_file()

    def add_config(
        self,
        name: str,
        config: dict[str, Any],
        obscure_passwords: bool = True,
        overwrite: bool = False,
    ) -> None:
        """Add or update a configuration.

        Args:
            name: Config name
            config: Configuration dictionary
            obscure_passwords: Whether to obscure sensitive fields

        Raises:
            ConfigExistsError: If config exists and you want to prevent overwrite
            FormatError: If config format is invalid
        """
        safe_name = _validate_config_name(name)

        config_file = self._get_config_file(safe_name)
        if config_file.is_file() and safe_name not in self._configs and not overwrite:
            raise ConfigExistsError(f"Config '{safe_name}' already exists")
        # Validate schema if provided
        if self.schema:
            config = self.schema.validate(config)

        # Get sensitive fields
        sensitive_fields = set()
        if self.schema:
            sensitive_fields = self.schema.get_sensitive_fields()

        # Obscure sensitive fields
        if obscure_passwords and sensitive_fields:
            config = config.copy()
            for field in sensitive_fields:
                _obscure_nested_value(config, field, self._obscurer)

        self._configs[safe_name] = ConfigEntry(
            safe_name, config, sensitive_fields, self._obscurer
        )
        self._save_config(safe_name)

        logger.info(f"Added config '{safe_name}'")

    def remove_config(self, name: str) -> bool:
        """Remove a configuration.

        Args:
            name: Config name

        Returns:
            True if config was removed, False if not found
        """
        safe_name = _validate_config_name(name)

        if safe_name not in self._configs:
            return False

        # Delete file
        config_file = self._get_config_file(safe_name)
        if config_file.exists():
            config_file.unlink()

        del self._configs[safe_name]
        logger.info(f"Removed config '{safe_name}'")
        return True

    def set_encryption_password(self, password: str) -> None:
        """Set or change the encryption password transactionally."""
        serialized = {
            name: self._serialize_config(
                name, self._config_passwords.get(name, password)
            )
            for name in self.list_configs()
        }
        try:
            self._write_configs_transactionally(serialized)
        except OSError as exc:
            raise EncryptionError(
                f"Failed to update encryption password: {exc}"
            ) from exc
        self._password = password
        logger.info("Updated encryption password for all configs")

    def remove_encryption(self) -> None:
        """Remove encryption from all configs transactionally."""
        serialized = {
            name: self._serialize_config(name, None) for name in self.list_configs()
        }
        self._write_configs_transactionally(serialized)
        self._password = None
        self._config_passwords.clear()
        logger.info("Removed encryption from all configs")

    def is_encrypted(self) -> bool:
        """Check if configs are encrypted (directory-level).

        Returns:
            True if directory-level encryption is enabled
        """
        return self._password is not None

    def encrypt_config(self, name: str, password: str) -> None:
        """Encrypt a specific config with its own password."""
        if name not in self._configs:
            raise ConfigNotFoundError(f"Config '{name}' not found")

        data = self._serialize_config(name, password)
        _secure_write_file(self._get_config_file(name), data)
        self._config_passwords[name] = password
        logger.info(f"Encrypted config '{name}'")

    def decrypt_config(self, name: str) -> None:
        """Remove encryption from a specific config."""
        if name not in self._configs:
            raise ConfigNotFoundError(f"Config '{name}' not found")

        data = self._serialize_config(name, None)
        _secure_write_file(self._get_config_file(name), data)
        self._config_passwords.pop(name, None)
        logger.info(f"Decrypted config '{name}'")

    def is_config_encrypted(self, name: str) -> bool:
        """Check if a specific config file is encrypted.

        Args:
            name: Config name

        Returns:
            True if config file is encrypted

        Raises:
            ConfigNotFoundError: If config file doesn't exist
        """
        config_file = self._get_config_file(name)

        if not config_file.exists():
            raise ConfigNotFoundError(f"Config '{name}' not found")

        with open(config_file, "rb") as f:
            data = f.read()

        return crypt.is_encrypted(data)

    def get_encryption_status(self) -> dict[str, bool]:
        """Get encryption status for all configs.

        Returns:
            Dictionary mapping config name to encryption status
        """
        status = {}
        for config_file in self._list_config_files():
            name = config_file.stem
            try:
                with open(config_file, "rb") as f:
                    data = f.read()
                status[name] = crypt.is_encrypted(data)
            except OSError as e:
                logger.error(f"Failed to check encryption for '{name}': {e}")
                status[name] = False

        return status
