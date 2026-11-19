"""Format handler implementations and registry."""

from __future__ import annotations

from vaultconfig.formats.base import ConfigFormat
from vaultconfig.formats.ini_format import INIFormat
from vaultconfig.formats.toml_format import TOMLFormat
from vaultconfig.formats.yaml_format import YAMLFormat

_FORMAT_HANDLERS: dict[str, type[ConfigFormat]] = {
    "toml": TOMLFormat,
    "ini": INIFormat,
    "yaml": YAMLFormat,
}


def supported_formats() -> tuple[str, ...]:
    """Return registered configuration format names."""
    return tuple(_FORMAT_HANDLERS)


def get_format_handler(format_name: str) -> ConfigFormat:
    """Create the registered handler for a format name."""
    try:
        handler = _FORMAT_HANDLERS[format_name]
    except KeyError:
        raise ValueError(f"Unsupported format: {format_name}") from None
    return handler()


def get_format_extensions(format_name: str) -> tuple[str, ...]:
    """Return extensions accepted for a registered format."""
    return get_format_handler(format_name).get_extensions()


def detect_format_from_extension(extension: str) -> str | None:
    """Return the format registered for a filename extension."""
    extension = extension.lower()
    for format_name in supported_formats():
        if extension in get_format_extensions(format_name):
            return format_name
    return None


__all__ = [
    "ConfigFormat",
    "INIFormat",
    "TOMLFormat",
    "YAMLFormat",
    "detect_format_from_extension",
    "get_format_extensions",
    "get_format_handler",
    "supported_formats",
]
