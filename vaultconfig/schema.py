"""Schema system for configuration validation using Pydantic."""

from __future__ import annotations

from collections.abc import Iterator
from types import UnionType
from typing import TYPE_CHECKING, Annotated, Any, Union, get_args, get_origin

if TYPE_CHECKING:
    from pydantic import BaseModel

try:
    from pydantic import BaseModel, ConfigDict, Field, ValidationError

    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    BaseModel = object  # type: ignore[assignment, misc]

    def Field(**kwargs: Any) -> Any:  # type: ignore[no-redef]
        """Stub for Field when pydantic is not available."""
        return

    ValidationError = Exception  # type: ignore[assignment, misc]
    ConfigDict = dict  # type: ignore[assignment, misc]

from vaultconfig.exceptions import SchemaValidationError


def _nested_model_annotations(
    annotation: Any, prefix: str
) -> Iterator[tuple[Any, str]]:
    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin is Annotated:
        yield from _nested_model_annotations(args[0], prefix)
    elif origin in (Union, UnionType):
        for argument in args:
            if argument is not type(None):
                yield from _nested_model_annotations(argument, prefix)
    elif origin is list:
        for argument in args:
            yield from _nested_model_annotations(argument, f"{prefix}.*")
    elif origin is dict and len(args) == 2:
        yield from _nested_model_annotations(args[1], f"{prefix}.*")
    elif isinstance(annotation, type):
        try:
            if issubclass(annotation, BaseModel):
                yield annotation, prefix
        except TypeError:
            return


def _get_sensitive_fields_for_model(
    model: Any, prefix: str = "", model_stack: frozenset[type] = frozenset()
) -> set[str]:
    """Recursively discover sensitive fields in a Pydantic model."""
    if not HAS_PYDANTIC or not hasattr(model, "model_fields") or model in model_stack:
        return set()

    sensitive: set[str] = set()
    model_stack = model_stack | {model}
    for field_name, field_info in model.model_fields.items():
        full_name = f"{prefix}.{field_name}" if prefix else field_name
        extra = field_info.json_schema_extra or {}
        if isinstance(extra, dict) and extra.get("sensitive", False):
            sensitive.add(full_name)

        for nested_model, nested_prefix in _nested_model_annotations(
            field_info.annotation, full_name
        ):
            sensitive |= _get_sensitive_fields_for_model(
                nested_model, nested_prefix, model_stack
            )
    return sensitive


class ConfigSchema:
    """Schema for configuration validation.

    This class provides a way to define and validate configuration structures
    using Pydantic models.
    """

    def __init__(self, model: Any) -> None:
        """Initialize schema with a Pydantic model.

        Args:
            model: Pydantic BaseModel class defining the schema

        Raises:
            ImportError: If Pydantic is not installed
        """
        if not HAS_PYDANTIC:
            raise ImportError(
                "Schema validation requires 'pydantic'. "
                "Install it with: pip install pydantic"
            )

        self.model = model

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate configuration data against schema.

        Args:
            data: Configuration data to validate

        Returns:
            Validated and normalized data

        Raises:
            SchemaValidationError: If validation fails
        """
        try:
            validated = self.model(**data)
            result: dict[str, Any] = validated.model_dump()
            return result
        except ValidationError as e:
            raise SchemaValidationError(f"Schema validation failed: {e}") from e
        except Exception as e:
            raise SchemaValidationError(f"Validation error: {e}") from e

    def get_sensitive_fields(self) -> set[str]:
        """Get set of sensitive field names that should be obscured.

        Recursively discovers sensitive fields in nested Pydantic models,
        returning dotted paths (e.g., ``'database.password'``).

        Returns:
            Set of dotted field paths marked as sensitive.
        """
        if not HAS_PYDANTIC:
            return set()

        return _get_sensitive_fields_for_model(self.model)

    def get_defaults(self) -> dict[str, Any]:
        """Get default values for all fields.

        Returns:
            Dictionary of field names to default values
        """
        defaults: dict[str, Any] = {}

        if not HAS_PYDANTIC:
            return defaults

        # Import PydanticUndefined to check for it
        from pydantic_core import PydanticUndefined as Undef

        for field_name, field_info in self.model.model_fields.items():
            if field_info.default is not Undef:
                defaults[field_name] = field_info.default
            elif field_info.default_factory is not None:
                defaults[field_name] = field_info.default_factory()

        return defaults


def create_simple_schema(fields: dict[str, FieldDef]) -> ConfigSchema:
    """Create a simple schema from field definitions.

    This is a helper function for creating schemas without writing
    full Pydantic models.

    Args:
        fields: Dictionary of field names to FieldDef objects

    Returns:
        ConfigSchema instance

    Raises:
        ImportError: If Pydantic is not installed

    Example:
        >>> schema = create_simple_schema({
        ...     "host": FieldDef(str, default="localhost"),
        ...     "port": FieldDef(int, default=5432),
        ...     "password": FieldDef(str, sensitive=True),
        ... })
    """
    if not HAS_PYDANTIC:
        raise ImportError(
            "Schema validation requires 'pydantic'. "
            "Install it with: pip install pydantic"
        )

    # Build field definitions for Pydantic
    pydantic_fields = {}
    for field_name, field_def in fields.items():
        field_kwargs: dict[str, Any] = {}

        if field_def.default is not ...:
            field_kwargs["default"] = field_def.default
        elif field_def.default_factory is not None:
            field_kwargs["default_factory"] = field_def.default_factory

        if field_def.description:
            field_kwargs["description"] = field_def.description

        # Add sensitive flag to json_schema_extra
        if field_def.sensitive:
            field_kwargs["json_schema_extra"] = {"sensitive": True}

        pydantic_fields[field_name] = (field_def.type, Field(**field_kwargs))

    # Create dynamic Pydantic model
    model = type(
        "DynamicConfigModel",
        (BaseModel,),
        {
            "__annotations__": {
                name: ftype for name, (ftype, _) in pydantic_fields.items()
            },
            **{name: fdef for name, (_, fdef) in pydantic_fields.items()},
            "model_config": ConfigDict(extra="allow"),
        },
    )

    return ConfigSchema(model)


class FieldDef:
    """Field definition for simple schema creation."""

    def __init__(
        self,
        type: type,
        default: Any = ...,
        default_factory: Any = None,
        sensitive: bool = False,
        description: str = "",
    ) -> None:
        """Initialize field definition.

        Args:
            type: Field type (e.g., str, int, bool)
            default: Default value (use ... for required fields)
            default_factory: Factory function for default value
            sensitive: If True, field will be obscured
            description: Field description
        """
        self.type = type
        self.default = default
        self.default_factory = default_factory
        self.sensitive = sensitive
        self.description = description
