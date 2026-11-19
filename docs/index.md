# VaultConfig documentation

VaultConfig manages named application configuration files and provides a separate API for storing secrets. TOML and INI are available with the core installation. YAML support is optional.

Configuration values are not automatically protected just because they are passwords. Schema-marked sensitive fields and explicit CLI obscuring use reversible concealment. Use configuration-file encryption or the dedicated secret-storage APIs when protection at rest is required.

## Short example

This doctest creates a temporary TOML configuration, reads it back, and removes the temporary directory when finished:

```{doctest}
>>> from tempfile import TemporaryDirectory
>>> from vaultconfig import ConfigManager
>>> with TemporaryDirectory() as directory:
...     manager = ConfigManager(directory)
...     manager.add_config("demo", {"endpoint": "https://example.test"})
...     entry = manager.get_config("demo")
...     print(entry.get("endpoint"))
https://example.test
```

```{toctree}
:maxdepth: 2
:caption: User guide

installation
quickstart
cli
security
secrets
examples
```

```{toctree}
:maxdepth: 2
:caption: API reference

api
```
