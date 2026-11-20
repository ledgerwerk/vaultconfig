[![PyPI - Version](https://img.shields.io/pypi/v/vaultconfig)](https://pypi.org/project/vaultconfig/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/vaultconfig)
[![codecov](https://codecov.io/gh/holgern/vaultconfig/graph/badge.svg?token=iCHXwbjAXG)](https://codecov.io/gh/holgern/vaultconfig)

# VaultConfig

VaultConfig manages application configuration files and provides separate APIs for
storing secrets. It supports TOML and INI directly, with optional YAML support, schema
validation, a command-line interface, and authenticated encryption for configuration
files.

## Features

- Manage named TOML, INI, or optional YAML configurations.
- Validate configuration data with Pydantic-backed schemas.
- Explicitly obscure schema-marked values or values passed to the CLI with `--obscure`.
  Obscuring is not encryption.
- Read and write configuration files protected by authenticated encryption using the V1
  configuration-encryption format.
- Store opaque secrets separately with a passphrase-protected `FileVault` or an optional
  OS-backed `KeyringVault`.

## Installation

VaultConfig requires Python 3.10 or later.

```bash
pip install vaultconfig
pip install 'vaultconfig[yaml]'       # Optional YAML format support
pip install 'vaultconfig[keyring]'    # Optional KeyringVault integration
```

For development, tests, and documentation:

```bash
pip install -e '.[dev,docs,yaml,keyring]'
```

See [installation](docs/installation.md) for the extras and [secrets](docs/secrets.md)
for keyring requirements.

## Configuration quick start

```python
from pathlib import Path
from vaultconfig import ConfigManager

manager = ConfigManager(config_dir=Path("./app-config"), format="toml")
manager.add_config("database", {"host": "localhost", "port": 5432})

entry = manager.get_config("database")
if entry is not None:
    print(entry.get("host"))
```

A value is obscured only when a schema marks it sensitive or the caller explicitly
requests obscuring. Do not put credentials in an unencrypted configuration file. For the
CLI, use `vaultconfig set --obscure`; for application secrets, prefer the dedicated
secret-storage API.

## CLI quick start

```bash
vaultconfig init --config-dir ./app-config --format toml
vaultconfig set --config-dir ./app-config --create database host=localhost port=5432
vaultconfig get --config-dir ./app-config database host
```

`init` creates a configuration directory. It does not enable persistent encryption. See
[CLI reference](docs/cli.md) for encryption commands, option aliases, format detection,
and environment export.

## Dedicated secret storage

```python
from getpass import getpass
from pathlib import Path
from vaultconfig.secrets import FileVault

vault = FileVault(Path.home() / ".local/share/myapp/credentials.vault")
# Run once when creating a new vault. This refuses to overwrite an existing file.
vault.initialize(getpass("Choose a vault passphrase: "))

with vault.open(getpass("Unlock the vault: ")) as store:
    store.create_secret("service-token", "value supplied by your application")
```

`FileVault` is included in the normal installation. `KeyringVault` requires the
`keyring` extra and an accepted, configured native OS keyring. Neither backend makes
secrets safe from code or processes that can access them while the application is
running. See [secrets](docs/secrets.md) and [security guide](docs/security.md).

`create_secret` is FileVault-only and never replaces an existing name; use `set_secret`
when replacement is intended. `vault.inspect()` reports validated format, entry count,
and KDF metadata without unlocking the vault or exposing secret names and values.
FileVault requires a strong passphrase, not a short numeric PIN. Its Argon2id policy
remains 2 operations and 64 MiB, without changing the V2 format.

## Security boundaries

Password obscuring is reversible concealment for casual viewing, not encryption. The
default key is part of the package; a custom obscuring key does not turn this feature
into secret storage. Configuration-file encryption and the V2 `FileVault` format are
separate formats and APIs. VaultConfig does not automatically migrate values between
them.

See [security guide](docs/security.md) for the threat model, password handling, file
permissions, and recovery limits.

## Documentation

- [quick start](docs/quickstart.md)
- [CLI reference](docs/cli.md)
- [API reference](docs/api.md)
- [secrets](docs/secrets.md)
- [examples](docs/examples.md)

## Development

```bash
pip install -e '.[dev,docs,yaml,keyring]'
pytest
ruff check .
ruff format --check .
```

The project is licensed under the MIT License. See [LICENSE](LICENSE).
