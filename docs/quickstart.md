# Quick start

This guide introduces the configuration API, sensitive-field handling, the CLI, and the
dedicated secret-storage API. For installation options, see {doc}`installation`.

## Manage configuration

`ConfigManager` reads and writes named configuration files. TOML is the default format
for the Python API; choose `ini` or `yaml` explicitly when needed. The YAML dependency
is optional.

```python
from pathlib import Path
from vaultconfig import ConfigManager

manager = ConfigManager(config_dir=Path("./app-config"), format="toml")
manager.add_config(
    "database",
    {"host": "localhost", "port": 5432},
)

entry = manager.get_config("database")
if entry is not None:
    print(entry.get("host"))
```

`add_config` creates or updates a named entry. Pass `overwrite=True` when replacing a
file that exists on disk but is not already loaded. `get_config` returns `None` when the
named file does not exist. Read failures for an existing file are reported rather than
treated as a missing configuration.

## Mark sensitive fields

Values are not classified as sensitive by their names. A schema must mark fields
explicitly. Marked string values are obscured when saved and revealed through the
`ConfigEntry` API. This is reversible concealment, not encryption.

```python
from pathlib import Path
from vaultconfig import ConfigManager, FieldDef, create_simple_schema

schema = create_simple_schema(
    {"password": FieldDef(str, sensitive=True)}
)
manager = ConfigManager(
    config_dir=Path("./app-config"),
    format="toml",
    schema=schema,
)
manager.add_config("database", {"password": "provided-at-runtime"})

entry = manager.get_config("database")
if entry is not None:
    password = entry.get("password")
```

For one-off CLI updates, `vaultconfig set --obscure` explicitly obscures the assigned
value. Do not treat either mechanism as protection from a person who can read the
configuration file and the package or key.

## Use the CLI

```bash
vaultconfig init --config-dir ./app-config --format toml
vaultconfig set --config-dir ./app-config --create database host=localhost port=5432
vaultconfig get --config-dir ./app-config database host
vaultconfig show --config-dir ./app-config database
```

`vaultconfig init` creates the directory and reports the format used for that
invocation. It does not persist a format setting or enable encryption. Use
`create --encrypted` or the `encrypt` commands for configuration-file encryption. See
{doc}`cli` for command signatures and option differences.

## Store application secrets separately

For new application secrets, use `FileVault` or, where an accepted native keyring is
configured, `KeyringVault`. A file vault must be initialized once and then explicitly
unlocked:

```python
from getpass import getpass
from pathlib import Path
from vaultconfig.secrets import FileVault

vault = FileVault(Path.home() / ".local/share/example/credentials.vault")
# Run only for a new vault. Existing vault files are not overwritten.
vault.initialize(getpass("Choose a vault passphrase: "))

with vault.open(getpass("Unlock the vault: ")) as store:
    store.set_secret("mail:alice@example.net", "application password")
```

The application obtains and supplies the passphrase. VaultConfig does not prompt or read
password environment variables implicitly for `FileVault`. See {doc}`secrets` for
recovery, permissions, keyring behavior, and limits.
