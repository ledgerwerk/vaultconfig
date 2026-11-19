# Examples

These examples use APIs and commands included in VaultConfig. For complete behavior and security limits, see {doc}`quickstart`, {doc}`cli`, and {doc}`security`.

## Schema-marked sensitive configuration

A schema must explicitly mark a value sensitive. That value is then obscured when saved and revealed by `ConfigEntry.get`:

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
manager.add_config("database", {"password": "value supplied by the application"})

entry = manager.get_config("database")
if entry is not None:
    password = entry.get("password")
```

Obscuring is reversible and does not protect the value from someone who can read the file and use the package. Use encrypted storage when protection at rest is required.

## Import, inspect, and execute from the CLI

```bash
vaultconfig import --config-dir ./app-config database --from-file database.yaml
vaultconfig show --config-dir ./app-config database --output json
vaultconfig run --config-dir ./app-config --prefix DB_ database python app.py
```

The `run` prefix defaults to the empty string. Use `vaultconfig run --help` for the current options.

## Store a secret in a file vault

Initialize a new vault once, then explicitly unlock it for operations:

```python
from getpass import getpass
from pathlib import Path
from vaultconfig.secrets import FileVault

vault = FileVault(Path.home() / ".local/share/example/credentials.vault")
vault.initialize(getpass("Choose a passphrase: "))

with vault.open(getpass("Unlock the vault: ")) as store:
    store.set_secret("service-token", "value supplied by the application")
```

Initialization refuses to overwrite an existing vault. For repeatedly run programs, provision the vault separately and do not call `initialize` on every startup.

## Use an OS keyring

```python
from vaultconfig.secrets import KeyringVault

store = KeyringVault(service="example:mail")
store.set_secret("alice@example.net", "value supplied by the application")
secret = store.get_secret("alice@example.net")
```

Install `vaultconfig[keyring]` and configure an accepted native OS keyring before using this example. Keyring availability and access policy depend on the operating system and user session.
