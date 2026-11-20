# API reference

## Configuration API

```{autoclass} vaultconfig.ConfigManager
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.ConfigEntry
:members:
:show-inheritance:
```

## Schema API

```{autoclass} vaultconfig.ConfigSchema
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.FieldDef
:members:
:show-inheritance:
```

```{autofunction} vaultconfig.create_simple_schema

```

## Secret-storage API

The public secret-storage classes and protocol are documented in {doc}`secrets`.

`vaultconfig.secrets.DEFAULT_MIN_PASSPHRASE_LENGTH` is the public default value (12).
Passphrase length-policy violations raise the structured `VaultPassphrasePolicyError`, a
`VaultError` subclass.

```{autoclass} vaultconfig.secrets.FileVault
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.secrets.VaultPassphrasePolicyError
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.secrets.KeyringVault
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.secrets.SecretStore
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.secrets.FileVaultInfo
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.secrets.SecretBackendInfo
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.secrets.CreateOnlySecretStore
:members:
:show-inheritance:
```

```{autoclass} vaultconfig.secrets.SecretExistsError
:members:
:show-inheritance:
```

## Encryption and obscuring

```{automodule} vaultconfig.crypt
:members:
:undoc-members:
```

```{automodule} vaultconfig.obscure
:members:
:undoc-members:
```

## Migration from 0.2.x

The 0.3 line adds the separate `vaultconfig.secrets` API. Existing V1 configuration
encryption remains a distinct format; VaultConfig does not convert V1 files to V2 secret
vaults automatically.

`vaultconfig init` creates a directory. Its `--format` option applies to that invocation
and is not saved as a directory setting. If automation previously passed
`init --encrypt`, remove that option and choose an explicit configuration-encryption
operation such as `create --encrypted` or `encrypt set`.

The `ConfigManager` API remains available. Review the command-specific help when
updating scripts because directory option aliases differ by command. The `run` command
supports both `--uppercase` and `--no-uppercase`; the default environment-variable
prefix is empty.
