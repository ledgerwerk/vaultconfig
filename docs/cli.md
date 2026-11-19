# Command-line reference

The `vaultconfig` command manages configuration files. Run `vaultconfig --help` or `vaultconfig <command> --help` for the options supported by the installed version.

## Directory and format selection

If no directory is supplied, the CLI uses its platform default: `~/.config/vaultconfig` on Linux and macOS, or `%APPDATA%\vaultconfig` on Windows. `VAULTCONFIG_DIR` overrides that default.

Commands expose different directory option aliases: for example, `init` and `set` use `-d`, while `get`, `create`, and `export` use `-C`. Most accept the long option `--config-dir`; `list` instead uses `--dir` and also accepts a positional directory. Check the command-specific help rather than assuming short aliases are uniform.

Commands that autodetect the configuration format accept a single format in the directory. If multiple formats are present, specify `--format`. TOML is used as the default when no format is detected. Managed YAML files support `.yaml` and `.yml`.

## Create and read configurations

```bash
vaultconfig init --config-dir ./app-config --format toml
vaultconfig set --config-dir ./app-config --create database host=localhost port=5432
vaultconfig get --config-dir ./app-config database host
vaultconfig show --config-dir ./app-config database --output json
vaultconfig list --dir ./app-config --output plain
```

`init` creates the directory and reports the format used for that invocation. It does not persist a format setting or enable encryption. `set --create` creates the configuration when it is absent. `get` and `show` can reveal values that were previously obscured when passed `--reveal`.

Use `--obscure` only when you explicitly want reversible concealment of an assigned string:

```bash
vaultconfig set --config-dir ./app-config --obscure database password=VALUE
```

This is not a substitute for encrypted storage. Avoid placing literal credentials in shell history.

## Import and export

```bash
vaultconfig import --config-dir ./app-config database --from-file database.json
vaultconfig export --config-dir ./app-config database --export-format json --output database.json
```

Import accepts JSON, YAML, TOML, or INI. It autodetects the input format when `--import-format` is omitted and refuses to replace an existing configuration unless `--overwrite` is supplied. Export supports JSON, YAML, and TOML. Both commands support repeated `--include` and `--exclude` filters; export also supports `--reveal`.

## Execute with environment variables

`run` flattens nested values, normalizes dotted and hyphenated keys to underscores, and converts keys to uppercase by default. Its prefix defaults to the empty string, not the configuration name.

```bash
vaultconfig run --config-dir ./app-config --prefix DB_ database python app.py
vaultconfig run --config-dir ./app-config --no-uppercase database python app.py
vaultconfig run --config-dir ./app-config --no-override database python app.py
```

`export-env` supports Bash, Zsh, Fish, Nushell, and PowerShell. Use `--dry-run` to inspect a preview before evaluating generated shell commands. Its default prefix is also empty.

```bash
vaultconfig export-env --config-dir ./app-config database --prefix DB_ --shell bash --dry-run
```

Both `run` and `export-env` support `--uppercase` and `--no-uppercase`.

## Configuration-file encryption

The CLI provides V1 configuration-file encryption separately from directory initialization. `create --encrypted` creates one encrypted configuration. `encrypt set` sets or changes directory-level encryption for the loaded configurations; `encrypt check` reports status, and `encrypt remove` removes encryption. The `encrypt-file`, `decrypt-file`, `encrypt-dir`, and `decrypt-dir` commands offer file- and directory-level operations.

```bash
vaultconfig create --config-dir ./app-config --encrypted database
vaultconfig encrypt set --config-dir ./app-config
vaultconfig encrypt check --config-dir ./app-config
```

Password prompts and password-related environment variables are described in {doc}`security`. V1 configuration encryption is distinct from the V2 `FileVault` format.

## Command groups

| Command | Purpose |
| --- | --- |
| `init`, `create`, `set`, `unset`, `delete` | Create and change configuration files and values |
| `list`, `show`, `get` | Inspect configurations and values |
| `import`, `export` | Read and write interchange formats |
| `run`, `export-env` | Provide configuration values to processes or shells |
| `encrypt`, `encrypt-file`, `encrypt-dir` | Encrypt configuration files |
| `decrypt-file`, `decrypt-dir` | Remove configuration-file encryption |
| `encryption` | Show encryption status |
| `copy`, `rename` | Copy or rename a configuration |
| `validate` | Validate a configuration against a YAML or JSON schema |
| `obscure generate-key` | Generate a custom key for reversible obscuring |

For the exact options and defaults, use the CLI help for each command.
