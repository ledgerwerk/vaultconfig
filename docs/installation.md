# Installation

VaultConfig supports Python 3.10 and later. Install the core package with pip:

```bash
pip install vaultconfig
```

The core installation includes TOML and INI handlers. Install optional integrations only
when needed.

## Optional extras

```bash
pip install 'vaultconfig[yaml]'      # YAML configuration files
pip install 'vaultconfig[keyring]'   # KeyringVault integration
```

YAML files may use either `.yaml` or `.yml`. `KeyringVault` also requires an available
native OS keyring backend accepted by VaultConfig. Installing the Python integration
does not configure the operating-system keyring.

## Development and documentation

The `dev` extra provides pytest, pytest-cov, Ruff, mypy, pre-commit, build, twine, and
PyYAML. The `docs` extra provides Sphinx, MyST, the Read the Docs theme, autodoc type
hints, and image support. These extras are separate.

From a source checkout, install the complete contributor environment with:

```bash
pip install -e '.[dev,docs,yaml,keyring]'
```

To install only the documentation dependencies:

```bash
pip install -e '.[docs]'
```

Build the HTML documentation from the repository root with:

```bash
python docs/make.py html
```

Or use `make -C docs html` on systems with GNU Make. Both paths run Sphinx in nitpicky,
warnings-as-errors mode.

## Verify the installation

```bash
vaultconfig --help
python -c 'from vaultconfig import ConfigManager; print(ConfigManager)'
```

For secret-store prerequisites and platform limits, see {doc}`secrets`.
