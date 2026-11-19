---
schema_version: 4
id: content-0005
kind: content
type: section
section: building_block_view
title: Building Block View
order: 50
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/cli.py
  - vaultconfig/config.py
  - vaultconfig/formats
  - vaultconfig/io.py
  - vaultconfig/schema.py
  - vaultconfig/env_export.py
  - vaultconfig/secrets
---

| Component | Responsibility |
| --- | --- |
| `vaultconfig.cli` | Click entry point for configuration management, import and export, encryption, and process launch. |
| `ConfigManager` and `ConfigEntry` | Resolve and persist named files, cache loaded entries, and read values by dotted path. |
| `formats` and `io` | Adapt TOML, INI, and optional YAML to mappings. Shared I/O handles JSON as well. |
| `schema` | Wrap Pydantic validation and identify sensitive paths, including nested fields. |
| `crypt` and `obscure` | Encrypt complete configuration byte streams or reversibly conceal selected string values, respectively. |
| `env_export` | Flatten and filter configuration values and format them for shell export or use in a child process. |
| `secrets` | Define `SecretStore`, implement `FileVault` and `KeyringVault`, and keep envelope parsing, cryptography, and filesystem handling separate from the public API. |
