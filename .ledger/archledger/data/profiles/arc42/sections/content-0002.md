---
schema_version: 4
id: content-0002
kind: content
type: section
section: architecture_constraints
title: Architecture Constraints
order: 20
status: accepted
version: 2
body_format: markdown
source_refs:
  - pyproject.toml
  - vaultconfig/formats
  - vaultconfig/crypt.py
  - vaultconfig/secrets/crypto.py
---

- The package supports Python 3.10 and later. TOML and INI are available in the core install. YAML requires the `yaml` extra.
- A `ConfigManager` uses one format per instance. The config name is the file stem, and the format handler supplies the allowed extensions. JSON is supported by shared mapping I/O, not as a managed configuration format.
- V1 configuration files and V2 secret vaults have separate wire formats. Neither implementation automatically migrates data to the other.
